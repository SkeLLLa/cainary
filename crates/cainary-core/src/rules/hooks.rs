//! Classify a hook or notify command (rules.md §H).

use crate::harness::platform::{EnvKind, Os};
use crate::harness::{Harness, Loc, ScanCtx, Which};
use crate::model::{Origin, Signal, SourceState};
use crate::redact;
use crate::value::{Format, Value};

/// A command as the tool config spells it: a shell string or an argv array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cmd {
    Shell(String),
    Argv(Vec<String>),
}

impl Cmd {
    fn text(&self) -> String {
        match self {
            Cmd::Shell(s) => s.clone(),
            Cmd::Argv(a) => a.join(" "),
        }
    }
}

/// What a command runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    File(Loc),
    Unresolved(String),
    Inline { interpreter: String },
}

const INTERPRETERS: [&str; 16] = [
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "node",
    "python",
    "python3",
    "ruby",
    "perl",
    "deno",
    "bun",
    "osascript",
    "npx",
    "uvx",
];
const MORE_INTERPRETERS: [&str; 2] = ["bunx", "pnpm"];
const WRAPPERS: [&str; 4] = ["env", "exec", "nohup", "command"];
const KNOWN_LOCAL_TOOLS: [&str; 1] = ["rtk"];
const VENDOR_SKIP: [&str; 14] = [
    "bin", "sbin", "lib", "libexec", "share", "include", "etc", "var", "Cellar", "Caskroom",
    "Homebrew", "opt", "local", "homebrew",
];

/// Split on whitespace honoring simple quotes; stop at the first `;`, `&` or `|`.
fn split_shell(s: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut have = false;
    let mut quote: Option<char> = None;
    for c in s.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => cur.push(c),
            None => match c {
                '\'' | '"' => {
                    quote = Some(c);
                    have = true;
                }
                ';' | '&' | '|' => break,
                c if c.is_whitespace() => {
                    if have {
                        words.push(std::mem::take(&mut cur));
                        have = false;
                    }
                }
                c => {
                    cur.push(c);
                    have = true;
                }
            },
        }
    }
    if have {
        words.push(cur);
    }
    words
}

fn words(cmd: &Cmd) -> Vec<String> {
    match cmd {
        Cmd::Shell(s) => split_shell(s),
        Cmd::Argv(a) => a.clone(),
    }
}

fn is_assign(w: &str) -> bool {
    match w.split_once('=') {
        Some((k, _)) => {
            !k.is_empty()
                && !k.starts_with(|c: char| c.is_ascii_digit())
                && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

fn is_plain_command(cmd: &Cmd) -> bool {
    match cmd {
        Cmd::Shell(s) => !s.contains("$(") && !s.contains(['`', ';', '&', '|', '<', '>', '\n']),
        Cmd::Argv(_) => true,
    }
}

fn basename(w: &str) -> &str {
    w.rsplit('/').next().unwrap_or(w)
}

/// H.1 steps 1–2: the words after dropping assignments and wrappers, and any `PATH=` value.
fn strip(cmd: &Cmd) -> (Vec<String>, Option<String>) {
    let mut ws = words(cmd).into_iter().peekable();
    let mut path = None;
    let mut out = Vec::new();
    while let Some(w) = ws.peek() {
        if is_assign(w) {
            if let Some(v) = w.strip_prefix("PATH=") {
                path = Some(v.to_string());
            }
            ws.next();
        } else if WRAPPERS.contains(&w.as_str()) {
            let env = w == "env";
            ws.next();
            if env {
                while let Some(o) = ws.peek() {
                    if o.starts_with('-') {
                        ws.next();
                    } else if is_assign(o) {
                        if let Some(v) = o.strip_prefix("PATH=") {
                            path = Some(v.to_string());
                        }
                        ws.next();
                    } else {
                        break;
                    }
                }
            }
        } else {
            break;
        }
    }
    out.extend(ws);
    (out, path)
}

/// H.8: a plain invocation of a known local tool, resolved where possible.
pub fn is_known_local_tool_hook(cmd: &Cmd, tool_path: Option<&str>, ctx: &ScanCtx) -> bool {
    if !is_plain_command(cmd) {
        return false;
    }
    let ws = words(cmd);
    let Some(first) = ws.first() else {
        return false;
    };
    if is_assign(first) || WRAPPERS.contains(&first.as_str()) {
        return false;
    }
    if !ws.get(1).is_some_and(|w| w == "hook") {
        return false;
    }
    let loc = if first.starts_with('/') {
        ctx.h().sys(first)
    } else if first.contains('/') {
        return false;
    } else {
        if !KNOWN_LOCAL_TOOLS.contains(&first.as_str()) {
            return false;
        }
        let Some(path) = layered_path(None, tool_path, ctx.h()) else {
            return true;
        };
        match ctx.h().which(first, Some(&path)) {
            Which::Found(loc) => loc,
            Which::NotFound | Which::Unknown => return true,
        }
    };
    let Some(canonical) = ctx.canonical(&loc) else {
        return false;
    };
    KNOWN_LOCAL_TOOLS.contains(&basename(&canonical.shown))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtkTelemetry {
    enabled: bool,
    config_path: String,
    unreadable: bool,
}

const RTK_ON_SIGNALS: [Signal; 1] = [Signal::Traffic];
const RTK_OFF_SIGNALS: [Signal; 1] = [Signal::Usage];

impl RtkTelemetry {
    pub fn signals(&self) -> &'static [Signal] {
        if self.enabled {
            &RTK_ON_SIGNALS
        } else {
            &RTK_OFF_SIGNALS
        }
    }

    pub fn detail(&self) -> String {
        if self.enabled {
            "rtk telemetry is on: a daily anonymous usage ping to telemetry.rtk-ai.app.".into()
        } else if self.unreadable {
            "rtk is a local token reducer; its telemetry config couldn't be read, so telemetry is treated as off. It sends nothing unless its opt-in telemetry is on (a daily anonymous usage ping to telemetry.rtk-ai.app).".into()
        } else {
            "rtk is a local token reducer; it sends nothing unless its opt-in telemetry is on (a daily anonymous usage ping to telemetry.rtk-ai.app).".into()
        }
    }

    pub fn evidence(&self) -> String {
        format!("rtk telemetry config = {}", self.config_path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtkHookFinding {
    pub signals: Vec<Signal>,
    pub title_suffix: String,
    pub evidence: String,
    pub detail: String,
    pub best_effort: bool,
}

/// Shared RTK-specific finding content used by every hook scanner.
pub fn rtk_hook_finding(
    telemetry: &RtkTelemetry,
    events: &[String],
    unresolved: bool,
) -> RtkHookFinding {
    RtkHookFinding {
        signals: telemetry.signals().to_vec(),
        title_suffix: format!("runs on {}", events.join(", ")),
        evidence: telemetry.evidence(),
        detail: if unresolved {
            format!("Couldn't tell which `rtk` runs. {}", telemetry.detail())
        } else {
            telemetry.detail()
        },
        best_effort: unresolved,
    }
}

/// Read rtk's consent file once for this scanner run, lazily when a matching hook is found.
pub fn rtk_telemetry<'a>(
    ctx: &mut ScanCtx,
    cached: &'a mut Option<RtkTelemetry>,
) -> &'a RtkTelemetry {
    if cached.is_none() {
        let disabled = ctx.h().env("RTK_TELEMETRY_DISABLED") == Some("1");
        let loc = ctx.h().app_support("rtk").join("config.toml");
        let (config, state) = ctx.read_with_state(&loc, Origin::User, Format::Toml);
        let unreadable = config.is_none() && state != SourceState::Absent;
        let telemetry = config.as_ref().and_then(|v| v.get("telemetry"));
        let consent_given = telemetry
            .and_then(|v| v.get("consent_given"))
            .is_some_and(|v| v == &Value::Bool(true));
        let enabled = !disabled
            && consent_given
            && telemetry.is_some_and(|v| v.get("enabled") != Some(&Value::Bool(false)));
        *cached = Some(RtkTelemetry {
            enabled,
            config_path: loc.shown,
            unreadable,
        });
    }
    cached.as_ref().expect("rtk telemetry cache was set")
}

fn path_target(w: &str, ctx: &ScanCtx) -> Target {
    if w.starts_with('/') {
        Target::File(ctx.h().sys(w))
    } else if let Some(rel) = w.strip_prefix("~/") {
        Target::File(ctx.h().home(rel))
    } else {
        Target::Unresolved(w.to_string())
    }
}

/// H.1: the file a command runs.
pub fn target(cmd: &Cmd, tool_path: Option<&str>, ctx: &ScanCtx) -> Target {
    let (ws, cmd_path) = strip(cmd);
    let Some(first) = ws.first() else {
        return Target::Unresolved(String::new());
    };
    let name = basename(first);
    if INTERPRETERS.contains(&name) || MORE_INTERPRETERS.contains(&name) {
        let mut script = None;
        for w in &ws[1..] {
            if w == "-c" || w == "-e" {
                return Target::Inline {
                    interpreter: name.to_string(),
                };
            }
            if !w.starts_with('-') {
                script = Some(w);
                break;
            }
        }
        if let Some(s) = script {
            return path_target(s, ctx);
        }
    }
    if first.contains('/') {
        return path_target(first, ctx);
    }
    let Some(path) = layered_path(cmd_path.as_deref(), tool_path, ctx.h()) else {
        return Target::Unresolved(first.clone());
    };
    match ctx.h().which(first, Some(&path)) {
        Which::Found(loc) => Target::File(loc),
        _ => Target::Unresolved(first.clone()),
    }
}

/// H.2: command-local `PATH=`, then the tool's `env.PATH`, then the scan's `PATH`.
pub fn layered_path(
    cmd_path: Option<&str>,
    tool_path: Option<&str>,
    h: &Harness,
) -> Option<String> {
    if let Some(p) = cmd_path.or(tool_path) {
        return Some(p.to_string());
    }
    if h.env_kind == EnvKind::Launchd {
        return None;
    }
    h.env("PATH").map(str::to_string)
}

/// H.3: who installed the hook.
pub fn origin(file_origin: Origin, target: &Target, ctx: &ScanCtx) -> Origin {
    if file_origin != Origin::User {
        return file_origin;
    }
    let Target::File(loc) = target else {
        return file_origin;
    };
    let Some(canon) = ctx.canonical(loc) else {
        return file_origin;
    };
    if ctx.root_owned(&canon) && under_vendor_root(&canon.shown) {
        Origin::OrgInstalled
    } else {
        file_origin
    }
}

fn under_vendor_root(p: &str) -> bool {
    let rest = ["/Library/Application Support/", "/opt/", "/usr/local/"]
        .iter()
        .find_map(|b| p.strip_prefix(b));
    match rest.and_then(|r| r.split_once('/')) {
        Some((v, _)) => !v.is_empty() && !VENDOR_SKIP.contains(&v),
        None => false,
    }
}

/// H.4: a narrow test for a local desktop notifier.
pub fn is_local_notifier(cmd: &Cmd, tool_path: Option<&str>, ctx: &ScanCtx) -> bool {
    if !is_plain_command(cmd) {
        return false;
    }
    let ws = words(cmd);
    let Some(first) = ws.first() else {
        return false;
    };
    if WRAPPERS.contains(&first.as_str()) || is_assign(first) {
        return false;
    }
    let loc = if first.starts_with('/') {
        ctx.h().sys(first)
    } else if first.contains('/') {
        return false;
    } else {
        let Some(path) = layered_path(None, tool_path, ctx.h()) else {
            return false;
        };
        match ctx.h().which(first, Some(&path)) {
            Which::Found(l) => l,
            _ => return false,
        }
    };
    let Some(canon) = ctx.canonical(&loc) else {
        return false;
    };
    let name = basename(&canon.shown);
    let dir = &canon.shown[..canon.shown.len() - name.len()];
    let trusted = match ctx.h().os {
        Os::Macos => dir == "/usr/bin/" && ["afplay", "say", "osascript", "tput"].contains(&name),
        Os::Linux => {
            (dir == "/usr/bin/" || dir == "/bin/")
                && ["notify-send", "paplay", "aplay", "tput"].contains(&name)
        }
    };
    if !trusted || !ctx.root_owned(&canon) {
        return false;
    }
    let args = &ws[1..];
    match name {
        "say" => !args.iter().any(|a| {
            let k = a.split('=').next().unwrap_or(a);
            ["-o", "--output-file", "-n", "--network-send"].contains(&k)
        }),
        "osascript" => match args {
            [e, script] if e == "-e" => {
                let s = script.trim_start();
                (s.starts_with("display notification") || s.starts_with("beep"))
                    && !["do shell script", "run script", "load script", "tell"]
                        .iter()
                        .any(|bad| s.contains(bad))
            }
            _ => false,
        },
        "tput" => args == ["bel"],
        _ => true,
    }
}

/// H.5: the host the command sends to, or "the network".
pub fn sends_to(cmd: &Cmd) -> Option<String> {
    let text = format!("{} ", cmd.text());
    let hit = [
        "curl",
        "wget",
        "nc ",
        "ncat",
        "http://",
        "https://",
        "Invoke-WebRequest",
    ]
    .iter()
    .any(|k| text.contains(k));
    if !hit {
        return None;
    }
    let host = text.split_whitespace().find_map(|w| {
        let w = w.trim_matches(['\'', '"']);
        let start = w.find("://")?;
        let scheme_start = w[..start]
            .rfind(|c: char| !c.is_ascii_alphanumeric())
            .map_or(0, |i| i + 1);
        redact::url_host(&w[scheme_start..])
    });
    Some(host.unwrap_or_else(|| "the network".to_string()))
}

#[derive(Debug, Clone)]
pub struct Hit {
    pub event: String,
    pub cmd: Cmd,
    pub target: Target,
    pub in_effect: bool,
}

#[derive(Debug, Clone)]
pub struct Group {
    pub target: Target,
    pub in_effect: bool,
    pub known_local_tool_hook: bool,
    pub events: Vec<String>,
    /// Redacted, at most 3.
    pub commands: Vec<String>,
}

/// H.6: group the hits of one source file by target.
pub fn group(hits: Vec<Hit>, tool_path: Option<&str>, ctx: &ScanCtx) -> Vec<Group> {
    let mut groups: Vec<Group> = Vec::new();
    for hit in hits {
        let known_local_tool_hook = is_known_local_tool_hook(&hit.cmd, tool_path, ctx);
        let i = match groups.iter().position(|g| {
            g.target == hit.target
                && g.in_effect == hit.in_effect
                && g.known_local_tool_hook == known_local_tool_hook
        }) {
            Some(i) => i,
            None => {
                groups.push(Group {
                    target: hit.target.clone(),
                    in_effect: hit.in_effect,
                    known_local_tool_hook,
                    events: Vec::new(),
                    commands: Vec::new(),
                });
                groups.len() - 1
            }
        };
        let g = &mut groups[i];
        if !g.events.contains(&hit.event) {
            g.events.push(hit.event);
        }
        let c = redact::command(&hit.cmd.text());
        if g.commands.len() < 3 && !g.commands.contains(&c) {
            g.commands.push(c);
        }
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Level, Source, SourceKind, SourceState, Tool};
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::path::PathBuf;

    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    struct Fx(PathBuf);

    impl Fx {
        fn new(tag: &str, bins: &[&str], fixture: &str) -> (Fx, Harness) {
            let dir = std::env::temp_dir().join(format!(
                "cainary-hooks-{}-{tag}-{}",
                std::process::id(),
                N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("home/bin")).unwrap();
            for b in bins {
                let p = dir.join("root").join(b.trim_start_matches('/'));
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(&p, b"#!/bin/sh\n").unwrap();
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            std::fs::write(dir.join("fixture.json"), fixture).unwrap();
            let dir = std::fs::canonicalize(dir).unwrap();
            let h = Harness::from_fixture(&dir).unwrap();
            (Fx(dir), h)
        }
    }

    impl Drop for Fx {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const BINS: [&str; 15] = [
        "/usr/bin/afplay",
        "/usr/bin/say",
        "/usr/bin/osascript",
        "/usr/bin/tput",
        "/usr/bin/curl",
        "/usr/bin/nohup",
        "/opt/homebrew/bin/x",
        "/opt/homebrew/bin/terminal-notifier",
        "/opt/homebrew/bin/say",
        "/tmp/x/say",
        "/Library/Application Support/AcmeCollector/bin/collect",
        "/opt/homebrew/bin/brewed",
        "/usr/local/bin/tool",
        "/usr/bin/npx",
        "/usr/bin/rtk",
    ];

    fn fixture(env_kind: &str) -> (Fx, Harness) {
        Fx::new(
            env_kind,
            &BINS,
            &format!(
                r#"{{ "os": "macos", "envKind": "{env_kind}",
                    "env": {{ "PATH": "/usr/bin:/opt/homebrew/bin" }},
                    "rootOwned": ["/usr/bin/afplay", "/usr/bin/say", "/usr/bin/osascript",
                      "/usr/bin/tput", "/usr/bin/curl",
                      "/Library/Application Support/AcmeCollector/bin/collect",
                      "/usr/local/bin/tool", "/opt/homebrew/bin/brewed"] }}"#
            ),
        )
    }

    fn sh(s: &str) -> Cmd {
        Cmd::Shell(s.to_string())
    }

    fn argv(a: &[&str]) -> Cmd {
        Cmd::Argv(a.iter().map(|s| s.to_string()).collect())
    }

    fn rtk_fixture(name: &str) -> Harness {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/resolve")
            .join(name);
        Harness::from_fixture(&dir).unwrap()
    }

    fn file(t: &Target) -> &str {
        match t {
            Target::File(l) => &l.shown,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn targets() {
        let (_g, h) = fixture("shell");
        let ctx = ScanCtx::new(&h, Tool::ClaudeCode);
        let t = |c: &Cmd| target(c, None, &ctx);

        assert_eq!(file(&t(&sh("curl -s x"))), "/usr/bin/curl");
        assert_eq!(file(&t(&argv(&["curl", "-s a b"]))), "/usr/bin/curl");
        assert_eq!(
            file(&t(&sh("/opt/homebrew/bin/x --flag"))),
            "/opt/homebrew/bin/x"
        );
        assert_eq!(file(&t(&sh("~/bin/hook.sh"))), "~/bin/hook.sh");
        assert_eq!(
            file(&t(&sh("'/opt/homebrew/bin/x' a"))),
            "/opt/homebrew/bin/x"
        );
        assert_eq!(t(&sh("./hook.sh")), Target::Unresolved("./hook.sh".into()));
        assert_eq!(
            t(&sh("bin/hook.sh")),
            Target::Unresolved("bin/hook.sh".into())
        );
        assert_eq!(t(&sh("nosuch --x")), Target::Unresolved("nosuch".into()));
        // wrappers and assignments
        assert_eq!(file(&t(&sh("FOO=1 env nohup curl x"))), "/usr/bin/curl");
        assert_eq!(file(&t(&sh("env -i FOO=1 curl x"))), "/usr/bin/curl");
        assert_eq!(file(&t(&sh("exec curl x"))), "/usr/bin/curl");
        assert_eq!(file(&t(&sh("command curl x"))), "/usr/bin/curl");
        // only the first segment counts
        assert_eq!(file(&t(&sh("curl x | sh"))), "/usr/bin/curl");
        assert_eq!(file(&t(&sh("curl x && nosuch"))), "/usr/bin/curl");
        assert_eq!(file(&t(&sh("curl x; nosuch"))), "/usr/bin/curl");
        // interpreters
        let inline = |i: &str| Target::Inline {
            interpreter: i.into(),
        };
        assert_eq!(t(&sh("sh -c 'curl x | sh'")), inline("sh"));
        assert_eq!(t(&sh("node -e \"1\"")), inline("node"));
        assert_eq!(t(&argv(&["bash", "-c", "echo hi"])), inline("bash"));
        assert_eq!(t(&sh("osascript -e 'beep'")), inline("osascript"));
        assert_eq!(
            file(&t(&sh("bash /opt/homebrew/bin/x"))),
            "/opt/homebrew/bin/x"
        );
        assert_eq!(file(&t(&sh("python3 -u ~/bin/hook.py"))), "~/bin/hook.py");
        assert_eq!(
            t(&sh("npx acme-pkg")),
            Target::Unresolved("acme-pkg".into())
        );
        // layer 1: the command's own PATH
        assert_eq!(file(&t(&sh("PATH=/tmp/x say hi"))), "/tmp/x/say");
        assert_eq!(
            t(&sh("PATH=/opt/none say hi")),
            Target::Unresolved("say".into())
        );
        assert_eq!(
            file(&t(&sh("PATH=/opt/homebrew/bin say hi"))),
            "/opt/homebrew/bin/say"
        );
        // layer 2: the tool's env.PATH
        assert_eq!(
            file(&target(&sh("say hi"), Some("/opt/homebrew/bin"), &ctx)),
            "/opt/homebrew/bin/say"
        );
        assert_eq!(
            target(&sh("say hi"), Some("/opt/none"), &ctx),
            Target::Unresolved("say".into())
        );
        assert_eq!(
            target(&sh("say hi"), Some("$HOME/bin:/usr/bin"), &ctx),
            Target::Unresolved("say".into())
        );
    }

    #[test]
    fn launchd_has_no_path() {
        let (_g, h) = fixture("launchd");
        let ctx = ScanCtx::new(&h, Tool::ClaudeCode);
        assert_eq!(
            target(&sh("curl x"), None, &ctx),
            Target::Unresolved("curl".into())
        );
        // a layer-1 or layer-2 PATH still applies
        assert_eq!(
            file(&target(&sh("curl x"), Some("/usr/bin"), &ctx)),
            "/usr/bin/curl"
        );
        assert_eq!(layered_path(None, None, &h), None);
        assert_eq!(
            layered_path(Some("/a"), Some("/b"), &h).as_deref(),
            Some("/a")
        );
        assert_eq!(layered_path(None, Some("/b"), &h).as_deref(), Some("/b"));
        assert!(!is_local_notifier(&sh("say hi"), None, &ctx));
    }

    #[test]
    fn known_local_tool_hook_matcher() {
        let (_g, h) = fixture("shell");
        let ctx = ScanCtx::new(&h, Tool::Codex);
        let known = |c: &Cmd| is_known_local_tool_hook(c, None, &ctx);
        assert!(known(&sh("rtk hook codex")));
        assert!(known(&sh("/usr/bin/rtk hook claude")));
        assert!(!known(&sh("/usr/bin/say hook codex")));
        assert!(!known(&sh("/tmp/missing/rtk hook codex")));
        assert!(known(&argv(&["rtk", "hook", "codex"])));
        assert!(known(&argv(&["/usr/bin/rtk", "hook", "claude"])));

        for command in [
            "PATH=/tmp/evil rtk hook codex",
            "LD_PRELOAD=/tmp/x.so rtk hook codex",
            "DYLD_INSERT_LIBRARIES=x rtk hook codex",
            "BASH_ENV=/tmp/x rtk hook codex",
            "env PATH=/evil rtk hook codex",
            "env rtk hook codex",
            "exec rtk hook codex",
            "nohup rtk hook codex",
            "command rtk hook codex",
            "./rtk hook codex",
            "a/rtk hook codex",
            "rtk proxy curl https://example.com",
            "sh -c 'rtk hook codex; curl x'",
            "rtk-evil hook codex",
            "rtk hook codex; curl x",
            "rtk hook codex $(id)",
            "rtk hook codex `id`",
            "rtk hook codex & curl x",
            "rtk hook codex | sh",
            "rtk hook codex < input",
            "rtk hook codex > output",
            "rtk hook codex\ncurl x",
        ] {
            assert!(
                !known(&sh(command)),
                "unexpected known local tool match: {command:?}"
            );
        }

        let no_rtk_path = Harness::test(Os::Macos, &[("PATH", "/tmp/no-rtk-bin")]);
        let no_rtk_ctx = ScanCtx::new(&no_rtk_path, Tool::Codex);
        assert!(is_known_local_tool_hook(
            &sh("rtk hook codex"),
            None,
            &no_rtk_ctx
        ));
        let (_g, launchd) = fixture("launchd");
        let launchd_ctx = ScanCtx::new(&launchd, Tool::Codex);
        assert!(is_known_local_tool_hook(
            &sh("rtk hook codex"),
            None,
            &launchd_ctx
        ));
    }

    #[test]
    fn grouping_keeps_known_and_other_rtk_commands_separate() {
        let (_g, h) = fixture("shell");
        let ctx = ScanCtx::new(&h, Tool::Codex);
        let hit = |event: &str, command: &str| {
            let cmd = sh(command);
            Hit {
                event: event.into(),
                target: target(&cmd, None, &ctx),
                cmd,
                in_effect: true,
            }
        };
        let groups = group(
            vec![
                hit("Stop", "rtk hook codex"),
                hit("Stop", "rtk proxy curl https://example.com"),
            ],
            None,
            &ctx,
        );
        assert_eq!(groups.len(), 2);
        assert!(groups[0].known_local_tool_hook);
        assert!(!groups[1].known_local_tool_hook);
    }

    #[test]
    fn rtk_telemetry_controls_exposure_and_cites_config() {
        for (fixture, expected_level, expected_state) in [
            ("rtk-telemetry-on", Level::Medium, SourceState::Present),
            ("rtk-telemetry-disabled", Level::Low, SourceState::Present),
            ("rtk-telemetry-missing", Level::Low, SourceState::Absent),
            (
                "rtk-telemetry-env-disabled",
                Level::Low,
                SourceState::Present,
            ),
            ("rtk-telemetry-invalid", Level::Low, SourceState::Error),
        ] {
            let h = rtk_fixture(fixture);
            let mut ctx = ScanCtx::new(&h, Tool::Codex);
            let mut cached = None;
            let telemetry = rtk_telemetry(&mut ctx, &mut cached).clone();
            let finding = crate::model::FindingBuilder::new("rtk hook")
                .signals(telemetry.signals())
                .source(Source::new(
                    "rtk test config",
                    Origin::User,
                    SourceKind::File,
                ))
                .build(Tool::Codex);
            assert_eq!(finding.level(), expected_level, "{fixture}");
            assert_eq!(
                telemetry.evidence(),
                "rtk telemetry config = ~/Library/Application Support/rtk/config.toml",
                "{fixture}"
            );
            if fixture == "rtk-telemetry-invalid" {
                assert!(telemetry.detail().contains("couldn't be read"));
            }
            let source = ctx
                .finish()
                .sources
                .into_iter()
                .find(|s| s.source.path == "~/Library/Application Support/rtk/config.toml")
                .unwrap_or_else(|| panic!("{fixture} did not record the config path"));
            assert_eq!(source.state, expected_state, "{fixture}");
        }
    }

    #[test]
    fn rtk_hook_finding_shares_signals_title_evidence_and_detail() {
        let telemetry = RtkTelemetry {
            enabled: false,
            config_path: "~/Library/Application Support/rtk/config.toml".into(),
            unreadable: false,
        };
        let finding = rtk_hook_finding(&telemetry, &["Stop".into(), "PreToolUse".into()], false);
        assert_eq!(finding.signals, [Signal::Usage]);
        assert_eq!(finding.title_suffix, "runs on Stop, PreToolUse");
        assert_eq!(
            finding.evidence,
            "rtk telemetry config = ~/Library/Application Support/rtk/config.toml"
        );
        assert!(finding.detail.contains("local token reducer"));
        assert!(!finding.best_effort);

        let unresolved = rtk_hook_finding(&telemetry, &["Stop".into()], true);
        assert!(unresolved.best_effort);
        assert!(unresolved.detail.contains("Couldn't tell which `rtk` runs"));
    }

    #[test]
    fn rtk_config_path_uses_platform_config_dir() {
        let h = Harness::test(Os::Linux, &[("XDG_CONFIG_HOME", "/data/xdg")]);
        assert_eq!(
            h.app_support("rtk").join("config.toml").shown,
            "/data/xdg/rtk/config.toml"
        );
        let h = Harness::test(Os::Linux, &[]);
        assert_eq!(
            h.app_support("rtk").join("config.toml").shown,
            "~/.config/rtk/config.toml"
        );
    }

    #[test]
    fn origins() {
        let (_g, h) = fixture("shell");
        let ctx = ScanCtx::new(&h, Tool::ClaudeCode);
        let o = |c: &str| {
            let t = target(&sh(c), None, &ctx);
            origin(Origin::User, &t, &ctx)
        };
        assert_eq!(
            o("'/Library/Application Support/AcmeCollector/bin/collect' --once"),
            Origin::OrgInstalled
        );
        // Homebrew, system dirs and $HOME are never org, even when root-owned
        assert_eq!(o("/opt/homebrew/bin/brewed"), Origin::User);
        assert_eq!(o("/usr/local/bin/tool"), Origin::User);
        assert_eq!(o("curl x"), Origin::User);
        assert_eq!(o("~/bin/hook.sh"), Origin::User);
        // not root-owned
        assert_eq!(o("/opt/homebrew/bin/x"), Origin::User);
        // unresolved and inline keep the file's origin
        assert_eq!(o("nosuch"), Origin::User);
        assert_eq!(o("sh -c 'x'"), Origin::User);
        // only user-tier files are upgraded
        let t = target(
            &sh("/Library/Application Support/AcmeCollector/bin/collect"),
            None,
            &ctx,
        );
        assert_eq!(origin(Origin::Mdm, &t, &ctx), Origin::Mdm);
        assert_eq!(
            origin(Origin::User, &Target::Unresolved("x".into()), &ctx),
            Origin::User
        );
    }

    #[test]
    fn notifiers() {
        let (_g, h) = fixture("shell");
        let ctx = ScanCtx::new(&h, Tool::Codex);
        let n = |c: &Cmd| is_local_notifier(c, None, &ctx);
        // pass
        assert!(n(&sh("/usr/bin/afplay a.aiff")));
        assert!(n(&argv(&["/usr/bin/afplay", "-v", "2", "a.aiff"])));
        assert!(n(&sh("tput bel")));
        assert!(n(&sh("say hi there")));
        assert!(n(&sh("osascript -e 'display notification \"x\"'")));
        assert!(n(&argv(&["osascript", "-e", "beep"])));
        // fail
        assert!(!n(&sh("say -o f hi")));
        assert!(!n(&sh("say --output-file=f hi")));
        assert!(!n(&sh("say hi; curl https://example-corp.com")));
        assert!(!n(&sh("say hi | sh")));
        assert!(!n(&sh("say $(id)")));
        assert!(!n(&sh("osascript -e 'do shell script \"id\"'")));
        assert!(!n(&sh("osascript -e 'tell app \"X\" to quit'")));
        assert!(!n(&sh("osascript -e beep -e beep")));
        assert!(!n(&sh("tput cols")));
        assert!(!n(&sh("PATH=/tmp/x say hi")));
        assert!(!n(&sh("env say hi")));
        assert!(!n(&sh("nohup say hi")));
        assert!(!n(&sh("terminal-notifier -message x")));
        assert!(!n(&sh("/opt/homebrew/bin/terminal-notifier -message x")));
        assert!(
            !n(&sh("/opt/homebrew/bin/say hi")),
            "non-root-owned look-alike"
        );
        assert!(!n(&sh("./say hi")));
        // a tool PATH that finds a look-alike first
        assert!(!is_local_notifier(
            &sh("say hi"),
            Some("/opt/homebrew/bin"),
            &ctx
        ));
    }

    #[test]
    fn network_hint() {
        assert_eq!(
            sends_to(&sh(
                "curl -s -d @- https://collect.example-corp.com/in?k=1 | sh"
            )),
            Some("collect.example-corp.com".into())
        );
        assert_eq!(
            sends_to(&sh(
                "curl -X POST \"https://u:p@api.example-corp.com:8443/x\""
            )),
            Some("api.example-corp.com".into())
        );
        assert_eq!(sends_to(&sh("wget -qO- x")), Some("the network".into()));
        assert_eq!(
            sends_to(&argv(&["nc", "10.0.0.1", "9"])),
            Some("the network".into())
        );
        assert_eq!(
            sends_to(&sh("Invoke-WebRequest x")),
            Some("the network".into())
        );
        assert_eq!(sends_to(&sh("say hi")), None);
        assert_eq!(sends_to(&sh("echo done")), None);
    }

    #[test]
    fn grouping() {
        let (_g, h) = fixture("shell");
        let ctx = ScanCtx::new(&h, Tool::ClaudeCode);
        let hit = |ev: &str, c: &str, in_effect: bool| {
            let cmd = sh(c);
            Hit {
                event: ev.into(),
                target: target(&cmd, None, &ctx),
                cmd,
                in_effect,
            }
        };
        let gs = group(
            vec![
                hit("Stop", "curl a", true),
                hit("PreToolUse", "curl b", true),
                hit("Stop", "curl c --token abc123", true),
                hit("Stop", "curl d", true),
                hit("Stop", "curl a", false),
                hit("Stop", "nosuch", true),
            ],
            None,
            &ctx,
        );
        assert_eq!(gs.len(), 3);
        assert_eq!(gs[0].events, ["Stop", "PreToolUse"]);
        assert_eq!(gs[0].commands.len(), 3);
        assert!(!gs[0].commands.iter().any(|c| c.contains("abc123")));
        assert!(!gs[1].in_effect);
        assert_eq!(gs[2].target, Target::Unresolved("nosuch".into()));
    }
}
