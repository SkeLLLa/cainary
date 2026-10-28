//! device scanner (rules.md §DV): MDM presence, PPPC grants, system extensions, web content
//! filter, the system proxy and package registries redirected to a local proxy. Never opens the
//! networkextension plists, Keychains or TCC.db.

use crate::harness::platform::Os;
use crate::harness::{Loc, Probe, ScanCtx};
use crate::model::{FindingBuilder, Origin, Signal, Source, SourceKind};
use crate::redact;
use crate::value::{Format, Value};

const REF_TCC: &str = "https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.TCC.configuration-profile-policy.yaml";
const REF_ELECTRON: &str = "https://www.electronjs.org/docs/latest/api/net";
const REF_VSCODE: &str = "https://code.visualstudio.com/docs/setup/network#_proxy-server-support";
const REF_CARGO: &str = "https://doc.rust-lang.org/cargo/reference/source-replacement.html";
const REF_PIP: &str = "https://pip.pypa.io/en/stable/topics/configuration/";
const REF_UV: &str = "https://docs.astral.sh/uv/concepts/configuration-files/";
const REF_GO: &str = "https://go.dev/ref/mod#environment-variables";
const REF_NUGET: &str = "https://learn.microsoft.com/en-us/nuget/reference/nuget-config-file";
const REF_NPM: &str = "https://docs.npmjs.com/cli/v10/using-npm/config#registry";
const REF_YARN: &str = "https://yarnpkg.com/configuration/yarnrc#npmRegistryServer";
const MANAGED: &str = "/Library/Managed Preferences";
const MAX_DOMAINS: usize = 40;

pub fn scan(ctx: &mut ScanCtx) {
    match ctx.h().os {
        Os::Macos => {
            managed_domains(ctx);
            pppc(ctx);
            system_extensions(ctx);
            web_filter(ctx);
            macos_proxy(ctx);
            registries(ctx);
            ctx.note("Whether a corporate root certificate is trusted can't be seen; cAInary doesn't read the Keychain.");
            ctx.note(
                "Permissions you granted yourself live in TCC.db, which needs Full Disk Access.",
            );
        }
        Os::Linux => {
            linux_proxy(ctx);
            registries(ctx);
            ctx.note("Linux has no standard device-management store; only /etc/environment proxies are checked.");
        }
    }
}

/// Public vendors by bundle-id prefix (lower case), for the monitor entry name.
const VENDORS: &[(&str, &str)] = &[
    ("com.crowdstrike.", "CrowdStrike Falcon"),
    ("com.paloaltonetworks.", "Palo Alto GlobalProtect"),
    ("com.zscaler.", "Zscaler"),
    ("com.netskope.", "Netskope"),
    ("com.sentinelone.", "SentinelOne"),
    ("com.microsoft.wdav", "Microsoft Defender"),
    ("com.jamf", "Jamf"),
    ("com.kandji", "Kandji"),
];

/// The same vendors by path component prefix (lower case), so a profile granting both the
/// bundle id and the binary path (`/usr/local/jamf/bin/jamf`) gives one monitor entry.
const VENDOR_PATHS: &[(&str, &str)] = &[
    ("crowdstrike", "CrowdStrike Falcon"),
    ("falcon.app", "CrowdStrike Falcon"),
    ("globalprotect", "Palo Alto GlobalProtect"),
    ("paloalto", "Palo Alto GlobalProtect"),
    ("zscaler", "Zscaler"),
    ("netskope", "Netskope"),
    ("sentinelone", "SentinelOne"),
    ("sentinel-agent", "SentinelOne"),
    ("microsoft defender", "Microsoft Defender"),
    ("jamf", "Jamf"),
    ("kandji", "Kandji"),
];

/// The monitor entry a bundle id or binary path belongs to: the vendor tables, else the
/// containing `.app` or `Application Support` directory name for a path, else the binary's
/// parent directory name (`/tmp/AcmeCollector/collector` → "AcmeCollector"), else the vendor
/// component of the bundle id (`com.acme.agent` → "Acme").
fn agent_name(id: &str) -> String {
    let lower = id.to_lowercase();
    if let Some((_, name)) = VENDORS.iter().find(|(p, _)| lower.starts_with(p)) {
        return (*name).to_string();
    }
    if id.contains('/') {
        let parts: Vec<&str> = id.split('/').filter(|p| !p.is_empty()).collect();
        let vendor = lower.split('/').find_map(|p| {
            VENDOR_PATHS
                .iter()
                .find(|(prefix, _)| p.starts_with(prefix))
                .map(|(_, name)| *name)
        });
        if let Some(name) = vendor {
            return name.to_string();
        }
        let app = parts.iter().find_map(|p| p.strip_suffix(".app"));
        let support = parts
            .iter()
            .position(|p| *p == "Application Support")
            .and_then(|i| parts.get(i + 1));
        // A plain binary groups with its product directory, unless that is a generic bin dir.
        let parent = parts
            .len()
            .checked_sub(2)
            .map(|i| parts[i])
            .filter(|p| !matches!(*p, "bin" | "sbin" | "libexec"));
        return app
            .or(support.copied())
            .or(parent)
            .or(parts.last().copied())
            .unwrap_or(id)
            .to_string();
    }
    let parts: Vec<&str> = id.split('.').collect();
    let vendor = match parts[..] {
        [tld, vendor, ..] if tld.len() <= 3 => vendor,
        [vendor, ..] => vendor,
        [] => id,
    };
    let mut chars = vendor.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_else(|| id.to_string())
}

fn named(agent: &Option<String>, b: FindingBuilder) -> FindingBuilder {
    match agent {
        Some(name) => b.agent(name.clone()),
        None => b,
    }
}

fn mdm_file(loc: &Loc) -> Source {
    Source::new(loc.shown.clone(), Origin::Mdm, SourceKind::File)
}

fn managed_domains(ctx: &mut ScanCtx) {
    let dir = ctx.h().sys(MANAGED);
    let names: Vec<String> = ctx
        .list(&dir, ".plist", Origin::Mdm)
        .iter()
        .filter_map(|l| l.shown.rsplit('/').next())
        .map(|n| n.trim_end_matches(".plist").to_string())
        .collect();
    if names.is_empty() {
        return;
    }
    ctx.emit(
        FindingBuilder::new(format!(
            "This Mac is managed: {} configuration domains",
            names.len()
        ))
        .evidence(
            names
                .iter()
                .take(MAX_DOMAINS)
                .map(|n| format!("domain = {n}")),
        )
        .agent("Device management")
        .source(Source::new(dir.shown, Origin::Mdm, SourceKind::Dir)),
    );
}

/// `Identifier` and the team id from `CodeRequirement`'s `subject.OU] = "<team>"`.
fn grantee(entry: &Value) -> String {
    let id = entry
        .get("Identifier")
        .and_then(Value::as_str)
        .unwrap_or("an app");
    let team = entry
        .get("CodeRequirement")
        .and_then(Value::as_str)
        .and_then(|r| r.split_once("subject.OU] = \"").map(|(_, rest)| rest))
        .and_then(|rest| rest.split('"').next());
    match team {
        Some(t) => format!("{id} (team {t})"),
        None => id.to_string(),
    }
}

fn pppc(ctx: &mut ScanCtx) {
    let loc = ctx
        .h()
        .sys("/Library/Managed Preferences/com.apple.TCC.configuration-profile-policy.plist");
    let Some(doc) = ctx.read(&loc, Origin::Mdm, Format::Plist) else {
        return;
    };
    // `Services` at the top level, and one level down in `PayloadContent[]`.
    let mut blocks = vec![&doc];
    blocks.extend(
        doc.get("PayloadContent")
            .and_then(Value::as_array)
            .into_iter()
            .flatten(),
    );
    let mut other = Vec::new();
    for block in blocks {
        for (service, entries) in block
            .get("Services")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            for entry in entries.as_array().into_iter().flatten() {
                let who = grantee(entry);
                let agent = entry
                    .get("Identifier")
                    .and_then(Value::as_str)
                    .map(agent_name);
                let auth = entry.get("Authorization").and_then(Value::as_str);
                let allowed = entry.get("Allowed").and_then(Value::as_bool);
                let evidence = vec![
                    format!("service = {service}"),
                    format!("grantee = {who}"),
                    format!(
                        "authorization = {}",
                        auth.unwrap_or(if allowed == Some(true) {
                            "Allowed"
                        } else {
                            "-"
                        })
                    ),
                ];
                let finding = |title: String| {
                    FindingBuilder::new(title)
                        .evidence(evidence.clone())
                        .source(mdm_file(&loc))
                        .reference(REF_TCC)
                };
                let is_allow = auth == Some("Allow") || (auth.is_none() && allowed == Some(true));
                let is_deny = auth == Some("Deny") || (auth.is_none() && allowed == Some(false));
                let user_choice = auth == Some("AllowStandardUserToSetSystemService");
                if is_deny {
                    ctx.emit(
                        finding(format!("MDM blocks {who} from {service}"))
                            .signals(&[Signal::Policy]),
                    );
                } else if is_allow && service == "SystemPolicyAllFiles" {
                    ctx.emit(
                        named(&agent, finding(format!("{who} can read all your files")))
                            .signals(&[Signal::DeviceAccess]),
                    );
                } else if is_allow && service == "Accessibility" {
                    ctx.emit(
                        named(&agent, finding(format!("{who} can control your Mac")))
                            .signals(&[Signal::DeviceAccess]),
                    );
                } else if user_choice && service == "ScreenCapture" {
                    ctx.emit(
                        named(
                            &agent,
                            finding(format!("{who} may be able to record your screen")),
                        )
                        .signals(&[Signal::DeviceAccess])
                        .best_effort(true),
                    );
                } else if user_choice && service == "ListenEvent" {
                    ctx.emit(
                        named(
                            &agent,
                            finding(format!("{who} may be able to watch your keyboard input")),
                        )
                        .signals(&[Signal::DeviceAccess])
                        .best_effort(true),
                    );
                } else if is_allow || user_choice {
                    other.push(format!("{who}: {service}"));
                }
            }
        }
    }
    if !other.is_empty() {
        ctx.emit(
            FindingBuilder::new(format!(
                "A profile allows {} other privacy permission{}",
                other.len(),
                if other.len() == 1 { "" } else { "s" }
            ))
            .evidence(other)
            .source(mdm_file(&loc))
            .reference(REF_TCC),
        );
    }
}

fn system_extensions(ctx: &mut ScanCtx) {
    let policy_loc = ctx
        .h()
        .sys("/Library/Managed Preferences/com.apple.system-extension-policy.plist");
    let policy = ctx.read(&policy_loc, Origin::Mdm, Format::Plist);
    let db_loc = ctx.h().sys("/Library/SystemExtensions/db.plist");
    let Some(db) = ctx.read(&db_loc, Origin::System, Format::Plist) else {
        return;
    };
    let allowed_team = |team: &str, id: &str| {
        let Some(p) = &policy else { return false };
        let listed = p
            .get("AllowedTeamIdentifiers")
            .and_then(Value::as_array)
            .is_some_and(|a| a.iter().any(|t| t.as_str() == Some(team)));
        let by_id = p
            .get("AllowedSystemExtensions")
            .and_then(|m| m.get(team))
            .and_then(Value::as_array)
            .is_some_and(|a| a.iter().any(|t| t.as_str() == Some(id)));
        listed || by_id
    };
    for ext in db
        .get("extensions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if ext.get("state").and_then(Value::as_str) != Some("activated_enabled") {
            continue;
        }
        let id = ext
            .get("identifier")
            .and_then(Value::as_str)
            .unwrap_or("a system extension");
        let team = ext
            .get("teamID")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let origin = if allowed_team(team, id) {
            Origin::Mdm
        } else {
            Origin::User
        };
        let cats: Vec<&str> = ext
            .get("categories")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let has = |c: &str| cats.iter().any(|x| x.contains(c));
        let source = Source::new(db_loc.shown.clone(), origin, SourceKind::File);
        let evidence = vec![format!("extension = {id}"), format!("team = {team}")];
        let agent = ext
            .get("identifier")
            .and_then(Value::as_str)
            .map(agent_name);
        if has("network_extension") {
            ctx.emit(
                named(
                    &agent,
                    FindingBuilder::new(format!(
                        "{id} may inspect or redirect network traffic, including AI tools'"
                    )),
                )
                .signals(&[Signal::Traffic])
                .best_effort(true)
                .evidence(evidence.clone())
                .source(source.clone()),
            );
        }
        if has("endpoint_security") {
            ctx.emit(
                named(
                    &agent,
                    FindingBuilder::new(format!("{id} can observe app launches and file access")),
                )
                .signals(&[Signal::DeviceAccess])
                .best_effort(true)
                .evidence(evidence)
                .source(source),
            );
        }
    }
}

fn web_filter(ctx: &mut ScanCtx) {
    let loc = ctx
        .h()
        .sys("/Library/Managed Preferences/com.apple.webcontent-filter.plist");
    if matches!(
        ctx.marker(&loc, Origin::Mdm),
        Probe::Missing | Probe::Failed
    ) {
        return;
    }
    ctx.emit(
        FindingBuilder::new("Your organization installed a web content filter")
            .agent("Web content filter")
            .signals(&[Signal::Traffic])
            .best_effort(true)
            .source(Source::new(loc.shown, Origin::Mdm, SourceKind::Marker)),
    );
}

fn on(proxy: &Value, key: &str) -> bool {
    match proxy.get(key) {
        Some(Value::Number(n)) => n.as_i64() == Some(1),
        Some(Value::String(s)) => s == "1",
        _ => false,
    }
}

fn text(proxy: &Value, key: &str) -> String {
    match proxy.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => String::new(),
    }
}

fn macos_proxy(ctx: &mut ScanCtx) {
    let Some(p) = ctx.system_proxy() else { return };
    let mut hosts = Vec::new();
    for (flag, host, port) in [
        ("HTTPEnable", "HTTPProxy", "HTTPPort"),
        ("HTTPSEnable", "HTTPSProxy", "HTTPSPort"),
        ("SOCKSEnable", "SOCKSProxy", "SOCKSPort"),
    ] {
        if on(&p, flag) {
            hosts.push(format!("{}:{}", text(&p, host), text(&p, port)));
        }
    }
    if on(&p, "ProxyAutoConfigEnable") {
        let url = text(&p, "ProxyAutoConfigURLString");
        hosts.push(format!(
            "the PAC file at {}",
            redact::url_host(&url).unwrap_or_else(|| "an unknown host".to_string())
        ));
    }
    if on(&p, "ProxyAutoDiscoveryEnable") {
        hosts.push("an auto-discovered proxy (WPAD)".to_string());
    }
    if hosts.is_empty() {
        return;
    }
    let mut evidence: Vec<String> = hosts.iter().map(|h| format!("proxy = {h}")).collect();
    if let Some(list) = p.get("ExceptionsList").and_then(Value::as_array) {
        evidence.push(format!("ExceptionsList = {} entries", list.len()));
    }
    proxy_finding(
        ctx,
        &hosts,
        evidence,
        Source::new("scutil --proxy", Origin::Unattributed, SourceKind::Command),
    );
}

/// Linux: `http_proxy`/`https_proxy`/`all_proxy` in `/etc/environment`, either case.
fn linux_proxy(ctx: &mut ScanCtx) {
    let loc = ctx.h().sys("/etc/environment");
    let Some(env) = ctx.read(&loc, Origin::System, Format::Env) else {
        return;
    };
    let mut hosts: Vec<String> = Vec::new();
    let mut evidence = Vec::new();
    for name in ["http_proxy", "https_proxy", "all_proxy"] {
        for key in [name.to_string(), name.to_uppercase()] {
            let Some(url) = env
                .get(&key)
                .and_then(Value::as_str)
                .filter(|u| !u.is_empty())
            else {
                continue;
            };
            let host = redact::url_host(url)
                .unwrap_or_else(|| url.rsplit_once(':').map_or(url, |(h, _)| h).to_string());
            evidence.push(format!("{key} = {}", redact::url(url)));
            if !hosts.contains(&host) {
                hosts.push(host);
            }
        }
    }
    if hosts.is_empty() {
        return;
    }
    proxy_finding(
        ctx,
        &hosts,
        evidence,
        Source::new(loc.shown, Origin::System, SourceKind::File),
    );
}

fn proxy_finding(ctx: &mut ScanCtx, hosts: &[String], evidence: Vec<String>, source: Source) {
    ctx.emit(
        FindingBuilder::new(format!(
            "Network traffic may go through a proxy at {}",
            hosts.join(", ")
        ))
        .agent("Network proxy")
        .signals(&[Signal::Traffic])
        .detail(
            "Electron apps (Claude Desktop, Cursor, VS Code) follow the system proxy; \
             command-line tools do only if they honor it.",
        )
        .best_effort(true)
        .evidence(evidence)
        .source(source)
        .reference(if ctx.h().os == Os::Macos {
            REF_ELECTRON
        } else {
            REF_VSCODE
        }),
    );
}

/// A package manager pointed at a registry on this machine.
struct Hit {
    manager: &'static str,
    /// The local registry URL as written (it may carry userinfo; only shown through `redact`).
    url: String,
    evidence: Vec<String>,
    source: Source,
    reference: &'static str,
    credentials: bool,
}

/// The first entry of a registry setting (`GOPROXY` is a `,`/`|` list) whose host is this machine.
fn local_url(value: &str) -> Option<&str> {
    value.split([',', '|']).map(str::trim).find(|u| {
        redact::url_host(u)
            .is_some_and(|h| matches!(h.to_lowercase().as_str(), "127.0.0.1" | "localhost" | "::1"))
    })
}

fn has_userinfo(url: &str) -> bool {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest[..rest.find('/').unwrap_or(rest.len())].contains('@')
}

/// `host:port` of a URL, userinfo dropped.
fn authority(url: &str) -> String {
    let shown = redact::url(url);
    let rest = shown.split_once("://").map_or(shown.as_str(), |(_, r)| r);
    rest[..rest.find('/').unwrap_or(rest.len())].to_string()
}

fn hit(
    manager: &'static str,
    key: &str,
    value: &str,
    source: Source,
    reference: &'static str,
) -> Option<Hit> {
    let url = local_url(value)?;
    Some(Hit {
        manager,
        url: url.to_string(),
        evidence: vec![format!("{key} = {}", redact::url(url))],
        source,
        reference,
        credentials: has_userinfo(url),
    })
}

/// A config file the user can't edit was put there by someone else.
fn file_source(ctx: &ScanCtx, loc: &Loc) -> Source {
    let origin = if ctx.locked(loc) {
        Origin::OrgInstalled
    } else {
        Origin::Unattributed
    };
    Source::new(loc.shown.clone(), origin, SourceKind::File)
}

/// Stat first so a machine without the file doesn't grow an `absent` source.
fn read_present(ctx: &mut ScanCtx, loc: &Loc, fmt: Format) -> Option<Value> {
    if matches!(ctx.probe(loc), Probe::Missing) {
        return None;
    }
    ctx.read(loc, Origin::Unattributed, fmt)
}

/// The first of `vars` that is set: an environment value beats any config file.
fn env_var(ctx: &ScanCtx, vars: &[&'static str]) -> Option<(&'static str, String)> {
    vars.iter()
        .find_map(|v| ctx.h().env(v).map(|val| (*v, val.to_string())))
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter()
        .try_fold(v, |v, k| v.get(*k))
        .and_then(Value::as_str)
}

/// The value of `<name> = ...` or `<name>: ...` at the start of a line, quotes stripped.
fn line_value<'a>(text: &'a str, name: &str, sep: char) -> Option<&'a str> {
    text.lines().find_map(|l| {
        let v = l.strip_prefix(name)?.trim_start().strip_prefix(sep)?;
        Some(v.trim().trim_matches(['"', '\'']))
    })
}

/// `attr="value"` inside one XML tag line.
fn xml_attr<'a>(line: &'a str, attr: &str) -> Option<&'a str> {
    let rest = line.split_once(&format!("{attr}=\""))?.1;
    rest.split('"').next()
}

fn cargo_hit(ctx: &mut ScanCtx) -> Option<Hit> {
    let base = ctx
        .h()
        .env("CARGO_HOME")
        .and_then(|p| ctx.h().usable_dir(p))
        .unwrap_or_else(|| ctx.h().home(".cargo"));
    for name in ["config.toml", "config"] {
        let loc = base.join(name);
        let Some(doc) = read_present(ctx, &loc, Format::Toml) else {
            continue;
        };
        let source = doc.get("source")?;
        let to = str_at(source, &["crates-io", "replace-with"])?;
        let registry = str_at(source, &[to, "registry"])?;
        let mut h = hit(
            "Cargo",
            &format!("source.{to}.registry"),
            registry,
            file_source(ctx, &loc),
            REF_CARGO,
        )?;
        h.evidence
            .insert(0, format!("source.crates-io.replace-with = {to}"));
        return Some(h);
    }
    None
}

fn pip_hit(ctx: &mut ScanCtx) -> Option<Hit> {
    if let Some((var, url)) = env_var(ctx, &["PIP_INDEX_URL"]) {
        return hit("pip", var, &url, ctx.env_source(var), REF_PIP);
    }
    let mut files = vec![
        ctx.h().xdg_config("pip/pip.conf"),
        ctx.h().home(".pip/pip.conf"),
    ];
    if ctx.h().os == Os::Macos {
        files.push(ctx.h().app_support("pip/pip.conf"));
    }
    files.iter().find_map(|loc| {
        let conf = read_present(ctx, loc, Format::Env)?;
        let url = conf.get("index-url")?.as_str()?;
        hit("pip", "index-url", url, file_source(ctx, loc), REF_PIP)
    })
}

fn uv_hit(ctx: &mut ScanCtx) -> Option<Hit> {
    if let Some((var, url)) = env_var(ctx, &["UV_DEFAULT_INDEX", "UV_INDEX_URL"]) {
        return hit("uv", var, &url, ctx.env_source(var), REF_UV);
    }
    let loc = ctx.h().xdg_config("uv/uv.toml");
    let doc = read_present(ctx, &loc, Format::Toml)?;
    let default_index = doc
        .get("index")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|i| i.get("default").and_then(Value::as_bool) == Some(true))
        .and_then(|i| i.get("url")?.as_str());
    let (key, url) = match (str_at(&doc, &["index-url"]), default_index) {
        (Some(u), _) => ("index-url", u),
        (None, Some(u)) => ("index.url", u),
        (None, None) => return None,
    };
    hit("uv", key, url, file_source(ctx, &loc), REF_UV)
}

fn go_hit(ctx: &mut ScanCtx) -> Option<Hit> {
    if let Some((var, url)) = env_var(ctx, &["GOPROXY"]) {
        return hit("Go", var, &url, ctx.env_source(var), REF_GO);
    }
    let loc = ctx.h().app_support("go/env");
    let env = read_present(ctx, &loc, Format::Env)?;
    hit(
        "Go",
        "GOPROXY",
        env.get("GOPROXY")?.as_str()?,
        file_source(ctx, &loc),
        REF_GO,
    )
}

fn nuget_hit(ctx: &mut ScanCtx) -> Option<Hit> {
    let loc = ctx.h().home(".nuget/NuGet/NuGet.Config");
    let text = read_present(ctx, &loc, Format::Text)?;
    let text = text.as_str()?;
    let (name, value) = text.lines().find_map(|l| {
        let l = l.trim();
        if !l.starts_with("<add ") {
            return None;
        }
        let value = xml_attr(l, "value")?;
        local_url(value)?;
        Some((xml_attr(l, "key")?, value))
    })?;
    let mut h = hit(
        "NuGet",
        &format!("packageSources.{name}"),
        value,
        file_source(ctx, &loc),
        REF_NUGET,
    )?;
    // Credentials are stored under an element named like the source, spaces as `_x0020_`.
    let element = format!("<{}>", name.replace(' ', "_x0020_"));
    h.credentials |= text
        .split_once("<packageSourceCredentials>")
        .is_some_and(|(_, creds)| creds.contains(&element));
    Some(h)
}

fn npm_hit(ctx: &mut ScanCtx) -> Option<Hit> {
    // `~/.npmrc` holds auth tokens and is on the credential deny-list, so only the
    // environment and Yarn's config are checked.
    if let Some((var, url)) = env_var(ctx, &["npm_config_registry", "NPM_CONFIG_REGISTRY"]) {
        return hit("npm", var, &url, ctx.env_source(var), REF_NPM);
    }
    let loc = ctx.h().home(".yarnrc.yml");
    let text = read_present(ctx, &loc, Format::Text)?;
    let url = line_value(text.as_str()?, "npmRegistryServer", ':')?;
    hit(
        "Yarn",
        "npmRegistryServer",
        url,
        file_source(ctx, &loc),
        REF_YARN,
    )
}

/// macOS: the root launchd daemon whose arguments listen on one of the registry ports, as
/// (monitor name, program).
fn daemon_owner(ctx: &mut ScanCtx, hits: &[Hit]) -> Option<(String, String)> {
    if ctx.h().os != Os::Macos {
        return None;
    }
    let ports: Vec<String> = hits
        .iter()
        .filter_map(|h| {
            authority(&h.url)
                .rsplit_once(':')
                .map(|(_, p)| format!(":{p}"))
        })
        .collect();
    let dir = ctx.h().sys("/Library/LaunchDaemons");
    for loc in ctx.list(&dir, ".plist", Origin::System) {
        let Some(doc) = ctx.read(&loc, Origin::System, Format::Plist) else {
            continue;
        };
        let args: Vec<&str> = doc
            .get("ProgramArguments")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let listens = args
            .iter()
            .flat_map(|a| a.split(|c: char| c.is_whitespace() || c == '='))
            .any(|t| ports.iter().any(|p| t.ends_with(p.as_str())));
        if let (true, Some(program)) = (listens, args.first()) {
            return Some((agent_name(program), (*program).to_string()));
        }
    }
    None
}

/// Package-manager registries redirected to a program on this machine: how an endpoint
/// "package firewall" sees (and can block) every package a developer downloads.
fn registries(ctx: &mut ScanCtx) {
    let hits: Vec<Hit> = [
        cargo_hit(ctx),
        pip_hit(ctx),
        uv_hit(ctx),
        go_hit(ctx),
        nuget_hit(ctx),
        npm_hit(ctx),
    ]
    .into_iter()
    .flatten()
    .collect();
    if hits.is_empty() {
        return;
    }
    let owner = daemon_owner(ctx, &hits);
    let agent = owner
        .as_ref()
        .map_or("Package registry proxy", |(name, _)| name.as_str());
    for mut h in hits {
        if let Some((_, program)) = &owner {
            h.evidence
                .push(format!("served by = {}", redact::command(program)));
        }
        let mut detail = "The names and versions of every package you download go to a program \
                          on this machine, which can log them or block them."
            .to_string();
        if h.credentials {
            h.evidence
                .push("credentials = present (not shown)".to_string());
            detail.push_str(" Credentials configured for this registry go to it too.");
        }
        ctx.emit(
            FindingBuilder::new(format!(
                "{} downloads go through a local proxy at {}",
                h.manager,
                authority(&h.url)
            ))
            .agent(agent)
            .signals(&[Signal::Traffic])
            .detail(detail)
            .evidence(h.evidence)
            .source(h.source)
            .reference(h.reference),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{agent_name, authority, has_userinfo, line_value, local_url, xml_attr};
    use crate::harness::Harness;
    use crate::model::Level;
    use crate::{ScanOptions, scan};
    use std::path::PathBuf;

    fn run(name: &str) -> crate::model::Report {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        scan(
            &Harness::from_fixture(&dir).unwrap(),
            &ScanOptions::default(),
        )
    }

    #[test]
    fn linux_checks_only_etc_environment() {
        let r = run("device-linux");
        let paths: Vec<&str> = r.sources.iter().map(|s| s.source.path.as_str()).collect();
        assert_eq!(paths, ["/etc/environment"]);
    }

    #[test]
    fn only_a_device_proxy_is_one_monitor_entry() {
        let r = run("device-only-proxy");
        assert!(r.apps.iter().all(|e| !e.installed));
        assert_eq!(r.status.level, Level::Medium);
        let ids: Vec<&str> = r.others.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["network-proxy", "device"]);
    }

    #[test]
    fn local_registry_urls() {
        for (v, want) in [
            (
                "sparse+http://127.0.0.1:4874/cargo/",
                Some("sparse+http://127.0.0.1:4874/cargo/"),
            ),
            (
                "http://localhost:4874/go,direct",
                Some("http://localhost:4874/go"),
            ),
            (
                "https://proxy.golang.org|http://[::1]:4874/go",
                Some("http://[::1]:4874/go"),
            ),
            ("http://LOCALHOST/simple", Some("http://LOCALHOST/simple")),
            ("https://registry.example-corp.com/npm/", None),
            ("https://proxy.golang.org,direct", None),
            ("http://127.0.0.1.example-corp.com/", None),
            ("direct", None),
        ] {
            assert_eq!(local_url(v), want, "{v}");
        }
    }

    #[test]
    fn url_parts_for_registries() {
        assert!(has_userinfo("http://alice:pw@127.0.0.1:4874/x"));
        assert!(!has_userinfo("http://127.0.0.1:4874/a@b"));
        assert_eq!(
            authority("http://alice:pw@127.0.0.1:4874/x"),
            "127.0.0.1:4874"
        );
        assert_eq!(
            xml_attr(r#"<add key="A B" value="http://x/" />"#, "key"),
            Some("A B")
        );
        assert_eq!(
            line_value(
                "a: 1\nnpmRegistryServer: \"http://x/\"\n",
                "npmRegistryServer",
                ':'
            ),
            Some("http://x/")
        );
    }

    #[test]
    fn package_proxy_is_one_attributed_monitor_with_a_finding_per_manager() {
        let r = run("device-package-proxy");
        let ids: Vec<&str> = r.others.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["acmecollector", "device"]);
        let findings = &r.others[0].findings;
        let managers: Vec<&str> = findings
            .iter()
            .filter_map(|f| f.title.split(' ').next())
            .collect();
        assert_eq!(managers, ["Cargo", "NuGet", "pip", "uv", "Go"]);
        assert_eq!(r.status.level, Level::Medium);
        assert!(
            findings
                .iter()
                .all(|f| f.source.origin == crate::model::Origin::OrgInstalled
                    || f.title.starts_with("Go"))
        );
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("s3cret"), "credentials must not be shown");
        assert!(
            findings
                .iter()
                .any(|f| f.evidence.iter().any(|e| e.starts_with("credentials")))
        );
    }

    #[test]
    fn remote_registries_are_not_reported() {
        let r = run("device-package-proxy-remote");
        assert!(r.others.is_empty());
        assert_eq!(r.status.level, Level::NotInstalled);
    }

    #[test]
    fn vendor_table_names() {
        for (id, want) in [
            ("com.crowdstrike.falcon.Agent", "CrowdStrike Falcon"),
            ("com.paloaltonetworks.gp.pangpsd", "Palo Alto GlobalProtect"),
            ("com.zscaler.zscaler", "Zscaler"),
            ("com.netskope.client.auxsvc", "Netskope"),
            ("com.sentinelone.sentineld", "SentinelOne"),
            ("com.microsoft.wdav.epsext", "Microsoft Defender"),
            ("com.jamfsoftware.jamf.daemon", "Jamf"),
            ("com.jamf.management.Jamf", "Jamf"),
            ("/usr/local/jamf/bin/jamf", "Jamf"),
            (
                "/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/Jamf",
                "Jamf",
            ),
            ("com.kandji.profile", "Kandji"),
            (
                "/Applications/Falcon.app/Contents/MacOS/Falcon",
                "CrowdStrike Falcon",
            ),
            ("/Library/CS/../CrowdStrike/falcond", "CrowdStrike Falcon"),
            ("/Applications/GlobalProtect.app", "Palo Alto GlobalProtect"),
            ("/Applications/Zscaler/Zscaler.app", "Zscaler"),
            (
                "/Library/Application Support/Netskope/STAgent/Netskope Client.app",
                "Netskope",
            ),
            (
                "/Library/Sentinel/sentinel-agent.bundle/Contents/MacOS/sentineld",
                "SentinelOne",
            ),
            ("/Applications/Microsoft Defender.app", "Microsoft Defender"),
            ("/Library/Kandji/Kandji Agent.app", "Kandji"),
            ("COM.CrowdStrike.Falcon", "CrowdStrike Falcon"),
        ] {
            assert_eq!(agent_name(id), want, "{id}");
        }
    }

    #[test]
    fn derived_names() {
        for (id, want) in [
            ("com.acme.collector", "Acme"),
            ("io.example-corp.agent.sysext", "Example-corp"),
            ("acme.collector", "Acme"),
            (
                "/Library/Application Support/AcmeCollector/collector",
                "AcmeCollector",
            ),
            (
                "/Applications/Acme Guard.app/Contents/MacOS/guard",
                "Acme Guard",
            ),
            ("/usr/local/bin/acme-guard", "acme-guard"),
            ("/tmp/AcmeCollector/collector", "AcmeCollector"),
            ("collector", "Collector"),
        ] {
            assert_eq!(agent_name(id), want, "{id}");
        }
    }
}
