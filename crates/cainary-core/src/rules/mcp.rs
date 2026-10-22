//! MCP server entry → finding (rules.md §H.7).

use crate::harness::ScanCtx;
use crate::model::{FindingBuilder, Origin, Signal};
use crate::redact;
use crate::rules::hooks::{self, Cmd, Target};
use crate::value::Value;

/// The finding for one MCP server entry. The caller adds `.source(…)`.
pub fn server(name: &str, entry: &Value, origin: Origin, ctx: &ScanCtx) -> FindingBuilder {
    let name = redact::text(name);
    let url = ["url", "http_url", "serverUrl"]
        .iter()
        .find_map(|k| entry.get(k).and_then(Value::as_str));
    let mut evidence = vec![format!("server = {name}")];
    let b = match url {
        Some(url) => {
            let host = redact::url_host(url).unwrap_or_else(|| "a remote host".into());
            evidence.push(format!("url = {}", redact::url(url)));
            for h in redact::header_names(entry.get("headers").unwrap_or(&Value::Null)) {
                evidence.push(format!("header {h} = <redacted>"));
            }
            FindingBuilder::new(format!(
                "MCP server `{name}` receives your tool requests at {host}"
            ))
            .signals(&[Signal::ToolDetails])
            .best_effort(true)
        }
        None => local(&name, entry, origin, ctx, &mut evidence),
    };
    if let Some(env) = entry.get("env").and_then(Value::as_object) {
        for (k, v) in env {
            evidence.push(format!("env {k} = {}", redact::value(k, v)));
        }
    }
    b.evidence(evidence)
}

fn local(
    name: &str,
    entry: &Value,
    origin: Origin,
    ctx: &ScanCtx,
    evidence: &mut Vec<String>,
) -> FindingBuilder {
    let command = entry.get("command").and_then(Value::as_str).unwrap_or("");
    let mut argv = vec![command.to_string()];
    if let Some(args) = entry.get("args").and_then(Value::as_array) {
        argv.extend(args.iter().filter_map(Value::as_str).map(str::to_string));
    }
    evidence.push(format!("command = {}", redact::command(&argv.join(" "))));
    let server_path = entry
        .get("env")
        .and_then(|e| e.get("PATH"))
        .and_then(Value::as_str);
    let target = hooks::target(&Cmd::Argv(argv), server_path, ctx);
    let base = match &target {
        Target::File(loc) => basename(&loc.shown),
        Target::Unresolved(s) => basename(s),
        Target::Inline { interpreter } => basename(interpreter),
    };
    let org = hooks::origin(origin, &target, ctx).is_org();
    let b = FindingBuilder::new(format!(
        "MCP server `{name}` runs {base} with your tool requests"
    ));
    if org {
        b.signals(&[Signal::ToolDetails]).best_effort(true)
    } else {
        b
    }
}

fn basename(s: &str) -> String {
    redact::text(s.rsplit('/').next().unwrap_or(s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::Harness;
    use crate::harness::platform::Os;
    use crate::model::{Source, SourceKind, Tool};
    use serde_json::json;

    fn run(h: &Harness, entry: Value, origin: Origin) -> crate::model::Finding {
        let ctx = ScanCtx::new(h, Tool::ClaudeCode);
        server("acme", &entry, origin, &ctx)
            .source(Source::new("test", origin, SourceKind::File))
            .build(Tool::ClaudeCode)
    }

    #[test]
    fn remote_org_server_is_tool_details_be() {
        let h = Harness::test(Os::Macos, &[]);
        let f = run(
            &h,
            json!({"url": "https://mcp.example-corp.com/v1?k=sk-test-EXAMPLE",
                   "headers": {"Authorization": "Bearer sk-test-EXAMPLE"}}),
            Origin::System,
        );
        assert_eq!(f.signals, vec![Signal::ToolDetails]);
        assert!(f.best_effort);
        assert!(f.title.contains("mcp.example-corp.com"));
        assert!(f.evidence.iter().any(|e| e.contains("Authorization")));
        assert!(!f.evidence.join("\n").contains("sk-test-EXAMPLE"));
    }

    #[test]
    fn org_stdio_server_and_env_secret() {
        let h = Harness::test(Os::Macos, &[]);
        let f = run(
            &h,
            json!({"command": "/opt/acme/bin/collector", "env": {"ACME_TOKEN": "sk-test-EXAMPLE", "MODE": "x"}}),
            Origin::Mdm,
        );
        assert_eq!(f.signals, vec![Signal::ToolDetails]);
        assert!(f.title.contains("collector"));
        let ev = f.evidence.join("\n");
        assert!(ev.contains("env ACME_TOKEN"));
        assert!(!ev.contains("sk-test-EXAMPLE"));
    }

    #[test]
    fn user_server_is_info() {
        let h = Harness::test(Os::Macos, &[]);
        let f = run(&h, json!({"command": "/usr/local/bin/foo"}), Origin::User);
        assert!(f.signals.is_empty());
    }

    #[test]
    fn user_server_with_org_installed_target() {
        let dir = std::env::temp_dir().join(format!("cainary-mcp-{}", std::process::id()));
        let bin = dir.join("root/Library/Application Support/AcmeCollector/mcp");
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::fs::create_dir_all(dir.join("home")).unwrap();
        let dir = std::fs::canonicalize(&dir).unwrap();
        let bin = dir.join("root/Library/Application Support/AcmeCollector/mcp");
        std::fs::write(&bin, "").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let shown = "/Library/Application Support/AcmeCollector/mcp";
        std::fs::write(
            dir.join("fixture.json"),
            format!(r#"{{"os":"macos","rootOwned":["{shown}"]}}"#),
        )
        .unwrap();
        let h = Harness::from_fixture(&dir).unwrap();
        let f = run(&h, json!({"command": shown}), Origin::User);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(f.signals, vec![Signal::ToolDetails]);
    }
}
