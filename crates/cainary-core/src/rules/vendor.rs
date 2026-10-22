//! Vendor-default telemetry findings and opt-outs (rules.md CC.7, CD, CX.5, CU, CP.5).

use crate::model::{FindingBuilder, Origin, Signal, Source, SourceKind, Tool};

/// The vendor-default finding for `tool`; not in effect when the user opted out.
///
/// The builder carries a placeholder source (origin vendor-default); a caller that knows the
/// opt-out variable or file replaces it with `.source(..)`. Returns `None` for tools with no
/// vendor default rule: Device, and ChatGPT (rules.md CG has no vendor-default row).
pub fn vendor_default(tool: Tool, opted_out: bool) -> Option<FindingBuilder> {
    // (title, detail, reference, best_effort, opt-out title)
    let (title, detail, reference, best_effort) = match tool {
        Tool::ClaudeCode => (
            "Anthropic receives usage metrics by default",
            "Claude Code sends usage metrics to Anthropic unless telemetry is turned off.",
            "https://code.claude.com/docs/en/data-usage#telemetry-services",
            false,
        ),
        Tool::ClaudeDesktop => (
            "Claude Desktop sends crash reports and product analytics to Anthropic",
            "Anthropic documents this only for third-party inference deployments, so on \
             a standard sign-in it may apply.",
            "https://claude.com/docs/third-party/claude-desktop/telemetry",
            true,
        ),
        Tool::Codex => (
            "OpenAI receives anonymous usage metrics by default",
            "Codex sends anonymous usage metrics to OpenAI unless the metrics exporter is \
             turned off.",
            "https://learn.chatgpt.com/docs/config-file/config-reference",
            false,
        ),
        Tool::Cursor => (
            "Cursor collects usage and device data",
            "Privacy Mode can't be read locally, so cAInary can't tell what Cursor keeps.",
            "https://cursor.com/privacy",
            true,
        ),
        Tool::Copilot => (
            "Copilot CLI sends usage telemetry to GitHub",
            "The Copilot CLI reports usage telemetry to GitHub by default.",
            "https://docs.github.com/en/copilot/how-tos/administer-copilot/manage-for-enterprise/use-managed-settings/deploy-managed-settings",
            false,
        ),
        Tool::Chatgpt | Tool::Device => return None,
    };
    let (title, detail) = if opted_out {
        (
            format!("{} is turned off", opt_out_subject(tool)),
            "A setting turns off the vendor's default telemetry, so nothing is sent by default."
                .to_string(),
        )
    } else {
        (title.to_string(), detail.to_string())
    };
    let b = FindingBuilder::new(title)
        .detail(detail)
        .source(Source::new(
            "vendor default",
            Origin::VendorDefault,
            SourceKind::Marker,
        ))
        .reference(reference)
        .best_effort(best_effort);
    Some(if opted_out {
        b.in_effect(false)
    } else {
        b.signals(&[Signal::Vendor])
    })
}

fn opt_out_subject(tool: Tool) -> &'static str {
    match tool {
        Tool::ClaudeCode => "Anthropic usage telemetry",
        Tool::ClaudeDesktop => "Claude Desktop crash and analytics reporting",
        Tool::Codex => "OpenAI usage metrics",
        Tool::Cursor => "Cursor data collection",
        Tool::Copilot => "Copilot CLI usage telemetry",
        Tool::Chatgpt | Tool::Device => "Vendor telemetry",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Finding;

    fn build(tool: Tool, opted_out: bool) -> Finding {
        vendor_default(tool, opted_out)
            .expect("tool has a vendor default")
            .build(tool)
    }

    const WITH_DEFAULT: [(Tool, bool); 5] = [
        (Tool::ClaudeCode, false),
        (Tool::ClaudeDesktop, true),
        (Tool::Codex, false),
        (Tool::Cursor, true),
        (Tool::Copilot, false),
    ];

    #[test]
    fn opted_in_per_tool() {
        for (tool, be) in WITH_DEFAULT {
            let f = build(tool, false);
            assert_eq!(f.tool, tool);
            assert_eq!(f.signals, vec![Signal::Vendor], "{tool:?}");
            assert!(f.in_effect, "{tool:?}");
            assert_eq!(f.best_effort, be, "{tool:?}");
            assert_eq!(f.source.origin, Origin::VendorDefault, "{tool:?}");
            assert!(f.reference.is_some(), "{tool:?}");
            assert!(!f.title.is_empty() && !f.detail.is_empty(), "{tool:?}");
        }
    }

    #[test]
    fn opted_out_per_tool() {
        for (tool, be) in WITH_DEFAULT {
            let f = build(tool, true);
            assert!(!f.in_effect, "{tool:?}");
            assert!(f.signals.is_empty(), "{tool:?}");
            assert_eq!(f.best_effort, be, "{tool:?}");
            assert_eq!(f.source.origin, Origin::VendorDefault, "{tool:?}");
        }
    }

    #[test]
    fn wording_follows_rules() {
        assert_eq!(
            build(Tool::ClaudeCode, false).title,
            "Anthropic receives usage metrics by default"
        );
        assert_eq!(
            build(Tool::Codex, false).title,
            "OpenAI receives anonymous usage metrics by default"
        );
        assert!(
            build(Tool::Cursor, false)
                .title
                .contains("Cursor collects usage and device data")
        );
        assert!(
            build(Tool::Copilot, false)
                .title
                .contains("sends usage telemetry to GitHub")
        );
        assert!(
            build(Tool::ClaudeDesktop, false)
                .title
                .contains("crash reports and product analytics")
        );
    }

    #[test]
    fn no_default_for_device_and_chatgpt() {
        for opted_out in [false, true] {
            assert!(vendor_default(Tool::Device, opted_out).is_none());
            assert!(vendor_default(Tool::Chatgpt, opted_out).is_none());
        }
    }
}
