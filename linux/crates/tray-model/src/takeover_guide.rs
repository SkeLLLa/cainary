//! Splits the collector's takeover instructions (`cainary-net` `setup::takeover()`, one string per
//! line) into the parts the Setup page shows: warnings, numbered steps, the undo and a footer.
//! The CLI text stays the source of every command. The step `kind` comes from what the commands
//! are, never from the wording, so a reworded title doesn't change which status the UI shows.

use serde::Serialize;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TakeoverGuide {
    /// The prose before the first step.
    pub warnings: Vec<String>,
    pub steps: Vec<GuideStep>,
    pub undo: GuideUndo,
    /// The prose after the undo commands.
    pub footer: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct GuideStep {
    /// `hosts`, `redirect`, `trust`, `restart` or `other`.
    pub kind: String,
    pub title: String,
    /// The indented lines under the title, with the indent removed.
    pub lines: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct GuideUndo {
    pub title: String,
    pub lines: Vec<String>,
}

/// `"3. title"` → `"title"`.
fn step_title(line: &str) -> Option<&str> {
    let digits = line.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    line[digits..].strip_prefix(". ")
}

fn indented(line: &str) -> Option<&str> {
    line.strip_prefix("  ").map(str::trim_end)
}

fn kind_of(lines: &[String]) -> &'static str {
    if lines
        .iter()
        .any(|l| l.starts_with("127.0.0.1 ") || l.starts_with("::1 "))
    {
        "hosts"
    } else if lines.iter().any(|l| l.contains("nft ")) {
        "redirect"
    } else if lines.iter().any(|l| l.contains("NODE_EXTRA_CA_CERTS")) {
        "trust"
    } else if lines.is_empty() {
        "restart"
    } else {
        "other"
    }
}

/// Parses the takeover lines. Text with no numbered step gives no steps, so the caller can show
/// the raw lines instead.
pub fn parse(lines: &[String]) -> TakeoverGuide {
    let mut guide = TakeoverGuide::default();
    let mut raw: Vec<(String, Vec<String>)> = Vec::new();
    let mut in_undo = false;
    for line in lines {
        let text = line.trim_end();
        if text.is_empty() {
            continue;
        }
        if text.starts_with("Undo:") && !text.starts_with(' ') {
            in_undo = true;
            guide.undo.title = text.to_owned();
        } else if let Some(command) = indented(text) {
            if in_undo {
                guide.undo.lines.push(command.to_owned());
            } else if let Some((_, step)) = raw.last_mut() {
                step.push(command.to_owned());
            } else {
                guide.warnings.push(text.trim_start().to_owned());
            }
        } else if in_undo {
            guide.footer.push(text.to_owned());
        } else if let Some(title) = step_title(text) {
            raw.push((title.to_owned(), Vec::new()));
        } else if raw.is_empty() {
            guide.warnings.push(text.to_owned());
        } else {
            guide.footer.push(text.to_owned());
        }
    }
    guide.steps = raw
        .into_iter()
        .map(|(title, lines)| GuideStep {
            kind: kind_of(&lines).into(),
            title,
            lines,
        })
        .collect();
    guide
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &str) -> Vec<String> {
        text.lines().map(str::to_owned).collect()
    }

    const SAMPLE: &str = "TLS takeover: read this first.\nNothing is forwarded.\n\n1. Point the host names at loopback (add these lines to /etc/hosts as root):\n  127.0.0.1 a.example\n  ::1 a.example\n2. Redirect port 443 to 8443 (run these yourself):\n  sudo nft add table inet t\n3. Trust the certificate:\n  Claude Code: env NODE_EXTRA_CA_CERTS=/ca.pem claude\n  Certificate SHA-256: ab\n4. Start the exporting process.\nUndo: remove the lines and the redirect:\n  sudo nft delete table inet t\nThe restriction is enforced.";

    #[test]
    fn splits_preamble_steps_undo_and_footer() {
        let g = parse(&lines(SAMPLE));
        assert_eq!(g.warnings.len(), 2);
        let kinds: Vec<_> = g.steps.iter().map(|s| s.kind.as_str()).collect();
        assert_eq!(kinds, ["hosts", "redirect", "trust", "restart"]);
        assert_eq!(g.steps[0].lines, ["127.0.0.1 a.example", "::1 a.example"]);
        assert_eq!(g.steps[2].lines.len(), 2);
        assert!(g.undo.title.starts_with("Undo:"));
        assert_eq!(g.undo.lines, ["sudo nft delete table inet t"]);
        assert_eq!(g.footer, ["The restriction is enforced."]);
    }

    #[test]
    fn kind_ignores_the_wording() {
        let g = parse(&lines(
            "1. Something else entirely:\n  sudo nft add table x",
        ));
        assert_eq!(g.steps[0].kind, "redirect");
        let g = parse(&lines("1. Point the host names at loopback:\n  echo hi"));
        assert_eq!(g.steps[0].kind, "other");
    }

    #[test]
    fn unstructured_text_gives_no_steps() {
        let g = parse(&lines("127.0.0.1 a\nNODE_EXTRA_CA_CERTS=/x"));
        assert!(g.steps.is_empty());
        assert!(parse(&[]).steps.is_empty());
    }

    #[test]
    fn undo_without_commands_keeps_the_title() {
        let g = parse(&lines(
            "1. Hosts:\n  ::1 a\nUndo: remove the lines and stop this program.\nFooter.",
        ));
        assert_eq!(
            g.undo.title,
            "Undo: remove the lines and stop this program."
        );
        assert!(g.undo.lines.is_empty());
        assert_eq!(g.footer, ["Footer."]);
    }
}
