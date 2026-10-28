//! User-facing strings shared by the Linux tray and its QML views.

use serde_json::{Value, json};

pub const ENVIRONMENT_NOTE: &str = "cAInary sees your desktop session's environment, not your shell's. Run `cainary scan` in a terminal to check your shell.";
pub const SUPPORT_NOTE: &str = "If cAInary is useful to you, please consider supporting Ukrainian defenders instead of sending money to the author.";
pub const ABOUT_DESCRIPTION: &str = "Shows what your AI tools and the device monitoring around them track and send, and where it goes. It only reads files and never uses the network.";
pub const LICENSE: &str = "cAInary is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License, version 3 or (at your option) any later version. It comes with ABSOLUTELY NO WARRANTY.";
pub const LICENSE_URL: &str = "https://github.com/SkeLLLa/cainary/blob/master/COPYING";
pub const COPYRIGHT: &str =
    "Copyright © SkeLLLa and contributors. Licensed under GPL-3.0-or-later.";
pub const REPOSITORY: &str = "https://github.com/SkeLLLa/cainary";

pub const SUPPORT_LINKS: [(&str, &str); 3] = [
    ("Come Back Alive", "https://savelife.in.ua/en/donate-en/"),
    ("Sternenko Fund", "https://www.sternenkofund.org/en/donate"),
    (
        "Prytula Foundation",
        "https://prytulafoundation.org/en/donation",
    ),
];

/// A referral link, shown only in Settings and About, never next to scan results.
pub const PROTON_NOTE: &str = "Private email, VPN, passwords and storage. This is a referral link: signing up through it gives the author a credit, at no cost to you.";
pub const PROTON_LINK: (&str, &str) = ("Proton", "https://pr.tn/ref/28M5WB8J");

pub const LEGEND: [(&str, &str, &str); 6] = [
    (
        "high",
        "HIGH",
        "Conversations: prompts, responses, transcripts.",
    ),
    (
        "medium",
        "MEDIUM",
        "Activity: commands, tool details, file contents, traffic, device access.",
    ),
    (
        "low",
        "LOW",
        "Usage, metrics, identity or vendor-default telemetry.",
    ),
    (
        "opted-out",
        "OPTED OUT",
        "The vendor's standard telemetry is turned off by a setting, and nothing else is sent.",
    ),
    ("ok", "OK", "Nothing tracked or sent that we can see."),
    (
        "not-installed",
        "NOT INSTALLED",
        "The app isn't on this computer.",
    ),
];

pub fn signal_name(slug: &str) -> String {
    match slug {
        "prompts" => "prompts",
        "responses" => "responses",
        "transcript" => "transcript",
        "tool-details" => "tool details",
        "file-contents" => "file contents",
        "traffic" => "traffic",
        "device-access" => "device access",
        "usage" => "usage",
        "identity" => "identity",
        "vendor" => "vendor telemetry",
        "policy" => "policy",
        other => return other.to_owned(),
    }
    .to_owned()
}

pub fn origin_phrase(slug: &str) -> String {
    match slug {
        "server" => "your organization's server",
        "mdm" => "your organization (MDM)",
        "system" => "system settings",
        "org-installed" => "your organization (installed file)",
        "unattributed" => "an unknown source",
        "environment" => "an environment variable",
        "user" => "you",
        "vendor-default" => "the vendor's default",
        other => return other.to_owned(),
    }
    .to_owned()
}

pub fn surface_name(slug: &str) -> String {
    match slug {
        "claude-code" => "Claude Code",
        "claude-desktop" => "Claude Desktop",
        "codex" => "Codex",
        "cursor" => "Cursor",
        "copilot" => "GitHub Copilot",
        "chatgpt" => "ChatGPT",
        "device" => "This device",
        other => return other.to_owned(),
    }
    .to_owned()
}

pub fn level_title(slug: &str) -> String {
    match slug {
        "opted-out" => "OPTED OUT".to_owned(),
        "not-installed" => "NOT INSTALLED".to_owned(),
        "unknown" => "UNKNOWN".to_owned(),
        other => other.to_uppercase(),
    }
}

pub fn level_meaning(slug: &str) -> &'static str {
    match slug {
        "high" => LEGEND[0].2,
        "medium" => LEGEND[1].2,
        "low" => LEGEND[2].2,
        "opted-out" => LEGEND[3].2,
        "ok" => LEGEND[4].2,
        "not-installed" => LEGEND[5].2,
        _ => "A level this version of cAInary doesn't know.",
    }
}

/// Static text and build metadata passed to QML once when the engine is created.
pub fn static_json(version: &str, commit: &str, built: &str) -> Value {
    json!({
        "legend": LEGEND.iter().map(|(level, title, meaning)| json!({
            "level": level, "title": title, "meaning": meaning
        })).collect::<Vec<_>>(),
        "support": {
            "note": SUPPORT_NOTE,
            "links": SUPPORT_LINKS.iter().map(|(title, url)| json!({"title": title, "url": url})).collect::<Vec<_>>()
        },
        "privacy": {
            "note": PROTON_NOTE,
            "links": [{"title": PROTON_LINK.0, "url": PROTON_LINK.1}]
        },
        "about": {
            "description": ABOUT_DESCRIPTION,
            "license": LICENSE,
            "licenseUrl": LICENSE_URL,
            "copyright": COPYRIGHT,
            "repo": REPOSITORY
        },
        "build": { "version": version, "commit": commit, "built": built }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_facing_slug_maps_are_stable() {
        assert_eq!(signal_name("tool-details"), "tool details");
        assert_eq!(origin_phrase("mdm"), "your organization (MDM)");
        assert_eq!(surface_name("device"), "This device");
    }
}
