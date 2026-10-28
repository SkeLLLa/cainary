//! Keep the Rust copies of macOS user-facing strings in sync without coupling either build.

use std::path::PathBuf;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

#[test]
fn linux_strings_track_the_macos_sources() {
    let root = repo();
    let files = [
        root.join("macos/Sources/Style.swift"),
        root.join("macos/Sources/SupportLinks.swift"),
        root.join("macos/Sources/About.swift"),
    ];
    if files.iter().any(|path| !path.is_file()) {
        eprintln!("skipping macOS string parity check: Swift sources aren't in this source tree");
        return;
    }
    let style = std::fs::read_to_string(&files[0]).unwrap();
    let support = std::fs::read_to_string(&files[1]).unwrap();
    let about = std::fs::read_to_string(&files[2]).unwrap();
    let rust =
        std::fs::read_to_string(root.join("linux/crates/tray-model/src/strings.rs")).unwrap();

    let style_strings = [
        (
            "Conversations: prompts, responses, transcripts.",
            "Conversations: prompts, responses, transcripts.",
        ),
        (
            "Activity: commands, tool details, file contents, traffic, device access.",
            "Activity: commands, tool details, file contents, traffic, device access.",
        ),
        (
            "Usage, metrics, identity or vendor-default telemetry.",
            "Usage, metrics, identity or vendor-default telemetry.",
        ),
        (
            "The vendor's standard telemetry is turned off by a setting, and nothing else is sent.",
            "The vendor's standard telemetry is turned off by a setting, and nothing else is sent.",
        ),
        (
            "Nothing tracked or sent that we can see.",
            "Nothing tracked or sent that we can see.",
        ),
        (
            "The app isn't on this Mac.",
            "The app isn't on this computer.",
        ),
        (
            "A level this version of cAInary doesn't know.",
            "A level this version of cAInary doesn't know.",
        ),
        ("prompts", "prompts"),
        ("responses", "responses"),
        ("transcript", "transcript"),
        ("tool details", "tool details"),
        ("file contents", "file contents"),
        ("traffic", "traffic"),
        ("device access", "device access"),
        ("usage", "usage"),
        ("identity", "identity"),
        ("vendor telemetry", "vendor telemetry"),
        ("policy", "policy"),
        ("your organization's server", "your organization's server"),
        ("your organization (MDM)", "your organization (MDM)"),
        ("system settings", "system settings"),
        (
            "your organization (installed file)",
            "your organization (installed file)",
        ),
        ("an unknown source", "an unknown source"),
        ("an environment variable", "an environment variable"),
        ("you", "you"),
        ("the vendor's default", "the vendor's default"),
        ("Claude Code", "Claude Code"),
        ("Claude Desktop", "Claude Desktop"),
        ("Codex", "Codex"),
        ("Cursor", "Cursor"),
        ("GitHub Copilot", "GitHub Copilot"),
        ("ChatGPT", "ChatGPT"),
        ("This device", "This device"),
    ];
    for (source, linux) in style_strings {
        assert!(
            style.contains(source),
            "macOS Style.swift is missing {source:?}"
        );
        assert!(
            rust.contains(linux),
            "Linux strings.rs is missing {linux:?}"
        );
    }
    assert!(style.contains("The app sees launchd's environment, not your shell's. Run `cainary scan` in a terminal to check your shell."));
    assert!(rust.contains("cAInary sees your desktop session's environment, not your shell's. Run `cainary scan` in a terminal to check your shell."));

    let support_strings = [
        "If cAInary is useful to you, please consider supporting Ukrainian defenders instead of sending money to the author.",
        "Come Back Alive",
        "https://savelife.in.ua/en/donate-en/",
        "Sternenko Fund",
        "https://www.sternenkofund.org/en/donate",
        "Prytula Foundation",
        "https://prytulafoundation.org/en/donation",
        "Private email, VPN, passwords and storage. This is a referral link: signing up through it gives the author a credit, at no cost to you.",
        "\"Proton\"",
        "https://pr.tn/ref/28M5WB8J",
    ];
    for value in support_strings {
        assert!(
            support.contains(value),
            "SupportLinks.swift is missing {value:?}"
        );
        assert!(rust.contains(value), "strings.rs is missing {value:?}");
    }

    let about_strings = [
        "Shows what your AI tools and the device monitoring around them track and send, and where it goes. It only reads files and never uses the network.",
        "cAInary is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License, version 3 or (at your option) any later version. It comes with ABSOLUTELY NO WARRANTY.",
        "Copyright © SkeLLLa and contributors. Licensed under GPL-3.0-or-later.",
        "https://github.com/SkeLLLa/cainary",
    ];
    for value in about_strings {
        assert!(about.contains(value), "About.swift is missing {value:?}");
        assert!(rust.contains(value), "strings.rs is missing {value:?}");
    }
    assert!(about.contains("blob/master/COPYING"));
    assert!(rust.contains("https://github.com/SkeLLLa/cainary/blob/master/COPYING"));
}
