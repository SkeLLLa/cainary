//! Feeds the real `cainary-net` takeover text into the parser, so a change to the CLI wording or
//! layout that the parser can't follow fails here instead of in the Setup page.

use cainary_net::setup::{Takeover, takeover};
use cainary_tray_model::takeover_guide::parse;

fn guide(
    port: u16,
    v4: bool,
    v6: bool,
) -> (
    cainary_tray_model::takeover_guide::TakeoverGuide,
    Vec<String>,
) {
    let hosts = vec![
        "otel.example-corp.com".to_owned(),
        "b.example-corp.com".to_owned(),
    ];
    let lines = takeover(&Takeover {
        hosts: &hosts,
        ca_path: "/home/demo/ca.pem",
        fingerprint: "3f9a",
        port,
        public_port: 443,
        v4,
        v6,
    });
    (parse(&lines), lines)
}

fn kinds(g: &cainary_tray_model::takeover_guide::TakeoverGuide) -> Vec<&str> {
    g.steps.iter().map(|s| s.kind.as_str()).collect()
}

#[test]
fn redirect_both_families() {
    let (g, _) = guide(8443, true, true);
    assert_eq!(kinds(&g), ["hosts", "redirect", "trust", "restart"]);
    assert_eq!(g.warnings.len(), 6);
    assert_eq!(g.steps[0].lines.len(), 4);
    assert_eq!(g.steps[0].lines[0], "127.0.0.1 otel.example-corp.com");
    assert_eq!(g.steps[0].lines[1], "::1 otel.example-corp.com");
    assert_eq!(g.steps[1].lines.len(), 4);
    assert!(g.steps[1].lines.iter().all(|l| l.starts_with("sudo nft ")));
    assert!(
        g.steps[2].lines[0].starts_with("Claude Code: env NODE_EXTRA_CA_CERTS=/home/demo/ca.pem")
    );
    assert!(g.steps[2].lines[1].starts_with("Codex: "));
    assert_eq!(g.steps[2].lines[2], "Certificate SHA-256: 3f9a");
    assert!(g.steps[3].lines.is_empty());
    assert!(g.undo.title.starts_with("Undo:"));
    assert_eq!(
        g.undo.lines,
        ["sudo nft delete table inet cainary_otel_debug"]
    );
    assert_eq!(g.footer.len(), 1);
}

#[test]
fn direct_port_has_no_redirect() {
    let (g, _) = guide(443, true, true);
    assert_eq!(kinds(&g), ["hosts", "trust", "restart"]);
    assert!(g.undo.lines.is_empty());
    assert!(g.undo.title.starts_with("Undo:"));
    assert_eq!(g.footer.len(), 1);
}

#[test]
fn v4_only_and_v6_only() {
    let (g, _) = guide(8443, true, false);
    assert_eq!(
        g.steps[0].lines,
        [
            "127.0.0.1 otel.example-corp.com",
            "127.0.0.1 b.example-corp.com"
        ]
    );
    assert_eq!(g.steps[1].lines.len(), 3);
    let (g, _) = guide(8443, false, true);
    assert_eq!(
        g.steps[0].lines,
        ["::1 otel.example-corp.com", "::1 b.example-corp.com"]
    );
    assert_eq!(kinds(&g), ["hosts", "redirect", "trust", "restart"]);
    assert_eq!(g.steps[1].lines.len(), 3);
}

#[test]
fn fixture_lines_match_the_real_output() {
    for port in [8443, 443] {
        let hosts = vec!["otel.example-corp.com".to_owned()];
        let real = takeover(&Takeover {
            hosts: &hosts,
            ca_path: "/home/demo/.local/state/cainary/otel-debug-ca.pem",
            fingerprint: "3f9a0c2177be5d1e8a64c0b9d27f41d2",
            port,
            public_port: 443,
            v4: true,
            v6: true,
        });
        assert_eq!(cainary_tray_model::fixtures::takeover_lines(port), real);
    }
}
