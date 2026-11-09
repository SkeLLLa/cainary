import Foundation

// Tests for TakeoverGuide.swift, the Swift twin of tray-model's takeover_guide.rs. The Linux
// text is the one linux/crates/tray-model/src/fixtures.rs `takeover_lines` builds (the text the
// drift test feeds the Rust parser), ported here line for line.

private func split(_ text: String) -> [String] {
    text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
}

private let ca = "/home/demo/.local/state/cainary/otel-debug-ca.pem"

/// `takeover_lines(port)` from fixtures.rs.
private func linuxTakeover(port: Int) -> [String] {
    var l = [
        "TLS takeover: read this first.",
        "Nothing is forwarded. While this runs, your organization's collector receives nothing from this machine, and every other request to the listed host names fails.",
        "Other programs that talk to these host names will fail their TLS handshake here; that is expected.",
        "The host names below are what you configured here, not an authenticated sender identity.",
        "If the exporting process uses HTTPS_PROXY, add these host names to its NO_PROXY; otherwise the proxy resolves them itself and nothing arrives here.",
        "Your organization's settings choose the format: OTLP over HTTP as JSON or protobuf, gzip or uncompressed, is read; gRPC is not.",
        "",
        "1. Point the host names at loopback (add these lines to /etc/hosts as root):",
        "  127.0.0.1 otel.example-corp.com",
        "  ::1 otel.example-corp.com",
    ]
    var step = 1
    if port != 443 {
        step += 1
        l.append(
            "\(step). Redirect port 443 to \(port), for connections this machine makes to loopback (run these yourself; they are not run for you):"
        )
        l.append("  sudo nft add table inet cainary_otel_debug")
        l.append(
            "  sudo nft 'add chain inet cainary_otel_debug out { type nat hook output priority -100 ; }'"
        )
        l.append(
            "  sudo nft add rule inet cainary_otel_debug out oifname lo ip daddr 127.0.0.1 tcp dport 443 redirect to :\(port)"
        )
        l.append(
            "  sudo nft add rule inet cainary_otel_debug out oifname lo ip6 daddr ::1 tcp dport 443 redirect to :\(port)"
        )
    }
    step += 1
    l.append(
        "\(step). Trust the certificate, for the exporting process only (never disable certificate verification):"
    )
    l.append("  Claude Code: env NODE_EXTRA_CA_CERTS=\(ca) claude")
    l.append(
        "  Codex: set SSL_CERT_FILE=\(ca) or CODEX_CA_CERTIFICATE=\(ca) for the codex process (see its documentation for which it honors)"
    )
    l.append("  Certificate SHA-256: 3f9a0c2177be5d1e8a64c0b9d27f41d2")
    step += 1
    l.append(
        "\(step). Start the exporting process after this certificate is published, and restart it after every run of this program: each run creates a new CA. Deleting the file does not revoke trust a process already loaded; `cainary-otel-debug --delete-ca` removes the file."
    )
    if port != 443 {
        l.append("Undo: remove the /etc/hosts lines, stop this program, and remove the redirect:")
        l.append("  sudo nft delete table inet cainary_otel_debug")
    } else {
        l.append("Undo: remove the /etc/hosts lines and stop this program.")
    }
    l.append(
        "The restriction to these names is enforced by this program: it issues certificates only for them and completes a handshake only for them. The certificate also carries name constraints, but those cover subdomains and depend on the client enforcing them. Its key exists only in this process's memory, and it is never installed in a system trust store."
    )
    return l
}

private let sample =
    "TLS takeover: read this first.\nNothing is forwarded.\n\n1. Point the host names at loopback (add these lines to /etc/hosts as root):\n  127.0.0.1 a.example\n  ::1 a.example\n2. Redirect port 443 to 8443 (run these yourself):\n  sudo nft add table inet t\n3. Trust the certificate:\n  Claude Code: env NODE_EXTRA_CA_CERTS=/ca.pem claude\n  Certificate SHA-256: ab\n4. Start the exporting process.\nUndo: remove the lines and the redirect:\n  sudo nft delete table inet t\nThe restriction is enforced."

@MainActor
func guideTests() {
    // takeover_guide.rs unit tests.
    let g = TakeoverGuide.parse(split(sample))
    check("guide: two warnings", g.warnings.count == 2)
    check(
        "guide: sample kinds", g.steps.map(\.kind) == [.hosts, .redirect, .trust, .restart])
    check("guide: step numbers", g.steps.map(\.number) == [1, 2, 3, 4])
    check(
        "guide: hosts lines", g.steps[0].lines == ["127.0.0.1 a.example", "::1 a.example"])
    check("guide: trust lines", g.steps[2].lines.count == 2)
    check("guide: undo title", g.undo.title.hasPrefix("Undo:"))
    check("guide: undo lines", g.undo.lines == ["sudo nft delete table inet t"])
    check("guide: footer", g.footer == ["The restriction is enforced."])
    check("guide: step title", g.steps[0].title.hasPrefix("Point the host names"))

    let nft = TakeoverGuide.parse(split("1. Something else entirely:\n  sudo nft add table x"))
    check("guide: kind ignores wording", nft.steps[0].kind == .redirect)
    let other = TakeoverGuide.parse(split("1. Point the host names at loopback:\n  echo hi"))
    check("guide: unknown commands are other", other.steps[0].kind == .other)

    let plain = TakeoverGuide.parse(split("127.0.0.1 a\nNODE_EXTRA_CA_CERTS=/x"))
    check("guide: unstructured text has no steps", plain.steps.isEmpty)
    check("guide: empty has no steps", TakeoverGuide.parse([]).steps.isEmpty)

    let bare = TakeoverGuide.parse(
        split("1. Hosts:\n  ::1 a\nUndo: remove the lines and stop this program.\nFooter."))
    check(
        "guide: undo without commands keeps the title",
        bare.undo.title == "Undo: remove the lines and stop this program."
            && bare.undo.lines.isEmpty
            && bare.footer == ["Footer."])

    // pfctl and dscacheutil kinds; flush is checked before restart.
    let mac = TakeoverGuide.parse(
        split(
            "1. Redirect:\n  echo 'rdr pass' | sudo pfctl -ef -\n2. Flush the cache:\n  sudo dscacheutil -flushcache\n3. Restart.\n"
        ))
    check("guide: pfctl is redirect", mac.steps[0].kind == .redirect)
    check("guide: dscacheutil is flush", mac.steps[1].kind == .flush)
    check("guide: no lines is restart", mac.steps[2].kind == .restart)
    let both = TakeoverGuide.parse(
        split("1. Both:\n  sudo dscacheutil -flushcache; env NODE_EXTRA_CA_CERTS=/x"))
    check("guide: flush before trust", both.steps[0].kind == .flush)

    // takeover_guide_drift.rs, against the Linux text.
    let both46 = TakeoverGuide.parse(linuxTakeover(port: 8443))
    check(
        "drift: redirect kinds",
        both46.steps.map(\.kind) == [.hosts, .redirect, .trust, .restart])
    check("drift: six warnings", both46.warnings.count == 6)
    check("drift: hosts lines", both46.steps[0].lines.first == "127.0.0.1 otel.example-corp.com")
    check(
        "drift: nft lines",
        both46.steps[1].lines.count == 4
            && both46.steps[1].lines.allSatisfy { $0.hasPrefix("sudo nft ") })
    check(
        "drift: trust lines",
        both46.steps[2].lines[0].hasPrefix("Claude Code: env NODE_EXTRA_CA_CERTS=\(ca)")
            && both46.steps[2].lines[1].hasPrefix("Codex: ")
            && both46.steps[2].lines[2] == "Certificate SHA-256: 3f9a0c2177be5d1e8a64c0b9d27f41d2")
    check("drift: restart has no lines", both46.steps[3].lines.isEmpty)
    check(
        "drift: undo",
        both46.undo.lines == ["sudo nft delete table inet cainary_otel_debug"]
            && both46.footer.count == 1)
    let direct = TakeoverGuide.parse(linuxTakeover(port: 443))
    check(
        "drift: direct port has no redirect",
        direct.steps.map(\.kind) == [.hosts, .trust, .restart])
    check(
        "drift: direct port undo",
        direct.undo.lines.isEmpty && direct.undo.title.hasPrefix("Undo:")
            && direct.footer.count == 1)

    // macOS goldens, once T1 has added them.
    let golden = repoRoot().appendingPathComponent("crates/cainary-net/tests/golden")
    let names =
        ((try? FileManager.default.contentsOfDirectory(atPath: golden.path)) ?? [])
        .filter { $0.hasPrefix("takeover-macos-") && $0.hasSuffix(".txt") }.sorted()
    for name in names {
        let text =
            (try? String(contentsOf: golden.appendingPathComponent(name), encoding: .utf8)) ?? ""
        let parsed = TakeoverGuide.parse(split(text))
        let kinds = parsed.steps.map(\.kind)
        let redirect = name.contains("redirect")
        check(
            "golden \(name): step kinds",
            kinds
                == (redirect
                    ? [.hosts, .redirect, .flush, .trust, .restart]
                    : [.hosts, .flush, .trust, .restart]))
        check(
            "golden \(name): pfctl only when redirecting, never nft",
            parsed.steps.filter { $0.kind == .redirect }.flatMap(\.lines)
                .contains { $0.contains("pfctl ") } == redirect && !text.contains("nft "))
    }
}
