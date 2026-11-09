import Foundation
import SwiftUI

// The collector Setup tab on fixtures only: example-corp.test names and a fixed fake path. The
// takeover text is the macOS redirect text the collector prints (crates/cainary-net golden file),
// with the CA path replaced.

private let fakeCA = "/Users/me/Library/Application Support/cAInary/otel-debug-ca.pem"

private let takeoverText = [
    "TLS takeover: read this first.",
    "Nothing is forwarded. While this runs, your organization's collector receives nothing from this machine, and every other request to the listed host names fails.",
    "Other programs that talk to these host names will fail their TLS handshake here; that is expected.",
    "The host names below are what you configured here, not an authenticated sender identity.",
    "If the exporting process uses HTTPS_PROXY, add these host names to its NO_PROXY; otherwise the proxy resolves them itself and nothing arrives here.",
    "",
    "1. Point the host names at loopback (add these lines to /etc/hosts as root):",
    "  127.0.0.1 otel.example-corp.test",
    "  ::1 otel.example-corp.test",
    "2. Redirect port 443 to 8443, for connections this machine makes to loopback (run these yourself; they are not run for you):",
    "  printf '%s\\n' 'rdr pass on lo0 inet proto tcp from any to 127.0.0.1 port 443 -> 127.0.0.1 port 8443' 'rdr pass on lo0 inet6 proto tcp from any to ::1 port 443 -> ::1 port 8443' | sudo pfctl -a com.apple/cainary -f -",
    "  sudo pfctl -E",
    "3. Flush the DNS cache, so the host names resolve to loopback now:",
    "  sudo dscacheutil -flushcache",
    "  sudo killall -HUP mDNSResponder",
    "4. Trust the certificate, for the exporting process only (never disable certificate verification):",
    "  Claude Code: env NODE_EXTRA_CA_CERTS=\(fakeCA) claude",
    "  Codex: set SSL_CERT_FILE=\(fakeCA) or CODEX_CA_CERTIFICATE=\(fakeCA) for the codex process (see its documentation for which it honors)",
    "  Certificate SHA-256: ab",
    "5. Start the exporting process after this certificate is published, and restart it after every run of this program: each run creates a new CA. Deleting the file does not revoke trust a process already loaded; `cainary-otel-debug --delete-ca` removes the file.",
    "Undo: remove the /etc/hosts lines, stop this program, remove the redirect, and flush the DNS cache:",
    "  sudo pfctl -a com.apple/cainary -F all",
    "  sudo dscacheutil -flushcache",
    "  sudo killall -HUP mDNSResponder",
    "The restriction to these names is enforced by this program: it issues certificates only for them and completes a handshake only for them. The certificate also carries name constraints, but those cover subdomains and depend on the client enforcing them. Its key exists only in this process's memory, and it is never installed in a system trust store.",
]

private let host = "otel.example-corp.test"

@MainActor
func collectorSetupSnapshots(out: URL) {
    func render(_ file: String, _ view: some View, heights: ClosedRange<CGFloat> = 100...4000) {
        let url = out.appendingPathComponent(file)
        checkPNG(file, url, size: writePNG(view, to: url), heights: heights)
    }

    func trust(claude: String, codex: String) -> TrustSnapshot {
        TrustSnapshot(
            status: TrustStatus(
                claudeCode: .init(
                    state: claude,
                    settingsPath: "/Users/me/.claude/settings.json"),
                codex: .init(
                    state: codex,
                    bundlePath: "/Users/me/Library/Application Support/cAInary/codex-ca.pem"),
                caPath: fakeCA, caExists: true))
    }

    func view(
        _ settings: CollectorSettings, state: TakeoverState, trust: TrustSnapshot = TrustSnapshot(),
        lines: [String]? = takeoverText, open: [String: Bool] = [:], on: Bool = true
    ) -> some View {
        CollectorSetupView(
            settings: settings, onChange: { _ in }, takeoverLines: lines,
            setup: CollectorHello.Setup(
                claudeCode: [
                    "export CLAUDE_CODE_ENABLE_TELEMETRY=1",
                    "export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318",
                ],
                codex: [
                    "otel = { exporter = { otlp-http = { endpoint = \"http://127.0.0.1:4318\" } } }"
                ]),
            endpoint: on ? "http://127.0.0.1:4318" : nil, collectorOn: on,
            state: state, trust: trust, openSteps: .constant(open), staticLayout: true
        )
        .padding(12).frame(width: 640, alignment: .topLeading)
        .fixedSize(horizontal: false, vertical: true)
    }

    var plain = CollectorSettings()
    plain.enabled = true
    render("collector-setup-plain.png", view(plain, state: TakeoverState(), lines: nil))

    var takeover = plain
    takeover.takeover = true
    takeover.takeoverHosts = [host]
    let hostsFile = { (s: BlockState) in
        HostsFileSummary(
            error: nil, analysis: HostsAnalysis(state: s, conflicts: [], reserved: []))
    }
    var pending = TakeoverState(hosts: [host])
    pending.helper = .ready(requirement: "req")
    pending.file = hostsFile(.absent)
    pending.lookups = [host: .elsewhere(["10.0.0.9"])]
    pending.redirect = .disabled
    render("collector-setup-takeover.png", view(takeover, state: pending))

    var done = pending
    done.file = hostsFile(.current)
    done.lookups = [host: .here]
    done.redirect = .enabled
    done.listening = true
    done.batchCount = 4
    done.hostsMessage = TakeoverMessage(text: "Added cAInary's lines to /etc/hosts.", tone: .info)
    let allOpen = [
        "hosts": true, "redirect": true, "flush": true, "trust": true, "restart": true,
    ]
    render(
        "collector-setup-done.png",
        view(
            takeover, state: done, trust: trust(claude: "applied", codex: "ready"),
            open: allOpen))

    var unsigned = pending
    unsigned.helper = .unavailable(HostsHelperCheck.unsignedReason)
    render(
        "collector-setup-unavailable.png", view(takeover, state: unsigned, open: ["hosts": true]))

    var failed = pending
    failed.hostsMessage = TakeoverMessage(
        text: "Couldn't change /etc/hosts: the helper refused (the file is busy).", tone: .error)
    render("collector-setup-hosts-error.png", view(takeover, state: failed, open: ["hosts": true]))

    var many = takeover
    many.takeoverHosts = (1...9).map { "h\($0).example-corp.test" }
    var tooMany = TakeoverState(hosts: many.validHosts)
    tooMany.helper = .ready(requirement: "req")
    tooMany.file = hostsFile(.absent)
    render("collector-setup-too-many.png", view(many, state: tooMany, open: ["hosts": true]))
}
