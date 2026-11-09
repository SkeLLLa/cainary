import Foundation
import SwiftUI

// The collector Rules, Logs and Failure views on fixture data (example-corp.test names only),
// with a fixed UTC clock so the PNGs don't depend on the machine's time zone.

@MainActor
func collectorPanelsSnapshots(out: URL) {
    let utc = { (ts: String) in formatClock(ts, timeZone: TimeZone(identifier: "UTC")!) }

    func render(_ file: String, _ view: some View, heights: ClosedRange<CGFloat> = 100...3000) {
        let url = out.appendingPathComponent(file)
        checkPNG(file, url, size: writePNG(view, to: url), heights: heights)
    }

    // Rules
    var settings = CollectorSettings()
    settings.patterns = [
        CollectorPattern(name: "internal-host", kind: "text", pattern: "build.example-corp.test"),
        CollectorPattern(
            name: "ticket", kind: "regex", pattern: "EXAMPLE-[0-9]+", caseSensitive: true),
        CollectorPattern(name: "Bad Name", kind: "text", pattern: "x"),
    ]
    func rules(_ s: CollectorSettings, height: CGFloat) -> some View {
        CollectorRulesView(settings: s, onChange: { _ in }, staticLayout: true)
            .frame(width: 640, height: height, alignment: .topLeading)
    }
    render("collector-rules.png", rules(settings, height: 640))
    render("collector-rules-empty.png", rules(CollectorSettings(), height: 420))

    // Logs
    func error(_ ts: String, _ code: String?, _ message: String, count: Int? = nil)
        -> CollectorError
    {
        CollectorError(ts: ts, source: "collector", message: message, code: code, count: count)
    }
    let errors = [
        error("2026-01-01T12:00:09Z", nil, "request body is not valid protobuf", count: 3),
        error("2026-01-01T12:00:04Z", "tls-handshake", "client rejected the certificate"),
        error("2026-01-01T12:00:01Z", "port-in-use", "listen tcp 127.0.0.1:8443: address in use"),
    ]
    let tail = [
        "cainary-otel-debug: listen 127.0.0.1:8443: Address already in use (os error 48)",
        "cainary-otel-debug: exiting",
    ]
    func logs(_ errors: [CollectorError], _ tail: [String], height: CGFloat) -> some View {
        CollectorLogsView(
            errors: errors, stderrTail: tail, formatTime: utc, onCopy: { _ in },
            staticLayout: true
        )
        .frame(width: 640, height: height)
    }
    render("collector-logs.png", logs(errors, tail, height: 420))
    render("collector-logs-empty.png", logs([], [], height: 240))

    // Failure
    func failure(_ code: String?, _ port: Int?, _ message: String) -> some View {
        CollectorFailureView(
            failure: CollectorFailure(code: code, port: port, message: message),
            onRetry: {}, onOpenSettings: {}, onOpenSetup: {}, onShowLogs: {}
        )
        .padding(10).frame(width: 640, alignment: .topLeading).fixedSize(
            horizontal: false, vertical: true)
    }
    render(
        "collector-failure-port.png",
        failure("port-in-use", 8443, "Address already in use"), heights: 40...400)
    render(
        "collector-failure-host.png",
        failure("tls-no-host", nil, "Add at least one host name for the HTTPS takeover."),
        heights: 40...400)
    render(
        "collector-failure-generic.png",
        failure(nil, nil, "Stopped: exited with code 101."), heights: 40...400)
}
