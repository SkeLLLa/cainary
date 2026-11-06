import Foundation

// Real `cainary-otel-debug --trust` / `--trust-status` output from the net crate, one line per
// call with its exit status (HOME replaced by /home/u).

enum TrustSamples {
    /// The net crate's fixed output (`caExists`, `note`, the "close Claude Code first" messages).
    static let v2: [(line: String, exit: Int32)] = [
        (#"{"v":1,"type":"trust-status","ts":"2026-11-06T16:29:49Z","claudeCode":{"state":"absent","settingsPath":"/home/u/.claude/settings.json","value":null},"codex":{"state":"absent","bundlePath":null,"command":null},"caPath":"/home/u/.local/state/cainary/otel-debug-ca.pem","caExists":false,"note":null}"#, 0),
        (#"{"v":1,"type":"trust","ts":"2026-11-06T16:29:49Z","target":"claude-code","action":"preview","message":"Would set env.NODE_EXTRA_CA_CERTS in your Claude Code settings, after a backup. Close Claude Code before applying this, and restart it afterwards. While the HTTPS takeover is active, your organization's collector receives nothing.","settingsPath":"/home/u/.claude/settings.json","backupPath":"/home/u/.claude/settings.json.cainary-20261106T162949Z.bak","key":"NODE_EXTRA_CA_CERTS","from":null,"to":"/home/u/.local/state/cainary/otel-debug-ca.pem","bundlePath":null,"command":null}"#, 0),
        (#"{"v":1,"type":"trust","ts":"2026-11-06T16:29:49Z","target":"claude-code","action":"applied","message":"Claude Code will trust the collector certificate once it is restarted.","settingsPath":"/home/u/.claude/settings.json","backupPath":"/home/u/.claude/settings.json.cainary-20261106T162949Z.bak","key":"NODE_EXTRA_CA_CERTS","from":null,"to":"/home/u/.local/state/cainary/otel-debug-ca.pem","bundlePath":null,"command":null}"#, 0),
        (#"{"v":1,"type":"trust-status","ts":"2026-11-06T16:29:49Z","claudeCode":{"state":"applied","settingsPath":"/home/u/.claude/settings.json","value":"/home/u/.local/state/cainary/otel-debug-ca.pem"},"codex":{"state":"absent","bundlePath":null,"command":null},"caPath":"/home/u/.local/state/cainary/otel-debug-ca.pem","caExists":false,"note":null}"#, 0),
        (#"{"v":1,"type":"trust","ts":"2026-11-06T16:29:49Z","target":"claude-code","action":"undone","message":"Restored your previous Claude Code setting. Close Claude Code before applying this, and restart it afterwards.","settingsPath":"/home/u/.claude/settings.json","backupPath":"/home/u/.claude/settings.json.cainary-20261106T162949Z-1.bak","key":"NODE_EXTRA_CA_CERTS","from":"/home/u/.local/state/cainary/otel-debug-ca.pem","to":null,"bundlePath":null,"command":null}"#, 0),
        (#"{"v":1,"type":"trust","ts":"2026-11-06T16:29:49Z","target":"codex","action":"refused","message":"Start the takeover once (cainary-otel-debug --tls …) so the collector certificate exists, then try again.","settingsPath":null,"backupPath":null,"key":null,"from":null,"to":null,"bundlePath":null,"command":null}"#, 1),
    ]

    /// A status with a note about an interrupted change.
    static let statusWithNote = statusCaExists.replacingOccurrences(
        of: #""caExists":true"#,
        with: #""caExists":true,"note":"A previous change was interrupted; it has been cleared.""#)
    /// `trust-status` with the `caExists` flag (the net crate's fix round).
    static let statusCaExists =
        #"{"v":1,"type":"trust-status","ts":"2026-11-06T16:17:20Z","claudeCode":{"state":"absent","settingsPath":"/home/u/.claude/settings.json","value":null},"codex":{"state":"absent","bundlePath":null,"command":null},"caPath":"/home/u/.local/state/cainary/otel-debug-ca.pem","caExists":true}"#
    static let statusCaMissing = statusCaExists.replacingOccurrences(of: #""caExists":true"#, with: #""caExists":false"#)

    static let all: [(line: String, exit: Int32)] = [
        (#"{"v":1,"type":"trust-status","ts":"2026-11-06T16:17:20Z","claudeCode":{"state":"absent","settingsPath":"/home/u/.claude/settings.json","value":null},"codex":{"state":"absent","bundlePath":null,"command":null},"caPath":"/home/u/.local/state/cainary/otel-debug-ca.pem"}"#, 0),
        (#"{"v":1,"type":"trust","ts":"2026-11-06T16:17:20Z","target":"claude-code","action":"preview","message":"Would set env.NODE_EXTRA_CA_CERTS in your Claude Code settings, after a backup. Restart Claude Code afterwards. While the HTTPS takeover is active, your organization's collector receives nothing.","settingsPath":"/home/u/.claude/settings.json","backupPath":"/home/u/.claude/settings.json.cainary-20261106T161720Z.bak","key":"NODE_EXTRA_CA_CERTS","from":null,"to":"/home/u/.local/state/cainary/otel-debug-ca.pem","bundlePath":null,"command":null}"#, 0),
        (#"{"v":1,"type":"trust","ts":"2026-11-06T16:17:20Z","target":"claude-code","action":"applied","message":"Claude Code will trust the collector certificate once it is restarted.","settingsPath":"/home/u/.claude/settings.json","backupPath":"/home/u/.claude/settings.json.cainary-20261106T161720Z.bak","key":"NODE_EXTRA_CA_CERTS","from":null,"to":"/home/u/.local/state/cainary/otel-debug-ca.pem","bundlePath":null,"command":null}"#, 0),
        (#"{"v":1,"type":"trust","ts":"2026-11-06T16:17:20Z","target":"claude-code","action":"already","message":"Claude Code already trusts the collector certificate.","settingsPath":"/home/u/.claude/settings.json","backupPath":null,"key":"NODE_EXTRA_CA_CERTS","from":"/home/u/.local/state/cainary/otel-debug-ca.pem","to":"/home/u/.local/state/cainary/otel-debug-ca.pem","bundlePath":null,"command":null}"#, 0),
        (#"{"v":1,"type":"trust-status","ts":"2026-11-06T16:17:20Z","claudeCode":{"state":"applied","settingsPath":"/home/u/.claude/settings.json","value":"/home/u/.local/state/cainary/otel-debug-ca.pem"},"codex":{"state":"absent","bundlePath":null,"command":null},"caPath":"/home/u/.local/state/cainary/otel-debug-ca.pem"}"#, 0),
        (#"{"v":1,"type":"trust","ts":"2026-11-06T16:17:20Z","target":"codex","action":"refused","message":"Start the takeover once (cainary-otel-debug --tls …) so the collector certificate exists, then try again.","settingsPath":null,"backupPath":null,"key":null,"from":null,"to":null,"bundlePath":null,"command":null}"#, 1),
        (#"{"v":1,"type":"trust","ts":"2026-11-06T16:17:20Z","target":"claude-code","action":"undone","message":"Restored your previous Claude Code setting. Restart Claude Code afterwards.","settingsPath":"/home/u/.claude/settings.json","backupPath":"/home/u/.claude/settings.json.cainary-20261106T161720Z-1.bak","key":"NODE_EXTRA_CA_CERTS","from":"/home/u/.local/state/cainary/otel-debug-ca.pem","to":null,"bundlePath":null,"command":null}"#, 0),
        (#"{"v":1,"type":"trust","ts":"2026-11-06T16:17:20Z","target":"claude-code","action":"nothing-to-undo","message":"cAInary has not changed your Claude Code settings.","settingsPath":null,"backupPath":null,"key":null,"from":null,"to":null,"bundlePath":null,"command":null}"#, 0),
        (#"{"v":1,"type":"trust","ts":"2026-11-06T16:17:20Z","target":"codex","action":"nothing-to-undo","message":"No Codex certificate bundle was prepared.","settingsPath":null,"backupPath":null,"key":null,"from":null,"to":null,"bundlePath":null,"command":null}"#, 0),
    ]
}
