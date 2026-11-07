import QtQuick
import ua.SkeLLLa.cAInary

// SettingsController.collectorJson parsed with defaults, and the edits the collector settings
// make. Every edit writes the whole table back through setCollector.
QtObject {
    id: root

    readonly property var value: {
        const defaults = { enabled: false, start_at_launch: false, port: 4318, tls: false, tls_port: 443, tls_hosts: [], log_to_file: false, log_path: "", presets: [], notify: true, patterns: [], patternErrors: [], tlsHostErrors: [], overLimit: false, logPathSuggestion: "" };
        try {
            const v = JSON.parse(SettingsController.collectorJson);
            return {
                enabled: v.enabled === true,
                start_at_launch: v.start_at_launch === true,
                port: v.port || 4318,
                tls: v.tls === true,
                tls_port: v.tls_port || 443,
                tls_hosts: v.tls_hosts || [],
                log_to_file: v.log_to_file === true,
                log_path: v.log_path || "",
                presets: v.presets || [],
                notify: v.notify !== false,
                patterns: v.patterns || [],
                patternErrors: v.patternErrors || [],
                tlsHostErrors: v.tlsHostErrors || [],
                overLimit: v.overLimit === true,
                logPathSuggestion: v.logPathSuggestion || ""
            };
        } catch (error) {
            return defaults;
        }
    }

    readonly property var presets: [
        { key: "email", label: qsTr("Email addresses") },
        { key: "private-key", label: qsTr("Private keys") },
        { key: "jwt", label: qsTr("JWTs") },
        { key: "aws-access-key", label: qsTr("AWS access keys") },
        { key: "github-token", label: qsTr("GitHub tokens") },
        { key: "anthropic-key", label: qsTr("Anthropic keys") },
        { key: "openai-key", label: qsTr("OpenAI keys") },
        { key: "slack-token", label: qsTr("Slack tokens") }
    ]

    function change(edit) {
        const next = JSON.parse(JSON.stringify(root.value));
        edit(next);
        SettingsController.setCollector(JSON.stringify(next));
    }

    function updatePattern(index, key, v) {
        change(next => { next.patterns[index][key] = v; });
    }

    function addTlsHost(host) {
        change(next => {
            if (next.tls_hosts.findIndex(item => item.toLowerCase() === host.toLowerCase()) < 0)
                next.tls_hosts.push(host);
        });
    }
}
