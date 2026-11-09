import Foundation

// Sample lines of the `cainary-otel-debug --json` stream, written from the line contract (architecture.md §12.6) with synthetic
// values only. Shared by the unit and snapshot binaries.

enum CollectorSamples {
    static let hello =
        #"{"v":1,"type":"hello","ts":"2026-01-01T12:00:00Z","generator":"cainary-otel-debug 0.6.0","listen":["127.0.0.1:4318","[::1]:4318"],"endpoint":"http://127.0.0.1:4318","showValues":false,"logFile":null,"redFlags":[{"name":"email","kind":"regex","preset":true,"caseSensitive":true}],"setup":{"claudeCode":["CLAUDE_CODE_ENABLE_TELEMETRY=1","OTEL_LOGS_EXPORTER=otlp","OTEL_EXPORTER_OTLP_PROTOCOL=http/json","OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318"],"codex":["otel.exporter={otlp-http={endpoint=\"http://127.0.0.1:4318/v1/logs\",protocol=\"json\"}}"],"notes":["Settings can override these."]}}"#

    static let batch =
        #"{"v":1,"type":"batch","ts":"2026-01-01T12:00:05Z","seq":1,"signal":"logs","path":"/v1/logs","bytes":20431,"vendor":"claude-code","service":{"name":"claude-code","version":"2.1.316"},"catalog":"claude-code 2.1.316","records":12,"notInCatalog":1,"summary":{"identity":["user.email","user.account_uuid"],"resource":["host.arch","os.type"],"records":[{"name":"claude_code.tool_result","kind":"event","count":3,"known":true,"what":"A tool finished: name, result, timing, sizes","attrs":[{"key":"tool_parameters","group":"content","flag":"OTEL_LOG_TOOL_DETAILS","known":true},{"key":"tool_name","group":"event","known":true},{"key":"foo","group":null,"known":false}]}]},"resources":[{"attrs":[{"key":"host.arch","group":"resource","known":true,"type":"string","len":5,"value":"<string, 5 chars>"}],"scopes":[{"name":"com.anthropic.claude_code.events","version":"2.1.316","records":[{"name":"claude_code.tool_result","kind":"event","known":true,"attrs":[]}]}]}]}"#

    static let alert =
        #"{"v":1,"type":"alert","ts":"2026-01-01T12:00:05Z","seq":1,"pattern":"aws-access-key","preset":true,"signal":"logs","event":"claude_code.tool_result","events":["claude_code.tool_result"],"attribute":"tool_input","where":"value","count":2,"match":"AKI…(20 chars)"}"#

    static let error =
        #"{"v":1,"type":"error","ts":"2026-01-01T12:00:06Z","source":"http","status":415,"method":"POST","path":"/v1/logs","message":"protobuf is not supported"}"#

    static let errorPortInUse =
        #"{"v":1,"type":"error","ts":"2026-01-01T12:00:00Z","source":"listen","code":"port-in-use","message":"127.0.0.1:4318 is already in use","port":4318}"#

    static let errorTLSNoHost =
        #"{"v":1,"type":"error","ts":"2026-01-01T12:00:00Z","source":"tls","code":"tls-no-host","message":"no host names to serve"}"#

    static let errorTLSCount =
        #"{"v":1,"type":"error","ts":"2026-01-01T12:00:08Z","source":"tls","message":"handshake failed","count":3}"#

    static let batchProtobufGzip =
        #"{"v":1,"type":"batch","ts":"2026-01-01T12:00:09Z","seq":2,"signal":"logs","path":"/v1/logs","host":"otel.example-corp.test","bytes":812,"format":"protobuf","encoding":"gzip","records":1}"#

    /// A future type, with keys the app doesn't know: skipped.
    static let future =
        #"{"v":1,"type":"leak","ts":"2026-01-01T12:00:07Z","host":"example.invalid"}"#

    static let version2 = #"{"v":2,"type":"hello","ts":"2026-01-01T12:00:00Z"}"#

    static func data(_ line: String) -> Data { Data(line.utf8) }
}
