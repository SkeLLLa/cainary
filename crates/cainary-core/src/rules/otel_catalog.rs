//! Static, versioned descriptions of the OTel records exported by supported vendors.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Vendor {
    ClaudeCode,
    Codex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Export {
    Logs,
    Metrics,
    Traces,
    Beta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ItemKind {
    Event,
    Metric,
    Span,
    SpanEvent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Group {
    Identity,
    Resource,
    Event,
    Content,
}

/// What a receiver gets while the gate is off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Off {
    Redacted(&'static str),
    Omitted,
    Generic(&'static str),
}

/// How a flag's value turns into on/off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    Truthy,
    NotFalse,
    FallbackTo(&'static str),
    RawInline,
    RawFile,
    RawAny,
    TomlTrue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flag {
    pub name: &'static str,
    pub rule: Rule,
    pub label: &'static str,
    pub doc: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gate {
    pub flag: &'static str,
    pub rule: Option<Rule>,
    pub off: Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attr {
    pub key: &'static str,
    pub group: Group,
    pub what: &'static str,
    pub value: Option<&'static str>,
    pub gate: Option<Gate>,
    pub only: Option<&'static [Export]>,
    pub best_effort: bool,
    pub observed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Item {
    pub name: &'static str,
    pub kind: ItemKind,
    pub exports: &'static [Export],
    pub what: &'static str,
    pub attrs: &'static [Attr],
    pub gate: Option<Gate>,
    pub open: bool,
    pub unit: Option<&'static str>,
    pub doc: Option<&'static str>,
    pub best_effort: bool,
    pub observed: bool,
    pub sample: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Catalog {
    pub vendor: Vendor,
    pub product: &'static str,
    pub version: &'static str,
    pub doc: &'static str,
    pub flags: &'static [Flag],
    pub identity: &'static [Attr],
    pub resource: &'static [Attr],
    pub common: &'static [Attr],
    pub items: &'static [Item],
}

const LOGS: &[Export] = &[Export::Logs];
const METRICS: &[Export] = &[Export::Metrics];
const TRACES: &[Export] = &[Export::Traces];
const BETA: &[Export] = &[Export::Beta];
const TRACES_BETA: &[Export] = &[Export::Traces, Export::Beta];
const LOGS_BETA: &[Export] = &[Export::Logs, Export::Beta];
const LOGS_METRICS: &[Export] = &[Export::Logs, Export::Metrics];
const LOGS_TRACES_BETA: &[Export] = &[Export::Logs, Export::Traces, Export::Beta];

const CC_DOC: &str = "https://code.claude.com/docs/en/monitoring-usage";
const CC_COMMON_DOC: &str =
    "https://code.claude.com/docs/en/monitoring-usage#common-configuration-variables";
const CC_METRICS_DOC: &str =
    "https://code.claude.com/docs/en/monitoring-usage#metrics-cardinality-control";
const CX_ADVANCED_DOC: &str =
    "https://learn.chatgpt.com/docs/config-file/config-advanced#observability-and-telemetry";
const CX_METRICS_CATALOG_DOC: &str =
    "https://learn.chatgpt.com/docs/config-file/config-advanced#metrics-catalog";
const CX_CONFIG_DOC: &str = "https://github.com/openai/codex/blob/40de81e7af/docs/config.md#otel";
const CX_SKILL_DOC: &str =
    "https://github.com/openai/codex/blob/main/codex-rs/otel/README.md#skill-invocation-logs";
const CX_GUARDIAN_DOC: &str =
    "https://github.com/openai/codex/blob/main/codex-rs/otel/README.md#guardian-assessment-logs";

const fn attr(key: &'static str, group: Group, what: &'static str) -> Attr {
    Attr {
        key,
        group,
        what,
        value: None,
        gate: None,
        only: None,
        best_effort: false,
        observed: false,
    }
}

const fn seen(mut a: Attr) -> Attr {
    a.observed = true;
    a
}

const fn maybe(mut a: Attr) -> Attr {
    a.best_effort = true;
    a
}

const fn gated(mut a: Attr, gate: Gate) -> Attr {
    a.gate = Some(gate);
    a
}

const fn limited(mut a: Attr, exports: &'static [Export]) -> Attr {
    a.only = Some(exports);
    a
}

const fn constant(mut a: Attr, value: &'static str) -> Attr {
    a.value = Some(value);
    a
}

const fn flag(name: &'static str, rule: Rule, label: &'static str, doc: &'static str) -> Flag {
    Flag {
        name,
        rule,
        label,
        doc,
    }
}

const fn event(
    name: &'static str,
    what: &'static str,
    attrs: &'static [Attr],
    doc: Option<&'static str>,
    best_effort: bool,
    observed: bool,
    sample: bool,
) -> Item {
    Item {
        name,
        kind: ItemKind::Event,
        exports: LOGS,
        what,
        attrs,
        gate: None,
        open: false,
        unit: None,
        doc,
        best_effort,
        observed,
        sample,
    }
}

#[allow(clippy::too_many_arguments)]
const fn event_with(
    name: &'static str,
    exports: &'static [Export],
    what: &'static str,
    attrs: &'static [Attr],
    gate: Option<Gate>,
    open: bool,
    doc: Option<&'static str>,
    best_effort: bool,
    observed: bool,
    sample: bool,
) -> Item {
    Item {
        name,
        kind: ItemKind::Event,
        exports,
        what,
        attrs,
        gate,
        open,
        unit: None,
        doc,
        best_effort,
        observed,
        sample,
    }
}

#[allow(clippy::too_many_arguments)]
const fn metric(
    name: &'static str,
    unit: Option<&'static str>,
    what: &'static str,
    attrs: &'static [Attr],
    doc: Option<&'static str>,
    best_effort: bool,
    observed: bool,
    sample: bool,
) -> Item {
    Item {
        name,
        kind: ItemKind::Metric,
        exports: METRICS,
        what,
        attrs,
        gate: None,
        open: false,
        unit,
        doc,
        best_effort,
        observed,
        sample,
    }
}

const fn open_metric(name: &'static str, what: &'static str, doc: Option<&'static str>) -> Item {
    Item {
        name,
        kind: ItemKind::Metric,
        exports: METRICS,
        what,
        attrs: &[],
        gate: None,
        open: true,
        unit: None,
        doc,
        best_effort: false,
        observed: false,
        sample: false,
    }
}

#[allow(clippy::too_many_arguments)]
const fn span(
    name: &'static str,
    exports: &'static [Export],
    what: &'static str,
    attrs: &'static [Attr],
    doc: Option<&'static str>,
    best_effort: bool,
    observed: bool,
    sample: bool,
) -> Item {
    Item {
        name,
        kind: ItemKind::Span,
        exports,
        what,
        attrs,
        gate: None,
        open: false,
        unit: None,
        doc,
        best_effort,
        observed,
        sample,
    }
}

const fn open_span(name: &'static str, what: &'static str) -> Item {
    Item {
        name,
        kind: ItemKind::Span,
        exports: TRACES,
        what,
        attrs: &[],
        gate: None,
        open: true,
        unit: None,
        doc: None,
        best_effort: true,
        observed: false,
        sample: true,
    }
}

#[allow(clippy::too_many_arguments)]
const fn span_event(
    name: &'static str,
    exports: &'static [Export],
    what: &'static str,
    attrs: &'static [Attr],
    gate: Option<Gate>,
    doc: Option<&'static str>,
    best_effort: bool,
    observed: bool,
) -> Item {
    Item {
        name,
        kind: ItemKind::SpanEvent,
        exports,
        what,
        attrs,
        gate,
        open: false,
        unit: None,
        doc,
        best_effort,
        observed,
        sample: false,
    }
}

fn item_accepts(item: &Item, export: Export) -> bool {
    if item.exports.contains(&export) {
        return true;
    }
    matches!(export, Export::Logs | Export::Traces) && item.exports.contains(&Export::Beta)
}

fn attr_accepts(attr: &Attr, export: Export) -> bool {
    match attr.only {
        None => true,
        Some(exports) => {
            if exports.contains(&export) {
                true
            } else {
                matches!(export, Export::Logs | Export::Traces) && exports.contains(&Export::Beta)
            }
        }
    }
}

fn key_matches(pattern: &str, key: &str) -> bool {
    if pattern == "*" {
        return key == "*";
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return key.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return key.ends_with(suffix);
    }
    pattern == key
}

impl Catalog {
    /// Finds an exact item name, then falls back to the catalog's declared open items.
    pub fn item(&self, name: &str, export: Export) -> Option<&'static Item> {
        self.items
            .iter()
            .find(|item| item.name == name && item_accepts(item, export))
            .or_else(|| {
                self.items.iter().find(|item| {
                    if !item.open || !item_accepts(item, export) {
                        return false;
                    }
                    if item.name == "*" {
                        return true;
                    }
                    item.name
                        .strip_suffix('*')
                        .is_some_and(|prefix| name.starts_with(prefix))
                })
            })
    }

    /// Looks up an attribute on the item, then common, identity, and resource attributes.
    pub fn attr(&self, item: Option<&Item>, key: &str, export: Export) -> Option<&'static Attr> {
        item.into_iter()
            .flat_map(|item| item.attrs.iter())
            .chain(self.common.iter())
            .chain(self.identity.iter())
            .chain(self.resource.iter())
            .find(|attr| attr_accepts(attr, export) && key_matches(attr.key, key))
    }

    /// Returns the vendor and fixture version shown in previews.
    pub fn label(&self) -> String {
        format!("{} {}", self.product, self.version)
    }
}

const CC_UP: Gate = Gate {
    flag: "OTEL_LOG_USER_PROMPTS",
    rule: None,
    off: Off::Redacted("<REDACTED>"),
};
const CC_AR: Gate = Gate {
    flag: "OTEL_LOG_ASSISTANT_RESPONSES",
    rule: None,
    off: Off::Redacted("<REDACTED>"),
};
const CC_TD_OMIT: Gate = Gate {
    flag: "OTEL_LOG_TOOL_DETAILS",
    rule: None,
    off: Off::Omitted,
};
const CC_TD_CUSTOM: Gate = Gate {
    flag: "OTEL_LOG_TOOL_DETAILS",
    rule: None,
    off: Off::Generic("custom"),
};
const CC_TD_THIRD_PARTY: Gate = Gate {
    flag: "OTEL_LOG_TOOL_DETAILS",
    rule: None,
    off: Off::Generic("third-party"),
};
const CC_TC: Gate = Gate {
    flag: "OTEL_LOG_TOOL_CONTENT",
    rule: None,
    off: Off::Omitted,
};
const CC_RB_ANY: Gate = Gate {
    flag: "OTEL_LOG_RAW_API_BODIES",
    rule: Some(Rule::RawAny),
    off: Off::Omitted,
};
const CC_RB_INLINE: Gate = Gate {
    flag: "OTEL_LOG_RAW_API_BODIES",
    rule: Some(Rule::RawInline),
    off: Off::Omitted,
};
const CC_RB_FILE: Gate = Gate {
    flag: "OTEL_LOG_RAW_API_BODIES",
    rule: Some(Rule::RawFile),
    off: Off::Omitted,
};
const CC_ACCOUNT_METRICS: Gate = Gate {
    flag: "OTEL_METRICS_INCLUDE_ACCOUNT_UUID",
    rule: None,
    off: Off::Omitted,
};
const CC_SESSION_METRICS: Gate = Gate {
    flag: "OTEL_METRICS_INCLUDE_SESSION_ID",
    rule: None,
    off: Off::Omitted,
};
const CC_VERSION_METRICS: Gate = Gate {
    flag: "OTEL_METRICS_INCLUDE_VERSION",
    rule: None,
    off: Off::Omitted,
};
const CC_ENTRYPOINT_METRICS: Gate = Gate {
    flag: "OTEL_METRICS_INCLUDE_ENTRYPOINT",
    rule: None,
    off: Off::Omitted,
};
const CC_RESOURCE_METRICS: Gate = Gate {
    flag: "OTEL_METRICS_INCLUDE_RESOURCE_ATTRIBUTES",
    rule: None,
    off: Off::Omitted,
};
const CC_REPOSITORY_METRICS: Gate = Gate {
    flag: "OTEL_METRICS_INCLUDE_REPOSITORY",
    rule: None,
    off: Off::Omitted,
};

static CC_FLAGS: &[Flag] = &[
    flag(
        "OTEL_LOG_USER_PROMPTS",
        Rule::Truthy,
        "Prompt text",
        CC_COMMON_DOC,
    ),
    flag(
        "OTEL_LOG_ASSISTANT_RESPONSES",
        Rule::FallbackTo("OTEL_LOG_USER_PROMPTS"),
        "Claude's response text",
        CC_COMMON_DOC,
    ),
    flag(
        "OTEL_LOG_TOOL_DETAILS",
        Rule::Truthy,
        "Full shell commands, tool input, and MCP, skill and plugin names",
        CC_COMMON_DOC,
    ),
    flag(
        "OTEL_LOG_TOOL_CONTENT",
        Rule::Truthy,
        "Tool output and file contents in trace spans",
        CC_COMMON_DOC,
    ),
    flag(
        "OTEL_LOG_RAW_API_BODIES",
        Rule::RawAny,
        "Full model requests and responses, the whole conversation",
        CC_COMMON_DOC,
    ),
    flag(
        "OTEL_LOG_MANAGED_SETTINGS",
        Rule::Truthy,
        "Your managed settings (redacted) and their SHA-256",
        CC_COMMON_DOC,
    ),
    flag(
        "OTEL_METRICS_INCLUDE_SESSION_ID",
        Rule::NotFalse,
        "Session ID on metrics",
        CC_METRICS_DOC,
    ),
    flag(
        "OTEL_METRICS_INCLUDE_ACCOUNT_UUID",
        Rule::NotFalse,
        "Account IDs on metrics",
        CC_METRICS_DOC,
    ),
    flag(
        "OTEL_METRICS_INCLUDE_VERSION",
        Rule::Truthy,
        "Claude Code version on metrics",
        CC_METRICS_DOC,
    ),
    flag(
        "OTEL_METRICS_INCLUDE_ENTRYPOINT",
        Rule::Truthy,
        "How Claude Code was started, on metrics",
        CC_METRICS_DOC,
    ),
    flag(
        "OTEL_METRICS_INCLUDE_RESOURCE_ATTRIBUTES",
        Rule::NotFalse,
        "Your custom attributes on metrics",
        CC_METRICS_DOC,
    ),
    flag(
        "OTEL_METRICS_INCLUDE_REPOSITORY",
        Rule::Truthy,
        "Repository URL, owner and name",
        CC_METRICS_DOC,
    ),
];

static CC_IDENTITY: &[Attr] = &[
    seen(attr(
        "user.email",
        Group::Identity,
        "your account email (when signed in with a Claude account)",
    )),
    limited(
        seen(attr(
            "user.account_uuid",
            Group::Identity,
            "your account UUID",
        )),
        LOGS_TRACES_BETA,
    ),
    limited(
        gated(
            seen(attr(
                "user.account_uuid",
                Group::Identity,
                "your account UUID",
            )),
            CC_ACCOUNT_METRICS,
        ),
        METRICS,
    ),
    limited(
        seen(attr(
            "user.account_id",
            Group::Identity,
            "your tagged account ID",
        )),
        LOGS_TRACES_BETA,
    ),
    limited(
        gated(
            seen(attr(
                "user.account_id",
                Group::Identity,
                "your tagged account ID",
            )),
            CC_ACCOUNT_METRICS,
        ),
        METRICS,
    ),
    seen(attr(
        "organization.id",
        Group::Identity,
        "your organization's UUID",
    )),
    seen(attr(
        "user.id",
        Group::Identity,
        "a random ID for this installation",
    )),
    limited(
        seen(attr("session.id", Group::Identity, "this session's ID")),
        LOGS_TRACES_BETA,
    ),
    limited(
        gated(
            seen(attr("session.id", Group::Identity, "this session's ID")),
            CC_SESSION_METRICS,
        ),
        METRICS,
    ),
    limited(
        attr("ccr.session.id", Group::Identity, "the cloud session's ID"),
        LOGS_TRACES_BETA,
    ),
    limited(
        gated(
            attr("ccr.session.id", Group::Identity, "the cloud session's ID"),
            CC_SESSION_METRICS,
        ),
        METRICS,
    ),
    seen(attr(
        "terminal.type",
        Group::Identity,
        "your terminal, such as iTerm.app, VS Code or tmux",
    )),
    maybe(limited(
        attr("app.version", Group::Identity, "the Claude Code version"),
        LOGS_TRACES_BETA,
    )),
    gated(
        limited(
            attr("app.version", Group::Identity, "the Claude Code version"),
            METRICS,
        ),
        CC_VERSION_METRICS,
    ),
    maybe(limited(
        attr(
            "app.entrypoint",
            Group::Identity,
            "how Claude Code was started",
        ),
        LOGS_TRACES_BETA,
    )),
    gated(
        limited(
            attr(
                "app.entrypoint",
                Group::Identity,
                "how Claude Code was started",
            ),
            METRICS,
        ),
        CC_ENTRYPOINT_METRICS,
    ),
    limited(
        attr(
            "vcs.repository.url.full",
            Group::Identity,
            "the repository's URL",
        ),
        LOGS,
    ),
    gated(
        limited(
            attr(
                "vcs.repository.url.full",
                Group::Identity,
                "the repository's URL",
            ),
            METRICS,
        ),
        CC_REPOSITORY_METRICS,
    ),
    limited(
        attr("vcs.owner.name", Group::Identity, "the repository owner"),
        LOGS,
    ),
    gated(
        limited(
            attr("vcs.owner.name", Group::Identity, "the repository owner"),
            METRICS,
        ),
        CC_REPOSITORY_METRICS,
    ),
    limited(
        attr(
            "vcs.repository.name",
            Group::Identity,
            "the repository name",
        ),
        LOGS,
    ),
    gated(
        limited(
            attr(
                "vcs.repository.name",
                Group::Identity,
                "the repository name",
            ),
            METRICS,
        ),
        CC_REPOSITORY_METRICS,
    ),
    limited(
        attr(
            "vcs.provider.name",
            Group::Identity,
            "the repository's host",
        ),
        LOGS,
    ),
    gated(
        limited(
            attr(
                "vcs.provider.name",
                Group::Identity,
                "the repository's host",
            ),
            METRICS,
        ),
        CC_REPOSITORY_METRICS,
    ),
    maybe(attr(
        "user.groups",
        Group::Identity,
        "your identity provider's groups",
    )),
    maybe(attr(
        "identity.source",
        Group::Identity,
        "your identity provider, such as gateway-oidc",
    )),
    limited(
        attr(
            "*",
            Group::Identity,
            "an attribute set by OTEL_RESOURCE_ATTRIBUTES",
        ),
        LOGS_TRACES_BETA,
    ),
    limited(
        gated(
            attr(
                "*",
                Group::Identity,
                "an attribute set by OTEL_RESOURCE_ATTRIBUTES",
            ),
            CC_RESOURCE_METRICS,
        ),
        METRICS,
    ),
];

static CC_RESOURCE: &[Attr] = &[
    constant(
        seen(attr(
            "service.name",
            Group::Resource,
            "the Claude Code service name",
        )),
        "claude-code",
    ),
    seen(attr(
        "service.version",
        Group::Resource,
        "the Claude Code version",
    )),
    seen(attr(
        "os.type",
        Group::Resource,
        "your operating system type",
    )),
    seen(attr(
        "os.version",
        Group::Resource,
        "your operating system version",
    )),
    seen(attr(
        "host.arch",
        Group::Resource,
        "your computer's architecture",
    )),
    attr("wsl.version", Group::Resource, "your WSL version"),
];

static CC_COMMON: &[Attr] = &[
    limited(
        seen(attr("event.name", Group::Event, "the event name")),
        LOGS_BETA,
    ),
    limited(
        seen(attr(
            "event.timestamp",
            Group::Event,
            "when the event occurred",
        )),
        LOGS_BETA,
    ),
    limited(
        seen(attr(
            "event.sequence",
            Group::Event,
            "the event's sequence number",
        )),
        LOGS_BETA,
    ),
    limited(
        seen(attr(
            "prompt.id",
            Group::Event,
            "the ID linking events from one prompt",
        )),
        LOGS_BETA,
    ),
    limited(
        attr(
            "workspace.host_paths",
            Group::Event,
            "your workspace folders",
        ),
        LOGS_BETA,
    ),
    limited(
        attr(
            "workflow.run_id",
            Group::Event,
            "the ID of the workflow run",
        ),
        TRACES_BETA,
    ),
    limited(
        gated(
            attr("workflow.name", Group::Event, "the name of the workflow"),
            CC_TD_CUSTOM,
        ),
        TRACES_BETA,
    ),
    limited(
        attr("agent_id", Group::Event, "the subagent's ID"),
        TRACES_BETA,
    ),
    limited(
        attr("parent_agent_id", Group::Event, "the parent agent's ID"),
        TRACES_BETA,
    ),
    limited(
        attr("span.type", Group::Event, "the span's type"),
        TRACES_BETA,
    ),
];

static CC_USER_PROMPT: &[Attr] = &[
    seen(attr("prompt_length", Group::Event, "the prompt length")),
    seen(attr(
        "message.uuid",
        Group::Event,
        "the ID of the prompt message",
    )),
    attr(
        "command_source",
        Group::Event,
        "how the prompt was submitted",
    ),
    gated(
        seen(attr("prompt", Group::Content, "the prompt text")),
        CC_UP,
    ),
    gated(
        seen(attr("prompt_text", Group::Content, "the prompt text")),
        CC_UP,
    ),
    gated(
        attr("command_name", Group::Content, "the command name"),
        CC_TD_CUSTOM,
    ),
];

static CC_ASSISTANT_RESPONSE: &[Attr] = &[
    seen(attr(
        "response_length",
        Group::Event,
        "the response length in characters",
    )),
    seen(attr("model", Group::Event, "the model name")),
    seen(attr("request_id", Group::Event, "the model request ID")),
    seen(attr(
        "message.uuid",
        Group::Event,
        "the ID of the response message",
    )),
    seen(attr(
        "query_source",
        Group::Event,
        "what issued the request",
    )),
    gated(
        seen(attr("response", Group::Content, "Claude's response text")),
        CC_AR,
    ),
];

static CC_TOOL_RESULT: &[Attr] = &[
    seen(attr("tool_name", Group::Event, "the tool's name")),
    seen(attr(
        "tool_use_id",
        Group::Event,
        "the ID of this tool invocation",
    )),
    seen(attr("request_id", Group::Event, "the model request ID")),
    seen(attr("success", Group::Event, "whether the tool succeeded")),
    seen(attr("duration_ms", Group::Event, "how long the tool took")),
    attr("error_type", Group::Event, "the tool error type"),
    attr(
        "decision_type",
        Group::Event,
        "the permission decision type",
    ),
    attr(
        "decision_source",
        Group::Event,
        "where the decision came from",
    ),
    seen(attr(
        "tool_input_size_bytes",
        Group::Event,
        "the size of the tool input",
    )),
    seen(attr(
        "tool_result_size_bytes",
        Group::Event,
        "the size of the tool result",
    )),
    attr(
        "mcp_server_scope",
        Group::Event,
        "where the MCP server was configured",
    ),
    gated(
        seen(attr(
            "tool_parameters",
            Group::Content,
            "the tool's parameters, including a Bash command in full",
        )),
        CC_TD_OMIT,
    ),
    gated(
        seen(attr("tool_input", Group::Content, "the tool's input")),
        CC_TD_OMIT,
    ),
    gated(
        attr("error", Group::Content, "the tool error message"),
        CC_TD_OMIT,
    ),
    gated(
        attr(
            "vcs.ref.head.*",
            Group::Content,
            "the current version-control reference",
        ),
        CC_TD_OMIT,
    ),
];

static CC_API_REQUEST: &[Attr] = &[
    seen(attr("model", Group::Event, "the model name")),
    seen(attr(
        "cost_usd",
        Group::Event,
        "the request cost in US dollars",
    )),
    seen(attr(
        "cost_usd_micros",
        Group::Event,
        "the request cost in microdollars",
    )),
    seen(attr(
        "duration_ms",
        Group::Event,
        "how long the request took",
    )),
    seen(attr("input_tokens", Group::Event, "the input token count")),
    seen(attr(
        "output_tokens",
        Group::Event,
        "the output token count",
    )),
    seen(attr(
        "cache_read_tokens",
        Group::Event,
        "the cache read token count",
    )),
    seen(attr(
        "cache_creation_tokens",
        Group::Event,
        "the cache creation token count",
    )),
    seen(attr(
        "cache_creation_5m_tokens",
        Group::Event,
        "the five-minute cache creation token count",
    )),
    seen(attr(
        "cache_creation_1h_tokens",
        Group::Event,
        "the one-hour cache creation token count",
    )),
    seen(attr("request_id", Group::Event, "the model request ID")),
    seen(attr(
        "client_request_id",
        Group::Event,
        "the client-generated request ID",
    )),
    seen(attr("speed", Group::Event, "whether fast mode was used")),
    seen(attr(
        "query_source",
        Group::Event,
        "what issued the request",
    )),
    seen(attr("effort", Group::Event, "the model effort level")),
    maybe(attr(
        "ttft_ms",
        Group::Event,
        "the time to the first response token",
    )),
    gated(
        attr("agent.name", Group::Content, "the agent name"),
        CC_TD_CUSTOM,
    ),
    gated(
        attr("skill.name", Group::Content, "the skill name"),
        CC_TD_THIRD_PARTY,
    ),
    gated(
        attr("plugin.name", Group::Content, "the plugin name"),
        CC_TD_THIRD_PARTY,
    ),
    gated(
        attr(
            "marketplace.name",
            Group::Content,
            "the plugin marketplace name",
        ),
        CC_TD_OMIT,
    ),
    gated(
        attr("mcp_server.name", Group::Content, "the MCP server name"),
        CC_TD_CUSTOM,
    ),
    gated(
        attr("mcp_tool.name", Group::Content, "the MCP tool name"),
        CC_TD_CUSTOM,
    ),
];

static CC_API_ERROR: &[Attr] = &[
    attr("model", Group::Event, "the model name"),
    attr("error", Group::Event, "the request error"),
    attr("status_code", Group::Event, "the HTTP status code"),
    attr("duration_ms", Group::Event, "how long the request took"),
    attr("attempt", Group::Event, "the attempt number"),
    attr("request_id", Group::Event, "the model request ID"),
    attr(
        "client_request_id",
        Group::Event,
        "the client-generated request ID",
    ),
    attr("speed", Group::Event, "whether fast mode was used"),
    attr("query_source", Group::Event, "what issued the request"),
    attr("effort", Group::Event, "the model effort level"),
    gated(
        attr("agent.name", Group::Content, "the agent name"),
        CC_TD_CUSTOM,
    ),
    gated(
        attr("skill.name", Group::Content, "the skill name"),
        CC_TD_THIRD_PARTY,
    ),
    gated(
        attr("plugin.name", Group::Content, "the plugin name"),
        CC_TD_THIRD_PARTY,
    ),
    gated(
        attr(
            "marketplace.name",
            Group::Content,
            "the plugin marketplace name",
        ),
        CC_TD_OMIT,
    ),
    gated(
        attr("mcp_server.name", Group::Content, "the MCP server name"),
        CC_TD_CUSTOM,
    ),
    gated(
        attr("mcp_tool.name", Group::Content, "the MCP tool name"),
        CC_TD_CUSTOM,
    ),
];

static CC_API_REFUSAL: &[Attr] = &[
    attr("model", Group::Event, "the model name"),
    attr("request_id", Group::Event, "the model request ID"),
    attr("query_source", Group::Event, "what issued the request"),
    attr("speed", Group::Event, "whether fast mode was used"),
    attr("attempt", Group::Event, "the attempt number"),
    attr("effort", Group::Event, "the model effort level"),
    attr(
        "server_fallback_hop",
        Group::Event,
        "whether a server fallback was used",
    ),
    attr(
        "has_category",
        Group::Event,
        "whether a refusal category is present",
    ),
    attr(
        "has_explanation",
        Group::Event,
        "whether a refusal explanation is present",
    ),
    gated(
        attr("category", Group::Content, "the refusal category"),
        CC_TD_OMIT,
    ),
    gated(
        attr("agent.name", Group::Content, "the agent name"),
        CC_TD_CUSTOM,
    ),
    gated(
        attr("skill.name", Group::Content, "the skill name"),
        CC_TD_THIRD_PARTY,
    ),
    gated(
        attr("plugin.name", Group::Content, "the plugin name"),
        CC_TD_THIRD_PARTY,
    ),
    gated(
        attr(
            "marketplace.name",
            Group::Content,
            "the plugin marketplace name",
        ),
        CC_TD_OMIT,
    ),
    gated(
        attr("mcp_server.name", Group::Content, "the MCP server name"),
        CC_TD_CUSTOM,
    ),
    gated(
        attr("mcp_tool.name", Group::Content, "the MCP tool name"),
        CC_TD_CUSTOM,
    ),
];

static CC_API_REQUEST_BODY: &[Attr] = &[
    attr("body_length", Group::Event, "the request body length"),
    attr(
        "body_truncated",
        Group::Event,
        "whether the request body was cut",
    ),
    attr("model", Group::Event, "the model name"),
    attr("query_source", Group::Event, "what issued the request"),
    attr(
        "request_body_id",
        Group::Event,
        "the ID of the request body",
    ),
    gated(
        attr("body", Group::Content, "the full model request body"),
        CC_RB_INLINE,
    ),
    gated(
        attr(
            "body_ref",
            Group::Content,
            "the path of the request body file on this machine",
        ),
        CC_RB_FILE,
    ),
];

static CC_API_RESPONSE_BODY: &[Attr] = &[
    attr("body_length", Group::Event, "the response body length"),
    attr(
        "body_truncated",
        Group::Event,
        "whether the response body was cut",
    ),
    attr("model", Group::Event, "the model name"),
    attr("query_source", Group::Event, "what issued the request"),
    attr(
        "request_body_id",
        Group::Event,
        "the ID of the request body",
    ),
    attr("request_id", Group::Event, "the model request ID"),
    attr("message.id", Group::Event, "the response message ID"),
    attr(
        "message.uuid",
        Group::Event,
        "the response transcript entry ID",
    ),
    gated(
        attr("body", Group::Content, "the full model response body"),
        CC_RB_INLINE,
    ),
    gated(
        attr(
            "body_ref",
            Group::Content,
            "the path of the response body file on this machine",
        ),
        CC_RB_FILE,
    ),
];

static CC_TOOL_DECISION: &[Attr] = &[
    seen(attr("tool_name", Group::Event, "the tool's name")),
    seen(attr(
        "tool_use_id",
        Group::Event,
        "the ID of this tool invocation",
    )),
    seen(attr("request_id", Group::Event, "the model request ID")),
    seen(attr(
        "decision",
        Group::Event,
        "whether the tool was allowed",
    )),
    seen(attr(
        "tool_source",
        Group::Event,
        "where the tool came from",
    )),
    seen(attr("source", Group::Event, "where the decision came from")),
    attr(
        "classifier_verdict",
        Group::Event,
        "the permission classifier result",
    ),
    seen(attr(
        "permission_mode",
        Group::Event,
        "the active permission mode",
    )),
    gated(
        attr(
            "classifier_category",
            Group::Content,
            "the permission classifier category",
        ),
        CC_TD_OMIT,
    ),
    gated(
        seen(attr(
            "tool_parameters",
            Group::Content,
            "the tool's parameters",
        )),
        CC_TD_OMIT,
    ),
];

static CC_SAFETY_EVENT: &[Attr] = &[
    attr("category", Group::Event, "the safety category"),
    attr("decision", Group::Event, "whether the action was allowed"),
    attr(
        "decision_source",
        Group::Event,
        "where the decision came from",
    ),
    attr("reason_code", Group::Event, "the policy reason code"),
    attr("reason_type", Group::Event, "the policy reason type"),
    attr("rule_source", Group::Event, "where the rule came from"),
    attr("grant_scope", Group::Event, "the permission grant scope"),
    attr("circuit_breaker", Group::Event, "the circuit breaker state"),
    attr("hook_event", Group::Event, "the hook event name"),
    attr("tool_class", Group::Event, "the class of tool"),
    attr("tool_name", Group::Event, "the tool's name"),
    attr("tool_source", Group::Event, "where the tool came from"),
    attr(
        "permission_mode",
        Group::Event,
        "the active permission mode",
    ),
    attr(
        "tool_use_id",
        Group::Event,
        "the ID of this tool invocation",
    ),
    attr(
        "sandbox_violation_count",
        Group::Event,
        "the number of sandbox violations",
    ),
    attr(
        "sandbox_enabled",
        Group::Event,
        "whether the sandbox is enabled",
    ),
    gated(
        attr(
            "classifier_category",
            Group::Content,
            "the permission classifier category",
        ),
        CC_TD_OMIT,
    ),
];

static CC_PERMISSION_MODE: &[Attr] = &[
    attr("from_mode", Group::Event, "the previous permission mode"),
    attr("to_mode", Group::Event, "the new permission mode"),
    attr("trigger", Group::Event, "what changed the permission mode"),
];

static CC_AUTH: &[Attr] = &[
    attr("action", Group::Event, "whether you logged in or out"),
    attr("success", Group::Event, "whether authentication succeeded"),
    attr("auth_method", Group::Event, "the authentication method"),
    attr(
        "error_category",
        Group::Event,
        "the authentication error kind",
    ),
    attr("status_code", Group::Event, "the HTTP status code"),
];

static CC_MCP_CONNECTION: &[Attr] = &[
    seen(attr("status", Group::Event, "the connection status")),
    seen(attr("transport_type", Group::Event, "the transport type")),
    seen(attr(
        "server_scope",
        Group::Event,
        "where the server was configured",
    )),
    seen(attr(
        "duration_ms",
        Group::Event,
        "how long the connection took",
    )),
    attr("error_code", Group::Event, "the connection error code"),
    seen(attr(
        "is_plugin",
        Group::Event,
        "whether the server is a plugin",
    )),
    attr(
        "plugin_id_hash",
        Group::Event,
        "a hash identifying the plugin",
    ),
    gated(
        attr("plugin.name", Group::Content, "the plugin name"),
        CC_TD_THIRD_PARTY,
    ),
    gated(
        seen(attr(
            "server_name",
            Group::Content,
            "your MCP server's name",
        )),
        CC_TD_OMIT,
    ),
    gated(
        attr("error", Group::Content, "the connection error"),
        CC_TD_OMIT,
    ),
];

static CC_PLUGIN_INSTALLED: &[Attr] = &[
    attr(
        "marketplace.is_official",
        Group::Event,
        "whether the marketplace is official",
    ),
    attr(
        "install.trigger",
        Group::Event,
        "how the plugin installation started",
    ),
    gated(
        attr("plugin.name", Group::Content, "the plugin name"),
        CC_TD_OMIT,
    ),
    gated(
        attr("plugin.version", Group::Content, "the plugin version"),
        CC_TD_OMIT,
    ),
    gated(
        attr(
            "marketplace.name",
            Group::Content,
            "the plugin marketplace name",
        ),
        CC_TD_OMIT,
    ),
];

static CC_PLUGIN_LOADED: &[Attr] = &[
    seen(attr("plugin.version", Group::Event, "the plugin version")),
    seen(attr(
        "plugin.scope",
        Group::Event,
        "where the plugin is installed",
    )),
    seen(attr(
        "enabled_via",
        Group::Event,
        "how the plugin was enabled",
    )),
    seen(attr(
        "plugin_id_hash",
        Group::Event,
        "a hash identifying the plugin",
    )),
    seen(attr(
        "has_hooks",
        Group::Event,
        "whether the plugin has hooks",
    )),
    seen(attr(
        "has_mcp",
        Group::Event,
        "whether the plugin has MCP servers",
    )),
    seen(attr(
        "host_owned_mcp",
        Group::Event,
        "whether the host owns its MCP servers",
    )),
    seen(attr(
        "skill_path_count",
        Group::Event,
        "the number of skill paths",
    )),
    seen(attr(
        "command_path_count",
        Group::Event,
        "the number of command paths",
    )),
    seen(attr(
        "agent_path_count",
        Group::Event,
        "the number of agent paths",
    )),
    seen(attr(
        "safe_mode",
        Group::Event,
        "whether safe mode is enabled",
    )),
    gated(
        seen(attr("plugin.name", Group::Content, "the plugin name")),
        CC_TD_THIRD_PARTY,
    ),
    gated(
        seen(attr(
            "marketplace.name",
            Group::Content,
            "the plugin marketplace name",
        )),
        CC_TD_THIRD_PARTY,
    ),
];

static CC_SKILL_ACTIVATED: &[Attr] = &[
    attr(
        "invocation_trigger",
        Group::Event,
        "how the skill was triggered",
    ),
    attr("skill.source", Group::Event, "where the skill came from"),
    attr("skill.kind", Group::Event, "the kind of skill"),
    gated(
        attr("skill.name", Group::Content, "the skill name"),
        Gate {
            flag: "OTEL_LOG_TOOL_DETAILS",
            rule: None,
            off: Off::Generic("custom_skill"),
        },
    ),
    gated(
        attr("plugin.name", Group::Content, "the plugin name"),
        CC_TD_OMIT,
    ),
    gated(
        attr(
            "marketplace.name",
            Group::Content,
            "the plugin marketplace name",
        ),
        CC_TD_OMIT,
    ),
];

static CC_AT_MENTION: &[Attr] = &[
    attr(
        "mention_type",
        Group::Event,
        "the kind of thing you mentioned",
    ),
    attr("success", Group::Event, "whether the mention succeeded"),
];

static CC_API_RETRIES: &[Attr] = &[
    attr("model", Group::Event, "the model name"),
    attr("error", Group::Event, "the final request error"),
    attr("status_code", Group::Event, "the HTTP status code"),
    attr("total_attempts", Group::Event, "the number of attempts"),
    attr(
        "total_retry_duration_ms",
        Group::Event,
        "the total time spent retrying",
    ),
    attr("speed", Group::Event, "whether fast mode was used"),
];

static CC_HOOK_REGISTERED: &[Attr] = &[
    seen(attr("hook_event", Group::Event, "the hook event name")),
    seen(attr(
        "hook_type",
        Group::Event,
        "the hook implementation type",
    )),
    seen(attr(
        "hook_source",
        Group::Event,
        "where the hook came from",
    )),
    seen(attr(
        "safe_mode",
        Group::Event,
        "whether safe mode is enabled",
    )),
    gated(
        attr("plugin.name", Group::Content, "the plugin name"),
        CC_TD_THIRD_PARTY,
    ),
    attr(
        "plugin_id_hash",
        Group::Event,
        "a hash identifying the plugin",
    ),
    gated(
        seen(attr("hook_matcher", Group::Content, "the hook's matcher")),
        CC_TD_OMIT,
    ),
];

static CC_HOOK_START: &[Attr] = &[
    seen(attr("hook_event", Group::Event, "the hook event name")),
    seen(attr("hook_name", Group::Event, "the hook name and matcher")),
    seen(attr(
        "num_hooks",
        Group::Event,
        "the number of matching hooks",
    )),
    seen(attr(
        "managed_only",
        Group::Event,
        "whether only managed hooks are allowed",
    )),
    seen(attr(
        "hook_source",
        Group::Event,
        "where the hook came from",
    )),
    seen(attr(
        "safe_mode",
        Group::Event,
        "whether safe mode is enabled",
    )),
    limited(
        gated(
            attr("hook_definitions", Group::Content, "the hook definitions"),
            CC_TD_OMIT,
        ),
        BETA,
    ),
];

static CC_HOOK_COMPLETE: &[Attr] = &[
    seen(attr("hook_event", Group::Event, "the hook event name")),
    seen(attr("hook_name", Group::Event, "the hook name and matcher")),
    seen(attr(
        "num_hooks",
        Group::Event,
        "the number of matching hooks",
    )),
    seen(attr(
        "num_success",
        Group::Event,
        "the number of successful hooks",
    )),
    seen(attr(
        "num_blocking",
        Group::Event,
        "the number of blocking hooks",
    )),
    seen(attr(
        "num_non_blocking_error",
        Group::Event,
        "the number of non-blocking hook errors",
    )),
    seen(attr(
        "num_cancelled",
        Group::Event,
        "the number of cancelled hooks",
    )),
    seen(attr(
        "total_duration_ms",
        Group::Event,
        "the combined time spent in hooks",
    )),
    seen(attr(
        "stdout_chars",
        Group::Event,
        "the number of output characters",
    )),
    seen(attr(
        "additional_context_chars",
        Group::Event,
        "the number of added context characters",
    )),
    seen(attr(
        "system_message_chars",
        Group::Event,
        "the number of system message characters",
    )),
    seen(attr(
        "initial_user_message_chars",
        Group::Event,
        "the number of initial user message characters",
    )),
    seen(attr(
        "num_outputs_persisted",
        Group::Event,
        "the number of saved hook outputs",
    )),
    seen(attr(
        "managed_only",
        Group::Event,
        "whether only managed hooks are allowed",
    )),
    seen(attr(
        "hook_source",
        Group::Event,
        "where the hook came from",
    )),
    seen(attr(
        "safe_mode",
        Group::Event,
        "whether safe mode is enabled",
    )),
    limited(
        gated(
            attr("hook_definitions", Group::Content, "the hook definitions"),
            CC_TD_OMIT,
        ),
        BETA,
    ),
];

static CC_HOOK_PLUGIN_METRICS: &[Attr] = &[
    attr("plugin_id", Group::Event, "the plugin identifier"),
    attr("hook_event", Group::Event, "the hook event name"),
];

static CC_COMPACTION: &[Attr] = &[
    attr(
        "trigger",
        Group::Event,
        "whether compaction was automatic or manual",
    ),
    attr("success", Group::Event, "whether compaction succeeded"),
    attr("duration_ms", Group::Event, "how long compaction took"),
    attr(
        "pre_tokens",
        Group::Event,
        "the estimated token count before",
    ),
    attr(
        "post_tokens",
        Group::Event,
        "the estimated token count after",
    ),
    attr("error", Group::Event, "the compaction error"),
    attr(
        "precompute_reuse",
        Group::Event,
        "whether a precomputed summary was reused",
    ),
];

static CC_SUBAGENT_COMPLETED: &[Attr] = &[
    attr("agent.source", Group::Event, "where the agent came from"),
    attr("is_built_in", Group::Event, "whether the agent is built in"),
    attr(
        "is_async",
        Group::Event,
        "whether the agent ran asynchronously",
    ),
    attr("total_tokens", Group::Event, "the total token count"),
    attr("total_tool_uses", Group::Event, "the number of tool uses"),
    attr("duration_ms", Group::Event, "how long the agent ran"),
    attr("model", Group::Event, "the model name"),
    attr("final_model", Group::Event, "the final model name"),
    attr("model_swapped", Group::Event, "whether the model changed"),
    attr(
        "plugin_id_hash",
        Group::Event,
        "a hash identifying the plugin",
    ),
    gated(
        attr("plugin.name", Group::Content, "the plugin name"),
        CC_TD_THIRD_PARTY,
    ),
    gated(
        attr("agent_type", Group::Content, "the agent type"),
        CC_TD_CUSTOM,
    ),
];

static CC_FEEDBACK_SURVEY: &[Attr] = &[
    attr("event_type", Group::Event, "the survey event type"),
    attr(
        "appearance_id",
        Group::Event,
        "the ID of this survey instance",
    ),
    attr("survey_type", Group::Event, "the kind of survey"),
    attr("response", Group::Event, "your survey response"),
    attr(
        "enabled_via_override",
        Group::Event,
        "whether a setting enabled the survey",
    ),
];

static CC_RETENTION_SWEEP: &[Attr] = &[
    attr("result", Group::Event, "the cleanup result"),
    attr("period_days", Group::Event, "the retention period in days"),
    attr(
        "used_default",
        Group::Event,
        "whether the default period was used",
    ),
    attr("skip_reason", Group::Event, "why cleanup was skipped"),
    attr(
        "transcripts_deleted",
        Group::Event,
        "the number of transcripts deleted",
    ),
    attr(
        "transcripts_exempted_desktop",
        Group::Event,
        "the number of desktop transcripts kept",
    ),
    attr(
        "session_files_deleted",
        Group::Event,
        "the number of session files deleted",
    ),
    attr(
        "artifacts_deleted",
        Group::Event,
        "the number of artifacts deleted",
    ),
    attr(
        "files_retained_fresh",
        Group::Event,
        "the number of recent files kept",
    ),
    attr(
        "files_past_cutoff",
        Group::Event,
        "the number of old files found",
    ),
    attr("error_count", Group::Event, "the number of cleanup errors"),
];

static CC_MANAGED_SETTINGS: &[Attr] = &[
    seen(attr(
        "managed_settings.trigger",
        Group::Event,
        "what caused managed settings to be applied",
    )),
    attr("error.type", Group::Event, "the settings error type"),
    seen(attr(
        "managed_settings.sources",
        Group::Event,
        "the managed settings sources",
    )),
    seen(attr(
        "managed_settings.source_behavior",
        Group::Event,
        "how managed settings sources behave",
    )),
    seen(attr(
        "managed_settings.helper.state",
        Group::Event,
        "the managed helper state",
    )),
    seen(attr(
        "managed_settings.helper.applied",
        Group::Event,
        "whether the managed helper was applied",
    )),
    attr(
        "managed_settings.helper.entry",
        Group::Event,
        "the managed helper entry",
    ),
    attr(
        "managed_settings.helper.path",
        Group::Event,
        "the path of the managed helper",
    ),
    attr(
        "managed_settings.settings_truncated",
        Group::Event,
        "whether the settings were cut",
    ),
    gated(
        attr(
            "managed_settings.resolved_sha256",
            Group::Content,
            "the SHA-256 digest of the settings",
        ),
        Gate {
            flag: "OTEL_LOG_MANAGED_SETTINGS",
            rule: None,
            off: Off::Omitted,
        },
    ),
    gated(
        attr(
            "managed_settings.settings",
            Group::Content,
            "the managed settings after redaction",
        ),
        Gate {
            flag: "OTEL_LOG_MANAGED_SETTINGS",
            rule: None,
            off: Off::Omitted,
        },
    ),
];

static CC_SESSION_COUNT: &[Attr] = &[seen(attr(
    "start_type",
    Group::Event,
    "how the session was started",
))];
static CC_LINES_OF_CODE: &[Attr] = &[
    attr("type", Group::Event, "whether lines were added or removed"),
    attr("model", Group::Event, "the model name"),
];
static CC_COST_USAGE: &[Attr] = &[
    seen(attr("model", Group::Event, "the model name")),
    seen(attr(
        "query_source",
        Group::Event,
        "what issued the request",
    )),
    attr("speed", Group::Event, "whether fast mode was used"),
    seen(attr("effort", Group::Event, "the model effort level")),
    gated(
        attr("agent.name", Group::Content, "the agent name"),
        CC_TD_CUSTOM,
    ),
    gated(
        attr("skill.name", Group::Content, "the skill name"),
        CC_TD_THIRD_PARTY,
    ),
    gated(
        attr("plugin.name", Group::Content, "the plugin name"),
        CC_TD_THIRD_PARTY,
    ),
    gated(
        attr(
            "marketplace.name",
            Group::Content,
            "the plugin marketplace name",
        ),
        CC_TD_OMIT,
    ),
    gated(
        attr("mcp_server.name", Group::Content, "the MCP server name"),
        CC_TD_CUSTOM,
    ),
    gated(
        attr("mcp_tool.name", Group::Content, "the MCP tool name"),
        CC_TD_CUSTOM,
    ),
];
static CC_TOKEN_USAGE: &[Attr] = &[
    seen(attr("type", Group::Event, "the kind of token usage")),
    seen(attr("model", Group::Event, "the model name")),
    seen(attr(
        "query_source",
        Group::Event,
        "what issued the request",
    )),
    seen(attr("effort", Group::Event, "the model effort level")),
    gated(
        attr("agent.name", Group::Content, "the agent name"),
        CC_TD_CUSTOM,
    ),
    gated(
        attr("skill.name", Group::Content, "the skill name"),
        CC_TD_THIRD_PARTY,
    ),
    gated(
        attr("plugin.name", Group::Content, "the plugin name"),
        CC_TD_THIRD_PARTY,
    ),
    gated(
        attr(
            "marketplace.name",
            Group::Content,
            "the plugin marketplace name",
        ),
        CC_TD_OMIT,
    ),
    gated(
        attr("mcp_server.name", Group::Content, "the MCP server name"),
        CC_TD_CUSTOM,
    ),
    gated(
        attr("mcp_tool.name", Group::Content, "the MCP tool name"),
        CC_TD_CUSTOM,
    ),
];
static CC_CODE_EDIT: &[Attr] = &[
    attr("tool_name", Group::Event, "the code editing tool's name"),
    attr("decision", Group::Event, "the permission decision"),
    attr("source", Group::Event, "where the decision came from"),
    attr(
        "language",
        Group::Event,
        "the edited file's programming language",
    ),
];
static CC_ACTIVE_TIME: &[Attr] = &[seen(attr(
    "type",
    Group::Event,
    "whether time was user activity or CLI processing",
))];

static CC_INTERACTION: &[Attr] = &[
    gated(
        attr("user_prompt", Group::Content, "your prompt text"),
        CC_UP,
    ),
    attr("user_prompt_length", Group::Event, "the prompt length"),
    attr(
        "interaction.sequence",
        Group::Event,
        "the interaction's sequence number",
    ),
    attr("parent.source", Group::Event, "how the span got its parent"),
    attr(
        "interaction.duration_ms",
        Group::Event,
        "how long the interaction took",
    ),
    limited(
        gated(
            attr(
                "new_context",
                Group::Content,
                "the new context after a clear",
            ),
            CC_UP,
        ),
        BETA,
    ),
];

static CC_LLM_REQUEST: &[Attr] = &[
    attr("model", Group::Event, "the model name"),
    constant(
        attr("gen_ai.system", Group::Event, "the model provider"),
        "anthropic",
    ),
    attr(
        "gen_ai.request.model",
        Group::Event,
        "the requested model name",
    ),
    attr(
        "query_source_safe",
        Group::Event,
        "a bounded label for what issued the request",
    ),
    attr("agent_id", Group::Event, "the subagent's ID"),
    attr("parent_agent_id", Group::Event, "the parent agent's ID"),
    attr("workflow.run_id", Group::Event, "the workflow run ID"),
    attr("speed", Group::Event, "whether fast mode was used"),
    attr("effort", Group::Event, "the model effort level"),
    attr(
        "llm_request.context",
        Group::Event,
        "the request span's context",
    ),
    attr("duration_ms", Group::Event, "how long the request took"),
    attr(
        "ttft_ms",
        Group::Event,
        "the time to the first response token",
    ),
    attr(
        "first_content_ms",
        Group::Event,
        "the time to the first content",
    ),
    attr("input_tokens", Group::Event, "the input token count"),
    attr("output_tokens", Group::Event, "the output token count"),
    attr(
        "cache_read_tokens",
        Group::Event,
        "the cache read token count",
    ),
    attr(
        "cache_creation_tokens",
        Group::Event,
        "the cache creation token count",
    ),
    attr("request_id", Group::Event, "the model request ID"),
    attr("gen_ai.response.id", Group::Event, "the response ID"),
    attr(
        "client_request_id",
        Group::Event,
        "the client-generated request ID",
    ),
    attr("attempt", Group::Event, "the attempt number"),
    attr("success", Group::Event, "whether the request succeeded"),
    attr("status_code", Group::Event, "the HTTP status code"),
    attr("error", Group::Event, "the request error"),
    attr("error_class", Group::Event, "the request error class"),
    attr(
        "response.has_tool_call",
        Group::Event,
        "whether the response called a tool",
    ),
    attr("stop_reason", Group::Event, "why the response stopped"),
    attr(
        "gen_ai.response.finish_reasons",
        Group::Event,
        "the reasons the response finished",
    ),
    limited(
        gated(
            attr(
                "query_source",
                Group::Content,
                "the detailed source of the request",
            ),
            CC_TD_CUSTOM,
        ),
        BETA,
    ),
    limited(
        gated(
            attr("workflow.name", Group::Content, "the workflow name"),
            CC_TD_CUSTOM,
        ),
        BETA,
    ),
    limited(
        gated(
            attr("new_context", Group::Content, "the new context"),
            CC_UP,
        ),
        BETA,
    ),
    limited(
        gated(
            attr(
                "system_reminders",
                Group::Content,
                "system reminders added to the request",
            ),
            CC_UP,
        ),
        BETA,
    ),
    limited(
        gated(
            attr(
                "system_prompt_preview",
                Group::Content,
                "a preview of the system prompt",
            ),
            CC_UP,
        ),
        BETA,
    ),
    limited(
        gated(
            attr(
                "user_system_prompt",
                Group::Content,
                "your custom system prompt",
            ),
            CC_UP,
        ),
        BETA,
    ),
    limited(
        gated(
            attr(
                "response.model_output",
                Group::Content,
                "Claude's response text",
            ),
            CC_UP,
        ),
        BETA,
    ),
];

static CC_TOOL_SPAN: &[Attr] = &[
    attr("tool_name", Group::Event, "the tool's name"),
    attr(
        "tool_name_safe",
        Group::Event,
        "a bounded label for the tool",
    ),
    attr(
        "bash_command_class",
        Group::Event,
        "the category of Bash command",
    ),
    attr(
        "bash_argv0",
        Group::Event,
        "the first Bash command argument",
    ),
    attr("duration_ms", Group::Event, "how long the tool took"),
    attr("result_tokens", Group::Event, "the result token count"),
    attr("agent_id", Group::Event, "the subagent's ID"),
    attr("parent_agent_id", Group::Event, "the parent agent's ID"),
    attr("workflow.run_id", Group::Event, "the workflow run ID"),
    attr(
        "tool_use_id",
        Group::Event,
        "the ID of this tool invocation",
    ),
    attr(
        "gen_ai.tool.call.id",
        Group::Event,
        "the OpenTelemetry tool call ID",
    ),
    gated(
        attr("workflow.name", Group::Content, "the workflow name"),
        CC_TD_CUSTOM,
    ),
    gated(
        attr("file_path", Group::Content, "the file path"),
        CC_TD_OMIT,
    ),
    gated(
        attr("full_command", Group::Content, "the full shell command"),
        CC_TD_OMIT,
    ),
    gated(
        attr("skill_name", Group::Content, "the skill name"),
        CC_TD_THIRD_PARTY,
    ),
    gated(
        attr("subagent_type", Group::Content, "the subagent type"),
        CC_TD_CUSTOM,
    ),
    limited(
        gated(
            attr("new_context", Group::Content, "the new context"),
            CC_TC,
        ),
        BETA,
    ),
    limited(
        gated(
            attr("tool_input", Group::Content, "the tool's input"),
            CC_TD_OMIT,
        ),
        BETA,
    ),
];

static CC_TOOL_BLOCKED: &[Attr] = &[
    attr("duration_ms", Group::Event, "how long permission took"),
    attr("decision", Group::Event, "whether the tool was allowed"),
    attr("source", Group::Event, "where the decision came from"),
];
static CC_TOOL_EXECUTION: &[Attr] = &[
    attr("duration_ms", Group::Event, "how long execution took"),
    attr(
        "tool_use_id",
        Group::Event,
        "the ID of this tool invocation",
    ),
    attr(
        "gen_ai.tool.call.id",
        Group::Event,
        "the OpenTelemetry tool call ID",
    ),
    attr("success", Group::Event, "whether the tool succeeded"),
    attr("error_class", Group::Event, "the tool error class"),
    gated(
        attr("error", Group::Content, "the error category"),
        Gate {
            flag: "OTEL_LOG_TOOL_DETAILS",
            rule: None,
            off: Off::Generic("the error category only"),
        },
    ),
];
static CC_HOOK_SPAN: &[Attr] = &[
    attr("hook_event", Group::Event, "the hook event name"),
    attr("hook_name", Group::Event, "the hook name and matcher"),
    attr("num_hooks", Group::Event, "the number of matching hooks"),
    attr("duration_ms", Group::Event, "how long the hooks took"),
    attr(
        "num_success",
        Group::Event,
        "the number of successful hooks",
    ),
    attr("num_blocking", Group::Event, "the number of blocking hooks"),
    attr(
        "num_non_blocking_error",
        Group::Event,
        "the number of non-blocking hook errors",
    ),
    attr(
        "num_cancelled",
        Group::Event,
        "the number of cancelled hooks",
    ),
    gated(
        limited(
            attr("hook_definitions", Group::Content, "the hook definitions"),
            BETA,
        ),
        CC_TD_OMIT,
    ),
];

static CC_TOOL_OUTPUT: &[Attr] = &[
    gated(attr("output", Group::Content, "the tool output"), CC_TC),
    attr(
        "*_truncated",
        Group::Event,
        "whether a piece of content was cut",
    ),
    attr(
        "*_original_length",
        Group::Event,
        "the original content length",
    ),
    gated(
        attr("content", Group::Content, "file or tool content"),
        CC_TD_OMIT,
    ),
    gated(attr("diff", Group::Content, "the file change"), CC_TD_OMIT),
    gated(
        attr("file_path", Group::Content, "the file path"),
        CC_TD_OMIT,
    ),
    gated(
        attr("bash_command", Group::Content, "the Bash command"),
        CC_TD_OMIT,
    ),
];
static CC_GEN_AI_ATTEMPT: &[Attr] = &[
    attr("attempt", Group::Event, "the retry number"),
    attr(
        "client_request_id",
        Group::Event,
        "the client-generated request ID",
    ),
];

static CC_ITEMS: &[Item] = &[
    event(
        "claude_code.user_prompt",
        "You sent a prompt",
        CC_USER_PROMPT,
        Some("https://code.claude.com/docs/en/monitoring-usage#user-prompt-event"),
        false,
        true,
        false,
    ),
    event(
        "claude_code.assistant_response",
        "Claude replied",
        CC_ASSISTANT_RESPONSE,
        Some("https://code.claude.com/docs/en/monitoring-usage#assistant-response-event"),
        false,
        true,
        false,
    ),
    event(
        "claude_code.tool_result",
        "A tool finished: name, result, timing, sizes",
        CC_TOOL_RESULT,
        Some("https://code.claude.com/docs/en/monitoring-usage#tool-result-event"),
        false,
        true,
        true,
    ),
    event(
        "claude_code.api_request",
        "A model request: model, tokens, cost, latency",
        CC_API_REQUEST,
        Some("https://code.claude.com/docs/en/monitoring-usage#api-request-event"),
        false,
        true,
        false,
    ),
    event(
        "claude_code.api_error",
        "A model request failed",
        CC_API_ERROR,
        Some("https://code.claude.com/docs/en/monitoring-usage#api-error-event"),
        false,
        false,
        false,
    ),
    event(
        "claude_code.api_refusal",
        "The model refused a request",
        CC_API_REFUSAL,
        Some("https://code.claude.com/docs/en/monitoring-usage#api-refusal-event"),
        false,
        false,
        false,
    ),
    event_with(
        "claude_code.api_request_body",
        LOGS,
        "The full request sent to the model",
        CC_API_REQUEST_BODY,
        Some(CC_RB_ANY),
        false,
        Some("https://code.claude.com/docs/en/monitoring-usage#api-request-body-event"),
        false,
        false,
        false,
    ),
    event_with(
        "claude_code.api_response_body",
        LOGS,
        "The full response from the model",
        CC_API_RESPONSE_BODY,
        Some(CC_RB_ANY),
        false,
        Some("https://code.claude.com/docs/en/monitoring-usage#api-response-body-event"),
        false,
        false,
        false,
    ),
    event(
        "claude_code.tool_decision",
        "A tool use was allowed or denied, and by whom",
        CC_TOOL_DECISION,
        Some("https://code.claude.com/docs/en/monitoring-usage#tool-decision-event"),
        false,
        true,
        false,
    ),
    event(
        "claude_code.safety_event",
        "A rule, policy, hook or sandbox allowed or blocked an action",
        CC_SAFETY_EVENT,
        Some("https://code.claude.com/docs/en/monitoring-usage#safety-event"),
        false,
        false,
        false,
    ),
    event(
        "claude_code.permission_mode_changed",
        "You switched permission mode",
        CC_PERMISSION_MODE,
        Some("https://code.claude.com/docs/en/monitoring-usage#permission-mode-changed-event"),
        false,
        false,
        false,
    ),
    event(
        "claude_code.auth",
        "You logged in or out",
        CC_AUTH,
        Some("https://code.claude.com/docs/en/monitoring-usage#auth-event"),
        false,
        false,
        false,
    ),
    event(
        "claude_code.mcp_server_connection",
        "An MCP server connected, failed or disconnected",
        CC_MCP_CONNECTION,
        Some("https://code.claude.com/docs/en/monitoring-usage#mcp-server-connection-event"),
        false,
        true,
        false,
    ),
    event(
        "claude_code.internal_error",
        "Claude Code hit an internal error",
        &[
            attr("error_name", Group::Event, "the error class name"),
            attr("error_code", Group::Event, "the error code"),
        ],
        Some("https://code.claude.com/docs/en/monitoring-usage#internal-error-event"),
        false,
        false,
        false,
    ),
    event(
        "claude_code.plugin_installed",
        "A plugin was installed",
        CC_PLUGIN_INSTALLED,
        Some("https://code.claude.com/docs/en/monitoring-usage#plugin-installed-event"),
        false,
        false,
        false,
    ),
    event(
        "claude_code.plugin_loaded",
        "A plugin was loaded",
        CC_PLUGIN_LOADED,
        Some("https://code.claude.com/docs/en/monitoring-usage#plugin-loaded-event"),
        false,
        true,
        false,
    ),
    event(
        "claude_code.skill_activated",
        "A skill ran",
        CC_SKILL_ACTIVATED,
        Some("https://code.claude.com/docs/en/monitoring-usage#skill-activated-event"),
        false,
        false,
        false,
    ),
    event(
        "claude_code.at_mention",
        "You mentioned a file, folder, agent or resource",
        CC_AT_MENTION,
        Some("https://code.claude.com/docs/en/monitoring-usage#at-mention-event"),
        false,
        false,
        false,
    ),
    event(
        "claude_code.api_retries_exhausted",
        "A model request gave up after retries",
        CC_API_RETRIES,
        Some("https://code.claude.com/docs/en/monitoring-usage#api-retries-exhausted-event"),
        false,
        false,
        false,
    ),
    event(
        "claude_code.hook_registered",
        "A hook is configured",
        CC_HOOK_REGISTERED,
        Some("https://code.claude.com/docs/en/monitoring-usage#hook-registered-event"),
        false,
        true,
        false,
    ),
    event(
        "claude_code.hook_execution_start",
        "Hooks started for an event",
        CC_HOOK_START,
        Some("https://code.claude.com/docs/en/monitoring-usage#hook-execution-start-event"),
        false,
        true,
        false,
    ),
    event(
        "claude_code.hook_execution_complete",
        "Hooks finished: counts, timing, output sizes",
        CC_HOOK_COMPLETE,
        Some("https://code.claude.com/docs/en/monitoring-usage#hook-execution-complete-event"),
        false,
        true,
        false,
    ),
    event_with(
        "claude_code.hook_plugin_metrics",
        LOGS,
        "Metrics from official plugin hooks, including up to 20 plugin-emitted boolean or numeric keys",
        CC_HOOK_PLUGIN_METRICS,
        None,
        true,
        Some("https://code.claude.com/docs/en/monitoring-usage#hook-plugin-metrics-event"),
        false,
        false,
        false,
    ),
    event(
        "claude_code.compaction",
        "The conversation was compacted",
        CC_COMPACTION,
        Some("https://code.claude.com/docs/en/monitoring-usage#compaction-event"),
        false,
        false,
        false,
    ),
    event(
        "claude_code.subagent_completed",
        "A subagent finished",
        CC_SUBAGENT_COMPLETED,
        Some("https://code.claude.com/docs/en/monitoring-usage#subagent-completed-event"),
        false,
        false,
        false,
    ),
    event(
        "claude_code.feedback_survey",
        "You saw or answered a feedback survey",
        CC_FEEDBACK_SURVEY,
        Some("https://code.claude.com/docs/en/monitoring-usage#feedback-survey-event"),
        false,
        false,
        false,
    ),
    event(
        "claude_code.retention_sweep",
        "Old local transcripts were cleaned up",
        CC_RETENTION_SWEEP,
        Some("https://code.claude.com/docs/en/monitoring-usage#retention-sweep-event"),
        false,
        false,
        false,
    ),
    event(
        "claude_code.managed_settings_resolved",
        "Managed settings were applied: sources and helper state",
        CC_MANAGED_SETTINGS,
        Some("https://code.claude.com/docs/en/monitoring-usage#managed-settings-resolved-event"),
        false,
        true,
        false,
    ),
    event_with(
        "claude_code.system_prompt",
        BETA,
        "The complete system prompt",
        &[],
        Some(Gate {
            flag: "OTEL_LOG_USER_PROMPTS",
            rule: None,
            off: Off::Omitted,
        }),
        false,
        Some("https://code.claude.com/docs/en/monitoring-usage#span-attributes"),
        false,
        false,
        false,
    ),
    metric(
        "claude_code.session.count",
        None,
        "Count of sessions started",
        CC_SESSION_COUNT,
        Some("https://code.claude.com/docs/en/monitoring-usage#session-counter"),
        false,
        true,
        false,
    ),
    metric(
        "claude_code.lines_of_code.count",
        None,
        "Lines of code changed",
        CC_LINES_OF_CODE,
        Some("https://code.claude.com/docs/en/monitoring-usage#lines-of-code-counter"),
        false,
        false,
        false,
    ),
    metric(
        "claude_code.pull_request.count",
        None,
        "Pull requests created",
        &[],
        Some("https://code.claude.com/docs/en/monitoring-usage#pull-request-counter"),
        false,
        false,
        false,
    ),
    metric(
        "claude_code.commit.count",
        None,
        "Git commits created",
        &[],
        Some("https://code.claude.com/docs/en/monitoring-usage#commit-counter"),
        false,
        false,
        false,
    ),
    metric(
        "claude_code.cost.usage",
        Some("USD"),
        "Cost per model request",
        CC_COST_USAGE,
        Some("https://code.claude.com/docs/en/monitoring-usage#cost-counter"),
        false,
        true,
        false,
    ),
    metric(
        "claude_code.token.usage",
        Some("tokens"),
        "Tokens used",
        CC_TOKEN_USAGE,
        Some("https://code.claude.com/docs/en/monitoring-usage#token-counter"),
        false,
        true,
        true,
    ),
    metric(
        "claude_code.code_edit_tool.decision",
        None,
        "Edit tool permission decisions",
        CC_CODE_EDIT,
        Some("https://code.claude.com/docs/en/monitoring-usage#code-edit-tool-decision-counter"),
        false,
        false,
        false,
    ),
    metric(
        "claude_code.active_time.total",
        Some("s"),
        "Active time",
        CC_ACTIVE_TIME,
        Some("https://code.claude.com/docs/en/monitoring-usage#active-time-counter"),
        false,
        true,
        false,
    ),
    span(
        "claude_code.interaction",
        TRACES_BETA,
        "One prompt and everything it caused",
        CC_INTERACTION,
        Some("https://code.claude.com/docs/en/monitoring-usage#span-attributes"),
        false,
        false,
        false,
    ),
    span(
        "claude_code.llm_request",
        BETA,
        "One model call",
        CC_LLM_REQUEST,
        Some("https://code.claude.com/docs/en/monitoring-usage#span-attributes"),
        false,
        false,
        true,
    ),
    span(
        "claude_code.tool",
        TRACES,
        "One tool use",
        CC_TOOL_SPAN,
        Some("https://code.claude.com/docs/en/monitoring-usage#span-attributes"),
        false,
        false,
        true,
    ),
    span(
        "claude_code.tool.blocked_on_user",
        TRACES_BETA,
        "Waiting for your permission",
        CC_TOOL_BLOCKED,
        Some("https://code.claude.com/docs/en/monitoring-usage#span-attributes"),
        false,
        false,
        false,
    ),
    span(
        "claude_code.tool.execution",
        TRACES_BETA,
        "The tool itself running",
        CC_TOOL_EXECUTION,
        Some("https://code.claude.com/docs/en/monitoring-usage#span-attributes"),
        false,
        false,
        false,
    ),
    span(
        "claude_code.hook",
        BETA,
        "Hooks running",
        CC_HOOK_SPAN,
        Some("https://code.claude.com/docs/en/monitoring-usage#span-attributes"),
        false,
        false,
        false,
    ),
    span_event(
        "tool.output",
        TRACES_BETA,
        "A tool's output",
        CC_TOOL_OUTPUT,
        Some(CC_TC),
        Some("https://code.claude.com/docs/en/monitoring-usage#tool-output-span-event"),
        false,
        false,
    ),
    span_event(
        "gen_ai.request.attempt",
        TRACES_BETA,
        "One retry of a model call",
        CC_GEN_AI_ATTEMPT,
        None,
        None,
        true,
        false,
    ),
];

pub static CLAUDE_CODE: Catalog = Catalog {
    vendor: Vendor::ClaudeCode,
    product: "claude-code",
    version: "2.1.316",
    doc: CC_DOC,
    flags: CC_FLAGS,
    identity: CC_IDENTITY,
    resource: CC_RESOURCE,
    common: CC_COMMON,
    items: CC_ITEMS,
};

const CX_PROMPT: Gate = Gate {
    flag: "otel.log_user_prompt",
    rule: None,
    off: Off::Redacted("[REDACTED]"),
};
const CX_RESPONSES: Gate = Gate {
    flag: "otel.log_agent_responses",
    rule: None,
    off: Off::Omitted,
};
const CX_GUARDIAN_GATE: Gate = Gate {
    flag: "otel.log_guardian_assessments",
    rule: None,
    off: Off::Omitted,
};

static CX_FLAGS: &[Flag] = &[
    flag(
        "otel.log_user_prompt",
        Rule::TomlTrue,
        "Prompt text",
        CX_ADVANCED_DOC,
    ),
    flag(
        "otel.log_agent_responses",
        Rule::TomlTrue,
        "Codex's final replies",
        CX_ADVANCED_DOC,
    ),
    flag(
        "otel.log_guardian_assessments",
        Rule::TomlTrue,
        "Automatic approval reviews, with their rationale",
        CX_ADVANCED_DOC,
    ),
];

static CX_IDENTITY: &[Attr] = &[
    limited(
        seen(attr(
            "user.email",
            Group::Identity,
            "your account email, when available",
        )),
        LOGS,
    ),
    limited(
        seen(attr(
            "user.account_id",
            Group::Identity,
            "your workspace account ID",
        )),
        LOGS,
    ),
    limited(
        seen(attr(
            "conversation.id",
            Group::Identity,
            "the conversation ID",
        )),
        LOGS,
    ),
    limited(
        seen(attr(
            "auth_mode",
            Group::Identity,
            "your authentication mode",
        )),
        LOGS,
    ),
    limited(
        seen(attr(
            "auth_mode",
            Group::Identity,
            "your authentication mode",
        )),
        METRICS,
    ),
    limited(
        maybe(attr(
            "conversation.id",
            Group::Identity,
            "the conversation ID",
        )),
        TRACES,
    ),
    limited(
        maybe(attr(
            "auth_mode",
            Group::Identity,
            "your authentication mode",
        )),
        TRACES,
    ),
    limited(
        seen(attr("terminal.type", Group::Identity, "your terminal type")),
        LOGS,
    ),
    limited(
        maybe(attr("terminal.type", Group::Identity, "your terminal type")),
        TRACES,
    ),
];

static CX_RESOURCE: &[Attr] = &[
    seen(attr(
        "service.name",
        Group::Resource,
        "the Codex service name, usually codex_cli_rs",
    )),
    seen(attr(
        "service.version",
        Group::Resource,
        "the Codex version",
    )),
    seen(attr(
        "env",
        Group::Resource,
        "the OpenTelemetry environment label, dev by default",
    )),
    limited(
        maybe(seen(attr(
            "host.name",
            Group::Resource,
            "your computer's host name",
        ))),
        LOGS,
    ),
    maybe(seen(attr(
        "telemetry.sdk.language",
        Group::Resource,
        "the telemetry SDK language",
    ))),
    maybe(seen(attr(
        "telemetry.sdk.name",
        Group::Resource,
        "the telemetry SDK name",
    ))),
    maybe(seen(attr(
        "telemetry.sdk.version",
        Group::Resource,
        "the telemetry SDK version",
    ))),
];

static CX_COMMON: &[Attr] = &[
    limited(
        seen(attr("event.name", Group::Event, "the event name")),
        LOGS,
    ),
    limited(
        seen(attr(
            "event.timestamp",
            Group::Event,
            "when the event occurred",
        )),
        LOGS,
    ),
    limited(
        seen(attr("app.version", Group::Event, "the Codex version")),
        LOGS_METRICS,
    ),
    limited(
        seen(attr("model", Group::Event, "the model name")),
        LOGS_METRICS,
    ),
    limited(
        seen(attr("slug", Group::Event, "the model's short name")),
        LOGS,
    ),
    limited(
        maybe(attr(
            "originator",
            Group::Event,
            "what started the Codex session",
        )),
        LOGS,
    ),
    limited(
        attr("originator", Group::Event, "what started the Codex session"),
        METRICS,
    ),
    limited(
        attr(
            "session_source",
            Group::Event,
            "what started the Codex session",
        ),
        METRICS,
    ),
];

static CX_CONVERSATION_STARTS: &[Attr] = &[
    seen(attr("provider_name", Group::Event, "the model provider")),
    seen(attr(
        "reasoning_effort",
        Group::Event,
        "the reasoning effort setting",
    )),
    seen(attr(
        "reasoning_summary",
        Group::Event,
        "the reasoning summary setting",
    )),
    attr("context_window", Group::Event, "the model context window"),
    attr(
        "max_output_tokens",
        Group::Event,
        "the maximum output token count",
    ),
    attr(
        "auto_compact_token_limit",
        Group::Event,
        "the automatic compaction token limit",
    ),
    seen(attr(
        "approval_policy",
        Group::Event,
        "the tool approval policy",
    )),
    seen(attr("sandbox_policy", Group::Event, "the sandbox policy")),
    seen(attr("mcp_servers", Group::Event, "your MCP server names")),
    attr(
        "active_profile",
        Group::Event,
        "the active configuration profile",
    ),
    maybe(seen(attr(
        "auth.env_openai_api_key_present",
        Group::Event,
        "whether an OpenAI API key variable is set, not its value",
    ))),
    maybe(seen(attr(
        "auth.env_codex_api_key_present",
        Group::Event,
        "whether a Codex API key variable is set, not its value",
    ))),
    maybe(seen(attr(
        "auth.env_codex_api_key_enabled",
        Group::Event,
        "whether the Codex API key variable is enabled",
    ))),
    maybe(seen(attr(
        "auth.env_refresh_token_url_override_present",
        Group::Event,
        "whether a refresh token URL override is set",
    ))),
];

static CX_API_REQUEST: &[Attr] = &[
    seen(attr("attempt", Group::Event, "the request attempt number")),
    seen(attr(
        "duration_ms",
        Group::Event,
        "how long the request took",
    )),
    seen(attr(
        "http.response.status_code",
        Group::Event,
        "the HTTP response status code",
    )),
    attr("error.message", Group::Event, "the request error message"),
    maybe(seen(attr(
        "auth.header_attached",
        Group::Event,
        "whether an authentication header was attached",
    ))),
    maybe(seen(attr(
        "auth.header_name",
        Group::Event,
        "the authentication header name",
    ))),
    maybe(seen(attr(
        "auth.mode",
        Group::Event,
        "the authentication mode",
    ))),
    maybe(seen(attr(
        "auth.env_*",
        Group::Event,
        "whether an authentication variable is set, not its value",
    ))),
    maybe(seen(attr(
        "endpoint",
        Group::Event,
        "the model service endpoint",
    ))),
    maybe(seen(attr(
        "success",
        Group::Event,
        "whether the request succeeded",
    ))),
];

static CX_SSE_EVENT: &[Attr] = &[
    seen(attr("event.kind", Group::Event, "the streamed event kind")),
    attr("duration_ms", Group::Event, "how long event handling took"),
    attr("error.message", Group::Event, "the event error message"),
    seen(attr(
        "input_token_count",
        Group::Event,
        "the input token count",
    )),
    seen(attr(
        "output_token_count",
        Group::Event,
        "the output token count",
    )),
    seen(attr(
        "cached_token_count",
        Group::Event,
        "the cached token count",
    )),
    seen(attr(
        "reasoning_token_count",
        Group::Event,
        "the reasoning token count",
    )),
    seen(attr(
        "tool_token_count",
        Group::Event,
        "the tool token count",
    )),
    maybe(seen(attr(
        "cache_write_token_count",
        Group::Event,
        "the cache write token count",
    ))),
    maybe(seen(attr(
        "ttft_ms",
        Group::Event,
        "the time to the first response token",
    ))),
    maybe(seen(attr(
        "model_reasoning_effort",
        Group::Event,
        "the model reasoning effort",
    ))),
];

static CX_WEBSOCKET_REQUEST: &[Attr] = &[
    seen(attr(
        "duration_ms",
        Group::Event,
        "how long the request took",
    )),
    maybe(seen(attr(
        "success",
        Group::Event,
        "whether the request succeeded",
    ))),
    maybe(seen(attr(
        "auth.connection_reused",
        Group::Event,
        "whether the authenticated connection was reused",
    ))),
    maybe(seen(attr(
        "auth.env_*",
        Group::Event,
        "whether an authentication variable is set, not its value",
    ))),
];

static CX_USER_PROMPT: &[Attr] = &[
    seen(attr("prompt_length", Group::Event, "the prompt length")),
    gated(
        seen(attr("prompt", Group::Content, "your prompt text")),
        CX_PROMPT,
    ),
];

static CX_TOOL_DECISION: &[Attr] = &[
    seen(attr("tool_name", Group::Event, "the tool's name")),
    seen(attr("call_id", Group::Event, "the tool call ID")),
    seen(attr(
        "decision",
        Group::Event,
        "whether the tool was allowed",
    )),
    seen(attr("source", Group::Event, "where the decision came from")),
    maybe(seen(attr(
        "tool_namespace",
        Group::Event,
        "the tool namespace",
    ))),
];

static CX_TOOL_RESULT: &[Attr] = &[
    seen(attr("tool_name", Group::Event, "the tool's name")),
    seen(attr("call_id", Group::Event, "the tool call ID")),
    seen(attr("duration_ms", Group::Event, "how long the tool took")),
    seen(attr("success", Group::Event, "whether the tool succeeded")),
    seen(attr(
        "arguments",
        Group::Content,
        "the tool arguments, including the command in full",
    )),
    seen(attr(
        "output",
        Group::Content,
        "the tool output, up to the configured byte limit",
    )),
    maybe(seen(attr("agent_name", Group::Event, "the agent name"))),
    maybe(seen(attr(
        "mcp_server",
        Group::Event,
        "the MCP server name",
    ))),
    maybe(seen(attr(
        "mcp_server_origin",
        Group::Event,
        "where the MCP server came from",
    ))),
    maybe(seen(attr(
        "output_truncated",
        Group::Event,
        "whether the output was cut",
    ))),
    maybe(seen(attr(
        "tool_namespace",
        Group::Event,
        "the tool namespace",
    ))),
    maybe(seen(attr(
        "tool_result_seq",
        Group::Event,
        "the tool result sequence number",
    ))),
];

static CX_AGENT_RESPONSE: &[Attr] = &[
    attr("agent.type", Group::Event, "the agent type"),
    attr("turn.id", Group::Event, "the turn ID"),
    attr("item.id", Group::Event, "the response item ID"),
    attr(
        "parent.conversation.id",
        Group::Event,
        "the parent conversation ID",
    ),
    attr("parent.turn.id", Group::Event, "the parent turn ID"),
    attr("root.turn.id", Group::Event, "the root turn ID"),
    attr(
        "initiating.agent.path",
        Group::Event,
        "the path of the agent that started this one",
    ),
    attr(
        "response_length",
        Group::Event,
        "the response length in characters",
    ),
    attr(
        "response_truncated",
        Group::Event,
        "whether the response was cut",
    ),
    attr("response", Group::Content, "Codex's final reply"),
];

static CX_GUARDIAN_ATTRS: &[Attr] = &[
    attr(
        "conversation.id",
        Group::Identity,
        "the reviewed conversation ID",
    ),
    attr("turn.id", Group::Event, "the reviewed turn ID"),
    attr("review.id", Group::Event, "the Guardian review ID"),
    attr(
        "target_item.id",
        Group::Event,
        "the reviewed target item ID",
    ),
    attr("status", Group::Event, "the review status"),
    attr("risk_level", Group::Event, "the assessed risk level"),
    attr(
        "user_authorization",
        Group::Event,
        "the user's authorization level",
    ),
    attr("outcome", Group::Event, "the review outcome"),
    attr(
        "rationale_length",
        Group::Event,
        "the review rationale length",
    ),
    attr(
        "rationale_truncated",
        Group::Event,
        "whether the rationale was cut",
    ),
    attr("rationale", Group::Content, "the review rationale"),
];

static CX_SKILL_INVOCATION: &[Attr] = &[
    attr("skill.name", Group::Event, "the skill name"),
    attr(
        "skill.invocation_type",
        Group::Event,
        "how the skill was used",
    ),
    attr("conversation.id", Group::Identity, "the conversation ID"),
    attr("turn.id", Group::Event, "the turn ID"),
    attr("skill.scope", Group::Event, "where the skill is defined"),
    attr(
        "skill.plugin_id",
        Group::Event,
        "the plugin that supplied the skill",
    ),
    attr("user.id", Group::Identity, "the authenticated user ID"),
    attr(
        "user.account_id",
        Group::Identity,
        "the workspace account ID",
    ),
];

static CX_STARTUP_PHASE: &[Attr] = &[
    attr("startup.phase", Group::Event, "the startup step"),
    attr("startup.status", Group::Event, "the startup step result"),
    attr(
        "duration_ms",
        Group::Event,
        "how long the startup step took",
    ),
];
static CX_TURN_TTFT: &[Attr] = &[attr(
    "duration_ms",
    Group::Event,
    "the time to the first token in the turn",
)];
static CX_WEBSOCKET_CONNECT: &[Attr] = &[
    attr(
        "auth.connection_reused",
        Group::Event,
        "whether the authenticated connection was reused",
    ),
    attr(
        "auth.env_*",
        Group::Event,
        "whether an authentication variable is set, not its value",
    ),
    attr(
        "auth.header_attached",
        Group::Event,
        "whether an authentication header was attached",
    ),
    attr(
        "auth.header_name",
        Group::Event,
        "the authentication header name",
    ),
    attr(
        "auth.retry_after_unauthorized",
        Group::Event,
        "whether Codex retried after an unauthorized response",
    ),
    attr("duration_ms", Group::Event, "how long the connection took"),
    attr("endpoint", Group::Event, "the model service endpoint"),
    attr("success", Group::Event, "whether the connection succeeded"),
];

static CX_METRIC_API_REQUEST: &[Attr] = &[
    attr("status", Group::Event, "the HTTP status"),
    attr("success", Group::Event, "whether the request succeeded"),
];
static CX_METRIC_SSE_EVENT: &[Attr] = &[
    attr("kind", Group::Event, "the streamed event kind"),
    attr("success", Group::Event, "whether handling succeeded"),
];
static CX_METRIC_WEBSOCKET_REQUEST: &[Attr] = &[attr(
    "success",
    Group::Event,
    "whether the WebSocket request succeeded",
)];
static CX_METRIC_WEBSOCKET_EVENT: &[Attr] = &[
    attr("kind", Group::Event, "the WebSocket event kind"),
    attr("success", Group::Event, "whether handling succeeded"),
];
static CX_METRIC_TOOL_CALL: &[Attr] = &[
    attr("tool", Group::Event, "the tool's name, never the command"),
    attr("success", Group::Event, "whether the tool call succeeded"),
];

macro_rules! cx_metric_attrs {
    ($($key:literal => $what:literal),* $(,)?) => {
        &[$(attr($key, Group::Event, $what)),*]
    };
}

macro_rules! cx_metric {
    ($name:literal, $unit:expr, $what:literal, $attrs:expr) => {
        metric(
            $name,
            $unit,
            $what,
            $attrs,
            Some(CX_METRICS_CATALOG_DOC),
            false,
            false,
            false,
        )
    };
}

static CX_ITEMS: &[Item] = &[
    event(
        "codex.conversation_starts",
        "A session started: model, approval and sandbox policy, MCP servers",
        CX_CONVERSATION_STARTS,
        Some(CX_CONFIG_DOC),
        false,
        true,
        false,
    ),
    event(
        "codex.api_request",
        "A request to the model API",
        CX_API_REQUEST,
        Some(CX_CONFIG_DOC),
        false,
        true,
        false,
    ),
    event(
        "codex.sse_event",
        "A streamed response event, with token counts",
        CX_SSE_EVENT,
        Some(CX_CONFIG_DOC),
        false,
        true,
        false,
    ),
    event(
        "codex.websocket_request",
        "A WebSocket request to the model",
        CX_WEBSOCKET_REQUEST,
        Some(CX_CONFIG_DOC),
        false,
        true,
        false,
    ),
    event_with(
        "codex.websocket_event",
        LOGS,
        "A WebSocket message",
        &[],
        None,
        true,
        Some(CX_ADVANCED_DOC),
        true,
        false,
        false,
    ),
    event(
        "codex.user_prompt",
        "You sent a prompt",
        CX_USER_PROMPT,
        Some(CX_CONFIG_DOC),
        false,
        true,
        false,
    ),
    event(
        "codex.tool_decision",
        "A tool use was approved or denied",
        CX_TOOL_DECISION,
        Some(CX_CONFIG_DOC),
        false,
        true,
        false,
    ),
    event(
        "codex.tool_result",
        "A tool finished, with its arguments and output",
        CX_TOOL_RESULT,
        Some(CX_CONFIG_DOC),
        false,
        true,
        true,
    ),
    event_with(
        "codex.agent_response",
        LOGS,
        "Final answers from the main agent and spawned task agents",
        CX_AGENT_RESPONSE,
        Some(CX_RESPONSES),
        false,
        Some("https://learn.chatgpt.com/docs/config-file/config-advanced#what-gets-emitted"),
        false,
        false,
        false,
    ),
    event_with(
        "codex.guardian_assessment",
        LOGS,
        "An automatic approval review",
        CX_GUARDIAN_ATTRS,
        Some(CX_GUARDIAN_GATE),
        true,
        Some(CX_GUARDIAN_DOC),
        false,
        false,
        false,
    ),
    event(
        "codex.skill_invocation",
        "A skill ran",
        CX_SKILL_INVOCATION,
        Some(CX_SKILL_DOC),
        false,
        false,
        false,
    ),
    event(
        "codex.startup_phase",
        "A startup step finished",
        CX_STARTUP_PHASE,
        None,
        true,
        true,
        false,
    ),
    event(
        "codex.turn_ttft",
        "The time to first token of a turn",
        CX_TURN_TTFT,
        None,
        true,
        true,
        false,
    ),
    event(
        "codex.websocket_connect",
        "A WebSocket connection",
        CX_WEBSOCKET_CONNECT,
        None,
        true,
        true,
        false,
    ),
    metric(
        "codex.api_request",
        None,
        "API request count by status and outcome",
        CX_METRIC_API_REQUEST,
        Some("https://learn.chatgpt.com/docs/config-file/config-advanced#otel-metrics-emitted"),
        false,
        false,
        false,
    ),
    metric(
        "codex.api_request.duration_ms",
        Some("ms"),
        "API request duration",
        CX_METRIC_API_REQUEST,
        Some("https://learn.chatgpt.com/docs/config-file/config-advanced#otel-metrics-emitted"),
        false,
        false,
        false,
    ),
    metric(
        "codex.sse_event",
        None,
        "SSE event count by kind and outcome",
        CX_METRIC_SSE_EVENT,
        Some("https://learn.chatgpt.com/docs/config-file/config-advanced#otel-metrics-emitted"),
        false,
        false,
        false,
    ),
    metric(
        "codex.sse_event.duration_ms",
        Some("ms"),
        "SSE event processing duration",
        CX_METRIC_SSE_EVENT,
        Some("https://learn.chatgpt.com/docs/config-file/config-advanced#otel-metrics-emitted"),
        false,
        false,
        false,
    ),
    metric(
        "codex.websocket.request",
        None,
        "WebSocket request count by outcome",
        CX_METRIC_WEBSOCKET_REQUEST,
        Some("https://learn.chatgpt.com/docs/config-file/config-advanced#otel-metrics-emitted"),
        false,
        false,
        false,
    ),
    metric(
        "codex.websocket.request.duration_ms",
        Some("ms"),
        "WebSocket request duration",
        CX_METRIC_WEBSOCKET_REQUEST,
        Some("https://learn.chatgpt.com/docs/config-file/config-advanced#otel-metrics-emitted"),
        false,
        false,
        false,
    ),
    metric(
        "codex.websocket.event",
        None,
        "WebSocket message count by kind and outcome",
        CX_METRIC_WEBSOCKET_EVENT,
        Some("https://learn.chatgpt.com/docs/config-file/config-advanced#otel-metrics-emitted"),
        false,
        false,
        false,
    ),
    metric(
        "codex.websocket.event.duration_ms",
        Some("ms"),
        "WebSocket message processing duration",
        CX_METRIC_WEBSOCKET_EVENT,
        Some("https://learn.chatgpt.com/docs/config-file/config-advanced#otel-metrics-emitted"),
        false,
        false,
        false,
    ),
    metric(
        "codex.tool.call",
        None,
        "Tool invocation count by tool name and outcome",
        CX_METRIC_TOOL_CALL,
        Some("https://learn.chatgpt.com/docs/config-file/config-advanced#otel-metrics-emitted"),
        false,
        false,
        true,
    ),
    metric(
        "codex.tool.call.duration_ms",
        Some("ms"),
        "Tool execution duration by tool name and outcome",
        CX_METRIC_TOOL_CALL,
        Some("https://learn.chatgpt.com/docs/config-file/config-advanced#otel-metrics-emitted"),
        false,
        false,
        false,
    ),
    cx_metric!(
        "codex.responses_api_overhead.duration_ms",
        Some("ms"),
        "Responses API overhead timing",
        &[]
    ),
    cx_metric!(
        "codex.responses_api_inference_time.duration_ms",
        Some("ms"),
        "Responses API inference timing",
        &[]
    ),
    cx_metric!(
        "codex.responses_api_engine_iapi_ttft.duration_ms",
        Some("ms"),
        "Responses API engine IAPI time to first token",
        &[]
    ),
    cx_metric!(
        "codex.responses_api_engine_service_ttft.duration_ms",
        Some("ms"),
        "Responses API engine service time to first token",
        &[]
    ),
    cx_metric!(
        "codex.responses_api_engine_iapi_tbt.duration_ms",
        Some("ms"),
        "Responses API engine IAPI time between tokens",
        &[]
    ),
    cx_metric!(
        "codex.responses_api_engine_service_tbt.duration_ms",
        Some("ms"),
        "Responses API engine service time between tokens",
        &[]
    ),
    cx_metric!(
        "codex.transport.fallback_to_http",
        None,
        "WebSocket to HTTP fallback count",
        cx_metric_attrs!("from_wire_api" => "whether the request used the wire API")
    ),
    cx_metric!(
        "codex.remote_models.fetch_update.duration_ms",
        Some("ms"),
        "Time to fetch remote model definitions",
        &[]
    ),
    cx_metric!(
        "codex.remote_models.load_cache.duration_ms",
        Some("ms"),
        "Time to load the remote model cache",
        &[]
    ),
    cx_metric!(
        "codex.startup_prewarm.duration_ms",
        Some("ms"),
        "Startup prewarm duration by outcome",
        cx_metric_attrs!("status" => "the prewarm outcome")
    ),
    cx_metric!(
        "codex.startup_prewarm.age_at_first_turn_ms",
        Some("ms"),
        "Startup prewarm age when the first turn resolves it",
        cx_metric_attrs!("status" => "the prewarm outcome")
    ),
    cx_metric!(
        "codex.cloud_requirements.fetch.duration_ms",
        Some("ms"),
        "Workspace managed requirements fetch duration",
        &[]
    ),
    cx_metric!(
        "codex.cloud_requirements.fetch_attempt",
        None,
        "Workspace managed requirements fetch attempts",
        cx_metric_attrs!(
            "trigger" => "what triggered the fetch",
            "attempt" => "the attempt number",
            "outcome" => "the fetch outcome",
            "status_code" => "the HTTP status code"
        )
    ),
    cx_metric!(
        "codex.cloud_requirements.fetch_final",
        None,
        "Final workspace managed requirements fetch outcome",
        cx_metric_attrs!(
            "trigger" => "what triggered the fetch",
            "outcome" => "the final outcome",
            "reason" => "why the fetch ended",
            "attempt_count" => "the number of attempts",
            "status_code" => "the HTTP status code"
        )
    ),
    cx_metric!(
        "codex.cloud_requirements.load",
        None,
        "Workspace managed requirements load outcome",
        cx_metric_attrs!(
            "trigger" => "what triggered the load",
            "outcome" => "the load outcome"
        )
    ),
    cx_metric!(
        "codex.turn.e2e_duration_ms",
        Some("ms"),
        "End to end time for a full turn",
        &[]
    ),
    cx_metric!(
        "codex.turn.ttft.duration_ms",
        Some("ms"),
        "Time to first token for a turn",
        &[]
    ),
    cx_metric!(
        "codex.turn.ttfm.duration_ms",
        Some("ms"),
        "Time to first model output item for a turn",
        &[]
    ),
    cx_metric!(
        "codex.turn.network_proxy",
        None,
        "Managed network proxy state for the turn",
        cx_metric_attrs!(
            "active" => "whether the managed proxy was active",
            "tmp_mem_enabled" => "whether temporary memory was enabled"
        )
    ),
    cx_metric!(
        "codex.turn.memory",
        None,
        "Per turn memory read availability and citation usage",
        cx_metric_attrs!(
            "read_allowed" => "whether memory reads were allowed",
            "feature_enabled" => "whether the memory feature was enabled",
            "config_use_memories" => "whether memory use was configured",
            "has_citations" => "whether the turn included memory citations"
        )
    ),
    cx_metric!(
        "codex.turn.tool.call",
        None,
        "Number of tool calls in the turn",
        cx_metric_attrs!("tmp_mem_enabled" => "whether temporary memory was enabled")
    ),
    cx_metric!(
        "codex.turn.token_usage",
        Some("tokens"),
        "Per turn token usage by token type",
        cx_metric_attrs!(
            "token_type" => "the token category",
            "tmp_mem_enabled" => "whether temporary memory was enabled"
        )
    ),
    cx_metric!(
        "codex.tool.unified_exec",
        None,
        "Unified exec tool calls by TTY mode",
        cx_metric_attrs!("tty" => "whether the tool ran with a TTY")
    ),
    cx_metric!(
        "codex.approval.requested",
        None,
        "Tool approval request results",
        cx_metric_attrs!(
            "tool" => "the internal tool name",
            "approved" => "the approval result"
        )
    ),
    cx_metric!(
        "codex.mcp.call",
        None,
        "MCP tool invocation results",
        cx_metric_attrs!(
            "status" => "the call status",
            "tool" => "the internal tool name",
            "connector_id" => "the connector ID when available",
            "connector_name" => "the connector name when available"
        )
    ),
    cx_metric!(
        "codex.mcp.call.duration_ms",
        Some("ms"),
        "MCP tool invocation duration",
        cx_metric_attrs!(
            "status" => "the call status",
            "tool" => "the internal tool name",
            "connector_id" => "the connector ID when available",
            "connector_name" => "the connector name when available"
        )
    ),
    cx_metric!(
        "codex.mcp.tools.list.duration_ms",
        Some("ms"),
        "MCP tool list duration",
        cx_metric_attrs!("cache" => "whether the tool list came from cache")
    ),
    cx_metric!(
        "codex.mcp.tools.fetch_uncached.duration_ms",
        Some("ms"),
        "Duration of MCP tool fetches that miss the cache",
        &[]
    ),
    cx_metric!(
        "codex.mcp.tools.cache_write.duration_ms",
        Some("ms"),
        "Duration of Codex Apps MCP tool cache writes",
        &[]
    ),
    cx_metric!(
        "codex.hooks.run",
        None,
        "Hook run counts by hook name source and status",
        cx_metric_attrs!(
            "hook_name" => "the hook name",
            "source" => "where the hook came from",
            "status" => "the hook result"
        )
    ),
    cx_metric!(
        "codex.hooks.run.duration_ms",
        Some("ms"),
        "Hook run duration",
        cx_metric_attrs!(
            "hook_name" => "the hook name",
            "source" => "where the hook came from",
            "status" => "the hook result"
        )
    ),
    cx_metric!(
        "codex.feature.state",
        None,
        "Feature values that differ from defaults",
        cx_metric_attrs!(
            "feature" => "the feature name",
            "value" => "the configured feature value"
        )
    ),
    cx_metric!(
        "codex.status_line",
        None,
        "Session started with a configured status line",
        &[]
    ),
    cx_metric!(
        "codex.model_warning",
        None,
        "A warning was sent to the model",
        &[]
    ),
    cx_metric!(
        "codex.thread.started",
        None,
        "New thread counts by Git repository state",
        cx_metric_attrs!("is_git" => "whether the working directory is in a Git repository")
    ),
    cx_metric!(
        "codex.conversation.turn.count",
        None,
        "User and assistant turns recorded at thread end",
        &[]
    ),
    cx_metric!(
        "codex.thread.fork",
        None,
        "New thread counts by fork source",
        cx_metric_attrs!("source" => "the fork source")
    ),
    cx_metric!("codex.thread.rename", None, "Thread rename count", &[]),
    cx_metric!(
        "codex.thread.side",
        None,
        "Side conversation counts by source",
        cx_metric_attrs!("source" => "the side conversation source")
    ),
    cx_metric!(
        "codex.thread.skills.enabled_total",
        None,
        "Enabled skills per new thread",
        &[]
    ),
    cx_metric!(
        "codex.thread.skills.kept_total",
        None,
        "Enabled skills kept after rendering",
        &[]
    ),
    cx_metric!(
        "codex.thread.skills.truncated",
        None,
        "Whether enabled skill rendering was truncated",
        &[]
    ),
    cx_metric!(
        "codex.task.compact",
        None,
        "Compaction counts by type",
        cx_metric_attrs!("type" => "the compaction type")
    ),
    cx_metric!("codex.task.review", None, "Review trigger count", &[]),
    cx_metric!("codex.task.undo", None, "Undo action count", &[]),
    cx_metric!(
        "codex.task.user_shell",
        None,
        "User shell action count",
        &[]
    ),
    cx_metric!(
        "codex.shell_snapshot",
        None,
        "Whether shell snapshot creation succeeded",
        cx_metric_attrs!(
            "success" => "whether the snapshot succeeded",
            "failure_reason" => "why snapshot creation failed"
        )
    ),
    cx_metric!(
        "codex.shell_snapshot.duration_ms",
        Some("ms"),
        "Time to create a shell snapshot",
        cx_metric_attrs!("success" => "whether the snapshot succeeded")
    ),
    cx_metric!(
        "codex.skill.injected",
        None,
        "Skill injection outcomes",
        cx_metric_attrs!(
            "status" => "the injection status",
            "skill" => "the skill name"
        )
    ),
    cx_metric!(
        "codex.plugins.startup_sync",
        None,
        "Curated plugin startup sync attempts",
        cx_metric_attrs!(
            "transport" => "the sync transport",
            "status" => "the sync status"
        )
    ),
    cx_metric!(
        "codex.plugins.startup_sync.final",
        None,
        "Final curated plugin startup sync outcome",
        cx_metric_attrs!(
            "transport" => "the sync transport",
            "status" => "the final sync status"
        )
    ),
    cx_metric!(
        "codex.multi_agent.spawn",
        None,
        "Agent spawn counts by role",
        cx_metric_attrs!("role" => "the agent role")
    ),
    cx_metric!("codex.multi_agent.resume", None, "Agent resume count", &[]),
    cx_metric!(
        "codex.multi_agent.nickname_pool_reset",
        None,
        "Agent nickname pool reset count",
        &[]
    ),
    cx_metric!(
        "codex.memory.phase1",
        None,
        "Memory phase one job counts",
        cx_metric_attrs!("status" => "the job status")
    ),
    cx_metric!(
        "codex.memory.phase1.e2e_ms",
        Some("ms"),
        "Memory phase one duration",
        &[]
    ),
    cx_metric!(
        "codex.memory.phase1.output",
        None,
        "Memory phase one outputs written",
        &[]
    ),
    cx_metric!(
        "codex.memory.phase1.token_usage",
        Some("tokens"),
        "Memory phase one token usage",
        cx_metric_attrs!("token_type" => "the token category")
    ),
    cx_metric!(
        "codex.memory.phase2",
        None,
        "Memory phase two job counts",
        cx_metric_attrs!("status" => "the job status")
    ),
    cx_metric!(
        "codex.memory.phase2.e2e_ms",
        Some("ms"),
        "Memory phase two duration",
        &[]
    ),
    cx_metric!(
        "codex.memory.phase2.input",
        None,
        "Memory phase two input count",
        &[]
    ),
    cx_metric!(
        "codex.memory.phase2.token_usage",
        Some("tokens"),
        "Memory phase two token usage",
        cx_metric_attrs!("token_type" => "the token category")
    ),
    cx_metric!(
        "codex.memories.usage",
        None,
        "Memory usage by kind tool and outcome",
        cx_metric_attrs!(
            "kind" => "the memory kind",
            "tool" => "the internal tool name",
            "success" => "whether the memory operation succeeded"
        )
    ),
    cx_metric!(
        "codex.external_agent_config.detect",
        None,
        "External agent configuration detections",
        cx_metric_attrs!(
            "migration_type" => "the migration item type",
            "skills_count" => "the number of skills when applicable"
        )
    ),
    cx_metric!(
        "codex.external_agent_config.import",
        None,
        "External agent configuration imports",
        cx_metric_attrs!(
            "migration_type" => "the migration item type",
            "skills_count" => "the number of skills when applicable"
        )
    ),
    cx_metric!(
        "codex.db.backfill",
        None,
        "Initial state database backfill results",
        cx_metric_attrs!("status" => "the backfill status")
    ),
    cx_metric!(
        "codex.db.backfill.duration_ms",
        Some("ms"),
        "Initial state database backfill duration",
        cx_metric_attrs!("status" => "the backfill status")
    ),
    cx_metric!(
        "codex.db.error",
        None,
        "Errors during state database operations",
        cx_metric_attrs!("stage" => "the database operation stage")
    ),
    cx_metric!(
        "codex.windows_sandbox.setup_success",
        None,
        "Windows sandbox setup successes",
        cx_metric_attrs!(
            "originator" => "what started sandbox setup",
            "mode" => "the sandbox mode"
        )
    ),
    cx_metric!(
        "codex.windows_sandbox.setup_failure",
        None,
        "Windows sandbox setup failures",
        cx_metric_attrs!(
            "originator" => "what started sandbox setup",
            "mode" => "the sandbox mode"
        )
    ),
    cx_metric!(
        "codex.windows_sandbox.setup_duration_ms",
        Some("ms"),
        "Windows sandbox setup duration",
        cx_metric_attrs!(
            "result" => "the setup result",
            "originator" => "what started sandbox setup",
            "mode" => "the sandbox mode"
        )
    ),
    cx_metric!(
        "codex.windows_sandbox.elevated_setup_success",
        None,
        "Elevated Windows sandbox setup successes",
        &[]
    ),
    cx_metric!(
        "codex.windows_sandbox.elevated_setup_failure",
        None,
        "Elevated Windows sandbox setup failures",
        cx_metric_attrs!(
            "code" => "the failure code when available",
            "message" => "the failure message when available",
            "originator" => "what started sandbox setup when available"
        )
    ),
    cx_metric!(
        "codex.windows_sandbox.elevated_setup_canceled",
        None,
        "Canceled elevated Windows sandbox setup attempts",
        &[]
    ),
    cx_metric!(
        "codex.windows_sandbox.elevated_setup_duration_ms",
        Some("ms"),
        "Elevated Windows sandbox setup duration",
        cx_metric_attrs!("result" => "the setup result")
    ),
    cx_metric!(
        "codex.windows_sandbox.elevated_prompt_shown",
        None,
        "Elevated sandbox setup prompt count",
        &[]
    ),
    cx_metric!(
        "codex.windows_sandbox.elevated_prompt_accept",
        None,
        "Elevated sandbox setup prompt acceptance count",
        &[]
    ),
    cx_metric!(
        "codex.windows_sandbox.elevated_prompt_use_legacy",
        None,
        "Legacy sandbox selection count from elevated prompt",
        &[]
    ),
    cx_metric!(
        "codex.windows_sandbox.elevated_prompt_quit",
        None,
        "Quit count from elevated sandbox prompt",
        &[]
    ),
    cx_metric!(
        "codex.windows_sandbox.fallback_prompt_shown",
        None,
        "Fallback sandbox prompt count",
        &[]
    ),
    cx_metric!(
        "codex.windows_sandbox.fallback_retry_elevated",
        None,
        "Elevated setup retry count from fallback prompt",
        &[]
    ),
    cx_metric!(
        "codex.windows_sandbox.fallback_use_legacy",
        None,
        "Legacy sandbox selection count from fallback prompt",
        &[]
    ),
    cx_metric!(
        "codex.windows_sandbox.fallback_prompt_quit",
        None,
        "Quit count from fallback sandbox prompt",
        &[]
    ),
    cx_metric!(
        "codex.windows_sandbox.legacy_setup_preflight_failed",
        None,
        "Legacy Windows sandbox preflight failures",
        cx_metric_attrs!("originator" => "what started sandbox setup when available")
    ),
    cx_metric!(
        "codex.windows_sandbox.setup_elevated_sandbox_command",
        None,
        "Elevated sandbox setup command count",
        &[]
    ),
    cx_metric!(
        "codex.windows_sandbox.createprocessasuserw_failed",
        None,
        "Windows CreateProcessAsUserW failures",
        cx_metric_attrs!(
            "error_code" => "the Windows error code",
            "path_kind" => "the path category",
            "exe" => "the executable name",
            "level" => "the sandbox level"
        )
    ),
    open_metric(
        "codex.*",
        "Another Codex runtime metric",
        Some("https://learn.chatgpt.com/docs/config-file/config-advanced#otel-metrics-emitted"),
    ),
    open_span(
        "codex.*",
        "Codex spans; their names and fields are undocumented",
    ),
];

pub static CODEX: Catalog = Catalog {
    vendor: Vendor::Codex,
    product: "codex",
    version: "0.166.0",
    doc: CX_ADVANCED_DOC,
    flags: CX_FLAGS,
    identity: CX_IDENTITY,
    resource: CX_RESOURCE,
    common: CX_COMMON,
    items: CX_ITEMS,
};

/// Returns the static catalog for a vendor.
pub fn catalog(vendor: Vendor) -> &'static Catalog {
    match vendor {
        Vendor::ClaudeCode => &CLAUDE_CODE,
        Vendor::Codex => &CODEX,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const ALL_EXPORTS: &[Export] = &[Export::Logs, Export::Metrics, Export::Traces, Export::Beta];

    fn catalogs() -> [&'static Catalog; 2] {
        [&CLAUDE_CODE, &CODEX]
    }

    fn gates_in_attrs(attrs: &[Attr]) -> impl Iterator<Item = Gate> + '_ {
        attrs.iter().filter_map(|attr| attr.gate)
    }

    fn assert_gate_known(catalog: &Catalog, gate: Gate) {
        assert!(
            catalog.flags.iter().any(|flag| flag.name == gate.flag),
            "{} has no flag named {}",
            catalog.product,
            gate.flag
        );
    }

    #[test]
    fn item_names_are_unique_per_export() {
        for catalog in catalogs() {
            for export in ALL_EXPORTS {
                let mut names = BTreeSet::new();
                for item in catalog.items {
                    if item.exports.contains(export) {
                        assert!(
                            names.insert(item.name),
                            "{} has duplicate {} item {}",
                            catalog.product,
                            match export {
                                Export::Logs => "logs",
                                Export::Metrics => "metrics",
                                Export::Traces => "traces",
                                Export::Beta => "beta",
                            },
                            item.name
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn undocumented_items_are_best_effort() {
        for item in CLAUDE_CODE.items.iter().chain(CODEX.items) {
            if item.doc.is_none() {
                assert!(item.best_effort, "{} needs best_effort", item.name);
            }
        }
    }

    #[test]
    fn every_gate_names_a_catalog_flag() {
        for catalog in catalogs() {
            for item in catalog.items {
                if let Some(gate) = item.gate {
                    assert_gate_known(catalog, gate);
                }
                for gate in gates_in_attrs(item.attrs) {
                    assert_gate_known(catalog, gate);
                }
            }
            for attrs in [catalog.identity, catalog.resource, catalog.common] {
                for gate in gates_in_attrs(attrs) {
                    assert_gate_known(catalog, gate);
                }
            }
        }
    }

    #[test]
    fn each_export_has_at_most_one_sample_item() {
        for catalog in catalogs() {
            for export in ALL_EXPORTS {
                let count = catalog
                    .items
                    .iter()
                    .filter(|item| item.exports.contains(export) && item.sample)
                    .count();
                assert!(
                    count <= 1,
                    "{} has {count} sample items for {export:?}",
                    catalog.product
                );
            }
        }
    }

    #[test]
    fn descriptions_do_not_contain_sample_delimiters() {
        for catalog in catalogs() {
            for item in catalog.items {
                assert!(
                    !item.what.contains(['<', '>']),
                    "{} has an unsafe description",
                    item.name
                );
                for attr in item.attrs {
                    assert!(
                        !attr.what.contains(['<', '>']),
                        "{}.{} has an unsafe description",
                        item.name,
                        attr.key
                    );
                }
            }
            for attr in catalog
                .identity
                .iter()
                .chain(catalog.resource)
                .chain(catalog.common)
            {
                assert!(
                    !attr.what.contains(['<', '>']),
                    "{} attribute {} has an unsafe description",
                    catalog.product,
                    attr.key
                );
            }
        }
    }

    #[test]
    fn labels_and_open_items_are_stable() {
        assert_eq!(catalog(Vendor::ClaudeCode).label(), "claude-code 2.1.316");
        assert_eq!(catalog(Vendor::Codex).label(), "codex 0.166.0");
        assert_eq!(
            CODEX
                .item("codex.runtime.new_metric", Export::Metrics)
                .map(|item| item.name),
            Some("codex.*")
        );
        assert_eq!(
            CODEX
                .item("codex.tool", Export::Traces)
                .map(|item| item.kind),
            Some(ItemKind::Span)
        );
        assert_eq!(
            CLAUDE_CODE
                .item("claude_code.system_prompt", Export::Logs)
                .map(|item| item.name),
            Some("claude_code.system_prompt")
        );
    }
}
