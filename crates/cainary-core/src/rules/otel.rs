//! OTEL_* and exporter classification (rules.md §CC.3). Pure: no `ScanCtx`.

use crate::redact;

/// One entry of an exporter list. `none` is dropped by [`exporters`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Otlp,
    Console,
    Prometheus,
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtelSignal {
    Metrics,
    Logs,
    Traces,
}

/// Parse a comma list such as `otlp,console`. Names are trimmed and matched without regard to
/// case; empty entries and `none` are dropped.
pub fn exporters(list: &str) -> Vec<Kind> {
    list.split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty() && !e.eq_ignore_ascii_case("none"))
        .map(|e| match e.to_ascii_lowercase().as_str() {
            "otlp" => Kind::Otlp,
            "console" => Kind::Console,
            "prometheus" => Kind::Prometheus,
            _ => Kind::Other(e.to_string()),
        })
        .collect()
}

/// Does any entry leave the machine (`Otlp` or `Other`)? `console` writes locally and
/// `prometheus` is pull-only.
pub fn sends(kinds: &[Kind]) -> bool {
    kinds
        .iter()
        .any(|k| matches!(k, Kind::Otlp | Kind::Other(_)))
}

/// The collector host for `s`, from the signal-specific endpoint, else the general one.
/// `get` looks up a variable by name. A blank value counts as unset. The signal-specific
/// endpoint wins even when it has no readable host (`None`), so a broken override never falls
/// back to the general endpoint.
pub fn endpoint_host(get: &dyn Fn(&str) -> Option<String>, s: OtelSignal) -> Option<String> {
    let specific = match s {
        OtelSignal::Metrics => "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
        OtelSignal::Logs => "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
        OtelSignal::Traces => "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    };
    let set = |name: &str| get(name).filter(|v| !v.trim().is_empty());
    let url = set(specific).or_else(|| set("OTEL_EXPORTER_OTLP_ENDPOINT"))?;
    redact::url_host(url.trim())
}

/// `"a=1,b=2"` → `["a", "b"]`. Names only: a value is never returned, and an entry without
/// `=` (a stray fragment of a value that held a comma) is skipped rather than shown.
pub fn header_names(v: &str) -> Vec<String> {
    v.split(',')
        .filter_map(|pair| pair.split_once('='))
        .map(|(name, _)| name.trim())
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn k(list: &str) -> Vec<Kind> {
        exporters(list)
    }

    #[test]
    fn exporters_table() {
        assert_eq!(k("otlp"), vec![Kind::Otlp]);
        assert_eq!(k("otlp,console"), vec![Kind::Otlp, Kind::Console]);
        assert_eq!(k(" none "), vec![]);
        assert_eq!(k("none,otlp"), vec![Kind::Otlp]);
        assert_eq!(k("NONE"), vec![]);
        assert_eq!(k(""), vec![]);
        assert_eq!(k(" , ,"), vec![]);
        assert_eq!(k(" OTLP , Prometheus "), vec![Kind::Otlp, Kind::Prometheus]);
        assert_eq!(
            k("console,zipkin"),
            vec![Kind::Console, Kind::Other("zipkin".into())]
        );
    }

    #[test]
    fn sends_table() {
        assert!(sends(&k("otlp")));
        assert!(sends(&k("otlp,console")));
        assert!(sends(&k("console,zipkin")));
        assert!(!sends(&k("console")));
        assert!(!sends(&k("prometheus")));
        assert!(!sends(&k("console,prometheus")));
        assert!(!sends(&k(" none ")));
        assert!(!sends(&[]));
    }

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        move |name| m.get(name).cloned()
    }

    #[test]
    fn endpoint_general_and_per_signal_override() {
        let get = env(&[
            (
                "OTEL_EXPORTER_OTLP_ENDPOINT",
                "https://otel.example-corp.com:4318",
            ),
            (
                "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
                "https://logs.example-corp.com/v1/logs",
            ),
        ]);
        assert_eq!(
            endpoint_host(&get, OtelSignal::Metrics).as_deref(),
            Some("otel.example-corp.com")
        );
        assert_eq!(
            endpoint_host(&get, OtelSignal::Traces).as_deref(),
            Some("otel.example-corp.com")
        );
        assert_eq!(
            endpoint_host(&get, OtelSignal::Logs).as_deref(),
            Some("logs.example-corp.com")
        );
    }

    #[test]
    fn endpoint_unset_blank_and_hosts_only() {
        assert_eq!(endpoint_host(&env(&[]), OtelSignal::Logs), None);
        let blank = env(&[
            ("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "  "),
            (
                "OTEL_EXPORTER_OTLP_ENDPOINT",
                "http://alice:sk-test-EXAMPLE@c.example-corp.com/x?k=1",
            ),
        ]);
        let host = endpoint_host(&blank, OtelSignal::Logs);
        assert_eq!(host.as_deref(), Some("c.example-corp.com"));
        assert!(!host.unwrap().contains("sk-test"));
    }

    #[test]
    fn header_names_table() {
        assert_eq!(
            header_names("Authorization=Bearer sk-test-EXAMPLE"),
            vec!["Authorization"]
        );
        assert_eq!(header_names("a=1,b=2"), vec!["a", "b"]);
        assert_eq!(header_names(" a = 1 , b=2 "), vec!["a", "b"]);
        assert_eq!(header_names("x-token=a=b==,y=2"), vec!["x-token", "y"]);
        assert_eq!(header_names(""), Vec::<String>::new());
        assert_eq!(header_names("=v,,novalue"), Vec::<String>::new());
        // A value that held a comma leaves a fragment; it must not surface as a name.
        assert_eq!(header_names("k=a,sk-test-EXAMPLE"), vec!["k"]);
    }
}
