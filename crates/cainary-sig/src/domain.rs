//! Signature domains. Each purpose signs under its own domain string, so a digest made for
//! one purpose can never validate for another. A domain only comes from these constants.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Domain(&'static str);

impl Domain {
    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

pub const ALERT_VALUE_AT_LOCATION: Domain = Domain("alert/value-at-location/v1");
pub const ALERT_VALUE_ANYWHERE: Domain = Domain("alert/value-anywhere/v1");
pub const ALERT_LOCATION: Domain = Domain("alert/location/v1");
pub const ALERT_PATTERN: Domain = Domain("alert/pattern/v1");
pub const KNOWN_FINDING: Domain = Domain("known-finding/v1");
pub const OTEL_SHAPE: Domain = Domain("otel-shape/v1");
pub const OTEL_SHAPE_VERSION: Domain = Domain("otel-shape-version/v1");
pub const NOTIFY_DEDUP: Domain = Domain("notify-dedup/v1");
pub const KEY_ID: Domain = Domain("key-id/v1");

impl Domain {
    /// Every domain, for lookups by name (golden vectors, stored rules).
    pub const ALL: [Domain; 9] = [
        ALERT_VALUE_AT_LOCATION,
        ALERT_VALUE_ANYWHERE,
        ALERT_LOCATION,
        ALERT_PATTERN,
        KNOWN_FINDING,
        OTEL_SHAPE,
        OTEL_SHAPE_VERSION,
        NOTIFY_DEDUP,
        KEY_ID,
    ];

    pub fn from_name(name: &str) -> Option<Domain> {
        Domain::ALL.into_iter().find(|d| d.0 == name)
    }
}
