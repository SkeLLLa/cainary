//! Whether the takeover host names reach this computer. Each name goes through the system
//! resolver (`getaddrinfo`, so nsswitch, `/etc/hosts` and systemd-resolved all count), never on
//! the UI thread, and never for longer than `LOOKUP_TIMEOUT`.

use std::net::{IpAddr, ToSocketAddrs};
use std::sync::mpsc;
use std::time::Duration;

use serde::Serialize;

/// A lookup that takes longer than this is reported as an error. Its thread is left to finish
/// on its own, so a stuck resolver can't hold up quitting.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum State {
    /// Every address is loopback.
    Here,
    /// At least one address is somewhere else; `address` says where.
    Elsewhere,
    /// The name didn't resolve; `message` says why.
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostResult {
    pub host: String,
    pub state: State,
    pub address: String,
    pub message: String,
}

/// The `hostCheck` object of the collector view. Before the first check, `results` is empty.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostCheck {
    pub running: bool,
    pub results: Vec<HostResult>,
}

/// What a set of resolved addresses means. Pure, so it can be tested without a resolver.
pub fn classify(addresses: &[IpAddr]) -> Result<(), Option<IpAddr>> {
    match addresses.iter().find(|address| !is_loopback(address)) {
        Some(address) => Err(Some(*address)),
        None if addresses.is_empty() => Err(None),
        None => Ok(()),
    }
}

pub(crate) fn is_loopback(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => v4.is_loopback(),
        // `::ffff:127.0.0.1` is loopback too.
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

pub fn result_for(host: &str, lookup: Result<Vec<IpAddr>, String>) -> HostResult {
    let (state, address, message) = match lookup {
        Err(message) => (State::Error, String::new(), message),
        Ok(addresses) => match classify(&addresses) {
            Ok(()) => (State::Here, String::new(), String::new()),
            Err(Some(address)) => (State::Elsewhere, address.to_string(), String::new()),
            Err(None) => (State::Error, String::new(), "No address found".into()),
        },
    };
    HostResult {
        host: host.into(),
        state,
        address,
        message,
    }
}

fn lookup(host: &str) -> Result<Vec<IpAddr>, String> {
    (host, 443)
        .to_socket_addrs()
        .map(|addresses| addresses.map(|address| address.ip()).collect())
        .map_err(|error| error.to_string())
}

/// Resolves every host, in order, each on its own short-lived thread. Blocks for at most
/// `LOOKUP_TIMEOUT` per host: call it from a worker.
pub fn check(hosts: &[String]) -> Vec<HostResult> {
    check_with(hosts, LOOKUP_TIMEOUT, lookup)
}

fn check_with(
    hosts: &[String],
    timeout: Duration,
    resolve: fn(&str) -> Result<Vec<IpAddr>, String>,
) -> Vec<HostResult> {
    let pending = hosts
        .iter()
        .map(|host| {
            let (sender, receiver) = mpsc::channel();
            let name = host.clone();
            let spawned = std::thread::Builder::new()
                .name("cainary-host-lookup".into())
                .spawn(move || {
                    let _ = sender.send(resolve(&name));
                });
            (host, spawned.is_ok().then_some(receiver))
        })
        .collect::<Vec<_>>();
    pending
        .into_iter()
        .map(|(host, receiver)| {
            let found = match receiver {
                None => Err("Couldn't start a lookup".into()),
                Some(receiver) => receiver
                    .recv_timeout(timeout)
                    .unwrap_or_else(|_| Err("The lookup timed out".into())),
            };
            result_for(host, found)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|ip| ip.parse().unwrap()).collect()
    }

    #[test]
    fn loopback_only_is_here() {
        assert_eq!(classify(&ips(&["127.0.0.1"])), Ok(()));
        assert_eq!(classify(&ips(&["127.8.9.10", "::1"])), Ok(()));
        assert_eq!(classify(&ips(&["::ffff:127.0.0.1"])), Ok(()));
    }

    #[test]
    fn any_other_address_is_elsewhere() {
        let other: IpAddr = "34.117.59.81".parse().unwrap();
        assert_eq!(classify(&ips(&["34.117.59.81"])), Err(Some(other)));
        assert_eq!(
            classify(&ips(&["127.0.0.1", "34.117.59.81"])),
            Err(Some(other))
        );
        assert_eq!(
            classify(&ips(&["::1", "2001:db8::1"])),
            Err(Some("2001:db8::1".parse().unwrap()))
        );
        assert!(classify(&ips(&["0.0.0.0"])).is_err());
    }

    #[test]
    fn nothing_resolved_is_an_error() {
        assert_eq!(classify(&[]), Err(None));
        let result = result_for("a.example", Ok(Vec::new()));
        assert_eq!(result.state, State::Error);
        assert_eq!(result.message, "No address found");
    }

    #[test]
    fn results_carry_the_address_or_message() {
        let elsewhere = result_for("otel.example", Ok(ips(&["34.117.59.81"])));
        assert_eq!(elsewhere.state, State::Elsewhere);
        assert_eq!(elsewhere.address, "34.117.59.81");
        let failed = result_for("otel.example", Err("Name or service not known".into()));
        assert_eq!(failed.state, State::Error);
        assert_eq!(failed.message, "Name or service not known");
    }

    #[test]
    fn view_serializes_camel_case() {
        let check = HostCheck {
            running: false,
            results: vec![result_for("h", Ok(ips(&["127.0.0.1"])))],
        };
        assert_eq!(
            serde_json::to_string(&check).unwrap(),
            r#"{"running":false,"results":[{"host":"h","state":"here","address":"","message":""}]}"#
        );
    }

    #[test]
    fn a_stuck_lookup_times_out() {
        fn slow(host: &str) -> Result<Vec<IpAddr>, String> {
            if host == "slow" {
                std::thread::sleep(Duration::from_secs(3));
            }
            Ok(ips(&["127.0.0.1"]))
        }
        let hosts = vec!["slow".to_string(), "fast".to_string()];
        let results = check_with(&hosts, Duration::from_millis(100), slow);
        assert_eq!(results[0].state, State::Error);
        assert_eq!(results[1].state, State::Here);
    }
}
