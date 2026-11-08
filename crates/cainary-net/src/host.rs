//! DNS host-name validation for `--tls-host`. Pure; not feature-gated, so
//! the argument parser can reject a bad name in any build.

pub const MAX_HOSTS: usize = 32;
pub const MAX_HOST_BYTES: usize = 253;

/// `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`, applied to the
/// already lowercased name: at least two labels, no wildcard, and not an IP-address shape.
pub fn valid_host(h: &str) -> bool {
    if h.is_empty() || h.len() > MAX_HOST_BYTES {
        return false;
    }
    let labels: Vec<&str> = h.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let label_ok = |l: &str| {
        let b = l.as_bytes();
        !b.is_empty()
            && b.len() <= 63
            && b[0] != b'-'
            && b[b.len() - 1] != b'-'
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
    };
    // An all-numeric last label would make `1.2.3.4` a "name".
    labels.iter().all(|l| label_ok(l))
        && !labels[labels.len() - 1].bytes().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_names() {
        for ok in [
            "otel.example-corp.test",
            "a.b",
            "x1.y2.z3.example",
            "a-b.c-d.io",
        ] {
            assert!(valid_host(ok), "{ok}");
        }
        let long_label = format!("{}.com", "a".repeat(64));
        let long_name = format!("{}example.com", "a.".repeat(130));
        for bad in [
            "",
            "localhost",
            "*.example.com",
            "1.2.3.4",
            "a..b",
            "-a.example.com",
            "a-.example.com",
            "a_b.example.com",
            "Example.com",
            "example.com.",
            "[::1]",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert!(!valid_host(bad), "{bad}");
        }
    }
}
