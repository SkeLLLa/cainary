//! Certificate bundles: PEM blocks, the combined bundles, the collector certificate and the
//! system roots.

use super::files::{read_bundle_text, read_in};
use crate::tls::ca_file::{CA_FILE, CaDir};
use cainary_core::harness::Harness;
use std::path::Path;

const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const END: &str = "-----END CERTIFICATE-----";

/// The certificate blocks of a PEM text, each normalized to one `BEGIN … END\n` string.
pub fn pem_certs(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(s) = rest.find(BEGIN) {
        let after = &rest[s..];
        let Some(e) = after.find(END) else { break };
        let block = &after[..e + END.len()];
        let body: Vec<&str> = block
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        out.push(format!("{}\n", body.join("\n")));
        rest = &after[e + END.len()..];
    }
    out
}

pub(super) fn bundle(parts: &[String], ca: &str) -> String {
    // The collector certificate is always last, and exactly once, whatever the parts hold.
    let mut seen = std::collections::HashSet::new();
    let mut out = String::new();
    for c in parts.iter().filter(|c| c.as_str() != ca) {
        if seen.insert(c.clone()) {
            out.push_str(c);
        }
    }
    out.push_str(ca);
    out
}

/// A certificate bundle of someone else (the file `NODE_EXTRA_CA_CERTS` already names, or the
/// system roots), as its certificate blocks only. The core harness refuses `*.pem` by design (they
/// may hold keys), so `files` reads the file itself, narrowly, and a file that holds a private key
/// is refused outright here, so key material is never handled at all.
pub(super) fn read_certs(path: &Path) -> Option<Vec<String>> {
    let text = read_bundle_text(path)?;
    if text.contains("PRIVATE KEY") {
        return None;
    }
    let certs = pem_certs(&text);
    (!certs.is_empty()).then_some(certs)
}

/// The system trust bundle: the first of the usual places that exists.
pub(super) fn system_roots(h: &Harness) -> Option<Vec<String>> {
    const CANDIDATES: [&str; 3] = [
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/cert.pem",
    ];
    CANDIDATES.iter().find_map(|c| read_certs(h.sys(c).path()))
}

pub(super) const COLLECTOR_MISSING: &str = "Start the takeover once (cainary-otel-debug --tls …) so the collector certificate exists, then try again.";

/// The collector's certificate, exactly one, from the CA directory.
pub(super) fn collector_ca(ca: &CaDir) -> Result<String, &'static str> {
    const MISSING: &str = COLLECTOR_MISSING;
    match read_in(ca, CA_FILE) {
        Ok(Some(b)) => {
            let certs = pem_certs(&String::from_utf8_lossy(&b));
            match certs.as_slice() {
                [one] => Ok(one.clone()),
                _ => Err(MISSING),
            }
        }
        _ => Err(MISSING),
    }
}

pub(super) fn sha_of(bytes: &[u8]) -> String {
    crate::tls::ca::sha256_hex(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::tests::*;
    use crate::trust::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn pem_blocks_are_extracted_and_normalized() {
        let text = format!(
            "junk\n{ROOT_A}more junk\n-----BEGIN CERTIFICATE-----\n  AAAA  \n\n-----END CERTIFICATE-----\ntrailing"
        );
        let c = pem_certs(&text);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0], ROOT_A);
        assert_eq!(
            c[1],
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        );
        assert!(pem_certs("-----BEGIN CERTIFICATE-----\nunterminated").is_empty());
        assert!(pem_certs("").is_empty());
        assert_eq!(stamp("2026-11-06T15:46:58Z"), "20261106T154658Z");
        assert_eq!(backup_stamp(std::time::UNIX_EPOCH), "19700101T000000Z");
    }

    #[test]
    fn a_bundle_with_a_private_key_or_open_permissions_is_never_used() {
        let fx = Fx::new("keys", "");
        let mine = fx.base.join("withkey.pem");
        fs::write(
            &mine,
            format!("{ROOT_A}-----BEGIN PRIVATE KEY-----\nU0VDUkVU\n-----END PRIVATE KEY-----\n"),
        )
        .unwrap();
        fx.write_settings(&format!(
            "{{\"env\":{{\"{KEY}\":\"{}\"}}}}\n",
            mine.display()
        ));
        let a = apply(&fx);
        assert_eq!(a.action, Action::Refused, "{a:?}");
        assert!(!fx.ca_dir.join(CLAUDE_BUNDLE).exists());
        fs::write(&mine, ROOT_A).unwrap();
        fs::set_permissions(&mine, fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            apply(&fx).action,
            Action::Refused,
            "a file others can write isn't a trustworthy source"
        );
        fs::set_permissions(&mine, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(apply(&fx).action, Action::Applied);
        // The bundle text never carried anything but certificates.
        let b = fs::read_to_string(fx.ca_dir.join(CLAUDE_BUNDLE)).unwrap();
        assert!(!b.contains("PRIVATE") && !b.contains("U0VDUkVU"));
    }
}
