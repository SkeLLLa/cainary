//! Certificate bundles: PEM blocks, the combined bundles, the collector certificate and the
//! system roots.

use super::MODES;
use super::files::{read_bundle_text, read_in};
use crate::tls::ca_file::{CA_FILE, CaDir};
use cainary_core::harness::Harness;
use std::collections::HashSet;
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

/// A bundle: the originals first, then one certificate per enabled mode in registry order. An
/// original that is one of the current mode certificates (by fingerprint) is dropped, so cAInary's
/// own certificates never come back as "originals" and a rotation never accumulates roots. Always
/// built from sources, never from the previous bundle.
pub(super) fn bundle(originals: &[String], cas: &[String]) -> String {
    let own: HashSet<String> = cas.iter().map(|c| cert_fingerprint(c)).collect();
    let mut seen = HashSet::new();
    let mut out = String::new();
    let originals = originals
        .iter()
        .filter(|c| !own.contains(&cert_fingerprint(c)));
    for c in originals.chain(cas) {
        if seen.insert(cert_fingerprint(c)) {
            out.push_str(c);
        }
    }
    out
}

/// The certificate blocks of a bundle of someone else, unless it lives in the collector directory:
/// a file there is cAInary's own (a CA, a bundle) and is never an "original".
pub(super) fn read_original(ca: &CaDir, path: &Path) -> Option<Vec<String>> {
    if path.starts_with(ca.path()) {
        return None;
    }
    read_certs(path)
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

/// The certificate in one CA file of the collector directory, exactly one.
fn one_cert(ca: &CaDir, file: &str) -> Option<String> {
    let b = read_in(ca, file).ok().flatten()?;
    match pem_certs(&String::from_utf8_lossy(&b)).as_slice() {
        [one] => Some(one.clone()),
        _ => None,
    }
}

/// The collector's certificate, exactly one, from the CA directory.
pub(super) fn collector_ca(ca: &CaDir) -> Result<String, &'static str> {
    one_cert(ca, CA_FILE).ok_or(COLLECTOR_MISSING)
}

/// A mode whose certificate file is missing or isn't exactly one certificate (or isn't a mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MissingCa(pub(super) &'static str);

/// The certificates of the enabled `modes`, one per mode, in registry order. Any enabled mode
/// without its certificate is an error: a bundle is never built without one of its CAs.
pub(super) fn mode_cas(ca: &CaDir, modes: &[String]) -> Result<Vec<String>, MissingCa> {
    if modes.iter().any(|m| !MODES.iter().any(|(n, _)| n == m)) {
        return Err(MissingCa("unknown"));
    }
    MODES
        .iter()
        .filter(|(n, _)| modes.iter().any(|m| m == n))
        .map(|(n, file)| one_cert(ca, file).ok_or(MissingCa(n)))
        .collect()
}

/// SHA-256 of a certificate's DER (what browsers and `openssl x509 -fingerprint` show). A block
/// that isn't valid base64 is hashed as its text, so every block still gets a stable value.
pub(super) fn cert_fingerprint(block: &str) -> String {
    let body: String = block.lines().filter(|l| !l.starts_with("-----")).collect();
    match unbase64(&body) {
        Some(der) if !der.is_empty() => sha_of(&der),
        _ => sha_of(block.as_bytes()),
    }
}

fn unbase64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in s
        .trim_end_matches('=')
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
    {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
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
