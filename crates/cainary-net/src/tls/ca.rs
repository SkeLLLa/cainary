//! The ephemeral CA and the per-host leaves (design §16.2, §16.7.1, §16.7.6).
//!
//! A new CA per start: ECDSA P-256, name-constrained to exactly the `--tls-host` names. Its
//! private key lives in this struct and nowhere else: it is never serialized, written, printed or
//! logged. The constraints are defence in depth; the exact-host restriction is enforced by
//! `Leaves` (it only ever signs for a configured host) and by the SNI allowlist.

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};
use time::{Duration, OffsetDateTime};

pub const CA_COMMON_NAME: &str = "cAInary OTel debug CA (ephemeral)";
pub use crate::host::{MAX_HOST_BYTES, MAX_HOSTS};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaError(pub String);

impl std::fmt::Display for CaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn fail<T, E>(what: &str) -> impl FnOnce(E) -> Result<T, CaError> + '_ {
    move |_| Err(CaError(format!("can't {what}")))
}

pub struct Ca {
    params: CertificateParams,
    key: KeyPair,
    cert: Certificate,
    hosts: Vec<String>,
    leaves: BTreeMap<String, OnceLock<Result<Arc<CertifiedKey>, CaError>>>,
    /// Serializes first builds, so one host's leaf is made once even under concurrent first use.
    build: Mutex<()>,
}

impl Ca {
    /// `hosts` must already be validated, lowercased and deduplicated.
    pub fn new(hosts: &[String]) -> Result<Ca, CaError> {
        if hosts.is_empty() || hosts.len() > MAX_HOSTS {
            return Err(CaError("between 1 and 32 hosts are required".into()));
        }
        let mut params = CertificateParams::new(Vec::<String>::new())
            .or_else(fail("create the CA parameters"))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, CA_COMMON_NAME);
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: hosts.iter().cloned().map(GeneralSubtree::DnsName).collect(),
            excluded_subtrees: Vec::new(),
        });
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::hours(1);
        params.not_after = now + Duration::days(30);
        let key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).or_else(fail("generate the CA key"))?;
        let cert = params
            .self_signed(&key)
            .or_else(fail("sign the CA certificate"))?;
        Ok(Ca {
            params,
            key,
            cert,
            hosts: hosts.to_vec(),
            leaves: hosts.iter().map(|h| (h.clone(), OnceLock::new())).collect(),
            build: Mutex::new(()),
        })
    }

    /// The public certificate, PEM. The only thing of the CA that is ever written.
    pub fn cert_pem(&self) -> String {
        self.cert.pem()
    }

    pub fn cert_der(&self) -> &CertificateDer<'static> {
        self.cert.der()
    }

    /// SHA-256 of the DER certificate, lowercase hex.
    pub fn fingerprint(&self) -> String {
        sha256_hex(self.cert.der())
    }

    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    /// The leaf for a configured host, built on first use and cached for the run. `None` for any
    /// other name: nothing is generated for it.
    pub fn leaf(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let cell = self.leaves.get(host)?;
        let built = cell.get_or_init(|| {
            let _one = self.build.lock().unwrap_or_else(|p| p.into_inner());
            self.issue(host)
        });
        built.as_ref().ok().cloned()
    }

    fn issue(&self, host: &str) -> Result<Arc<CertifiedKey>, CaError> {
        let mut params = CertificateParams::new(vec![host.to_string()])
            .or_else(fail("create a leaf's parameters"))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = self.params.not_before;
        params.not_after = self.params.not_after;
        params.use_authority_key_identifier_extension = true;
        let key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).or_else(fail("generate a leaf key"))?;
        let issuer = Issuer::from_params(&self.params, &self.key);
        let cert = params
            .signed_by(&key, &issuer)
            .or_else(fail("sign a leaf"))?;
        let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let signing =
            rustls::crypto::ring::sign::any_ecdsa_type(&der).or_else(fail("load a leaf key"))?;
        Ok(Arc::new(CertifiedKey::new(
            vec![cert.der().clone()],
            signing,
        )))
    }

    /// For the tests: the CA's issuing parts, so a test can sign things this type never would.
    #[cfg(test)]
    pub(crate) fn issuing_parts(&self) -> (&CertificateParams, &KeyPair) {
        (&self.params, &self.key)
    }
}

// ── SHA-256 (FIPS 180-4), so the fingerprint needs no further dependency ─────────────────────

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for block in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, c) in block.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [
                t1.wrapping_add(t2),
                v[0],
                v[1],
                v[2],
                v[3].wrapping_add(t1),
                v[4],
                v[5],
                v[6],
            ];
        }
        for (a, b) in h.iter_mut().zip(v) {
            *a = a.wrapping_add(b);
        }
    }
    let mut out = [0u8; 32];
    for (i, x) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&x.to_be_bytes());
    }
    out
}

pub fn sha256_hex(data: &[u8]) -> String {
    sha256(data).iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(&[b'a'; 1000]),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );
    }

    fn hosts() -> Vec<String> {
        vec![
            "otel.example-corp.test".into(),
            "logs.example-corp.test".into(),
        ]
    }

    /// The bytes of an extension: its OID, then `critical` (01 01 ff) when marked critical.
    fn has_critical_ext(der: &[u8], oid_tail: &[u8]) -> bool {
        let mut needle = vec![0x06, 0x03, 0x55, 0x1d];
        needle.extend_from_slice(oid_tail);
        needle.extend_from_slice(&[0x01, 0x01, 0xff]);
        der.windows(needle.len()).any(|w| w == needle.as_slice())
    }

    #[test]
    fn the_ca_is_constrained_to_exactly_the_hosts() {
        let ca = Ca::new(&hosts()).unwrap();
        let der: &[u8] = ca.cert_der();
        assert!(has_critical_ext(der, &[0x1e]), "critical nameConstraints");
        assert!(has_critical_ext(der, &[0x13]), "critical basicConstraints");
        assert!(has_critical_ext(der, &[0x0f]), "critical keyUsage");
        for h in hosts() {
            assert!(
                der.windows(h.len()).any(|w| w == h.as_bytes()),
                "{h} is permitted"
            );
        }
        assert!(!der.windows(11).any(|w| w == b"example.org"));
        assert!(ca.cert_pem().starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(!ca.cert_pem().contains("PRIVATE"));
        assert_eq!(ca.fingerprint().len(), 64);
        let der_bytes = ca.cert_der().as_ref().to_vec();
        assert_eq!(ca.fingerprint(), sha256_hex(&der_bytes));
        let cn = CA_COMMON_NAME.as_bytes();
        assert!(der.windows(cn.len()).any(|w| w == cn));
    }

    #[test]
    fn leaves_only_for_configured_hosts_and_built_once() {
        let ca = Ca::new(&hosts()).unwrap();
        let a = ca.leaf("otel.example-corp.test").unwrap();
        let b = ca.leaf("otel.example-corp.test").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert!(ca.leaf("logs.example-corp.test").is_some());
        for other in [
            "example.org",
            "OTEL.example-corp.test",
            "",
            "sub.otel.example-corp.test",
        ] {
            assert!(ca.leaf(other).is_none(), "{other}");
        }
    }

    #[test]
    fn concurrent_first_use_builds_one_leaf() {
        let ca = Arc::new(Ca::new(&hosts()).unwrap());
        let keys: Vec<_> = (0..8)
            .map(|_| {
                let ca = Arc::clone(&ca);
                std::thread::spawn(move || ca.leaf("otel.example-corp.test").unwrap())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();
        assert!(keys.windows(2).all(|w| Arc::ptr_eq(&w[0], &w[1])));
    }

    #[test]
    fn host_count_is_bounded() {
        let many: Vec<String> = (0..33).map(|i| format!("h{i}.example.test")).collect();
        assert!(Ca::new(&many).is_err());
        assert!(Ca::new(&[]).is_err());
        let ok: Vec<String> = (0..32).map(|i| format!("h{i}.example.test")).collect();
        assert!(Ca::new(&ok).is_ok());
    }

    // ── what a real verifier says (test-only keys; rustls is the client) ──────────────────────

    use rustls::client::ClientConfig;
    use rustls::pki_types::ServerName;
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::{ClientConnection, RootCertStore, ServerConfig, ServerConnection};

    #[derive(Debug)]
    struct Fixed(Arc<CertifiedKey>);
    impl ResolvesServerCert for Fixed {
        fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(Arc::clone(&self.0))
        }
    }

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    /// An in-memory handshake: the client trusts `ca`, the server offers `key`.
    fn handshake(ca: &Ca, key: Arc<CertifiedKey>, name: &str) -> Result<(), String> {
        let mut roots = RootCertStore::empty();
        roots.add(ca.cert_der().clone()).unwrap();
        let client_cfg = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_cfg = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Fixed(key)));
        let mut c = ClientConnection::new(
            Arc::new(client_cfg),
            ServerName::try_from(name.to_string()).unwrap(),
        )
        .unwrap();
        let mut sv = ServerConnection::new(Arc::new(server_cfg)).unwrap();
        for _ in 0..20 {
            let mut buf = Vec::new();
            c.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                sv.read_tls(&mut buf.as_slice()).unwrap();
                sv.process_new_packets()
                    .map_err(|e| format!("server: {e}"))?;
            }
            let mut buf = Vec::new();
            sv.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                c.read_tls(&mut buf.as_slice()).unwrap();
                c.process_new_packets()
                    .map_err(|e| format!("client: {e}"))?;
            }
            if !c.is_handshaking() && !sv.is_handshaking() {
                return Ok(());
            }
        }
        Err("no progress".into())
    }

    /// A leaf signed by `issuer_params`/`issuer_key`, which this crate's `Ca` never does.
    fn forge(
        issuer_params: &CertificateParams,
        issuer_key: &KeyPair,
        name: &str,
        not_after: OffsetDateTime,
        chain: Vec<CertificateDer<'static>>,
    ) -> Arc<CertifiedKey> {
        let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
        params.is_ca = IsCa::ExplicitNoCa;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = OffsetDateTime::now_utc() - Duration::days(2);
        params.not_after = not_after;
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let issuer = Issuer::from_params(issuer_params, issuer_key);
        let cert = params.signed_by(&key, &issuer).unwrap();
        let mut ders = vec![cert.der().clone()];
        ders.extend(chain);
        let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        Arc::new(CertifiedKey::new(
            ders,
            rustls::crypto::ring::sign::any_ecdsa_type(&der).unwrap(),
        ))
    }

    #[test]
    fn a_verifier_accepts_the_configured_host_and_nothing_else() {
        let ca = Ca::new(&hosts()).unwrap();
        let (params, key) = ca.issuing_parts();
        let future = OffsetDateTime::now_utc() + Duration::days(1);
        // The real leaf for the real name.
        handshake(
            &ca,
            ca.leaf("otel.example-corp.test").unwrap(),
            "otel.example-corp.test",
        )
        .expect("the configured host verifies");
        // The same leaf presented for another name.
        assert!(
            handshake(
                &ca,
                ca.leaf("otel.example-corp.test").unwrap(),
                "logs.example-corp.test"
            )
            .is_err()
        );
        // A leaf for an unrelated name, signed by the real CA: the name constraints refuse it.
        let other = forge(params, key, "api.unrelated.example", future, vec![]);
        let e = handshake(&ca, other, "api.unrelated.example").unwrap_err();
        assert!(e.starts_with("client:"), "{e}");
        // An expired leaf for a permitted name.
        let past = OffsetDateTime::now_utc() - Duration::hours(1);
        let expired = forge(params, key, "otel.example-corp.test", past, vec![]);
        assert!(handshake(&ca, expired, "otel.example-corp.test").is_err());
        // A subordinate CA under it, and a leaf below that for a name the constraints don't
        // permit. (webpki does not enforce a *trust anchor's* pathLen, so a sub-CA leaf for a
        // *permitted* name verifies; that is the "defence in depth, not containment" of
        // design 16.7.1, and why the leaf issuer and the SNI allowlist carry the restriction.)
        let mut sub = CertificateParams::new(Vec::<String>::new()).unwrap();
        sub.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        sub.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        sub.not_before = params.not_before;
        sub.not_after = params.not_after;
        let sub_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let sub_cert = sub
            .signed_by(&sub_key, &Issuer::from_params(params, key))
            .unwrap();
        let chained = forge(
            &sub,
            &sub_key,
            "api.unrelated.example",
            future,
            vec![sub_cert.der().clone()],
        );
        assert!(handshake(&ca, chained, "api.unrelated.example").is_err());
    }

    #[test]
    fn the_private_key_is_never_serialized_by_this_module() {
        // The only serialization of key material in this file is the *leaf* key handed straight
        // to rustls; the CA key has no path to PEM or DER at all.
        let src = include_str!("ca.rs");
        let code = &src[..src.find("#[cfg(test)]").unwrap()];
        assert_eq!(code.matches("serialize_der()").count(), 1);
        assert!(!code.contains("serialize_pem"));
        assert!(!code.contains("key.pem") && !code.contains("PRIVATE KEY"));
    }
}
