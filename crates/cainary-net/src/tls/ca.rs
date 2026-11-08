//! The ephemeral CA and the per-host leaves.
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

pub use cainary_sig::{sha256, sha256_hex};

/// Whether `der` parses as a certificate usable as a trust anchor (the TLS stack's own reader).
pub fn parses_as_trust_anchor(der: &[u8]) -> bool {
    rustls::RootCertStore::empty()
        .add(rustls::pki_types::CertificateDer::from(der.to_vec()))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // architecture.md §12.10, and why the leaf issuer and the SNI allowlist carry the restriction.)
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
