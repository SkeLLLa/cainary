//! The endpoint takeover (design §16): a TLS receiver for a pinned HTTPS telemetry host.
//!
//! The user points that host name at loopback; this accepts the connection with a certificate
//! from an ephemeral, name-constrained CA whose public half is written to a file the exporting
//! process can be told to trust. Nothing is forwarded: while it runs, the real collector gets
//! nothing from this machine. `ca` holds the CA and the leaves, `ca_file` the one file write.

pub mod ca;
pub mod ca_file;

use crate::server::{Clipped, Wire};
use ca::Ca;
use rustls::server::{Acceptor, ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Why a handshake didn't complete: fixed categories only, never a name, a TLS error text or
/// anything else the peer controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// The client sent no SNI.
    NoSni,
    /// An SNI that isn't a configured host (the name is not kept).
    ServerName,
    /// The client offered ALPN protocols and `http/1.1` isn't among them.
    Alpn,
    /// The client sent an alert saying it doesn't trust the certificate (unknown_ca,
    /// bad_certificate, certificate_unknown, decrypt_error, ...).
    ClientRejectedCertificate,
    /// The first bytes weren't a TLS record: typically plain HTTP to the TLS port.
    NotTls,
    /// A TLS record, but malformed or out of order.
    Protocol,
    /// The client went away, or stalled past the deadline, before the handshake finished.
    Closed,
}

impl Refusal {
    /// The one-line explanation. `ca_path` is this run's own certificate path.
    pub fn message(self, ca_path: &str) -> String {
        match self {
            Refusal::NoSni => "tls handshake refused: no SNI (no server name sent)".into(),
            Refusal::ServerName => "tls handshake refused: SNI not in --tls-host".into(),
            Refusal::Alpn => {
                "tls handshake refused: no common ALPN (this serves http/1.1 only)".into()
            }
            Refusal::ClientRejectedCertificate => format!(
                "tls handshake failed: the client rejected the certificate (it doesn't trust the CA: start it with NODE_EXTRA_CA_CERTS={})",
                crate::output::escape(ca_path)
            ),
            Refusal::NotTls => "tls handshake failed: not TLS (plain HTTP to the TLS port?)".into(),
            Refusal::Protocol => "tls handshake failed: protocol error".into(),
            Refusal::Closed => {
                "tls handshake failed: the client closed the connection or stalled".into()
            }
        }
    }
}

/// SNI → the configured host's leaf. The allowlist check already happened in `accept`, so a
/// miss here (it can't happen for an accepted connection) simply refuses.
#[derive(Debug)]
struct Resolver(Arc<Ca>);

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.leaf(&hello.server_name()?.to_ascii_lowercase())
    }
}

impl std::fmt::Debug for Ca {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ca")
            .field("hosts", &self.hosts())
            .finish_non_exhaustive()
    }
}

/// Everything a TLS run needs, built once at startup.
pub struct Tls {
    ca: Arc<Ca>,
    config: Arc<ServerConfig>,
    /// The published certificate and the lock; dropped (lock released) at exit.
    _published: ca_file::Published,
    pub ca_path: PathBuf,
}

impl Tls {
    /// Generates the CA and publishes its certificate under `dir` (taking the run lock).
    pub fn start(hosts: &[String], dir: &std::path::Path) -> Result<Tls, StartError> {
        let ca = Arc::new(Ca::new(hosts).map_err(|e| StartError::Failed(e.to_string()))?);
        // Build every leaf now: a failure is a startup error, and the first handshake is fast.
        for h in hosts {
            if ca.leaf(h).is_none() {
                return Err(StartError::Failed("can't build a leaf certificate".into()));
            }
        }
        let published = ca_file::publish(dir, &ca.cert_pem()).map_err(|e| match e {
            ca_file::CaFileError::Busy(_) => StartError::Busy(e.to_string()),
            other => StartError::Failed(other.to_string()),
        })?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| StartError::Failed("can't set the TLS versions".into()))?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Resolver(Arc::clone(&ca))));
        // http/1.1 only; no h2. No early data (the default is 0, stated here so it stays so).
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.max_early_data_size = 0;
        let ca_path = published.path.clone();
        Ok(Tls {
            ca,
            config: Arc::new(config),
            _published: published,
            ca_path,
        })
    }

    pub fn hosts(&self) -> &[String] {
        self.ca.hosts()
    }

    pub fn fingerprint(&self) -> String {
        self.ca.fingerprint()
    }

    /// Runs the handshake on `sock` (already deadline-clipped). On success the stream carries the
    /// accepted SNI, which is the only host the requests on it may name.
    pub(crate) fn accept(&self, mut sock: Clipped) -> Result<TlsStream, Refusal> {
        // What a failed acceptor means depends on whether the first byte was a TLS record.
        let bad_start = |sock: &Clipped| match sock.first_byte() {
            Some(0x16) => Refusal::Protocol,
            Some(_) => Refusal::NotTls,
            None => Refusal::Closed,
        };
        // A read that ends or fails: the client left, unless what it sent wasn't TLS at all.
        let cut_short = |sock: &Clipped| match sock.first_byte() {
            Some(b) if b != 0x16 => Refusal::NotTls,
            _ => Refusal::Closed,
        };
        let mut acceptor = Acceptor::default();
        let accepted = loop {
            match acceptor.read_tls(&mut sock) {
                Ok(0) | Err(_) => return Err(cut_short(&sock)),
                Ok(_) => {}
            }
            match acceptor.accept() {
                Ok(Some(a)) => break a,
                Ok(None) => {}
                Err((_, mut alert)) => {
                    let _ = alert.write(&mut sock);
                    return Err(bad_start(&sock));
                }
            }
        };
        let hello = accepted.client_hello();
        let sni = hello.server_name().map(str::to_ascii_lowercase);
        let alpn_ok = match hello.alpn() {
            None => true,
            Some(mut it) => it.any(|p| p == b"http/1.1"),
        };
        let Some(sni) = sni else {
            return Err(Refusal::NoSni);
        };
        if !self.ca.hosts().contains(&sni) {
            return Err(Refusal::ServerName);
        }
        if !alpn_ok {
            return Err(Refusal::Alpn);
        }
        let mut conn = match accepted.into_connection(Arc::clone(&self.config)) {
            Ok(c) => c,
            Err((_, mut alert)) => {
                let _ = alert.write(&mut sock);
                return Err(Refusal::Protocol);
            }
        };
        // Bounded buffers: rustls queues at most this much unsent or unread data.
        conn.set_buffer_limit(Some(64 * 1024));
        let mut stream = StreamOwned::new(conn, sock);
        // Finish the handshake here, so a failure is a refusal and not a mysterious read error.
        while stream.conn.is_handshaking() {
            if let Err(e) = stream.conn.complete_io(&mut stream.sock) {
                return Err(classify_io(&e));
            }
        }
        Ok(TlsStream { inner: stream, sni })
    }
}

/// A handshake I/O error as a category: an alert from the client about the certificate, a
/// protocol violation, or the client simply going away.
fn classify_io(e: &io::Error) -> Refusal {
    use rustls::AlertDescription as A;
    match e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        Some(rustls::Error::AlertReceived(a)) => match a {
            A::UnknownCA
            | A::BadCertificate
            | A::UnsupportedCertificate
            | A::CertificateRevoked
            | A::CertificateExpired
            | A::CertificateUnknown
            | A::DecryptError
            | A::AccessDenied
            | A::BadCertificateStatusResponse
            | A::BadCertificateHashValue => Refusal::ClientRejectedCertificate,
            A::CloseNotify | A::UserCanceled => Refusal::Closed,
            _ => Refusal::Protocol,
        },
        Some(_) => Refusal::Protocol,
        None => Refusal::Closed,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartError {
    /// Another run owns the certificate file: exit 1.
    Busy(String),
    Failed(String),
}

pub(crate) struct TlsStream {
    inner: StreamOwned<ServerConnection, Clipped>,
    sni: String,
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Wire for TlsStream {
    fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.inner.sock.set_read_timeout(d)
    }
    fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.inner.sock.set_write_timeout(d)
    }
    fn set_nodelay(&self) {
        self.inner.sock.set_nodelay();
    }
    fn shutdown_write(&self) {
        self.inner.sock.shutdown_write();
    }
    fn sni(&self) -> Option<&str> {
        Some(&self.sni)
    }
    fn first_request_done(&self) {
        self.inner.sock.first_request_done();
    }
    fn set_deadline(&self, until: Option<Instant>) {
        self.inner.sock.set_deadline(until);
    }
    fn finish(&mut self) {
        self.inner.conn.send_close_notify();
        let _ = self.inner.flush();
    }
}
