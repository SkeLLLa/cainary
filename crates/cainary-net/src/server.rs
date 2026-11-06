//! The listener: the only `std::net` in this crate (design §8.2, §14.1, §14.4, §14.5).
//!
//! Loopback only, no outbound connection of any kind, bind from `SocketAddr` values (no DNS).
//! One acceptor per listener, at most 16 connection threads, at most 2 parse/match jobs at a
//! time, and an output queue bounded by items and bytes.

use crate::http::{self, HttpError, Limits, Response};
use crate::logfile::LogFile;
use crate::otlp::{self, Ctx, Route};
use crate::output::{self, ErrorEvent, Event, FlagInfo, Hello};
use crate::queue::{Queue, Refused, Semaphore};
use crate::redflag::Matcher;
use crate::setup;
use std::cell::Cell;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const MAX_CONNECTIONS: usize = 16;
pub const MAX_JOBS: usize = 2;
pub const QUEUE_ITEMS: usize = 256;
pub const QUEUE_BYTES: usize = 8 << 20;
pub const WIRE_BUDGET: usize = 20 << 20;
pub const ERRORS_PER_SECOND: u32 = 10;

#[derive(Debug, Clone)]
pub struct Tunables {
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    /// Per request, from its first byte (slowloris).
    pub request_deadline: Duration,
    /// Keep-alive idle time.
    pub idle_timeout: Duration,
    pub max_connections: usize,
    pub max_jobs: usize,
    pub queue_items: usize,
    pub queue_bytes: usize,
    pub wire_budget: usize,
    pub limits: Limits,
    /// Window of the rejection-line rate limit (`ERRORS_PER_SECOND` per window).
    pub error_window: Duration,
    /// Takeover mode: absolute time from accept for the handshake and the first request.
    pub first_request_deadline: Duration,
    /// Takeover mode: at most one `error` line per handshake category in this window, with a count.
    pub tls_error_window: Duration,
}

impl Default for Tunables {
    fn default() -> Tunables {
        Tunables {
            read_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(10),
            request_deadline: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(10),
            max_connections: MAX_CONNECTIONS,
            max_jobs: MAX_JOBS,
            queue_items: QUEUE_ITEMS,
            queue_bytes: QUEUE_BYTES,
            wire_budget: WIRE_BUDGET,
            limits: Limits::default(),
            error_window: Duration::from_secs(1),
            first_request_deadline: Duration::from_secs(30),
            tls_error_window: Duration::from_secs(10),
        }
    }
}

pub struct Config {
    /// Validated loopback addresses; empty means 127.0.0.1 then ::1.
    pub listen: Vec<String>,
    pub port: u16,
    pub tunables: Tunables,
    pub matcher: Arc<Matcher>,
    pub show_values: bool,
    pub json: bool,
    pub once: bool,
    pub log: Option<LogFile>,
    pub sink: Box<dyn Write + Send>,
    pub status: Box<dyn Write + Send>,
    pub generator: String,
    /// Takeover mode (design §16): the TLS state, and the port the exporter's URL uses.
    #[cfg(feature = "tls")]
    pub tls: Option<TlsRun>,
}

/// A takeover run: the built TLS state and the port a redirect forwards from (443).
#[cfg(feature = "tls")]
pub struct TlsRun {
    pub tls: crate::tls::Tls,
    pub public_port: u16,
}

impl Config {
    pub fn new(sink: Box<dyn Write + Send>) -> Config {
        Config {
            listen: Vec::new(),
            port: 0,
            tunables: Tunables::default(),
            matcher: Arc::new(Matcher::new(Vec::new()).expect("an empty matcher compiles")),
            show_values: false,
            json: true,
            once: false,
            log: None,
            sink,
            status: Box::new(io::sink()),
            generator: format!("cainary-otel-debug {}", env!("CARGO_PKG_VERSION")),
            #[cfg(feature = "tls")]
            tls: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupError {
    pub code: u8,
    pub message: String,
    /// Set when `bind` was refused for lack of privilege: the port, so the caller can explain.
    pub denied_port: Option<u16>,
}

fn setup_err(code: u8, message: impl Into<String>) -> SetupError {
    SetupError {
        code,
        message: message.into(),
        denied_port: None,
    }
}

/// `--listen` validation: an IP literal that is loopback. `::ffff:127.0.0.1` is refused, since
/// `IpAddr::is_loopback` is false for it.
pub fn check_listen(s: &str) -> Result<(), String> {
    let ip: IpAddr = s
        .parse()
        .map_err(|_| format!("--listen needs an IP address, not '{s}'"))?;
    if ip.is_loopback() {
        Ok(())
    } else {
        Err(format!(
            "refusing to listen on {s}: only loopback addresses (127.0.0.0/8, ::1)"
        ))
    }
}

pub struct Server {
    /// Bound addresses.
    pub addrs: Vec<SocketAddr>,
    pub port: u16,
    /// A verified capability drop happened between bind and accept (builds with `tls`).
    pub caps_dropped: bool,
    stop: Arc<AtomicBool>,
    queue: Arc<Queue>,
    active: Arc<AtomicUsize>,
    output: Option<JoinHandle<output::End>>,
    acceptors: Vec<JoinHandle<()>>,
}

impl Server {
    /// Connections currently being served.
    pub fn connections(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    /// Blocks until the output thread ends: `--once` done, the queue closed, or the sink failed.
    pub fn wait(mut self) -> output::End {
        let h = self.output.take().expect("wait is called once");
        match h.join() {
            Ok(end) => end,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    /// Stops accepting and lets the output thread drain; in-flight connections finish on their own.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.queue.close();
    }

    /// Stops and waits for the acceptors, so the listening sockets are closed on return.
    pub fn shutdown(mut self) -> output::End {
        self.stop();
        for a in self.acceptors.drain(..) {
            let _ = a.join();
        }
        self.wait()
    }
}

struct ErrLimiter {
    span: Duration,
    window: Instant,
    count: u32,
    dropped: u64,
}

impl ErrLimiter {
    /// Whether to emit this rejection, and how many earlier ones the previous second dropped.
    fn admit(&mut self, now: Instant) -> (bool, Option<u64>) {
        let mut summary = None;
        if now.duration_since(self.window) >= self.span {
            if self.dropped > 0 {
                summary = Some(self.dropped);
            }
            *self = ErrLimiter {
                span: self.span,
                window: now,
                count: 0,
                dropped: 0,
            };
        }
        if self.count < ERRORS_PER_SECOND {
            self.count += 1;
            (true, summary)
        } else {
            self.dropped += 1;
            (false, summary)
        }
    }
}

struct Shared {
    ctx: Ctx,
    t: Tunables,
    queue: Arc<Queue>,
    jobs: Arc<Semaphore>,
    limiter: Mutex<ErrLimiter>,
    hosts: Vec<String>,
    /// Takeover mode: the configured hosts (empty in plain mode) and the ports a `Host` may name.
    tls_hosts: Vec<String>,
    host_ports: Vec<u16>,
    #[cfg(feature = "tls")]
    tls: Option<crate::tls::Tls>,
    #[cfg(feature = "tls")]
    tls_seen: Mutex<std::collections::HashMap<crate::tls::Refusal, (Option<Instant>, u64)>>,
    active: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

struct Slot(Arc<AtomicUsize>);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn bind_all(cfg: &Config) -> Result<(Vec<TcpListener>, Vec<String>), SetupError> {
    let ips: Vec<IpAddr> = if cfg.listen.is_empty() {
        vec![
            IpAddr::from([127, 0, 0, 1]),
            IpAddr::from(std::net::Ipv6Addr::LOCALHOST),
        ]
    } else {
        let mut v = Vec::new();
        for s in &cfg.listen {
            check_listen(s).map_err(|m| setup_err(2, m))?;
            v.push(
                s.parse::<IpAddr>()
                    .map_err(|_| setup_err(2, "invalid --listen address"))?,
            );
        }
        v
    };
    let defaults = cfg.listen.is_empty();
    let mut port = cfg.port;
    let mut listeners = Vec::new();
    let mut notes = Vec::new();
    for (i, ip) in ips.iter().enumerate() {
        let addr = SocketAddr::new(*ip, port);
        match TcpListener::bind(addr) {
            Ok(l) => {
                let local = l
                    .local_addr()
                    .map_err(|e| setup_err(1, format!("can't read the listening address: {e}")))?;
                // Defence in depth: never serve on anything but loopback, whatever bind did.
                if !local.ip().is_loopback() {
                    return Err(setup_err(
                        2,
                        format!(
                            "refusing to listen on {}: only loopback addresses (127.0.0.0/8, ::1)",
                            local.ip()
                        ),
                    ));
                }
                port = local.port();
                listeners.push(l);
            }
            // The default ::1 listener is best effort (the host may have no IPv6).
            Err(e) if defaults && i > 0 => notes.push(format!("{addr} (not available: {e})")),
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                let next = port.saturating_add(1);
                return Err(setup_err(
                    1,
                    format!("port {port} is in use (another collector?); try --port {next}"),
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                return Err(SetupError {
                    denied_port: Some(port),
                    ..setup_err(1, format!("can't listen on {addr}: permission denied"))
                });
            }
            Err(e) => return Err(setup_err(1, format!("can't listen on {addr}: {e}"))),
        }
    }
    Ok((listeners, notes))
}

pub fn run(cfg: Config) -> Result<Server, SetupError> {
    let (listeners, notes) = bind_all(&cfg)?;
    // Whatever privilege bind needed is dropped before the first accept (design §16.7.5): in
    // every mode of a build that can hold the capability, since a file capability applies to
    // the executable however it is invoked. Fail-closed: an error here ends the run.
    #[cfg(feature = "tls")]
    let caps_dropped = {
        crate::tls::privdrop::drop_capabilities()
            .map_err(|e| setup_err(1, format!("can't drop capabilities after binding: {e}")))?;
        true
    };
    #[cfg(not(feature = "tls"))]
    let caps_dropped = false;
    let addrs: Vec<SocketAddr> = listeners
        .iter()
        .map(|l| l.local_addr().expect("bound"))
        .collect();
    let port = addrs[0].port();
    for l in &listeners {
        l.set_nonblocking(true)
            .map_err(|e| setup_err(1, format!("can't configure the listener: {e}")))?;
    }

    let mut hosts: Vec<String> = ["127.0.0.1", "[::1]", "localhost"]
        .iter()
        .map(|h| format!("{h}:{port}"))
        .collect();
    hosts.extend(addrs.iter().map(SocketAddr::to_string));

    let queue = Queue::new(cfg.tunables.queue_items, cfg.tunables.queue_bytes);
    let stop = Arc::new(AtomicBool::new(false));
    let first = addrs[0];
    #[cfg(feature = "tls")]
    let scheme = if cfg.tls.is_some() { "https" } else { "http" };
    #[cfg(not(feature = "tls"))]
    let scheme = "http";
    let endpoint = match first.ip() {
        IpAddr::V4(ip) => format!("{scheme}://{ip}:{port}"),
        IpAddr::V6(ip) => format!("{scheme}://[{ip}]:{port}"),
    };
    let mut listen: Vec<String> = addrs.iter().map(SocketAddr::to_string).collect();
    listen.extend(notes);
    #[allow(unused_mut)]
    let mut tls_hosts: Vec<String> = Vec::new();
    #[allow(unused_mut)]
    let mut host_ports: Vec<u16> = Vec::new();
    #[allow(unused_mut)]
    let mut setup_info = setup::setup(&endpoint);
    #[allow(unused_mut)]
    let mut mode = "receiver";
    #[allow(unused_mut)]
    let mut tls_hello = None;
    #[cfg(feature = "tls")]
    if let Some(run) = &cfg.tls {
        mode = "tls-receiver";
        tls_hosts = run.tls.hosts().to_vec();
        host_ports = vec![port];
        if run.public_port != port {
            host_ports.push(run.public_port);
        }
        let ca_path = run.tls.ca_path.display().to_string();
        let fingerprint = run.tls.fingerprint();
        // The plain endpoint lines would point at http://; here the exporter keeps its own URL
        // and only needs to trust the certificate.
        setup_info.claude_code = vec![format!("NODE_EXTRA_CA_CERTS={ca_path}")];
        setup_info.codex = vec![
            format!("SSL_CERT_FILE={ca_path}"),
            format!("CODEX_CA_CERTIFICATE={ca_path}"),
        ];
        setup_info.takeover = Some(setup::takeover(&setup::Takeover {
            hosts: &tls_hosts,
            ca_path: &ca_path,
            fingerprint: &fingerprint,
            port,
            public_port: run.public_port,
            v4: addrs.iter().any(SocketAddr::is_ipv4),
            v6: addrs.iter().any(SocketAddr::is_ipv6),
        }));
        tls_hello = Some(output::TlsHello {
            hosts: tls_hosts.clone(),
            ca_path,
            ca_sha256: fingerprint,
        });
    }
    let hello = Hello {
        generator: cfg.generator.clone(),
        mode,
        tls: tls_hello,
        listen,
        endpoint: endpoint.clone(),
        show_values: cfg.show_values,
        log_file: cfg.log.as_ref().map(|l| l.path().display().to_string()),
        red_flags: cfg
            .matcher
            .patterns()
            .iter()
            .map(|p| FlagInfo {
                name: p.name.clone(),
                kind: p.kind.as_str(),
                preset: p.preset,
                case_sensitive: p.case_sensitive,
            })
            .collect(),
        setup: setup_info,
    };

    let out_cfg = output::Config {
        json: cfg.json,
        once: cfg.once,
        hello,
        log: cfg.log,
        sink: cfg.sink,
        status: cfg.status,
    };
    let out_queue = Arc::clone(&queue);
    let output = thread::Builder::new()
        .name("output".into())
        .spawn(move || output::run(out_queue, out_cfg))
        .map_err(|e| setup_err(1, format!("can't start the output thread: {e}")))?;

    let error_window = cfg.tunables.error_window;
    let shared = Arc::new(Shared {
        ctx: Ctx {
            matcher: cfg.matcher,
            show_values: cfg.show_values,
        },
        jobs: Semaphore::new(cfg.tunables.max_jobs),
        t: cfg.tunables,
        queue: Arc::clone(&queue),
        limiter: Mutex::new(ErrLimiter {
            span: error_window,
            window: Instant::now(),
            count: 0,
            dropped: 0,
        }),
        hosts,
        tls_hosts,
        host_ports,
        #[cfg(feature = "tls")]
        tls: cfg.tls.map(|r| r.tls),
        #[cfg(feature = "tls")]
        tls_seen: Mutex::new(std::collections::HashMap::new()),
        active: Arc::new(AtomicUsize::new(0)),
        stop: Arc::clone(&stop),
    });
    let acceptors = listeners
        .into_iter()
        .map(|l| {
            let sh = Arc::clone(&shared);
            thread::Builder::new()
                .name("accept".into())
                .spawn(move || accept_loop(l, sh))
                .map_err(|e| setup_err(1, format!("can't start an acceptor: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Server {
        addrs,
        port,
        caps_dropped,
        stop,
        queue,
        active: Arc::clone(&shared.active),
        output: Some(output),
        acceptors,
    })
}

fn accept_loop(l: TcpListener, sh: Arc<Shared>) {
    while !sh.stop.load(Ordering::SeqCst) {
        let stream = match l.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
                continue;
            }
            Err(_) => {
                // EMFILE and friends: back off instead of spinning.
                thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        let accepted_at = Instant::now();
        let _ = stream.set_nonblocking(false);
        // The slot comes before any TLS state exists for the connection (design §16.7.3).
        if sh.active.fetch_add(1, Ordering::SeqCst) >= sh.t.max_connections {
            sh.active.fetch_sub(1, Ordering::SeqCst);
            // No handshake and no plaintext reply on a TLS port: just close.
            if sh.tls_hosts.is_empty() {
                busy(stream);
            }
            continue;
        }
        let slot = Slot(Arc::clone(&sh.active));
        let shared = Arc::clone(&sh);
        let spawned = thread::Builder::new().name("conn".into()).spawn(move || {
            let _slot = slot;
            connection(stream, accepted_at, &shared);
        });
        // On failure the closure (slot included) is dropped, which frees the slot.
        drop(spawned);
    }
}

fn busy(stream: TcpStream) {
    let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
    let r = Response::error(503, "too many connections");
    let _ = (&stream).write_all(&r.to_bytes());
    let _ = stream.shutdown(Shutdown::Both);
}

/// One connection's byte stream: plain TCP, or TLS over a deadline-clipped TCP stream in
/// takeover mode. Requests and responses go through this one object; the methods are what the
/// server needs from the socket underneath, so nothing outside this file names a socket type.
pub(crate) trait Wire: Read + Write {
    fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()>;
    fn set_nodelay(&self);
    fn shutdown_write(&self);
    /// The server name the TLS handshake accepted; `None` on plain TCP.
    fn sni(&self) -> Option<&str> {
        None
    }
    /// The first request on the connection finished: the accept deadline ends.
    fn first_request_done(&self) {}
    /// An absolute deadline for every underlying read and write from now on, until the next
    /// call. TLS turns one logical read into several socket reads, so a per-read timeout alone
    /// would let a trickled record outlive the idle or request deadline.
    fn set_deadline(&self, _until: Option<Instant>) {}
    /// Before closing: a TLS `close_notify`.
    fn finish(&mut self) {}
}

impl Wire for TcpStream {
    fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, d)
    }
    fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        TcpStream::set_write_timeout(self, d)
    }
    fn set_nodelay(&self) {
        let _ = TcpStream::set_nodelay(self, true);
    }
    fn shutdown_write(&self) {
        let _ = self.shutdown(Shutdown::Write);
    }
}

/// A TCP stream under an absolute deadline: every read and write first clips the socket's
/// timeout to the time left, so a trickling handshake or a stalled write can't outlive it,
/// whatever the layers above do. `release_deadline` ends it after the first request.
#[cfg_attr(not(feature = "tls"), allow(dead_code))]
pub(crate) struct Clipped {
    tcp: TcpStream,
    /// From accept: covers the handshake and the first request, then is released.
    until: Cell<Option<Instant>>,
    /// The current idle, request, write or linger deadline, set by the layer above.
    cap: Cell<Option<Instant>>,
    /// The first byte the peer ever sent, to tell a TLS record from plain HTTP.
    first: Cell<Option<u8>>,
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
impl Clipped {
    pub(crate) fn new(tcp: TcpStream, until: Instant) -> Clipped {
        Clipped {
            tcp,
            until: Cell::new(Some(until)),
            cap: Cell::new(None),
            first: Cell::new(None),
        }
    }

    pub(crate) fn first_byte(&self) -> Option<u8> {
        self.first.get()
    }

    pub(crate) fn release_deadline(&self) {
        self.until.set(None);
    }

    /// The time left before `until`, or a timeout error.
    fn left(&self) -> io::Result<Option<Duration>> {
        let sooner = match (self.until.get(), self.cap.get()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        match sooner {
            None => Ok(None),
            Some(t) => match t.checked_duration_since(Instant::now()) {
                Some(d) if !d.is_zero() => Ok(Some(d)),
                _ => Err(io::Error::from(io::ErrorKind::TimedOut)),
            },
        }
    }
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
fn clip(current: Option<Duration>, left: Option<Duration>) -> Option<Duration> {
    match (current, left) {
        (Some(c), Some(l)) => Some(c.min(l)),
        (None, l) => l,
        (c, None) => c,
    }
}

impl Read for Clipped {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(left) = self.left()? {
            let cur = self.tcp.read_timeout()?;
            self.tcp.set_read_timeout(clip(cur, Some(left)))?;
        }
        let n = (&self.tcp).read(buf)?;
        if n > 0 && self.first.get().is_none() {
            self.first.set(Some(buf[0]));
        }
        Ok(n)
    }
}

impl Write for Clipped {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(left) = self.left()? {
            let cur = self.tcp.write_timeout()?;
            self.tcp.set_write_timeout(clip(cur, Some(left)))?;
        }
        (&self.tcp).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        (&self.tcp).flush()
    }
}

impl Wire for Clipped {
    fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.tcp.set_read_timeout(d)
    }
    fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.tcp.set_write_timeout(d)
    }
    fn set_nodelay(&self) {
        let _ = self.tcp.set_nodelay(true);
    }
    fn shutdown_write(&self) {
        let _ = self.tcp.shutdown(Shutdown::Write);
    }
    fn first_request_done(&self) {
        self.release_deadline();
    }
    fn set_deadline(&self, until: Option<Instant>) {
        self.cap.set(until);
    }
}

/// One accepted connection, in its own thread: plain, or the takeover's TLS handshake first.
fn connection(stream: TcpStream, accepted_at: Instant, sh: &Shared) {
    #[cfg(feature = "tls")]
    if let Some(tls) = &sh.tls {
        let _ = stream.set_read_timeout(Some(sh.t.read_timeout));
        let _ = stream.set_write_timeout(Some(sh.t.write_timeout));
        let clipped = Clipped::new(stream, accepted_at + sh.t.first_request_deadline);
        match tls.accept(clipped) {
            Ok(s) => serve(s, sh),
            Err(refusal) => sh.emit_tls(refusal, &tls.ca_path.display().to_string()),
        }
        return;
    }
    let _ = accepted_at;
    serve(stream, sh);
}

/// The stream plus the clocks: a deadline checked before every read, a read timeout clipped to
/// what's left of it, and the per-request wire budget.
struct Guarded<S: Wire> {
    stream: S,
    deadline: Cell<Instant>,
    read_timeout: Duration,
    wire_left: Cell<usize>,
}

impl<S: Wire> Read for Guarded<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let now = Instant::now();
        let deadline = self.deadline.get();
        if now >= deadline {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        let left = self.wire_left.get();
        if left == 0 {
            return Err(io::Error::from(io::ErrorKind::FileTooLarge));
        }
        self.stream.set_deadline(Some(deadline));
        self.stream
            .set_read_timeout(Some(self.read_timeout.min(deadline - now)))?;
        let take = buf.len().min(left);
        let n = self.stream.read(&mut buf[..take])?;
        self.wire_left.set(left - n);
        Ok(n)
    }
}

enum Next {
    KeepAlive,
    Close { linger: bool },
}

fn serve<S: Wire>(stream: S, sh: &Shared) {
    stream.set_nodelay();
    let _ = stream.set_write_timeout(Some(sh.t.write_timeout));
    let mut reader = BufReader::with_capacity(
        8192,
        Guarded {
            stream,
            deadline: Cell::new(Instant::now()),
            read_timeout: sh.t.read_timeout,
            wire_left: Cell::new(sh.t.wire_budget),
        },
    );
    let linger = loop {
        let g = reader.get_ref();
        g.wire_left.set(sh.t.wire_budget);
        g.deadline.set(Instant::now() + sh.t.idle_timeout);
        match reader.fill_buf() {
            Ok(b) if !b.is_empty() => {}
            _ => break false,
        }
        let g = reader.get_ref();
        g.wire_left.set(sh.t.wire_budget);
        g.deadline.set(Instant::now() + sh.t.request_deadline);
        match request(&mut reader, sh) {
            Next::KeepAlive => reader.get_ref().stream.first_request_done(),
            Next::Close { linger } => break linger,
        }
    };
    let stream = &mut reader.get_mut().stream;
    stream.set_deadline(Some(Instant::now() + Duration::from_secs(1)));
    stream.finish();
    stream.shutdown_write();
    if linger {
        stream.set_deadline(Some(Instant::now() + Duration::from_millis(300)));
        // Read what the client is still sending, briefly, so closing doesn't turn into a reset
        // that destroys the response it hasn't read yet.
        let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
        let end = Instant::now() + Duration::from_millis(250);
        let mut sink = [0u8; 4096];
        let mut total = 0usize;
        while Instant::now() < end && total < (1 << 20) {
            match stream.read(&mut sink) {
                Ok(0) | Err(_) => break,
                Ok(n) => total += n,
            }
        }
    }
}

impl Shared {
    /// A handshake failure: one line per category per window, then a count of the ones skipped,
    /// so a browser's retry storm can't flood the output.
    #[cfg(feature = "tls")]
    fn emit_tls(&self, r: crate::tls::Refusal, ca_path: &str) {
        let now = Instant::now();
        let n = {
            let mut seen = self.tls_seen.lock().unwrap_or_else(|p| p.into_inner());
            let e = seen.entry(r).or_insert((None, 0));
            let due =
                e.0.is_none_or(|t| now.duration_since(t) >= self.t.tls_error_window);
            if due {
                let n = e.1 + 1;
                *e = (Some(now), 0);
                Some(n)
            } else {
                e.1 += 1;
                None
            }
        };
        if let Some(n) = n {
            self.emit_error(ErrorEvent::tls(&r.message(ca_path), n));
        }
    }

    /// A rejection's `error` line: best effort, rate-limited, never blocks for long.
    fn emit_error(&self, ev: ErrorEvent) {
        let (emit, summary) = {
            let mut l = self.limiter.lock().unwrap_or_else(|p| p.into_inner());
            l.admit(Instant::now())
        };
        if let Some(n) = summary {
            self.try_send(Event::Error(ErrorEvent::dropped(n)));
        }
        if emit {
            self.try_send(Event::Error(ev));
        }
    }

    fn try_send(&self, ev: Event) {
        if let Ok(p) = self
            .queue
            .reserve(&[ev.size()], Instant::now() + Duration::from_millis(100))
        {
            p.send(vec![ev]);
        }
    }
}

fn send<S: Wire>(r: &mut BufReader<Guarded<S>>, bytes: &[u8]) -> bool {
    // Writes get the request's deadline too, so a stalled peer can't hold a TLS write open.
    let until = r.get_ref().deadline.get();
    let s = &mut r.get_mut().stream;
    s.set_deadline(Some(until));
    s.write_all(bytes).and_then(|()| s.flush()).is_ok()
}

fn write_response<S: Wire>(r: &mut BufReader<Guarded<S>>, resp: &Response) -> bool {
    send(r, &resp.to_bytes())
}

/// Answers a rejection and reports it.
fn reject<S: Wire>(
    sh: &Shared,
    w: &mut BufReader<Guarded<S>>,
    r: Response,
    method: Option<&str>,
    path: Option<&str>,
    message: &str,
) -> Next {
    let status = r.status;
    write_response(w, &r);
    sh.emit_error(ErrorEvent::http(status, method, path, message));
    Next::Close { linger: true }
}

fn request<S: Wire>(reader: &mut BufReader<Guarded<S>>, sh: &Shared) -> Next {
    let head = match http::read_head(reader, &sh.t.limits) {
        Ok(h) => h,
        Err(HttpError::Bad { status, message }) => {
            return reject(
                sh,
                reader,
                Response::error(status, &message),
                None,
                None,
                &message,
            );
        }
        Err(HttpError::Io(e)) => return io_close(sh, reader, &e),
        Err(HttpError::Eof) => return Next::Close { linger: false },
    };
    let method = Some(head.method.as_str());
    let path = otlp::known_path(head.path());
    let deadline = reader.get_ref().deadline.get();
    macro_rules! deny {
        ($status:expr, $message:expr) => {{
            let message: &str = $message;
            reject(
                sh,
                reader,
                Response::error($status, message),
                method,
                path,
                message,
            )
        }};
    }

    // DNS rebinding and browsers (design §14.4, §16.7.4): before any body is read or 100 sent.
    let hosts: Vec<&str> = head
        .headers
        .iter()
        .filter(|(k, _)| k == "host")
        .map(|(_, v)| v.as_str())
        .collect();
    let tls_mode = !sh.tls_hosts.is_empty();
    let mut batch_host: Option<String> = None;
    if tls_mode {
        let sni = reader.get_ref().stream.sni().map(str::to_string);
        match takeover_host(&hosts, sni.as_deref(), &sh.host_ports) {
            Ok(h) => batch_host = Some(h),
            Err((status, message)) => return deny!(status, message),
        }
    } else {
        match hosts.as_slice() {
            [h] if sh.hosts.iter().any(|a| a.eq_ignore_ascii_case(h)) => {}
            [_] => return deny!(421, "unexpected Host"),
            _ => return deny!(400, "exactly one Host header is required"),
        }
    }
    if head
        .headers
        .iter()
        .any(|(k, _)| k == "origin" || k.starts_with("sec-fetch-"))
    {
        return deny!(403, "browser requests are refused");
    }

    // Plain mode keeps the strict routes; takeover mode takes any path (POST only) and works
    // the signal out from the path, then the body.
    let route = if tls_mode {
        if head.method == "POST" {
            Route::Signal(otlp::route_any(head.path()).unwrap_or(otlp::Signal::Logs))
        } else {
            Route::NotAllowed
        }
    } else {
        otlp::route(&head.method, head.path())
    };
    let hint = if tls_mode {
        otlp::route_any(head.path())
    } else {
        None
    };
    #[allow(unused_assignments)]
    let mut signal = match route {
        Route::Signal(s) => s,
        Route::NotFound => return deny!(404, "not found"),
        Route::NotAllowed => {
            let r = Response::error(405, "method not allowed").with_header("Allow", "POST");
            return reject(sh, reader, r, method, path, "method not allowed");
        }
    };
    if let Err(rej) = otlp::check_content(&head) {
        return deny!(rej.status, rej.message);
    }
    let framing = match http::framing(&head, &sh.t.limits) {
        Ok(f) => f,
        Err(HttpError::Bad { status, message }) => return deny!(status, &message),
        Err(_) => return Next::Close { linger: false },
    };

    // The job permit comes before the body is allocated.
    let Some(permit) = sh.jobs.acquire(deadline) else {
        return deny!(503, "busy");
    };
    if head.expects_continue() && !send(reader, http::CONTINUE) {
        return Next::Close { linger: false };
    }
    let body = match http::read_body(reader, framing, &sh.t.limits) {
        Ok(b) => b,
        Err(HttpError::Bad { status, message }) => return deny!(status, &message),
        Err(HttpError::Io(e)) => return io_close(sh, reader, &e),
        Err(HttpError::Eof) => return Next::Close { linger: false },
    };
    let doc = match otlp::parse(&body) {
        Ok(d) => d,
        Err(m) => return deny!(400, &m),
    };
    if tls_mode {
        signal = match (hint, otlp::root_signal(&doc)) {
            (Some(h), Ok(Some(r))) if h != r => {
                return deny!(400, "the path and the body name different signals");
            }
            (Some(h), Ok(_)) => h,
            (None, Ok(Some(r))) => r,
            (None, Ok(None)) => return deny!(400, "can't tell which signal this is"),
            (_, Err(_)) => return deny!(400, "the body names more than one signal"),
        };
    }
    let bytes = body.len();
    let meta = otlp::Meta {
        // Paths are never printed: the canonical one, or a fixed marker (design §16.7.7).
        path: tls_mode.then_some(path.unwrap_or("<custom path>")),
        host: batch_host.as_deref(),
    };
    let prepared = match otlp::process_with(signal, bytes, &doc, &sh.ctx, &meta) {
        Ok(p) => p,
        Err(f) => return deny!(f.status(), &f.message()),
    };
    drop(doc);
    drop(body);
    drop(permit);

    // Room in the output queue is reserved before the 200 is written, so an accepted batch is
    // never lost to a full queue, and `--once` can't cut the response.
    let mut events = vec![Event::Batch(prepared.batch)];
    events.extend(prepared.extra.into_iter().map(Event::Error));
    let sizes: Vec<usize> = events.iter().map(Event::size).collect();
    let permit = match sh.queue.reserve(&sizes, deadline) {
        Ok(p) => p,
        Err(Refused::TooLarge) => return deny!(413, "batch too large to show"),
        Err(Refused::Timeout) => return deny!(503, "busy"),
    };
    let keep = head.keep_alive();
    let resp = Response::json(200, "{}".to_string(), keep);
    if !write_response(reader, &resp) {
        return Next::Close { linger: false };
    }
    permit.send(events);
    if keep {
        Next::KeepAlive
    } else {
        Next::Close { linger: false }
    }
}

/// Takeover mode's `Host` rule (design §16.7.4): exactly one, a DNS name equal to the SNI the
/// handshake accepted, with no port (443) or a port the listener is reachable on.
fn takeover_host(
    hosts: &[&str],
    sni: Option<&str>,
    ports: &[u16],
) -> Result<String, (u16, &'static str)> {
    let [h] = hosts else {
        return Err((400, "exactly one Host header is required"));
    };
    let h = h.to_ascii_lowercase();
    let (name, port) = match h.rsplit_once(':') {
        Some((n, text)) if !n.is_empty() => match text.parse::<u16>() {
            // No signs, no leading zeros: the text must be the number's own spelling.
            Ok(p) if p.to_string() == text => (n.to_string(), p),
            _ => return Err((400, "malformed Host header")),
        },
        _ => (h.clone(), 443),
    };
    if !crate::host::valid_host(&name) {
        return Err((400, "malformed Host header"));
    }
    if Some(name.as_str()) != sni || !ports.contains(&port) {
        return Err((421, "unexpected Host"));
    }
    Ok(name)
}

/// A read failed: the wire budget is answered with 413, timeouts and resets just close.
fn io_close<S: Wire>(sh: &Shared, w: &mut BufReader<Guarded<S>>, e: &io::Error) -> Next {
    if e.kind() == io::ErrorKind::FileTooLarge {
        return reject(
            sh,
            w,
            Response::error(413, "request too large"),
            None,
            None,
            "request too large",
        );
    }
    Next::Close { linger: false }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_check() {
        for ok in ["127.0.0.1", "127.5.5.5", "::1"] {
            assert!(check_listen(ok).is_ok(), "{ok}");
        }
        for bad in [
            "0.0.0.0",
            "::",
            "192.168.1.1",
            "::ffff:127.0.0.1",
            "localhost",
            "",
            "10.0.0.1",
        ] {
            assert!(check_listen(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn limiter_allows_ten_then_drops_and_summarises() {
        let t0 = Instant::now();
        let mut l = ErrLimiter {
            span: Duration::from_secs(1),
            window: t0,
            count: 0,
            dropped: 0,
        };
        for _ in 0..10 {
            assert_eq!(l.admit(t0), (true, None));
        }
        assert_eq!(l.admit(t0), (false, None));
        assert_eq!(l.admit(t0), (false, None));
        assert_eq!(l.admit(t0 + Duration::from_millis(1100)), (true, Some(2)));
        assert_eq!(l.admit(t0 + Duration::from_millis(1200)), (true, None));
    }

    fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (b, _) = l.accept().unwrap();
        (a, b)
    }

    #[test]
    fn clipped_reads_stop_at_the_absolute_deadline() {
        let (server_side, _client) = pair();
        // No socket timeout at all: only the absolute deadline can end a silent peer.
        let mut c = Clipped::new(server_side, Instant::now() + Duration::from_millis(250));
        let t = Instant::now();
        let e = c.read(&mut [0u8; 8]).unwrap_err();
        assert!(
            matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "{e:?}"
        );
        assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
        // Past the deadline nothing is attempted.
        assert_eq!(
            c.read(&mut [0u8; 8]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(c.write(b"x").unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn clipped_writes_to_a_peer_that_never_reads_stop_at_the_deadline() {
        let (server_side, _client_never_reads) = pair();
        let mut c = Clipped::new(server_side, Instant::now() + Duration::from_millis(400));
        let chunk = vec![0u8; 256 * 1024];
        let t = Instant::now();
        let mut err = None;
        while t.elapsed() < Duration::from_secs(10) {
            match c.write_all(&chunk) {
                Ok(()) => {}
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        let e = err.expect("a stalled peer must stop the writer");
        assert!(
            matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "{e:?}"
        );
        assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    }

    #[test]
    fn released_deadlines_stop_clipping() {
        let (server_side, mut client) = pair();
        let mut c = Clipped::new(server_side, Instant::now() + Duration::from_millis(100));
        c.release_deadline();
        std::thread::sleep(Duration::from_millis(200));
        client.write_all(b"hi").unwrap();
        let mut b = [0u8; 2];
        assert_eq!(c.read(&mut b).unwrap(), 2);
    }

    #[test]
    fn clip_picks_the_sooner_limit() {
        let s = |n| Some(Duration::from_secs(n));
        assert_eq!(clip(s(10), s(3)), s(3));
        assert_eq!(clip(s(2), s(3)), s(2));
        assert_eq!(clip(None, s(3)), s(3));
        assert_eq!(clip(s(2), None), s(2));
    }

    #[test]
    fn takeover_host_rules() {
        let ports = [8443u16, 443];
        let ok = |h: &str| takeover_host(&[h], Some("a.example.test"), &ports);
        assert_eq!(ok("a.example.test"), Ok("a.example.test".to_string()));
        assert_eq!(ok("A.Example.Test:8443"), Ok("a.example.test".to_string()));
        assert_eq!(ok("a.example.test:443"), Ok("a.example.test".to_string()));
        assert_eq!(ok("b.example.test"), Err((421, "unexpected Host")));
        assert_eq!(ok("a.example.test:80"), Err((421, "unexpected Host")));
        for bad in [
            "a.example.test:",
            ":443",
            "a.example.test:+443",
            "a.example.test:0443",
            "127.0.0.1:8443",
            "[::1]:443",
            "",
        ] {
            assert_eq!(ok(bad).unwrap_err().0, 400, "{bad:?}");
        }
        assert_eq!(
            takeover_host(&[], Some("a.example.test"), &ports)
                .unwrap_err()
                .0,
            400
        );
        assert_eq!(
            takeover_host(
                &["a.example.test", "a.example.test"],
                Some("a.example.test"),
                &ports
            )
            .unwrap_err()
            .0,
            400
        );
        assert_eq!(
            takeover_host(&["a.example.test"], None, &ports)
                .unwrap_err()
                .0,
            421
        );
    }
}
