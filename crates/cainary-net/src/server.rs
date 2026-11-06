//! The listener: the only `std::net` in this crate (design §8.2, §14.1, §14.4, §14.5).
//!
//! Loopback only, no outbound connection of any kind, bind from `SocketAddr` values (no DNS).
//! One acceptor per listener, at most 16 connection threads, at most 2 parse/match jobs at a
//! time, and an output queue bounded by items and bytes.

use crate::http::{self, Framing, HttpError, Limits, Response};
use crate::logfile::LogFile;
use crate::otlp::{self, Ctx, Route};
use crate::output::{self, ErrorEvent, Event, FlagInfo, Hello};
use crate::queue::{Queue, Semaphore};
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
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupError {
    pub code: u8,
    pub message: String,
}

fn setup_err(code: u8, message: impl Into<String>) -> SetupError {
    SetupError {
        code,
        message: message.into(),
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
    stop: Arc<AtomicBool>,
    queue: Arc<Queue>,
    output: Option<JoinHandle<output::End>>,
    acceptors: Vec<JoinHandle<()>>,
}

impl Server {
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
    window: Instant,
    count: u32,
    dropped: u64,
}

impl ErrLimiter {
    /// Whether to emit this rejection, and how many earlier ones the previous second dropped.
    fn admit(&mut self, now: Instant) -> (bool, Option<u64>) {
        let mut summary = None;
        if now.duration_since(self.window) >= Duration::from_secs(1) {
            if self.dropped > 0 {
                summary = Some(self.dropped);
            }
            *self = ErrLimiter {
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
            Err(e) => return Err(setup_err(1, format!("can't listen on {addr}: {e}"))),
        }
    }
    Ok((listeners, notes))
}

pub fn run(cfg: Config) -> Result<Server, SetupError> {
    let (listeners, notes) = bind_all(&cfg)?;
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
    let endpoint = match first.ip() {
        IpAddr::V4(ip) => format!("http://{ip}:{port}"),
        IpAddr::V6(ip) => format!("http://[{ip}]:{port}"),
    };
    let mut listen: Vec<String> = addrs.iter().map(SocketAddr::to_string).collect();
    listen.extend(notes);
    let hello = Hello {
        generator: cfg.generator.clone(),
        listen,
        endpoint,
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
        setup: setup::setup(port),
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

    let shared = Arc::new(Shared {
        ctx: Ctx {
            matcher: cfg.matcher,
            show_values: cfg.show_values,
        },
        jobs: Semaphore::new(cfg.tunables.max_jobs),
        t: cfg.tunables,
        queue: Arc::clone(&queue),
        limiter: Mutex::new(ErrLimiter {
            window: Instant::now(),
            count: 0,
            dropped: 0,
        }),
        hosts,
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
        stop,
        queue,
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
        let _ = stream.set_nonblocking(false);
        if sh.active.fetch_add(1, Ordering::SeqCst) >= sh.t.max_connections {
            sh.active.fetch_sub(1, Ordering::SeqCst);
            busy(stream);
            continue;
        }
        let slot = Slot(Arc::clone(&sh.active));
        let shared = Arc::clone(&sh);
        let spawned = thread::Builder::new().name("conn".into()).spawn(move || {
            let _slot = slot;
            serve(stream, &shared);
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

/// The socket plus the clocks: a deadline checked before every read, a read timeout clipped to
/// what's left of it, and the per-request wire budget.
struct Guarded {
    stream: TcpStream,
    deadline: Cell<Instant>,
    read_timeout: Duration,
    wire_left: Cell<usize>,
}

impl Read for Guarded {
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

fn serve(stream: TcpStream, sh: &Shared) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_write_timeout(Some(sh.t.write_timeout));
    let Ok(writer) = stream.try_clone() else {
        return;
    };
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
        match request(&mut reader, &writer, sh) {
            Next::KeepAlive => {}
            Next::Close { linger } => break linger,
        }
    };
    let stream = &reader.get_ref().stream;
    let _ = stream.shutdown(Shutdown::Write);
    if linger {
        // Read what the client is still sending, briefly, so closing doesn't turn into a reset
        // that destroys the response it hasn't read yet.
        let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
        let end = Instant::now() + Duration::from_millis(250);
        let mut sink = [0u8; 4096];
        let mut total = 0usize;
        let mut s = stream;
        while Instant::now() < end && total < (1 << 20) {
            match s.read(&mut sink) {
                Ok(0) | Err(_) => break,
                Ok(n) => total += n,
            }
        }
    }
}

impl Shared {
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
        let bytes = ev.reserved_bytes(self.t.queue_bytes);
        if let Some(p) = self
            .queue
            .reserve(bytes, Instant::now() + Duration::from_millis(100))
        {
            p.send(ev);
        }
    }
}

fn write_response(w: &TcpStream, r: &Response) -> bool {
    (&*w).write_all(&r.to_bytes()).is_ok()
}

/// Answers a rejection and reports it.
fn reject(
    sh: &Shared,
    w: &TcpStream,
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

fn request(reader: &mut BufReader<Guarded>, w: &TcpStream, sh: &Shared) -> Next {
    let head = match http::read_head(reader, &sh.t.limits) {
        Ok(h) => h,
        Err(HttpError::Bad { status, message }) => {
            return reject(
                sh,
                w,
                Response::error(status, &message),
                None,
                None,
                &message,
            );
        }
        Err(HttpError::Io(e)) => return io_close(sh, w, &e),
        Err(HttpError::Eof) => return Next::Close { linger: false },
    };
    let method = Some(head.method.as_str());
    let path = otlp::known_path(head.path());
    let deadline = reader.get_ref().deadline.get();
    let deny = |status: u16, message: &str| {
        reject(
            sh,
            w,
            Response::error(status, message),
            method,
            path,
            message,
        )
    };

    // DNS rebinding and browsers (design §14.4): before any body is read or 100 sent.
    let hosts: Vec<&str> = head
        .headers
        .iter()
        .filter(|(k, _)| k == "host")
        .map(|(_, v)| v.as_str())
        .collect();
    match hosts.as_slice() {
        [h] if sh.hosts.iter().any(|a| a.eq_ignore_ascii_case(h)) => {}
        [_] => return deny(421, "unexpected Host"),
        _ => return deny(400, "exactly one Host header is required"),
    }
    if head
        .headers
        .iter()
        .any(|(k, _)| k == "origin" || k.starts_with("sec-fetch-"))
    {
        return deny(403, "browser requests are refused");
    }

    let signal = match otlp::route(&head.method, head.path()) {
        Route::Signal(s) => s,
        Route::NotFound => return deny(404, "not found"),
        Route::NotAllowed => {
            let r = Response::error(405, "method not allowed").with_header("Allow", "POST");
            return reject(sh, w, r, method, path, "method not allowed");
        }
    };
    if let Err(rej) = otlp::check_content(&head) {
        return deny(rej.status, rej.message);
    }
    let framing = match http::framing(&head, &sh.t.limits) {
        Ok(f) => f,
        Err(HttpError::Bad { status, message }) => return deny(status, &message),
        Err(_) => return Next::Close { linger: false },
    };

    // The job permit comes before the body is allocated.
    let Some(permit) = sh.jobs.acquire(deadline) else {
        return deny(503, "busy");
    };
    if head.expects_continue() && (&*w).write_all(http::CONTINUE).is_err() {
        return Next::Close { linger: false };
    }
    let body = match http::read_body(reader, framing, &sh.t.limits) {
        Ok(b) => b,
        Err(HttpError::Bad { status, message }) => return deny(status, &message),
        Err(HttpError::Io(e)) => return io_close(sh, w, &e),
        Err(HttpError::Eof) => return Next::Close { linger: false },
    };
    let _ = Framing::None;
    let doc = match otlp::parse(&body) {
        Ok(d) => d,
        Err(m) => return deny(400, &m),
    };
    let bytes = body.len();
    let prepared = match otlp::process(signal, bytes, &doc, &sh.ctx) {
        Ok(p) => p,
        Err(f) => return deny(f.status(), &f.message()),
    };
    drop(doc);
    drop(body);
    drop(permit);

    // Room in the output queue is reserved before the 200 is written, so an accepted batch is
    // never lost to a full queue, and `--once` can't cut the response.
    let batch = Event::Batch(prepared.batch);
    let extra: Vec<Event> = prepared.extra.into_iter().map(Event::Error).collect();
    let cap = sh.t.queue_bytes;
    let mut permits = Vec::new();
    for ev in std::iter::once(&batch).chain(extra.iter()) {
        match sh.queue.reserve(ev.reserved_bytes(cap), deadline) {
            Some(p) => permits.push(p),
            None => return deny(503, "busy"),
        }
    }
    let keep = head.keep_alive();
    let resp = Response::json(200, "{}".to_string(), keep);
    if !write_response(w, &resp) {
        return Next::Close { linger: false };
    }
    let mut permits = permits.into_iter();
    permits.next().expect("batch permit").send(batch);
    for (p, ev) in permits.zip(extra) {
        p.send(ev);
    }
    if keep {
        Next::KeepAlive
    } else {
        Next::Close { linger: false }
    }
}

/// A read failed: the wire budget is answered with 413, timeouts and resets just close.
fn io_close(sh: &Shared, w: &TcpStream, e: &io::Error) -> Next {
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
}
