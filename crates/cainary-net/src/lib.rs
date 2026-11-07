//! cAInary's OTel debug collector: a loopback-only OTLP/JSON receiver (design §8, §14).
//!
//! Network access lives in `server` only, file writing in `logfile` only, and the process
//! environment in `main` only; `cainary-core/tests/guards.rs` keeps it that way.

pub mod args;
pub mod config;
pub mod decode;
pub mod host;
pub mod http;
pub mod jsonedit;
pub mod listenfd;
pub mod logfile;
pub mod otlp;
pub mod otlp_pb;
pub mod output;
pub mod peer;
#[cfg(target_os = "linux")]
pub mod peer_proc;
pub mod privdrop;
pub mod queue;
pub mod redflag;
pub mod server;
pub mod setup;
#[cfg(feature = "tls")]
pub mod tls;
#[cfg(feature = "tls")]
pub mod trust;
