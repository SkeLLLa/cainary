//! The scanner registry (architecture.md §7): a static array of `(Tool, fn)`.

pub mod chatgpt;
pub mod claude_code;
pub mod claude_code_hooks;
pub mod claude_code_policy;
pub mod claude_code_telemetry;
pub mod claude_desktop;
pub mod codex;
pub mod codex_telemetry;
pub mod copilot;
pub mod copilot_telemetry;
pub mod cursor;
pub mod device;

use crate::harness::ScanCtx;
use crate::model::Tool;

pub type ScanFn = fn(&mut ScanCtx);

/// Registry in `Tool` order.
pub const REGISTRY: [(Tool, ScanFn); 7] = [
    (Tool::ClaudeCode, claude_code::scan),
    (Tool::ClaudeDesktop, claude_desktop::scan),
    (Tool::Codex, codex::scan),
    (Tool::Cursor, cursor::scan),
    (Tool::Copilot, copilot::scan),
    (Tool::Chatgpt, chatgpt::scan),
    (Tool::Device, device::scan),
];
