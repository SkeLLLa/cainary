# Prompt and status-bar integrations

`cainary status` prints one short line with the overall level, so it fits in a shell prompt or a
status bar. The forms and their meaning are in [architecture.md](architecture.md) §8.2:

| level | `cainary status` | `--format text` |
| --- | --- | --- |
| high | `🔴 HIGH (7)` | `ai:high:7` |
| medium | `🟠 MEDIUM` | `ai:medium` |
| low | `🟡 LOW` | `ai:low` |
| opted-out | `🔵 OPTED OUT` | `ai:opted-out` |
| ok | `🟢 OK` | `ai:ok` |
| not-installed | `⚪ NO AI APPS` | `ai:not-installed` |
| nothing sent, scan incomplete | `❔ INCOMPLETE` | `ai:incomplete` |

- The count is the number of entries at `low` or above, shown when there are two or more.
- An incomplete scan adds ` ⚠` to the emoji form (` !incomplete` to text).
- "NO AI APPS" means nothing was found at all.

There is no cache: each call runs a fresh scan, which takes about 20–25 ms (50–75 ms inside
starship). Narrow it with `--tool`: `--tool claude --tool openai --tool cursor --tool copilot` for
AI apps only, `--tool device` for other monitoring only. To hide the output at some levels, filter
it with `grep`; an empty output hides a starship module.

## Starship

These examples need `cainary` on `PATH`, for example
`ln -s /Applications/cAInary.app/Contents/Helpers/cainary ~/.local/bin/cainary`, or
`mise use -g packslip:github.com/SkeLLLa/cainary` (see [Distribution](distribution.md)). The Linux
packages install it as `/usr/bin/cainary`, and `install-user.sh` as `~/.local/bin/cainary`. The
output is the same on macOS and Linux, so one `starship.toml` works on both. `when = true` is
required, because a custom module is off by default. `shell = ["sh"]` keeps your fish or zsh
startup files out of every prompt and makes `|` work the same everywhere. With a custom top-level
`format`, add `${custom.cainary}` (or `$custom`) to it.

**Simple: one module, one scan.** The emoji carries the colour.

```toml
[custom.cainary]
command = "cainary status"
when = true
shell = ["sh"]
format = "[$output]($style) "
style = "bold"
```

**Hidden when OK.** The module shows only at `low` and above, or when the scan is incomplete.

```toml
[custom.cainary]
command = "cainary status | grep -v -e 🟢 -e 🔵 -e ⚪"
when = true
shell = ["sh"]
format = "[($output )]($style)"
style = "bold"
```

**Coloured text, per level.** Three modules, one scan each; starship runs them in parallel, so
the prompt takes no longer than with one. Hidden at `ok`, `opted-out` and `not-installed`; an
incomplete scan shows in yellow.

```toml
[custom.cainary_high]
command = "cainary status --format text | grep '^ai:high'"
when = true
shell = ["sh"]
format = "[($output )]($style)"
style = "bold red"

[custom.cainary_medium]
command = "cainary status --format text | grep '^ai:medium'"
when = true
shell = ["sh"]
format = "[($output )]($style)"
style = "bold 208"

[custom.cainary_low]
command = "cainary status --format text | grep -E '^ai:(low|incomplete)'"
when = true
shell = ["sh"]
format = "[($output )]($style)"
style = "bold yellow"
```

For Nerd Font glyphs, use `--format nerd` and grep for the glyph (see below).

### Nerd Font glyphs

`--format nerd` prints one Material Design glyph, then the count when two or more entries are at
`low` or above, then 󰀨 when the scan is incomplete.

| level | glyph | codepoint | name |
| --- | --- | --- | --- |
| high | 󰈈 | U+F0208 | `nf-md-eye` |
| medium | 󰆍 | U+F018D | `nf-md-console` |
| low | 󰄨 | U+F0128 | `nf-md-chart_bar` |
| opted-out, ok | 󰗠 | U+F05E0 | `nf-md-check_circle` |
| not-installed | 󰄰 | U+F0130 | `nf-md-checkbox_blank_circle_outline` |
| nothing sent, scan incomplete | 󰋗 | U+F02D7 | `nf-md-help_circle` |
| incomplete marker | 󰀨 | U+F0028 | `nf-md-alert_circle` |

**Timeouts:** a cold first scan (just after login or a new install) can take longer than
starship's 500 ms `command_timeout`, and starship then skips the module for that prompt. To avoid
this, set `command_timeout = 1000` at the top of `starship.toml`. Don't set `ignore_timeout`: the
prompt would wait for every scan.

## tmux

tmux runs `#()` in the background every `status-interval`, so the scan never delays typing.

```tmux
set -g status-right '#(cainary status) %H:%M'
```

Coloured text, with the colours applied by tmux's own `#[fg=…]` styles:

```tmux
set -g status-right '#(cainary status --format text | sed -e "s/^ai:high.*/#[fg=red]&#[default]/" -e "s/^ai:medium.*/#[fg=colour208]&#[default]/" -e "s/^ai:low.*/#[fg=yellow]&#[default]/")'
```

## Claude Code statusline

Claude Code shows the command's stdout and ignores its exit code. `cainary status` doesn't read
the JSON that Claude Code sends on stdin. In `~/.claude/settings.json`:

```json
{ "statusLine": { "type": "command", "command": "cainary status" } }
```

## Scripts

`cainary status --format json` prints one line, for example
`{"schema":3,"level":"high","label":"HIGH","badge":2,"complete":true,"entries":{"claude":{"level":"high","installed":true},…}}`.
To be notified about changes, keep the last `scan --json` and pass it to `--since`
(architecture.md §4).
