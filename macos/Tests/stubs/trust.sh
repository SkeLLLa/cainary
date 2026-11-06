#!/bin/sh
# A stateful `cainary-otel-debug --trust …` stub. $CAINARY_STUB_DIR holds `args` (every call), the
# state files `claude` and `codex`, and `refuse` (when present, claude-code calls are refused).
dir=${CAINARY_STUB_DIR:?needs CAINARY_STUB_DIR}
echo "$*" >> "$dir/args"
ts=2026-01-01T12:00:00Z
settings=/home/u/.claude/settings.json
report() { # action message exit
  printf '{"v":1,"type":"trust","ts":"%s","target":"claude-code","action":"%s","message":"%s","settingsPath":"%s","backupPath":"%s.cainary-20260101T120000Z.bak","key":"NODE_EXTRA_CA_CERTS","from":null,"to":"/home/u/ca.pem","bundlePath":null,"command":null}\n' "$ts" "$1" "$2" "$settings" "$settings"
  exit "$3"
}
case "$*" in
"--trust claude-code"*)
  if [ -f "$dir/refuse" ]; then report refused "your organization's managed settings set NODE_EXTRA_CA_CERTS" 1; fi
  case "$*" in
  *--dry-run*) report preview "Would set env.NODE_EXTRA_CA_CERTS" 0 ;;
  *--undo*) echo absent > "$dir/claude"; report undone "Removed env.NODE_EXTRA_CA_CERTS" 0 ;;
  *) echo applied > "$dir/claude"; report applied "Set env.NODE_EXTRA_CA_CERTS" 0 ;;
  esac
  ;;
"--trust codex --undo --json")
  echo absent > "$dir/codex"
  printf '{"v":1,"type":"trust","ts":"%s","target":"codex","action":"undone","message":"Removed the bundle"}\n' "$ts"
  ;;
"--trust codex --json")
  if [ -f "$dir/codex-refuse" ]; then
    printf '{"v":1,"type":"trust","ts":"%s","target":"codex","action":"refused","message":"Start the takeover once (cainary-otel-debug --tls …) so the collector certificate exists, then try again.","settingsPath":null,"backupPath":null,"key":null,"from":null,"to":null,"bundlePath":null,"command":null}\n' "$ts"
    exit 1
  fi
  echo ready > "$dir/codex"
  printf '{"v":1,"type":"trust","ts":"%s","target":"codex","action":"applied","message":"Wrote the bundle","bundlePath":"/home/u/bundle.pem","command":"env CODEX_CA_CERTIFICATE=/home/u/bundle.pem codex"}\n' "$ts"
  ;;
"--trust-status --json")
  claude=$(cat "$dir/claude" 2>/dev/null || echo absent)
  codex=$(cat "$dir/codex" 2>/dev/null || echo absent)
  printf '{"v":1,"type":"trust-status","ts":"%s","claudeCode":{"state":"%s","settingsPath":"%s","value":null},"codex":{"state":"%s","bundlePath":null,"command":"env CODEX_CA_CERTIFICATE=/home/u/bundle.pem codex"},"caPath":"/home/u/Library/Application Support/cainary/otel-debug-ca.pem"}\n' "$ts" "$claude" "$settings" "$codex"
  ;;
*)
  echo "cainary-otel-debug: unexpected arguments: $*" >&2
  exit 2
  ;;
esac
