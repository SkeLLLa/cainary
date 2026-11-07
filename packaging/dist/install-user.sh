#!/bin/sh
# Install or remove the Linux tarball under the current user's home directory.
set -eu

usage() {
    echo "usage: $0 [--uninstall]" >&2
    exit 2
}

ACTION=install
case "$#" in
    0) ;;
    1)
        case "$1" in
            --uninstall) ACTION=uninstall ;;
            -h | --help) echo "usage: $0 [--uninstall]"; exit 0 ;;
            *) usage ;;
        esac
        ;;
    *) usage ;;
esac

HOME_DIR=${HOME:?HOME must be set}
case "${XDG_DATA_HOME:-}" in
    /*) DATA_HOME=$XDG_DATA_HOME ;;
    *) DATA_HOME=$HOME_DIR/.local/share ;;
esac
BIN_DIR=$HOME_DIR/.local/bin
APP_ID=ua.SkeLLLa.cAInary
ROOT_DIR=$(CDPATH='' cd "$(dirname "$0")" && pwd)
ICON_DIR=$DATA_HOME/icons/hicolor

# Desktop Entry Exec quoting of $1: always double-quoted, with ", `, $ and \ escaped and a
# literal % written %%. A literal backslash is four in the file: the Exec quoting rule wants
# two, and the general string escape rule (applied first) halves them.
quote_exec() {
    printf '"%s"' "$(printf '%s' "$1" | sed -e 's/\\/\\\\\\\\/g' -e 's/["`$]/\\&/g' -e 's/%/%%/g')"
}

# Copy the packaged desktop entry to $target with Exec= pointing at the installed binary, since
# ~/.local/bin is not always on the session PATH.
install_desktop_entry() {
    install -d "$(dirname "$target")"
    exec_line="Exec=$(quote_exec "$BIN_DIR/cainary-tray")"
    sed "s|^Exec=.*|$(printf '%s' "$exec_line" | sed -e 's/[\\&|]/\\&/g')|" \
        "$ROOT_DIR/share/applications/$APP_ID.desktop" >"$target.tmp"
    chmod 644 "$target.tmp"
    mv "$target.tmp" "$target"
}

# Root-owned system files (the root helpers and their polkit policies): a user install skips them.
system_file() {
    case "$1" in
        usr/libexec/* | usr/share/polkit-1/*) return 0 ;;
        *) return 1 ;;
    esac
}

# Where the list's destination `usr/bin/...` or `usr/share/...` goes for this user.
user_path() {
    case "$1" in
        usr/bin/*) printf '%s/%s' "$BIN_DIR" "${1#usr/bin/}" ;;
        usr/share/*) printf '%s/%s' "$DATA_HOME" "${1#usr/share/}" ;;
        *) echo "error: linux-assets.txt: unexpected destination '$1'" >&2; exit 1 ;;
    esac
}

refresh_caches() {
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache --force --ignore-theme-index "$ICON_DIR" ||
            echo "warning: could not refresh the hicolor icon cache" >&2
    fi
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database "$DATA_HOME/applications" ||
            echo "warning: could not refresh the desktop database" >&2
    fi
}

if [ "$ACTION" = uninstall ]; then
    while read -r mode path dest; do
        case "$mode" in "" | "#"*) continue ;; esac
        if system_file "$dest"; then continue; fi
        rm -f "$(user_path "$dest")"
    done < "$ROOT_DIR/linux-assets.txt"
    # Icons that earlier releases installed.
    for level in busy error info warn alert ok unknown plain dimmed opted-out low medium high; do
        rm -f "$ICON_DIR/scalable/status/$APP_ID-$level-symbolic.svg"
    done
    refresh_caches
    echo "Removed cAInary from $HOME_DIR/.local"
    exit 0
fi

while read -r mode path dest; do
    case "$mode" in "" | "#"*) continue ;; esac
    if system_file "$dest"; then continue; fi
    target="$(user_path "$dest")"
    case "$path" in
        "share/applications/$APP_ID.desktop") install_desktop_entry ;;
        *) install -D -m "$mode" "$ROOT_DIR/$path" "$target" ;;
    esac
done < "$ROOT_DIR/linux-assets.txt"
refresh_caches

cat <<EOF
Installed cAInary under $HOME_DIR/.local.

Add $BIN_DIR to PATH to use cainary, cainary-otel-debug and cainary-tray from a terminal.
The tray app can be configured to start at login from its Settings page.

Ports below 1024 (443 for HTTPS) need the root helper, which a user install cannot add. It runs
only through pkexec, on an explicit click in the tray. An administrator installs it from this
directory (these commands are only printed, not run; they work in sh and fish):
  sudo install -d -m 0755 -o root -g root /usr/libexec/cainary
  sudo install -m 0755 -o root -g root "$ROOT_DIR/libexec/cainary/cainary-bind-helper" /usr/libexec/cainary/cainary-bind-helper
  sudo install -m 0644 -o root -g root "$ROOT_DIR/share/polkit-1/actions/ua.SkeLLLa.cAInary.policy" /usr/share/polkit-1/actions/ua.SkeLLLa.cAInary.policy
Remove:
  sudo rm /usr/libexec/cainary/cainary-bind-helper /usr/share/polkit-1/actions/ua.SkeLLLa.cAInary.policy
Adding host names to /etc/hosts from the tray ("Add to /etc/hosts...") needs a second root helper,
installed the same way; it too asks for the admin password every time:
  sudo install -m 0755 -o root -g root "$ROOT_DIR/libexec/cainary/cainary-hosts-helper" /usr/libexec/cainary/cainary-hosts-helper
  sudo install -m 0644 -o root -g root "$ROOT_DIR/share/polkit-1/actions/ua.SkeLLLa.cAInary.hosts.policy" /usr/share/polkit-1/actions/ua.SkeLLLa.cAInary.hosts.policy
Remove:
  sudo rm /usr/libexec/cainary/cainary-hosts-helper /usr/share/polkit-1/actions/ua.SkeLLLa.cAInary.hosts.policy
  sudo rmdir /usr/libexec/cainary
EOF
