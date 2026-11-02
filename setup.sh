#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -eq 0 ]]; then
  echo "Run setup as your normal GUI user; sudo is used only for the root launcher and sudoers file." >&2
  exit 1
fi
if [[ "$(uname -s)" != Darwin ]]; then
  echo "This setup requires macOS." >&2
  exit 1
fi
if [[ $# -gt 1 || ( $# -eq 1 && "$1" != --print-sudoers ) ]]; then
  echo "Usage: ./setup.sh [--print-sudoers]" >&2
  exit 2
fi

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
USER_NAME="$(id -un)"
ROOT_HELPER="/usr/local/libexec/wgapp-root"

if command -v brew >/dev/null 2>&1; then BREW="$(command -v brew)"
elif [[ -x /opt/homebrew/bin/brew ]]; then BREW=/opt/homebrew/bin/brew
elif [[ -x /usr/local/bin/brew ]]; then BREW=/usr/local/bin/brew
else
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  if [[ -x /opt/homebrew/bin/brew ]]; then BREW=/opt/homebrew/bin/brew; else BREW=/usr/local/bin/brew; fi
fi
BREW_PREFIX="$("$BREW" --prefix)"
export PATH="$BREW_PREFIX/bin:$BREW_PREFIX/sbin:/usr/bin:/bin:/usr/sbin:/sbin"

print_sudoers() {
  cat <<SUDOERS
Defaults:${USER_NAME} secure_path="${BREW_PREFIX}/bin:/usr/bin:/bin:/usr/sbin:/sbin"
${USER_NAME} ALL=(root) NOPASSWD: ${ROOT_HELPER} up, ${ROOT_HELPER} down, ${ROOT_HELPER} status
SUDOERS
}

if [[ "${1:-}" == --print-sudoers ]]; then print_sudoers; exit 0; fi

if ! xcrun --find swiftc >/dev/null 2>&1 || ! xcrun --sdk macosx --show-sdk-path >/dev/null 2>&1; then
  echo "Install Apple Command Line Tools with xcode-select --install, then rerun setup." >&2
  exit 1
fi

SUMMARY=()
MISSING_FORMULAE=()
for formula in wireguard-tools wireguard-go; do
  if "$BREW" list --versions "$formula" >/dev/null 2>&1; then SUMMARY+=("Skipped $formula: already installed")
  else MISSING_FORMULAE+=("$formula")
  fi
done
if [[ ${#MISSING_FORMULAE[@]} -gt 0 ]]; then
  "$BREW" install "${MISSING_FORMULAE[@]}"
  for formula in "${MISSING_FORMULAE[@]}"; do SUMMARY+=("Installed $formula"); done
fi
for tool in wg wireguard-go; do
  [[ -x "$BREW_PREFIX/bin/$tool" ]] || { echo "Missing executable: $BREW_PREFIX/bin/$tool" >&2; exit 1; }
done

PROXY_CLIENT_READY=false
if bash "$PROJECT_ROOT/scripts/install-gost.sh"; then
  PROXY_CLIENT_READY=true
else
  SUMMARY+=("GOST proxy client unavailable: direct mode remains usable; resolve the reported installation error, then rerun ./b install")
fi

"$PROJECT_ROOT/build.sh"
BUILT_HELPER="$PROJECT_ROOT/build/Build/Products/Debug/WGApp.app/Contents/Helpers/WGRootHelper"
[[ -x "$BUILT_HELPER" ]] || { echo "The build did not produce WGRootHelper." >&2; exit 1; }
/usr/bin/codesign --verify --strict "$BUILT_HELPER"

SUDOERS_TMP="$(mktemp)"
trap 'rm -f "$SUDOERS_TMP"' EXIT
print_sudoers > "$SUDOERS_TMP"
sudo /usr/sbin/visudo -cf "$SUDOERS_TMP"
sudo /usr/bin/install -d -o root -g wheel -m 755 /usr/local/libexec /etc/sudoers.d
sudo /usr/bin/install -o root -g wheel -m 755 "$BUILT_HELPER" "$ROOT_HELPER"
if [[ "$PROXY_CLIENT_READY" == true ]]; then
  sudo /usr/bin/install -o root -g wheel -m 755 "$PROJECT_ROOT/build/tools/gost" /usr/local/libexec/wgapp-gost
  SUMMARY+=("Installed pinned GOST 3.3.2 proxy client at /usr/local/libexec/wgapp-gost")
fi
sudo /usr/bin/install -o root -g wheel -m 440 "$SUDOERS_TMP" /etc/sudoers.d/wgapp
sudo -n -l "$ROOT_HELPER" status >/dev/null

SUMMARY+=("Installed signed root launcher at $ROOT_HELPER (root:wheel, 755)")
SUMMARY+=("Installed exact up/down/status sudo authorization at /etc/sudoers.d/wgapp")
SUMMARY+=("No WireGuard profile or key was written during setup")
printf '\nSetup summary:\n'
for item in "${SUMMARY[@]}"; do printf -- '- %s\n' "$item"; done
printf 'Use ./b build and ./b run. No Apple Account or paid signing identity is required.\n'
