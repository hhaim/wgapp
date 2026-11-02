#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -eq 0 ]]; then
  echo "Run this script as your normal user; it uses sudo only for installed root-owned files." >&2
  exit 1
fi

if [[ -d /var/run/wgapp ]] && sudo /usr/bin/find /var/run/wgapp -maxdepth 1 -type f -name '*.pid' -size +0c | /usr/bin/grep -q .; then
  echo "Disconnect the active WGApp tunnel before uninstalling." >&2
  exit 1
fi

cat <<'MSG'
Before the app is removed, turn off “Launch at Login” in its settings menu.
Press Return after doing so, or Ctrl-C to cancel.
Keychain profiles are preserved; delete them in WGApp first if you do not want to keep them.
MSG
read -r _

if [[ -e /etc/sudoers.d/wgapp ]]; then sudo /bin/rm -f /etc/sudoers.d/wgapp; fi
if [[ -e /usr/local/libexec/wgapp-root ]]; then sudo /bin/rm -f /usr/local/libexec/wgapp-root; fi
if [[ -e /usr/local/libexec/wgapp-wstunnel ]]; then sudo /bin/rm -f /usr/local/libexec/wgapp-wstunnel; fi
if [[ -e /usr/local/libexec/wgapp-gost ]]; then sudo /bin/rm -f /usr/local/libexec/wgapp-gost; fi

# Remove metadata from the previous file-based implementation. These files never
# contained the WireGuard configuration itself.
LEGACY_DATA="$(dscl . -read "/Users/$(id -un)" NFSHomeDirectory | awk '{print $2}')/.wgapp"
if [[ -d "$LEGACY_DATA/links" ]]; then
  find "$LEGACY_DATA/links" -maxdepth 1 -type l -name '*.conf' -delete
  rmdir "$LEGACY_DATA/links" 2>/dev/null || true
fi
rm -f "$LEGACY_DATA/profiles.json" "$LEGACY_DATA/state.json" "$LEGACY_DATA/dns-snapshot.json"
rmdir "$LEGACY_DATA" 2>/dev/null || true

echo "Removed the WGApp root launcher and sudoers entry. Keychain profiles were preserved."
