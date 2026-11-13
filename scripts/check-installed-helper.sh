#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
installed=/usr/local/libexec/wgapp-root
bundled="${1:-build/Build/Products/Debug/WGApp.app/Contents/Helpers/WGRootHelper}"
for helper in "$installed" "$bundled"; do
  if [[ ! -x "$helper" ]]; then printf 'Missing helper: %s\n' "$helper" >&2; exit 1; fi
  /usr/bin/stat -f 'Helper: %N; owner=%Su:%Sg; mode=%Sp; modified=%Sm' "$helper"
  /usr/bin/shasum -a 256 "$helper"
done
if ! /usr/bin/cmp -s "$installed" "$bundled"; then
  echo 'MISMATCH: the installed helper is not the bundled build. Disconnect and run ./b install before live testing.' >&2
  exit 1
fi
echo 'MATCH: installed and bundled helper bytes are identical.'
