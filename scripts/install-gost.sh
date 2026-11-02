#!/usr/bin/env bash
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION=3.3.2
TOOLS_DIR="$PROJECT_ROOT/build/tools"
case "$(uname -m)" in
  arm64) RELEASE_ARCH=arm64; EXPECTED=7f60400399240d717d5efe0e0e968dd2b6fe33862c4ea9a1b073c18a0a3961f4;;
  x86_64) RELEASE_ARCH=amd64; EXPECTED=b1267243d6118213ac6a88151b06c885ba0d067abd0a814b50622be5e5a88939;;
  *) echo 'Unsupported Mac architecture' >&2; exit 1;;
esac
mkdir -p "$TOOLS_DIR"
STAGE="$(mktemp -d "$TOOLS_DIR/.gost-download.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
ARCHIVE="gost_${VERSION}_darwin_${RELEASE_ARCH}.tar.gz"
# Reuse the verified project-local download from the GOST evaluation if present.
CACHED="$PROJECT_ROOT/build/gost-check/$ARCHIVE"
if [[ -f "$CACHED" ]]; then
  cp "$CACHED" "$STAGE/$ARCHIVE"
else
  curl -fLsS --retry 3 "https://github.com/go-gost/gost/releases/download/v${VERSION}/$ARCHIVE" -o "$STAGE/$ARCHIVE"
fi
ACTUAL="$(shasum -a 256 "$STAGE/$ARCHIVE" | awk '{print $1}')"
[[ "$EXPECTED" == "$ACTUAL" ]] || { echo 'GOST checksum verification failed' >&2; exit 1; }
tar -xzf "$STAGE/$ARCHIVE" -C "$STAGE" gost
chmod 755 "$STAGE/gost"
[[ "$("$STAGE/gost" -V)" == "gost $VERSION ("* ]] || { echo 'The official GOST client could not run on this Mac.' >&2; exit 1; }
mv "$STAGE/gost" "$TOOLS_DIR/gost"
echo "Verified official GOST $VERSION at $TOOLS_DIR/gost"
