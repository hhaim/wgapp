#!/usr/bin/env bash
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_ROOT"
SWIFT_COMPILER="$(xcrun --find swiftc)"
MACOS_SDK="$(xcrun --sdk macosx --show-sdk-path)"
BUILD_ARCH="$(uname -m)"
BUILD_PRODUCTS="$PROJECT_ROOT/build/Build/Products/Debug"
mkdir -p "$BUILD_PRODUCTS" "$PROJECT_ROOT/build/ModuleCache"
BUILD_STAGE="$(mktemp -d "$BUILD_PRODUCTS/.wgapp-build.XXXXXX")"
trap 'rm -rf "$BUILD_STAGE"' EXIT
APP_STAGE="$BUILD_STAGE/WGApp.app"
mkdir -p "$APP_STAGE/Contents/MacOS" "$APP_STAGE/Contents/Helpers" "$APP_STAGE/Contents/Resources"
COMMON_ARGS=(
  -swift-version 5 -parse-as-library
  -target "$BUILD_ARCH-apple-macosx14.0" -sdk "$MACOS_SDK"
  -module-cache-path "$PROJECT_ROOT/build/ModuleCache"
)
HELPER_CACHE="$PROJECT_ROOT/build/KeychainHelper"
mkdir -p "$HELPER_CACHE"
HELPER_FINGERPRINT="$(
  { printf '%s\n' 'keychain-helper-build-v2' "$SWIFT_COMPILER" "$MACOS_SDK" "$BUILD_ARCH";
    "$SWIFT_COMPILER" --version;
    shasum -a 256 Sources/Shared/AppConstants.swift Sources/WGProfileHelper/main.swift;
  } | shasum -a 256 | awk '{print $1}'
)"
if [[ ! -x "$HELPER_CACHE/WGProfileHelper" || ! -f "$HELPER_CACHE/inputs.sha256" ||
      "$(cat "$HELPER_CACHE/inputs.sha256")" != "$HELPER_FINGERPRINT" ]]; then
  "$SWIFT_COMPILER" "${COMMON_ARGS[@]}" -module-name WGProfileHelper \
    Sources/Shared/AppConstants.swift Sources/WGProfileHelper/main.swift \
    -o "$HELPER_CACHE/WGProfileHelper"
  /usr/bin/codesign --force --sign - --identifier com.example.wgapp.profile-helper "$HELPER_CACHE/WGProfileHelper"
  printf '%s\n' "$HELPER_FINGERPRINT" > "$HELPER_CACHE/inputs.sha256"
fi
/usr/bin/codesign --verify --strict "$HELPER_CACHE/WGProfileHelper"
cp "$HELPER_CACHE/WGProfileHelper" "$APP_STAGE/Contents/Helpers/WGProfileHelper"
"$SWIFT_COMPILER" "${COMMON_ARGS[@]}" -module-name WGRootHelper \
  Sources/Shared/AppConstants.swift Sources/Shared/ProfileModels.swift Sources/Shared/GOSTConfiguration.swift Sources/WGRootHelper/*.swift \
  -o "$APP_STAGE/Contents/Helpers/WGRootHelper"
"$SWIFT_COMPILER" -swift-version 5 -parse-as-library -module-name WGApp \
  -target "$BUILD_ARCH-apple-macosx14.0" -sdk "$MACOS_SDK" \
  -module-cache-path "$PROJECT_ROOT/build/ModuleCache" Sources/Shared/AppConstants.swift Sources/Shared/ProfileModels.swift Sources/WGApp/*.swift \
  -o "$APP_STAGE/Contents/MacOS/WGApp"
cp Sources/WGApp/Info.plist "$APP_STAGE/Contents/Info.plist"
python3 scripts/build-app-icon.py Sources/WGApp/Assets.xcassets/AppIcon.appiconset \
  "$APP_STAGE/Contents/Resources/AppIcon.icns"
/usr/bin/codesign --force --sign - --identifier com.example.wgapp.root-helper "$APP_STAGE/Contents/Helpers/WGRootHelper"
/usr/bin/codesign --force --sign - "$APP_STAGE"
/usr/bin/codesign --verify --deep --strict "$APP_STAGE"
rm -rf "$BUILD_PRODUCTS/WGApp.app"
mv "$APP_STAGE" "$BUILD_PRODUCTS/WGApp.app"
printf 'Built WGApp and signed Keychain/root helpers: %s\n' "$BUILD_PRODUCTS/WGApp.app"
