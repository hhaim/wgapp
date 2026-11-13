#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build/ModuleCache
xcrun swiftc -swift-version 5 -parse-as-library -module-cache-path build/ModuleCache \
  Sources/Shared/AppConstants.swift Sources/Shared/ProfileModels.swift \
  Sources/WGApp/Core.swift Sources/WGApp/SudoRunner.swift \
  scripts/verify-launcher-cleanup.swift -o build/verify-launcher-cleanup
build/verify-launcher-cleanup
