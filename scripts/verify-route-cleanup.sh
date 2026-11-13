#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build/ModuleCache
xcrun swiftc -swift-version 5 -parse-as-library -D ROUTE_TESTS \
  -module-cache-path build/ModuleCache \
  Sources/Shared/AppConstants.swift Sources/Shared/ProfileModels.swift \
  Sources/Shared/GOSTConfiguration.swift Sources/WGRootHelper/*.swift \
  scripts/verify-route-cleanup.swift -o build/verify-route-cleanup
build/verify-route-cleanup
