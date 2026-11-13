import Foundation

@main
struct VerifyLauncherCleanup {
    @MainActor
    static func main() async throws {
        let key = Data(repeating: 0, count: 32).base64EncodedString()
        let profile = WGProfile(name: "launcher-regression", privateKey: key, peerPublicKey: key,
                                address: "198.18.43.1", allowedIPs: ["198.18.42.0/24"], dns: "198.18.43.53",
                                endpointIPv4: "192.0.2.200", endpointIPv6: "2001:db8::200")
        let request = RootUpRequest(logicalName: "wga-0000000000", privateKey: key, peerPublicKey: key,
                                   address: profile.address, allowedIPs: profile.allowedIPs,
                                   endpointHost: profile.endpointIPv4, endpointPort: 51820,
                                   endpointFamily: .ipv4, persistentKeepalive: 25)
        let legacy = Data(#"{"active":true,"interfaceName":"utun42","latestHandshake":0,"receivedBytes":0,"sentBytes":0,"launcherVersion":3}"#.utf8)
        let current = try JSONEncoder().encode(RootStatusResult(active: false, latestHandshake: 0,
                                                               receivedBytes: 0, sentBytes: 0))

        // Test the actual ProfileStore error handler, not only the launcher preflight.
        for failure in ["legacy", "status-error", "up-error", "invalid-profile"] {
            let store = ProfileStore(recoverProfiles: false)
            var commands: [String] = []
            var downs: [String] = []
            var candidate = profile
            if failure == "invalid-profile" { candidate.privateKey = "invalid" }
            store.connect(candidate, options: ConnectionOptions(), launch: { request in
                try await RootLauncherClient.up(request, execute: { action, _ in
                    commands.append(action)
                    if failure == "status-error" { throw AppError.message("status failed") }
                    if action == "up" { throw AppError.message("up failed and rolled back") }
                    return failure == "legacy" ? legacy : current
                })
            }, cleanup: { downs.append($0) })
            for _ in 0..<200 where store.networkBusy { try await Task.sleep(for: .milliseconds(5)) }
            precondition(!store.networkBusy && store.activeTunnel == nil && store.lastError != nil)
            precondition(downs.isEmpty, "Connect failure called down before owning a session")
            switch failure {
            case "invalid-profile": precondition(commands.isEmpty)
            case "up-error": precondition(commands == ["status", "up"])
            default: precondition(commands == ["status"])
            }
        }
        print("PASS rejected/failed Connect never calls down on a pre-existing session")

        do {
            var commands: [String] = []
            do {
                try await RootLauncherClient.down(logicalName: request.logicalName, execute: { action, _ in
                    commands.append(action)
                    return legacy
                })
                fatalError("Legacy disconnect was allowed")
            } catch is AppError { }
            precondition(commands == ["status"])
        }
        print("PASS Disconnect refuses a stale helper, including a recovered active tunnel")

        do {
            var commands: [String] = []
            try await RootLauncherClient.down(logicalName: request.logicalName, execute: { action, _ in
                commands.append(action)
                return action == "status" ? current : Data()
            })
            precondition(commands == ["status", "down"])
        }
        print("PASS Disconnect reaches down only after safe-helper verification")

        do {
            var commands: [String] = []
            do {
                _ = try await RootLauncherClient.up(request, execute: { action, _ in
                    commands.append(action)
                    return action == "status" ? current : Data("unreadable response".utf8)
                })
                fatalError("Unreadable up response was accepted")
            } catch is DecodingError { }
            precondition(commands == ["status", "up", "down"])
        }
        print("PASS successful up with unreadable response still cleans up its own session")
        print("All launcher cleanup regressions passed; no helper processes or real routes were changed.")
    }
}
