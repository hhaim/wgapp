import Foundation
import CryptoKit

struct CommandFailure: LocalizedError {
    let output: String
    let status: Int32

    var errorDescription: String? {
        if output.localizedCaseInsensitiveContains("a password is required") ||
            output.localizedCaseInsensitiveContains("not allowed to execute") {
            return "Run ./b install_sudo once to install the root launcher and its narrow sudoers rule.\n\n" + output
        }
        return output.isEmpty ? "Command failed (exit \(status))." : output
    }
}

enum ProcessRunner {
    static func run(executable: String, arguments: [String], input: Data? = nil) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = arguments
            let output = Pipe()
            process.standardOutput = output
            process.standardError = output
            var inputPipe: Pipe?
            if input != nil {
                let pipe = Pipe()
                inputPipe = pipe
                process.standardInput = pipe
            } else {
                process.standardInput = FileHandle.nullDevice
            }
            process.terminationHandler = { finished in
                let data = output.fileHandleForReading.readDataToEndOfFile()
                if finished.terminationStatus == 0 {
                    continuation.resume(returning: data)
                } else {
                    let text = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                    continuation.resume(throwing: CommandFailure(output: text, status: finished.terminationStatus))
                }
            }
            do {
                if let input, let inputPipe {
                    try inputPipe.fileHandleForWriting.write(contentsOf: input)
                    try inputPipe.fileHandleForWriting.close()
                }
                try process.run()
            } catch {
                try? inputPipe?.fileHandleForWriting.close()
                continuation.resume(throwing: error)
            }
        }
    }
}

enum ProfileHelperClient {
    static var executable: String {
        Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/WGProfileHelper").path
    }

    static func requireInstalled() throws {
        guard FileManager.default.isExecutableFile(atPath: executable) else {
            throw AppError.message("The signed Keychain helper is missing from WGApp.app.")
        }
    }

    static func list() async throws -> [String] {
        try requireInstalled()
        let data = try await ProcessRunner.run(executable: executable, arguments: ["list"])
        return try JSONDecoder().decode([String].self, from: data)
    }

    static func get(_ name: String) async throws -> WGProfile {
        try requireInstalled()
        let data = try await ProcessRunner.run(executable: executable, arguments: ["get", name])
        return try JSONDecoder().decode(WGProfile.self, from: data)
    }

    static func add(_ profile: WGProfile) async throws {
        try requireInstalled()
        let normalized = try ProfileValidator.normalized(profile)
        _ = try await ProcessRunner.run(executable: executable, arguments: ["add", normalized.name],
                                        input: try JSONEncoder().encode(normalized))
    }

    static func edit(_ profile: WGProfile) async throws {
        try requireInstalled()
        let normalized = try ProfileValidator.normalized(profile)
        _ = try await ProcessRunner.run(executable: executable, arguments: ["edit", normalized.name],
                                        input: try JSONEncoder().encode(normalized))
    }

    static func delete(_ name: String) async throws {
        try requireInstalled()
        _ = try await ProcessRunner.run(executable: executable, arguments: ["delete", name])
    }
}

enum RootLauncherClient {
    static func requireInstalled() throws {
        guard FileManager.default.isExecutableFile(atPath: wgAppRootHelperPath) else {
            throw AppError.message("The root launcher is not installed. Run ./b install_sudo.")
        }
    }

    static func up(_ request: RootUpRequest) async throws -> RootUpResult {
        try requireInstalled()
        let capabilities = try await status(logicalName: request.logicalName)
        guard capabilities.routeCleanupVersion == 1 else {
            throw AppError.message("The installed root helper needs the route cleanup fix. Disconnect, then run ./b install to update it.")
        }
        if request.proxy != nil {
            guard capabilities.launcherVersion == 3 else {
                throw AppError.message("The installed root helper does not support GOST proxy mode. Run ./b install to update it.")
            }
        }
        let data = try await invoke("up", input: try JSONEncoder().encode(request))
        return try JSONDecoder().decode(RootUpResult.self, from: data)
    }

    static func down(logicalName: String) async throws {
        try requireInstalled()
        _ = try await invoke("down", input: try JSONEncoder().encode(RootNameRequest(logicalName: logicalName)))
    }

    static func status(logicalName: String) async throws -> RootStatusResult {
        try requireInstalled()
        let data = try await invoke("status", input: try JSONEncoder().encode(RootNameRequest(logicalName: logicalName)))
        return try JSONDecoder().decode(RootStatusResult.self, from: data)
    }

    private static func invoke(_ command: String, input: Data) async throws -> Data {
        try await ProcessRunner.run(executable: "/usr/bin/sudo", arguments: ["-n", wgAppRootHelperPath, command], input: input)
    }
}

enum ManagedInterfaceName {
    static func forProfile(_ name: String) -> String {
        let digest = SHA256.hash(data: Data(name.lowercased().utf8))
        return "wga-" + digest.prefix(5).map { String(format: "%02x", $0) }.joined()
    }
}
