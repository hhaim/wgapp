import Foundation
import Darwin
import OSLog

// `route get` is a longest-prefix lookup, not proof that the requested route exists.
struct RouteNetwork: Equatable {
    let bytes: [UInt8]
    let prefix: Int
    let family: Int32

    init(_ value: String, mask: String? = nil, host: Bool = false) throws {
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard (1...2).contains(parts.count), !parts[0].isEmpty else {
            throw RootError.message("Invalid route address.")
        }
        let address = String(parts[0])
        let family = address.contains(":") ? AF_INET6 : AF_INET
        self.family = family
        let width = family == AF_INET ? 4 : 16
        var raw = [UInt8](repeating: 0, count: width)
        guard address.withCString({ inet_pton(family, $0, &raw) }) == 1 else {
            throw RootError.message("Could not parse a numeric route address.")
        }
        if let mask {
            var maskBytes = [UInt8](repeating: 0, count: width)
            guard mask.withCString({ inet_pton(family, $0, &maskBytes) }) == 1 else {
                throw RootError.message("Could not parse a route mask.")
            }
            let bits = maskBytes.flatMap { byte in (0..<8).reversed().map { (byte >> $0) & 1 } }
            let leading = bits.prefix(while: { $0 == 1 }).count
            guard bits.dropFirst(leading).allSatisfy({ $0 == 0 }) else {
                throw RootError.message("Non-contiguous route mask.")
            }
            prefix = leading
        } else if parts.count == 2, let length = Int(parts[1]), (0...width * 8).contains(length) {
            prefix = length
        } else if parts.count == 1, host {
            prefix = width * 8
        } else {
            throw RootError.message("Missing route prefix.")
        }
        let prefix = self.prefix
        bytes = raw.enumerated().map { index, byte in
            let bits = max(0, min(8, prefix - index * 8))
            return byte & (bits == 0 ? 0 : UInt8(truncatingIfNeeded: 0xff << (8 - bits)))
        }
    }

    var address: String {
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        bytes.withUnsafeBytes { _ = inet_ntop(family, $0.baseAddress, &buffer, socklen_t(buffer.count)) }
        return String(cString: buffer)
    }

    var cidr: String { "\(address)/\(prefix)" }
    var familyFlag: String { family == AF_INET ? "-inet" : "-inet6" }
    var routeArguments: [String] {
        prefix == bytes.count * 8 ? ["-host", address] : ["-net", cidr]
    }
}

struct RouteSnapshot {
    var network: RouteNetwork
    var interface: String
    var gateway: String?
    var flags: Set<String>

    init(output: String) throws {
        var fields: [String: String] = [:]
        for line in output.split(separator: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            if parts.count == 2 { fields[parts[0]] = parts[1] }
        }
        guard let destination = fields["destination"], let interface = fields["interface"],
              let flagText = fields["flags"] else {
            throw RootError.message("Incomplete route identity; refusing route changes.")
        }
        flags = Set(flagText.trimmingCharacters(in: CharacterSet(charactersIn: "<>"))
            .split(separator: ",").map(String.init))
        let mask = fields["mask"]
        if mask == "default" {
            let address = destination == "default" ? (fields["route to"]?.contains(":") == true ? "::" : "0.0.0.0") : destination
            network = try RouteNetwork("\(address)/0")
        } else {
            network = try RouteNetwork(destination, mask: mask, host: flags.contains("HOST"))
        }
        self.interface = interface
        gateway = fields["gateway"]
    }
}

final class RouteManager {
    typealias Execute = ([String]) throws -> CommandResult
    private let execute: Execute
    private let interfaceIndex: (String) -> UInt32
    private let log: (String) -> Void

    init(execute: @escaping Execute = { try run("/sbin/route", $0, requireSuccess: false) },
         interfaceIndex: @escaping (String) -> UInt32 = { if_nametoindex($0) },
         log: @escaping (String) -> Void = routeLog) {
        self.execute = execute
        self.interfaceIndex = interfaceIndex
        self.log = log
    }

    private func lookup(_ network: RouteNetwork) throws -> RouteSnapshot? {
        let result = try execute(["-n", "get", network.familyFlag] + network.routeArguments)
        guard result.status == 0 else {
            if result.output.localizedCaseInsensitiveContains("not in table") { return nil }
            throw RootError.message("Could not verify route ownership (status \(result.status)).")
        }
        let snapshot = try RouteSnapshot(output: result.output)
        return snapshot.network == network ? snapshot : nil
    }

    // Add-only: never change/delete an existing route to make room for a tunnel.
    // This also avoids replacing cloned host routes as a side effect of RTM_ADD.
    func add(_ destination: String, interface: String, gateway: String? = nil) throws -> ManagedRoute? {
        let network = try RouteNetwork(destination, host: !destination.contains("/"))
        let index = interfaceIndex(interface)
        guard index != 0 else { throw RootError.message("Route interface is no longer available.") }
        if let existing = try lookup(network) {
            if gateway == nil {
                log("skip-add destination=\(network.cidr) interface=\(existing.interface); existing route retained, tunnel continues")
                return nil
            }
            if gateway != nil, existing.interface == interface,
               !existing.flags.contains("REJECT"), !existing.flags.contains("BLACKHOLE") {
                log("reuse destination=\(network.cidr) interface=\(interface); existing route retained")
                return nil
            }
            log("conflict destination=\(network.cidr) interface=\(existing.interface); existing route retained")
            throw RootError.message("A route for \(network.cidr) already exists on \(existing.interface); it was left unchanged.")
        }
        let route = ManagedRoute(destination: network.cidr, interface: interface, interfaceIndex: index, gateway: gateway)
        let target = gateway.map { ["-gateway", $0, "-ifp", interface] } ?? ["-interface", interface]
        let result = try execute(["-q", "-n", "add", network.familyFlag] + network.routeArguments + target + ["-proto1", "-proto2"])
        log("add destination=\(network.cidr) interface=\(interface) index=\(index) gateway=\(gateway ?? "direct") status=\(result.status)")
        guard result.status == 0 else {
            if gateway == nil, let existing = try lookup(network) {
                log("skip-add destination=\(network.cidr) interface=\(existing.interface); route appeared during setup, tunnel continues")
                return nil
            }
            throw RootError.message("Could not add route for \(network.cidr); existing routes were left unchanged.")
        }
        return route
    }

    // Consumed records are removed even when DNS restoration later needs a retry.
    @discardableResult
    func cleanup(_ routes: inout [ManagedRoute]) -> Bool {
        routes = routes.filter { route in
            // Unlinking wireguard-go's socket tears down its utun. The kernel then
            // removes that interface's routes without targeting a replacement LAN
            // route. Darwin RTM_DELETE has no atomic gateway/ownership comparison.
            guard let gateway = route.gateway else {
                log("release destination=\(route.destination) interface=\(route.interface); owned by interface teardown")
                return false
            }
            guard interfaceIndex(route.interface) == route.interfaceIndex else {
                log("skip-delete destination=\(route.destination); interface changed or disappeared")
                return false
            }
            do {
                let network = try RouteNetwork(route.destination)
                guard let current = try lookup(network), current.interface == route.interface,
                      current.gateway == gateway,
                      current.flags.isSuperset(of: ["UP", "HOST", "GATEWAY", "STATIC", "PROTO1", "PROTO2"]),
                      current.flags.isDisjoint(with: ["IFSCOPE", "REJECT", "BLACKHOLE", "WASCLONED"]) else {
                    log("skip-delete destination=\(route.destination); route absent or ownership changed")
                    return false
                }
                // Only endpoint/relay host routes reach here. Include the recorded
                // gateway/interface, and never fall back to destination-only deletion.
                let result = try execute(["-q", "-n", "delete", network.familyFlag] + network.routeArguments
                    + ["-gateway", gateway, "-ifp", route.interface])
                log("delete destination=\(route.destination) interface=\(route.interface) index=\(route.interfaceIndex) gateway=\(gateway) status=\(result.status)")
                return result.status != 0
            } catch {
                log("defer-delete destination=\(route.destination); could not verify or remove route")
                return true
            }
        }
        return routes.isEmpty
    }
}

func routeLog(_ message: String) {
    // Never log request JSON, WireGuard configuration, command output, or proxy credentials.
    Logger(subsystem: "com.example.wgapp.root-helper", category: "routes").notice("\(message, privacy: .public)")
}
