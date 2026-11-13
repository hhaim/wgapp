import Foundation
import Darwin

// No root, Keychain, real network mutations, or profile material. The fake deliberately
// models Darwin's destination-only RTM_DELETE so a gateway argument cannot hide a bug.
final class FakeRoutes {
    struct Entry: Equatable {
        var destination: String
        var interface: String
        var gateway: String? = nil
        var flags: Set<String> = ["UP", "STATIC"]

        func output() throws -> String {
            let network = try RouteNetwork(destination)
            var maskBytes = network.bytes.indices.map { index -> UInt8 in
                let bits = max(0, min(8, network.prefix - index * 8))
                return bits == 0 ? 0 : UInt8(truncatingIfNeeded: 0xff << (8 - bits))
            }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            _ = inet_ntop(network.family, &maskBytes, &buffer, socklen_t(buffer.count))
            let mask = network.prefix == 0 ? "default" : String(cString: buffer)
            return """
            destination: \(network.prefix == 0 && network.family == AF_INET ? "default" : network.address)
            mask: \(mask)
            interface: \(interface)
            flags: <\(flags.sorted().joined(separator: ","))>
            \(gateway.map { "gateway: \($0)" } ?? "")
            """
        }
    }

    var entries: [String: Entry] = [:]
    var indexes: [String: UInt32] = ["en0": 4, "en1": 5, "utun42": 42]
    var commands: [[String]] = []
    var logs: [String] = []
    var failLookup = false
    var failDelete = false
    var mutations: [[String]] { commands.filter { $0.contains("add") || $0.contains("delete") } }

    func manager() -> RouteManager {
        RouteManager(execute: { try self.execute($0) }, interfaceIndex: { self.indexes[$0] ?? 0 }, log: { self.logs.append($0) })
    }

    func execute(_ arguments: [String]) throws -> CommandResult {
        commands.append(arguments)
        let host = arguments.contains("-host")
        let position = arguments.firstIndex(of: host ? "-host" : "-net")!
        let network = try RouteNetwork(arguments[position + 1], host: host)
        let destination = network.cidr
        func value(_ flag: String) -> String? { arguments.firstIndex(of: flag).map { arguments[$0 + 1] } }
        if arguments.contains("get") {
            if failLookup { return CommandResult(output: "route socket denied", status: 1) }
            if let entry = entries[destination] { return CommandResult(output: try entry.output(), status: 0) }
            // A default route is a lookup result, never the requested exact route.
            let fallback = Entry(destination: network.family == AF_INET ? "0.0.0.0/0" : "::/0", interface: "en0",
                                 gateway: network.family == AF_INET ? "10.0.0.138" : "fe80::1%en0", flags: ["UP", "GATEWAY"])
            return CommandResult(output: try fallback.output(), status: 0)
        }
        if arguments.contains("add") {
            if entries[destination] != nil { return CommandResult(output: "File exists", status: 1) }
            let gateway = value("-gateway")
            var flags: Set<String> = ["UP", "STATIC", "PROTO1", "PROTO2"]
            if host { flags.insert("HOST") }
            if gateway != nil { flags.insert("GATEWAY") }
            entries[destination] = Entry(destination: destination, interface: value("-interface") ?? value("-ifp")!, gateway: gateway, flags: flags)
            return CommandResult(output: "", status: 0)
        }
        precondition(arguments.contains("delete"))
        if failDelete { return CommandResult(output: "temporary error", status: 1) }
        // Deliberately ignore gateway/interface exactly as unscoped RTM_DELETE does.
        entries.removeValue(forKey: destination)
        return CommandResult(output: "", status: 0)
    }

    func teardown(_ name: String, _ interface: String, _ index: UInt32?) -> Bool {
        if indexes[interface] == index {
            entries = entries.filter { $0.value.interface != interface }
            indexes.removeValue(forKey: interface)
        }
        return true
    }
}

@main
struct VerifyRouteCleanup {
    static let lan = FakeRoutes.Entry(destination: "10.0.0.0/24", interface: "en0")
    static let endpoint = "198.51.100.20"

    static func state(_ routes: [ManagedRoute]) -> SupervisorState {
        SupervisorState(logicalName: "wga-0000000000", interfaceName: "utun42", endpointAddress: endpoint,
                        endpointRouteAdded: false, routes: [], dnsBaseline: [], managedRoutes: routes, interfaceIndex: 42)
    }

    static func main() throws {
        // The old implementation deletes the replacement LAN route; demonstrate the regression trigger.
        do {
            let fake = FakeRoutes()
            fake.entries[lan.destination] = lan
            _ = try fake.execute(["delete", "-inet", "-net", lan.destination])
            precondition(fake.entries[lan.destination] == nil)
            print("PASS reproduced old destination-only deletion of a replacement LAN route")
        }
        // Pre-tunnel routes remain byte-for-byte intact, including routes with our protocol flags.
        for flags: Set<String> in [["UP", "STATIC"], ["UP", "STATIC", "PROTO1", "PROTO2"]] {
            let fake = FakeRoutes()
            var existing = lan
            existing.flags = flags
            fake.entries[lan.destination] = existing
            let baseline = fake.entries
            do {
                _ = try fake.manager().add("10.0.0.24/24", interface: "utun42")
                fatalError("Overlapping LAN route was accepted")
            } catch is RootError { }
            precondition(fake.entries == baseline && fake.mutations.isEmpty)
        }
        print("PASS exact LAN/tunnel overlap and pre-existing tagged routes are preserved")
        // Broader and narrower tunnel prefixes coexist without changing the original LAN route.
        for subnet in ["10.0.0.0/8", "10.0.0.0/25"] {
            let fake = FakeRoutes()
            fake.entries[lan.destination] = lan
            let baseline = fake.entries
            let route = try fake.manager().add(subnet, interface: "utun42")!
            var session = state([route])
            precondition(cleanup(&session, routeManager: fake.manager(), teardown: fake.teardown, restoreDNSState: { _ in true }))
            precondition(fake.entries == baseline)
            precondition(!fake.commands.contains { $0.contains("delete") })
        }
        print("PASS broader/narrower LAN overlaps retain the pre-tunnel baseline on disconnect")
        // Startup failure after some routes were added follows the same teardown path.
        do {
            let fake = FakeRoutes()
            fake.entries[lan.destination] = lan
            let baseline = fake.entries
            let first = try fake.manager().add("192.0.2.0/24", interface: "utun42")!
            var pending = [first]
            do {
                _ = try fake.manager().add(lan.destination, interface: "utun42")
                fatalError("Collision was accepted")
            } catch is RootError { }
            precondition(fake.manager().cleanup(&pending))
            _ = fake.teardown("wga-0000000000", "utun42", 42)
            precondition(fake.entries == baseline)
        }
        print("PASS partial startup rollback preserves all baseline routes")
        // The reported race: tunnel vanished and Wi-Fi owns the same prefix before cleanup.
        for interfaceGone in [false, true] {
            let fake = FakeRoutes()
            let route = try fake.manager().add(lan.destination, interface: "utun42")!
            fake.entries[lan.destination] = lan
            if interfaceGone { fake.indexes.removeValue(forKey: "utun42") }
            var session = state([route])
            for dnsRestored in [false, false, true, true] {
                _ = cleanup(&session, routeManager: fake.manager(), teardown: fake.teardown, restoreDNSState: { _ in dnsRestored })
                precondition(fake.entries[lan.destination] == lan)
            }
            precondition(!fake.commands.contains { $0.contains("delete") })
        }
        print("PASS replacement Wi-Fi route survives tunnel exit and repeated DNS-failure cleanup")
        // Normal cleanup removes only the endpoint route we created, with a verified identity.
        do {
            let fake = FakeRoutes()
            fake.entries[lan.destination] = lan
            let baseline = fake.entries
            let tunnel = try fake.manager().add("192.0.2.0/24", interface: "utun42")!
            let bypass = try fake.manager().add(endpoint, interface: "en0", gateway: "10.0.0.138")!
            var session = state([tunnel, bypass])
            var teardowns = 0
            for dnsRestored in [false, false, true, true] {
                _ = cleanup(&session, routeManager: fake.manager(), teardown: { a, b, c in
                    teardowns += 1
                    return fake.teardown(a, b, c)
                }, restoreDNSState: { _ in dnsRestored })
            }
            let deletes = fake.commands.filter { $0.contains("delete") }
            precondition(fake.entries == baseline && deletes.count == 1 && teardowns == 1)
            precondition(deletes[0].contains("-gateway") && deletes[0].contains("-ifp"))
        }
        print("PASS normal disconnect restores pre-tunnel route set; DNS retries do not repeat mutations")
        // Another component replaces a physical host route on the same or a new Wi-Fi interface.
        for replacement in 0..<6 {
            let fake = FakeRoutes()
            let bypass = try fake.manager().add(endpoint, interface: "en0", gateway: "10.0.0.138")!
            var other = fake.entries[bypass.destination]!
            switch replacement {
            case 0: other.interface = "en1"
            case 1: other.gateway = "10.0.0.1"
            case 2: other.flags.remove("PROTO2")
            case 3: other.flags.insert("IFSCOPE")
            case 4: other.flags.insert("REJECT")
            default: fake.indexes["en0"] = 99 // Same name, new interface generation.
            }
            fake.entries[bypass.destination] = other
            var routes = [bypass]
            precondition(fake.manager().cleanup(&routes))
            precondition(fake.entries[bypass.destination] == other)
            precondition(!fake.commands.contains { $0.contains("delete") })
        }
        print("PASS changed gateway, interface, index, ownership flags and scope prevent deletion")
        do {
            let fake = FakeRoutes()
            let existing = FakeRoutes.Entry(destination: "\(endpoint)/32", interface: "en0", flags: ["UP", "HOST", "LLINFO", "WASCLONED", "IFSCOPE"])
            fake.entries[existing.destination] = existing
            let reused = try fake.manager().add(endpoint, interface: "en0", gateway: "10.0.0.138")
            precondition(reused == nil)
            precondition(fake.entries[existing.destination] == existing && fake.mutations.isEmpty)
        }
        print("PASS existing physical endpoint route is reused without becoming cleanup-owned")
        do {
            let fake = FakeRoutes()
            let bypass = try fake.manager().add(endpoint, interface: "en0", gateway: "10.0.0.138")!
            var routes = [bypass]
            fake.failLookup = true
            precondition(!fake.manager().cleanup(&routes) && routes == [bypass])
            precondition(!fake.commands.contains { $0.contains("delete") })
            fake.failLookup = false
            fake.failDelete = true
            precondition(!fake.manager().cleanup(&routes) && routes == [bypass])
            fake.failDelete = false
            precondition(fake.manager().cleanup(&routes) && routes.isEmpty)
        }
        print("PASS lookup/delete errors retain pending records for safe retry")
        do {
            let fake = FakeRoutes()
            let route = try fake.manager().add("2001:db8:1234::1/64", interface: "utun42")!
            let bypass = try fake.manager().add("2001:db8::20", interface: "en0", gateway: "fe80::1%en0")!
            var session = state([route, bypass])
            precondition(cleanup(&session, routeManager: fake.manager(), teardown: fake.teardown, restoreDNSState: { _ in true }))
            precondition(fake.entries.isEmpty)
            let ipv4 = try RouteNetwork("10.0.0.24/24")
            let ipv6 = try RouteNetwork("2001:0db8::a/64")
            precondition(ipv4.cidr == "10.0.0.0/24")
            precondition(ipv6.cidr == "2001:db8::/64")
        }
        print("PASS IPv4/IPv6 canonical prefixes, default fallback and link-local gateway handling")
        do {
            let fake = FakeRoutes()
            fake.entries[lan.destination] = lan
            var session = state([])
            session.managedRoutes = nil
            session.routes = [lan.destination]
            session.endpointRouteAdded = true
            session.transportRoutes = [lan.destination]
            precondition(cleanup(&session, routeManager: fake.manager(), teardown: fake.teardown, restoreDNSState: { _ in true }))
            precondition(fake.entries[lan.destination] == lan && fake.mutations.isEmpty)
        }
        print("PASS legacy destination-only records never authorize route deletion")
        do {
            let fake = FakeRoutes()
            var session = state([])
            var attempts = 0
            precondition(!cleanup(&session, routeManager: fake.manager(), teardown: { _, _, _ in attempts += 1; return false }, restoreDNSState: { _ in true }))
            precondition(cleanup(&session, routeManager: fake.manager(), teardown: { _, _, _ in attempts += 1; return true }, restoreDNSState: { _ in true }))
            precondition(attempts == 2)
        }
        print("PASS failed interface teardown retries before reporting cleanup complete")
        print("All route-cleanup regressions passed (simulated Darwin routing table).")
        if CommandLine.arguments.contains("--read-only") {
            for destination in ["127.0.0.1", "::1", "198.18.42.0/24", "2001:db8::/64"] {
                let network = try RouteNetwork(destination, host: !destination.contains("/"))
                let result = try run("/sbin/route", ["-n", "get", network.familyFlag] + network.routeArguments, requireSuccess: false)
                if result.status == 0 {
                    _ = try RouteSnapshot(output: result.output)
                } else {
                    precondition(result.output.localizedCaseInsensitiveContains("not in table"))
                }
            }
            print("PASS read-only native IPv4/IPv6 host and default-route lookups (no mutations)")
        }
    }
}
