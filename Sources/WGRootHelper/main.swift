import Foundation
import Darwin
import Dispatch

enum RootError: LocalizedError {
    case message(String)

    var errorDescription: String? {
        switch self { case .message(let message): return message }
    }
}

struct CommandResult {
    var output: String
    var status: Int32
}

let runtimeDirectory = "/var/run/wgapp"

func tool(_ name: String) throws -> String {
    for directory in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"] {
        let path = directory + "/" + name
        if FileManager.default.isExecutableFile(atPath: path) { return path }
    }
    throw RootError.message("Missing required executable: \(name)")
}

@discardableResult
func run(_ executable: String, _ arguments: [String], input: Data? = nil,
         environment: [String: String]? = nil, requireSuccess: Bool = true) throws -> CommandResult {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    if let environment { process.environment = environment }
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
    try process.run()
    if let input, let inputPipe {
        try inputPipe.fileHandleForWriting.write(contentsOf: input)
        try inputPipe.fileHandleForWriting.close()
    }
    process.waitUntilExit()
    let data = output.fileHandleForReading.readDataToEndOfFile()
    let text = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    if requireSuccess && process.terminationStatus != 0 {
        throw RootError.message(text.isEmpty ? "Command failed: \(executable)" : text)
    }
    return CommandResult(output: text, status: process.terminationStatus)
}

func runQuiet(_ executable: String, _ arguments: [String], environment: [String: String]? = nil) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    if let environment { process.environment = environment }
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else {
        throw RootError.message("wireguard-go could not create a utun interface.")
    }
}

func readStdin<T: Decodable>(_ type: T.Type) throws -> T {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    guard !data.isEmpty else { throw RootError.message("Expected JSON on stdin.") }
    return try JSONDecoder().decode(type, from: data)
}

func writeJSON<T: Encodable>(_ value: T) throws {
    try FileHandle.standardOutput.write(contentsOf: JSONEncoder().encode(value))
}

func validateLogicalName(_ name: String) throws {
    guard name.range(of: #"^wga-[a-f0-9]{10}$"#, options: .regularExpression) != nil else {
        throw RootError.message("Invalid managed interface name.")
    }
}

func nameFile(_ logicalName: String) -> String { "/var/run/wireguard/\(logicalName).name" }
func pidFile(_ logicalName: String) -> String { "\(runtimeDirectory)/\(logicalName).pid" }

func ensureRuntimeDirectories() throws {
    for path in ["/var/run/wireguard", runtimeDirectory] {
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: path)
    }
}

func liveSupervisorPID(for logicalName: String) -> pid_t? {
    guard let text = try? String(contentsOfFile: pidFile(logicalName), encoding: .utf8),
          let value = Int32(text.trimmingCharacters(in: .whitespacesAndNewlines)), value > 1,
          kill(value, 0) == 0 else { return nil }
    let command = (try? run("/bin/ps", ["-p", String(value), "-o", "command="], requireSuccess: false).output) ?? ""
    guard command.hasSuffix("wgapp-root supervise") || command.hasSuffix("WGRootHelper supervise") else { return nil }
    return value
}

func rejectAnotherTunnel(except logicalName: String) throws {
    try ensureRuntimeDirectories()
    let files = (try? FileManager.default.contentsOfDirectory(atPath: runtimeDirectory)) ?? []
    for file in files where file.hasSuffix(".pid") {
        let candidate = String(file.dropLast(4))
        if let pid = liveSupervisorPID(for: candidate) {
            throw RootError.message(candidate == logicalName
                ? "This profile is already active (supervisor \(pid))."
                : "Another WGApp profile is already active.")
        }
        try? FileManager.default.removeItem(atPath: pidFile(candidate))
    }
    let wireGuardFiles = (try? FileManager.default.contentsOfDirectory(atPath: "/var/run/wireguard")) ?? []
    for file in wireGuardFiles where file.hasPrefix("wga-") && file.hasSuffix(".name") {
        let candidate = String(file.dropLast(5))
        if let interface = interfaceForLogicalName(candidate),
           FileManager.default.fileExists(atPath: "/var/run/wireguard/\(interface).sock") {
            throw RootError.message(candidate == logicalName ? "This profile has an active WireGuard interface." : "Another WGApp profile is already active.")
        }
        try? FileManager.default.removeItem(atPath: nameFile(candidate))
    }
}

func routeInfo(family: EndpointFamily) throws -> (gateway: String, interface: String, mtu: Int) {
    let familyFlag = family == .ipv4 ? "-inet" : "-inet6"
    let result = try run("/sbin/route", ["-n", "get", familyFlag, "default"]).output
    var gateway: String?
    var interface: String?
    for line in result.split(separator: "\n") {
        let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
        guard parts.count == 2 else { continue }
        if parts[0] == "gateway" { gateway = parts[1] }
        if parts[0] == "interface" { interface = parts[1] }
    }
    guard let gateway, let interface else { throw RootError.message("No physical default route is available for \(family.title).") }
    let ifconfig = try run("/sbin/ifconfig", [interface]).output
    guard let range = ifconfig.range(of: #"mtu [0-9]+"#, options: .regularExpression),
          let mtu = Int(ifconfig[range].split(separator: " ").last ?? "") else {
        throw RootError.message("Could not determine MTU for \(interface).")
    }
    return (gateway, interface, mtu)
}

func resolve(_ host: String, family: EndpointFamily) throws -> String {
    try resolveAll(host, family: family)[0]
}

func resolveAll(_ host: String, family: EndpointFamily) throws -> [String] {
    var hints = addrinfo()
    hints.ai_family = family.addressFamily
    hints.ai_socktype = SOCK_DGRAM
    hints.ai_protocol = IPPROTO_UDP
    var head: UnsafeMutablePointer<addrinfo>?
    let status = getaddrinfo(host, nil, &hints, &head)
    guard status == 0, let first = head else {
        throw RootError.message("Could not resolve \(host) as \(family.title): \(String(cString: gai_strerror(status))).")
    }
    defer { freeaddrinfo(first) }
    var addresses: [String] = []
    var current: UnsafeMutablePointer<addrinfo>? = first
    while let entry = current {
        var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        if getnameinfo(entry.pointee.ai_addr, entry.pointee.ai_addrlen,
                       &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0 {
            let address = String(cString: buffer)
            if !addresses.contains(address) { addresses.append(address) }
        }
        current = entry.pointee.ai_next
    }
    guard !addresses.isEmpty else { throw RootError.message("No usable endpoint addresses were resolved.") }
    return addresses
}

struct TransportPlan {
    var address: String
    var port: UInt16
    var display: String
    var gateway: String
    var physicalInterface: String
    var physicalFamily: EndpointFamily
    var mtu: Int
    var addedRoutes: [String]
    var proxyProcess: Process?
}

func availableLoopbackPort() throws -> UInt16 {
    let descriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    guard descriptor >= 0 else { throw RootError.message("Could not reserve a local UDP port.") }
    defer { close(descriptor) }
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_addr.s_addr = inet_addr("127.0.0.1")
    let addressLength = socklen_t(MemoryLayout<sockaddr_in>.size)
    let bound = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(descriptor, $0, addressLength) }
    }
    var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    let named = withUnsafeMutablePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(descriptor, $0, &length) }
    }
    guard bound == 0, named == 0 else { throw RootError.message("Could not reserve a local UDP port.") }
    return UInt16(bigEndian: address.sin_port)
}

func prepareTransport(_ request: RootUpRequest) throws -> TransportPlan {
    guard let proxy = request.proxy else {
        let route = try routeInfo(family: request.endpointFamily)
        let address = try resolve(request.endpointHost, family: request.endpointFamily)
        let added = try addEndpointRoute(address: address, gateway: route.gateway, physicalInterface: route.interface)
        return TransportPlan(address: address, port: request.endpointPort,
                             display: endpointText(address: request.endpointHost, port: request.endpointPort),
                             gateway: route.gateway, physicalInterface: route.interface,
                             physicalFamily: request.endpointFamily, mtu: route.mtu - request.endpointFamily.directOverhead,
                             addedRoutes: added ? [address] : [], proxyProcess: nil)
    }
    try ProfileValidator.validateProxy(proxy)
    let executable = "/usr/local/libexec/wgapp-gost"
    guard FileManager.default.isExecutableFile(atPath: executable) else {
        throw RootError.message("The GOST proxy client is missing. Run ./b install to install it and refresh the root helper.")
    }
    let version = try run(executable, ["-V"]).output
    guard version.hasPrefix("gost 3.3.2 (") else {
        throw RootError.message("Proxy mode requires GOST 3.3.2. Run ./b install to refresh it.")
    }
    var candidates: [(address: String, gateway: String, interface: String, family: EndpointFamily)] = []
    for family in EndpointFamily.allCases {
        guard let route = try? routeInfo(family: family),
              !route.interface.hasPrefix("utun"),
              let addresses = try? resolveAll(proxy.domain, family: family) else { continue }
        candidates += addresses.map { ($0, route.gateway, route.interface, family) }
    }
    guard !candidates.isEmpty else { throw RootError.message("The proxy domain could not be resolved through a physical network.") }
    var addedRoutes: [String] = []
    var process: Process?
    var ready = false
    defer {
        if !ready {
            if let process, process.isRunning { process.terminate(); process.waitUntilExit() }
            for route in addedRoutes { deleteRoute(route) }
        }
    }
    // Protect every resolved address before changing routes or DNS. The client is
    // pinned to one reachable address, while SNI/Host retain the real TLS name.
    for candidate in candidates {
        if try addEndpointRoute(address: candidate.address, gateway: candidate.gateway, physicalInterface: candidate.interface) {
            addedRoutes.append(candidate.address)
        }
    }
    let reachable = candidates.first { candidate in
        let ip = candidate.address.contains(":") ? "[\(candidate.address)]" : candidate.address
        return (try? run("/usr/bin/curl", ["--silent", "--output", "/dev/null", "--noproxy", "*",
                                           "--connect-timeout", "4", "--max-time", "8",
                                           "--resolve", "\(proxy.domain):443:\(ip)",
                                           "https://\(proxy.domain)/"], requireSuccess: false).status) == 0
    }
    guard let reachable else { throw RootError.message("The proxy domain is not reachable over verified HTTPS on port 443.") }
    let port = try availableLoopbackPort()
    let client = Process()
    client.executableURL = URL(fileURLWithPath: executable)
    client.arguments = ["-C", "-"]
    client.environment = ["PATH": "/usr/bin:/bin"]
    client.currentDirectoryURL = URL(fileURLWithPath: "/")
    let input = Pipe()
    client.standardInput = input
    client.standardOutput = FileHandle.nullDevice
    client.standardError = FileHandle.nullDevice
    try client.run()
    process = client
    // The complete client definition and credentials travel only through stdin.
    defer { try? input.fileHandleForWriting.close() }
    try input.fileHandleForWriting.write(contentsOf: GOSTConfiguration.data(
        proxy: proxy, localPort: port, endpointHost: request.endpointHost,
        endpointPort: request.endpointPort, relayAddress: reachable.address))
    try input.fileHandleForWriting.close()
    let deadline = Date().addingTimeInterval(4)
    var listening = false
    while Date() < deadline, client.isRunning {
        let sockets = try run("/usr/sbin/lsof", ["-a", "-p", String(client.processIdentifier),
                                               "-iUDP@127.0.0.1:\(port)", "-Fn"], requireSuccess: false)
        if sockets.status == 0 { listening = true; break }
        usleep(100_000)
    }
    guard listening else { throw RootError.message("The proxy client could not start its local UDP listener.") }
    ready = true
    return TransportPlan(address: "127.0.0.1", port: port,
                         display: "\(endpointText(address: request.endpointHost, port: request.endpointPort)) via \(proxy.domain)",
                         gateway: reachable.gateway, physicalInterface: reachable.interface,
                         physicalFamily: reachable.family, mtu: 1280,
                         addedRoutes: addedRoutes, proxyProcess: client)
}

func endpointText(address: String, port: UInt16) -> String {
    address.contains(":") ? "[\(address)]:\(port)" : "\(address):\(port)"
}

func networkFamily(_ cidr: String) -> String { cidr.contains(":") ? "-inet6" : "-inet" }

func routedInterface(for address: String) -> String? {
    let result = try? run("/sbin/route", ["-n", "get", networkFamily(address), address], requireSuccess: false)
    guard result?.status == 0 else { return nil }
    for line in result?.output.split(separator: "\n") ?? [] {
        let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
        if parts.count == 2, parts[0] == "interface" { return parts[1] }
    }
    return nil
}

func addEndpointRoute(address: String, gateway: String, physicalInterface: String) throws -> Bool {
    let result = try run("/sbin/route", ["-q", "-n", "add", networkFamily(address), address, "-gateway", gateway],
                         requireSuccess: false)
    if result.status == 0 { return true }
    guard routedInterface(for: address) == physicalInterface else {
        throw RootError.message("Could not protect the WireGuard endpoint with a route through \(physicalInterface).")
    }
    return false
}

func deleteRoute(_ cidr: String) {
    _ = try? run("/sbin/route", ["-q", "-n", "delete", networkFamily(cidr), cidr], requireSuccess: false)
}

func addTunnelRoute(_ cidr: String, interface: String) throws {
    try run("/sbin/route", ["-q", "-n", "add", networkFamily(cidr), cidr, "-interface", interface])
}

func configureAddress(_ address: String, interface: String) throws {
    if address.contains(":") {
        try run("/sbin/ifconfig", [interface, "inet6", "\(address)/128", "alias"])
    } else {
        try run("/sbin/ifconfig", [interface, "inet", "\(address)/32", address, "alias"])
    }
}

func networkServices() throws -> [String] {
    let output = try run("/usr/sbin/networksetup", ["-listallnetworkservices"]).output
    return output.split(separator: "\n").dropFirst().map {
        var name = $0.trimmingCharacters(in: .whitespacesAndNewlines)
        if name.hasPrefix("*") { name.removeFirst() }
        return name.trimmingCharacters(in: .whitespacesAndNewlines)
    }.filter { !$0.isEmpty }
}

func currentDNSServers(service: String) throws -> [String] {
    let output = try run("/usr/sbin/networksetup", ["-getdnsservers", service]).output
    if output.isEmpty || output.localizedCaseInsensitiveContains("There aren't any") { return [] }
    return output.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
}

func captureDNSBaseline() throws -> [DNSServiceState] {
    try networkServices().map { DNSServiceState(name: $0, servers: try currentDNSServers(service: $0)) }
}

func setDNS(_ server: String) throws {
    for service in try networkServices() {
        try run("/usr/sbin/networksetup", ["-setdnsservers", service, server])
    }
}

func restoreDNS(_ baseline: [DNSServiceState]) -> Bool {
    guard !baseline.isEmpty else { return true }
    guard let current = try? Set(networkServices()) else { return false }
    var restored = true
    for state in baseline {
        guard current.contains(state.name) else { continue }
        let values = state.servers.isEmpty ? ["Empty"] : state.servers
        let result = try? run("/usr/sbin/networksetup", ["-setdnsservers", state.name] + values, requireSuccess: false)
        if result?.status != 0 { restored = false }
    }
    return restored
}

func interfaceForLogicalName(_ logicalName: String) -> String? {
    guard let value = try? String(contentsOfFile: nameFile(logicalName), encoding: .utf8)
        .trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else { return nil }
    return value
}

func removeInterface(logicalName: String, interfaceName: String) {
    try? FileManager.default.removeItem(atPath: "/var/run/wireguard/\(interfaceName).sock")
    try? FileManager.default.removeItem(atPath: nameFile(logicalName))
}

func cleanup(_ state: SupervisorState) -> Bool {
    for route in state.routes { deleteRoute(route) }
    removeInterface(logicalName: state.logicalName, interfaceName: state.interfaceName)
    if state.endpointRouteAdded { deleteRoute(state.endpointAddress) }
    if let proxyPID = state.proxyPID, isProxyProcess(proxyPID) { kill(proxyPID, SIGTERM) }
    for route in state.transportRoutes ?? [] { deleteRoute(route) }
    guard restoreDNS(state.dnsBaseline) else { return false }
    try? FileManager.default.removeItem(atPath: pidFile(state.logicalName))
    return true
}

func isProxyProcess(_ pid: Int32) -> Bool {
    guard pid > 1, kill(pid, 0) == 0 else { return false }
    let command = (try? run("/bin/ps", ["-p", String(pid), "-o", "command="], requireSuccess: false).output) ?? ""
    return command.hasPrefix("/usr/local/libexec/wgapp-gost -C -")
        || command.hasPrefix("/usr/local/libexec/wgapp-wstunnel ") // Clean up earlier sessions too.
}

func launchSupervisor(_ state: SupervisorState) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
    process.arguments = ["supervise"]
    let input = Pipe()
    process.standardInput = input
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    try input.fileHandleForWriting.write(contentsOf: JSONEncoder().encode(state))
    try input.fileHandleForWriting.close()
    let deadline = Date().addingTimeInterval(3)
    while Date() < deadline {
        if liveSupervisorPID(for: state.logicalName) == process.processIdentifier { return }
        if !process.isRunning { break }
        usleep(50_000)
    }
    if process.isRunning { process.terminate() }
    throw RootError.message("The cleanup supervisor did not start.")
}

func startTunnel() throws -> RootUpResult {
    var request = try readStdin(RootUpRequest.self)
    try validateLogicalName(request.logicalName)
    try ProfileValidator.validate(WGProfile(
        name: request.logicalName,
        privateKey: request.privateKey,
        presharedKey: request.presharedKey,
        peerPublicKey: request.peerPublicKey,
        address: request.address,
        allowedIPs: request.allowedIPs,
        dns: request.dns ?? "127.0.0.1",
        endpointIPv4: request.endpointHost,
        endpointIPv6: request.endpointHost,
        endpointPort: request.endpointPort,
        proxy: request.proxy))
    guard request.persistentKeepalive == 25 else { throw RootError.message("PersistentKeepalive must be 25 seconds.") }
    try rejectAnotherTunnel(except: request.logicalName)

    let transport = try prepareTransport(request)
    let mtu = transport.mtu
    var interfaceName: String?
    var addedRoutes: [String] = []
    var dnsBaseline: [DNSServiceState] = []
    var supervisorStarted = false
    defer {
        if !supervisorStarted {
            for route in addedRoutes { deleteRoute(route) }
            if let interfaceName { removeInterface(logicalName: request.logicalName, interfaceName: interfaceName) }
            if let process = transport.proxyProcess, process.isRunning { process.terminate(); process.waitUntilExit() }
            for route in transport.addedRoutes { deleteRoute(route) }
            _ = restoreDNS(dnsBaseline)
        }
    }
    guard mtu >= 576 else { throw RootError.message("The physical interface MTU is too small for WireGuard.") }

    var environment = ProcessInfo.processInfo.environment
    environment["WG_TUN_NAME_FILE"] = nameFile(request.logicalName)
    try runQuiet(try tool("wireguard-go"), ["utun"], environment: environment)
    guard let createdInterface = interfaceForLogicalName(request.logicalName) else {
        throw RootError.message("wireguard-go did not report its utun interface.")
    }
    interfaceName = createdInterface

    var configuration = "[Interface]\nPrivateKey = \(request.privateKey)\n\n[Peer]\nPublicKey = \(request.peerPublicKey)\n"
    if let presharedKey = request.presharedKey, !presharedKey.isEmpty {
        configuration += "PresharedKey = \(presharedKey)\n"
    }
    configuration += "AllowedIPs = \(request.allowedIPs.joined(separator: ", "))\n"
    configuration += "Endpoint = \(endpointText(address: transport.address, port: transport.port))\n"
    configuration += "PersistentKeepalive = \(request.persistentKeepalive)\n"
    do {
        try run(try tool("wg"), ["setconf", createdInterface, "/dev/stdin"], input: Data(configuration.utf8))
    } catch {
        throw RootError.message("wg rejected the in-memory configuration.")
    }
    configuration.removeAll(keepingCapacity: false)
    request.privateKey.removeAll(keepingCapacity: false)
    request.presharedKey = nil

    try configureAddress(request.address, interface: createdInterface)
    try run("/sbin/ifconfig", [createdInterface, "mtu", String(mtu)])
    try run("/sbin/ifconfig", [createdInterface, "up"])
    for allowedIP in request.allowedIPs.sorted(by: {
        Int($0.split(separator: "/").last ?? "0") ?? 0 > Int($1.split(separator: "/").last ?? "0") ?? 0
    }) {
        try addTunnelRoute(allowedIP, interface: createdInterface)
        addedRoutes.append(allowedIP)
    }
    if let dns = request.dns {
        dnsBaseline = try captureDNSBaseline()
        try setDNS(dns)
    }

    let state = SupervisorState(logicalName: request.logicalName, interfaceName: createdInterface,
                                endpointAddress: transport.address, endpointRouteAdded: false,
                                routes: addedRoutes, dnsBaseline: dnsBaseline,
                                transportRoutes: transport.addedRoutes,
                                proxyPID: transport.proxyProcess?.processIdentifier,
                                physicalFamily: request.proxy == nil ? nil : transport.physicalFamily,
                                physicalInterface: transport.physicalInterface, physicalGateway: transport.gateway)
    try launchSupervisor(state)
    supervisorStarted = true
    return RootUpResult(logicalName: request.logicalName, interfaceName: createdInterface,
                        endpointAddress: transport.address,
                        endpointDisplay: transport.display,
                        physicalInterface: transport.physicalInterface, gateway: transport.gateway, mtu: mtu,
                        dnsApplied: request.dns != nil)
}

func stopTunnel() throws {
    let request = try readStdin(RootNameRequest.self)
    try validateLogicalName(request.logicalName)
    if let pid = liveSupervisorPID(for: request.logicalName) {
        guard kill(pid, SIGTERM) == 0 else { throw RootError.message("Could not signal the cleanup supervisor.") }
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline {
            if kill(pid, 0) != 0 { return }
            usleep(100_000)
        }
        throw RootError.message("Cleanup did not finish within ten seconds.")
    }
    if let interface = interfaceForLogicalName(request.logicalName) {
        removeInterface(logicalName: request.logicalName, interfaceName: interface)
        throw RootError.message("Recovered an orphaned interface, but its in-memory DNS baseline was unavailable.")
    }
}

func parseFirstValue(_ output: String) -> (String, String)? {
    let fields = output.split(separator: "\t", omittingEmptySubsequences: false)
    guard fields.count >= 2 else { return nil }
    return (String(fields[0]), String(fields[1]))
}

func tunnelStatus() throws -> RootStatusResult {
    let request = try readStdin(RootNameRequest.self)
    try validateLogicalName(request.logicalName)
    guard let interface = interfaceForLogicalName(request.logicalName) else {
        return RootStatusResult(active: false, interfaceName: nil, endpoint: nil, latestHandshake: 0,
                                receivedBytes: 0, sentBytes: 0, mtu: nil)
    }
    let wg = try tool("wg")
    let handshakeOutput = try run(wg, ["show", interface, "latest-handshakes"], requireSuccess: false)
    guard handshakeOutput.status == 0 else {
        return RootStatusResult(active: false, interfaceName: nil, endpoint: nil, latestHandshake: 0,
                                receivedBytes: 0, sentBytes: 0, mtu: nil)
    }
    let handshake = parseFirstValue(handshakeOutput.output).flatMap { Int64($0.1) } ?? 0
    let transferFields = try run(wg, ["show", interface, "transfer"], requireSuccess: false).output
        .split(separator: "\t", omittingEmptySubsequences: false)
    let received = transferFields.count >= 3 ? UInt64(transferFields[1]) ?? 0 : 0
    let sent = transferFields.count >= 3 ? UInt64(transferFields[2]) ?? 0 : 0
    let endpoint = parseFirstValue(try run(wg, ["show", interface, "endpoints"], requireSuccess: false).output)?.1
    let ifconfig = try run("/sbin/ifconfig", [interface], requireSuccess: false).output
    let mtu = ifconfig.range(of: #"mtu [0-9]+"#, options: .regularExpression)
        .flatMap { Int(ifconfig[$0].split(separator: " ").last ?? "") }
    return RootStatusResult(active: true, interfaceName: interface, endpoint: endpoint,
                            latestHandshake: handshake, receivedBytes: received, sentBytes: sent, mtu: mtu)
}

func supervise() throws -> Never {
    let state = try readStdin(SupervisorState.self)
    try validateLogicalName(state.logicalName)
    try ensureRuntimeDirectories()
    try Data("\(getpid())\n".utf8).write(to: URL(fileURLWithPath: pidFile(state.logicalName)), options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: pidFile(state.logicalName))
    signal(SIGTERM, SIG_IGN)
    signal(SIGINT, SIG_IGN)
    let queue = DispatchQueue(label: "com.example.wgapp.cleanup")
    let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: queue)
    let interrupt = DispatchSource.makeSignalSource(signal: SIGINT, queue: queue)
    let monitor = DispatchSource.makeTimerSource(queue: queue)
    var stopping = false
    let attemptCleanup = {
        stopping = true
        if cleanup(state) { exit(0) }
    }
    term.setEventHandler(handler: attemptCleanup)
    interrupt.setEventHandler(handler: attemptCleanup)
    monitor.schedule(deadline: .now() + 1, repeating: 1)
    monitor.setEventHandler {
        let proxyStopped = state.proxyPID.map { !isProxyProcess($0) } ?? false
        var networkChanged = false
        if let family = state.physicalFamily {
            let route = try? routeInfo(family: family)
            networkChanged = route?.interface != state.physicalInterface || route?.gateway != state.physicalGateway
        }
        if stopping || proxyStopped || networkChanged || !FileManager.default.fileExists(atPath: "/var/run/wireguard/\(state.interfaceName).sock") {
            attemptCleanup()
        }
    }
    term.resume()
    interrupt.resume()
    monitor.resume()
    dispatchMain()
}

@main
struct WGRootHelper {
    static func main() {
        do {
            guard geteuid() == 0 else { throw RootError.message("wgapp-root must run as root.") }
            let arguments = Array(CommandLine.arguments.dropFirst())
            guard arguments.count == 1 else { throw RootError.message("Usage: wgapp-root {up|down|status}") }
            switch arguments[0] {
            case "up": try writeJSON(try startTunnel())
            case "down": try stopTunnel()
            case "status": try writeJSON(try tunnelStatus())
            case "supervise": try supervise()
            default: throw RootError.message("Usage: wgapp-root {up|down|status}")
            }
        } catch {
            FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
            exit(1)
        }
    }
}
