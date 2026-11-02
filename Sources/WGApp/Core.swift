import Foundation
import Combine
import Darwin
import ServiceManagement

struct ProfileSummary: Identifiable, Equatable {
    var name: String
    var isInvalid = false
    var isStored = true
    var issue: String?
    var id: String { name }
}

struct InterfaceStats: Equatable {
    var rxBytes: UInt64 = 0
    var txBytes: UInt64 = 0
    var rxPackets: UInt64 = 0
    var txPackets: UInt64 = 0
    var rxErrors: UInt64 = 0
    var txErrors: UInt64 = 0
}

struct TrafficRate: Equatable {
    var rxBytesPerSecond: UInt64 = 0
    var txBytesPerSecond: UInt64 = 0
}

enum TunnelPhase: String {
    case connecting = "Connecting"
    case connected = "Connected"
    case stale = "Stale"
}

struct TunnelRuntime: Equatable {
    var profileName: String
    var logicalName: String
    var interfaceName: String
    var phase: TunnelPhase
    var family: EndpointFamily
    var endpointDisplay: String
    var endpointAddress: String
    var physicalInterface: String
    var gateway: String
    var mtu: Int
    var dnsApplied: Bool
    var connectedAt: Date
    var latestHandshake: Date?
    var wireGuardReceivedBytes: UInt64 = 0
    var wireGuardSentBytes: UInt64 = 0
    var proxyDomain: String? = nil
    var recovered = false
    var usesProxy: Bool { proxyDomain != nil || endpointAddress.hasPrefix("127.0.0.1:") }
}

struct PendingConnection: Identifiable {
    let profile: WGProfile
    let id = UUID()
}

struct ProfileEditor: Identifiable {
    var profile: WGProfile
    var isNew: Bool
    let id = UUID()
}

struct ConnectionOptions {
    var family: EndpointFamily = .ipv4
    var replaceDNS = true
    var useProxy = false
}

enum AppError: LocalizedError {
    case message(String)
    var errorDescription: String? { switch self { case .message(let message): return message } }
}

@MainActor
final class ProfileStore: ObservableObject {
    @Published private(set) var profiles: [ProfileSummary] = []
    @Published private(set) var activeTunnel: TunnelRuntime?
    @Published private(set) var networkBusy = false
    @Published private(set) var counters = InterfaceStats()
    @Published private(set) var rate = TrafficRate()
    @Published var pendingConnection: PendingConnection?
    @Published var profileEditor: ProfileEditor?
    @Published var editorError: String?
    @Published var lastError: String?
    @Published var launchAtLogin = UserDefaults.standard.bool(forKey: "launchAtLogin")

    private var previousStats: InterfaceStats?
    private var monitor: Monitor?
    private var statusBusy = false
    private var lastStatusRefresh = Date.distantPast
    private var savedProfileNames = Set<String>()
    private var unsavedProfiles: [String: ProfileEditor] = [:]

    init() {
        monitor = Monitor { [weak self] in self?.monitorTick() }
        Task { await reloadProfilesAndRecover() }
    }

    var activeCount: Int { activeTunnel == nil ? 0 : 1 }
    var statusText: String { activeTunnel?.phase.rawValue ?? "Disconnected" }

    func isActive(_ profile: ProfileSummary) -> Bool { activeTunnel?.profileName == profile.name }

    func newProfile() {
        editorError = nil
        profileEditor = ProfileEditor(profile: WGProfile(
            name: "", privateKey: "", presharedKey: nil, peerPublicKey: "",
            address: "", allowedIPs: [], dns: "", endpointIPv4: "",
            endpointIPv6: "", endpointPort: 51820, proxy: nil), isNew: true)
    }

    func beginEdit(_ profile: ProfileSummary) {
        guard !networkBusy, !isActive(profile) else { return }
        editorError = nil
        if let draft = unsavedProfiles[profile.name] {
            profileEditor = draft
            return
        }
        networkBusy = true
        Task {
            defer { networkBusy = false }
            do {
                profileEditor = ProfileEditor(profile: try await ProfileHelperClient.get(profile.name), isNew: false)
            } catch { lastError = error.localizedDescription }
        }
    }

    func saveProfile(_ editor: ProfileEditor) {
        guard !networkBusy else { return }
        editorError = nil
        networkBusy = true
        Task {
            defer { networkBusy = false }
            do {
                let normalized = try ProfileValidator.normalized(editor.profile)
                if editor.isNew {
                    guard !savedProfileNames.contains(where: { $0.localizedCaseInsensitiveCompare(normalized.name) == .orderedSame }) else {
                        throw AppError.message("That profile name is already in use.")
                    }
                    do {
                        try await ProfileHelperClient.add(normalized)
                    } catch {
                        retainUnsaved(ProfileEditor(profile: normalized, isNew: true), error: error)
                        return
                    }
                } else {
                    do {
                        try await ProfileHelperClient.edit(normalized)
                    } catch {
                        retainUnsaved(ProfileEditor(profile: normalized, isNew: false), error: error)
                        return
                    }
                }
                unsavedProfiles.removeValue(forKey: normalized.name)
                profileEditor = nil
                try await reloadProfiles()
            } catch {
                editorError = error.localizedDescription
            }
        }
    }

    func remove(_ profile: ProfileSummary) {
        guard !networkBusy else { return }
        if let draft = unsavedProfiles[profile.name], draft.isNew {
            unsavedProfiles.removeValue(forKey: profile.name)
            rebuildProfileSummaries()
            return
        }
        networkBusy = true
        Task {
            defer { networkBusy = false }
            do {
                if isActive(profile) { try await disconnectInternal() }
                try await ProfileHelperClient.delete(profile.name)
                unsavedProfiles.removeValue(forKey: profile.name)
                try await reloadProfiles()
            } catch { lastError = error.localizedDescription }
        }
    }

    func toggle(_ profile: ProfileSummary) {
        guard !profile.isInvalid else {
            lastError = profile.issue ?? "Edit and save this profile before connecting."
            return
        }
        if isActive(profile) { disconnect() }
        else { prepareConnection(profile) }
    }

    func prepareConnection(_ profile: ProfileSummary) {
        guard !networkBusy else { return }
        guard !profile.isInvalid else {
            lastError = profile.issue ?? "Edit and save this profile before connecting."
            return
        }
        guard activeTunnel == nil else {
            lastError = "Disconnect the active profile before connecting another one."
            return
        }
        networkBusy = true
        Task {
            defer { networkBusy = false }
            do { pendingConnection = PendingConnection(profile: try await ProfileHelperClient.get(profile.name)) }
            catch { lastError = error.localizedDescription }
        }
    }

    func connect(_ profile: WGProfile, options: ConnectionOptions) {
        guard !networkBusy, activeTunnel == nil else { return }
        pendingConnection = nil
        networkBusy = true
        Task {
            defer { networkBusy = false }
            var attemptedLogicalName: String?
            do {
                try ProfileValidator.validate(profile)
                let logicalName = ManagedInterfaceName.forProfile(profile.name)
                attemptedLogicalName = logicalName
                let host = options.family == .ipv4 ? profile.endpointIPv4 : profile.endpointIPv6
                if options.useProxy && profile.proxy == nil {
                    throw AppError.message("Edit this profile and configure its Fly.io proxy first.")
                }
                let request = RootUpRequest(
                    logicalName: logicalName,
                    privateKey: profile.privateKey,
                    presharedKey: profile.presharedKey,
                    peerPublicKey: profile.peerPublicKey,
                    address: profile.address,
                    allowedIPs: profile.allowedIPs,
                    dns: options.replaceDNS ? profile.dns : nil,
                    endpointHost: host,
                    endpointPort: profile.endpointPort,
                    endpointFamily: options.family,
                    persistentKeepalive: 25,
                    proxy: options.useProxy ? profile.proxy : nil)
                let result = try await RootLauncherClient.up(request)
                activeTunnel = TunnelRuntime(
                    profileName: profile.name, logicalName: logicalName,
                    interfaceName: result.interfaceName, phase: .connecting,
                    family: options.family, endpointDisplay: result.endpointDisplay,
                    endpointAddress: result.endpointAddress, physicalInterface: result.physicalInterface,
                    gateway: result.gateway, mtu: result.mtu, dnsApplied: result.dnsApplied,
                    connectedAt: Date(), latestHandshake: nil)
                activeTunnel?.proxyDomain = options.useProxy ? profile.proxy?.domain : nil
                counters = InterfaceStats()
                rate = TrafficRate()
                previousStats = nil
                try await awaitHandshake(logicalName: logicalName)
            } catch {
                if let logicalName = attemptedLogicalName { try? await RootLauncherClient.down(logicalName: logicalName) }
                activeTunnel = nil
                lastError = error.localizedDescription
            }
        }
    }

    func disconnect() {
        guard !networkBusy, activeTunnel != nil else { return }
        networkBusy = true
        Task {
            defer { networkBusy = false }
            do { try await disconnectInternal() }
            catch { lastError = error.localizedDescription }
        }
    }

    func setLaunchAtLogin(_ enabled: Bool) {
        do {
            if enabled { try SMAppService.mainApp.register() }
            else { try SMAppService.mainApp.unregister() }
            launchAtLogin = enabled
            UserDefaults.standard.set(enabled, forKey: "launchAtLogin")
        } catch { lastError = error.localizedDescription }
    }

    private func reloadProfilesAndRecover() async {
        do {
            try await reloadProfiles()
            guard FileManager.default.isExecutableFile(atPath: wgAppRootHelperPath) else { return }
            for profile in profiles where !profile.isInvalid {
                let logicalName = ManagedInterfaceName.forProfile(profile.name)
                let status = try await RootLauncherClient.status(logicalName: logicalName)
                guard status.active, let interface = status.interfaceName else { continue }
                let family: EndpointFamily = status.endpoint?.contains("[") == true ? .ipv6 : .ipv4
                let handshake = status.latestHandshake > 0 ? Date(timeIntervalSince1970: TimeInterval(status.latestHandshake)) : nil
                activeTunnel = TunnelRuntime(
                    profileName: profile.name, logicalName: logicalName, interfaceName: interface,
                    phase: phase(for: handshake), family: family,
                    endpointDisplay: status.endpoint ?? "Unknown", endpointAddress: status.endpoint ?? "Unknown",
                    physicalInterface: "Unknown", gateway: "Unknown", mtu: status.mtu ?? 0,
                    dnsApplied: false, connectedAt: Date(), latestHandshake: handshake,
                    wireGuardReceivedBytes: status.receivedBytes, wireGuardSentBytes: status.sentBytes)
                activeTunnel?.recovered = true
                break
            }
        } catch { lastError = error.localizedDescription }
    }

    private func reloadProfiles() async throws {
        savedProfileNames = Set(try await ProfileHelperClient.list())
        rebuildProfileSummaries()
    }

    private func retainUnsaved(_ editor: ProfileEditor, error: Error) {
        let message = error.localizedDescription
        unsavedProfiles[editor.profile.name] = editor
        profileEditor = nil
        editorError = nil
        lastError = message
        rebuildProfileSummaries()
    }

    private func rebuildProfileSummaries() {
        let names = savedProfileNames.union(unsavedProfiles.keys)
        profiles = names.map { name in
            ProfileSummary(name: name,
                           isInvalid: unsavedProfiles[name] != nil,
                           isStored: savedProfileNames.contains(name),
                           issue: unsavedProfiles[name] == nil ? nil : "Not saved. Edit this profile to retry.")
        }.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    private func disconnectInternal() async throws {
        guard let active = activeTunnel else { return }
        try await RootLauncherClient.down(logicalName: active.logicalName)
        activeTunnel = nil
        counters = InterfaceStats()
        rate = TrafficRate()
        previousStats = nil
    }

    private func awaitHandshake(logicalName: String) async throws {
        let deadline = Date().addingTimeInterval(35)
        while Date() < deadline {
            let status = try await RootLauncherClient.status(logicalName: logicalName)
            guard status.active else { throw AppError.message("The WireGuard interface stopped before completing a handshake.") }
            apply(status)
            if status.latestHandshake > 0 { return }
            try await Task.sleep(for: .seconds(1))
        }
        throw AppError.message("WireGuard did not complete a handshake within 35 seconds.")
    }

    private func monitorTick() {
        guard let active = activeTunnel else { return }
        if let current = InterfaceReader.stats(for: active.interfaceName) {
            if let previous = previousStats {
                rate = TrafficRate(
                    rxBytesPerSecond: current.rxBytes >= previous.rxBytes ? current.rxBytes - previous.rxBytes : 0,
                    txBytesPerSecond: current.txBytes >= previous.txBytes ? current.txBytes - previous.txBytes : 0)
            }
            previousStats = current
            counters = current
        }
        guard !statusBusy, !networkBusy, Date().timeIntervalSince(lastStatusRefresh) >= 2 else { return }
        statusBusy = true
        lastStatusRefresh = Date()
        Task {
            defer { statusBusy = false }
            do { apply(try await RootLauncherClient.status(logicalName: active.logicalName)) }
            catch { lastError = error.localizedDescription }
        }
    }

    private func apply(_ status: RootStatusResult) {
        guard var active = activeTunnel else { return }
        guard status.active else {
            activeTunnel = nil
            return
        }
        let handshake = status.latestHandshake > 0 ? Date(timeIntervalSince1970: TimeInterval(status.latestHandshake)) : nil
        active.interfaceName = status.interfaceName ?? active.interfaceName
        active.latestHandshake = handshake
        active.phase = phase(for: handshake)
        active.wireGuardReceivedBytes = status.receivedBytes
        active.wireGuardSentBytes = status.sentBytes
        if let mtu = status.mtu { active.mtu = mtu }
        activeTunnel = active
    }

    private func phase(for handshake: Date?) -> TunnelPhase {
        guard let handshake else { return .connecting }
        return Date().timeIntervalSince(handshake) > 180 ? .stale : .connected
    }
}

@MainActor
final class Monitor {
    private var subscription: AnyCancellable?
    init(tick: @escaping @MainActor () -> Void) {
        subscription = Timer.publish(every: 1, on: .main, in: .common).autoconnect().sink { _ in
            Task { @MainActor in tick() }
        }
    }
}

enum InterfaceReader {
    static func stats(for interface: String) -> InterfaceStats? {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return nil }
        defer { freeifaddrs(head) }
        var current: UnsafeMutablePointer<ifaddrs>? = first
        while let pointer = current {
            let item = pointer.pointee
            if let name = item.ifa_name.map({ String(cString: $0) }), name == interface,
               let address = item.ifa_addr, Int32(address.pointee.sa_family) == AF_LINK,
               let dataPointer = item.ifa_data {
                let data = dataPointer.assumingMemoryBound(to: if_data.self).pointee
                return InterfaceStats(rxBytes: UInt64(data.ifi_ibytes), txBytes: UInt64(data.ifi_obytes),
                                      rxPackets: UInt64(data.ifi_ipackets), txPackets: UInt64(data.ifi_opackets),
                                      rxErrors: UInt64(data.ifi_ierrors), txErrors: UInt64(data.ifi_oerrors))
            }
            current = item.ifa_next
        }
        return nil
    }
}
