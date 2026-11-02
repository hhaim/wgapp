import SwiftUI
import AppKit

@main
struct WGApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var store = ProfileStore()

    var body: some Scene {
        Window("WireGuard", id: "main") {
            MainView()
                .environmentObject(store)
                .frame(minWidth: 560, minHeight: 380)
        }
        .defaultSize(width: 640, height: 520)
        MenuBarExtra {
            MenuBarView().environmentObject(store)
        } label: {
            StatusIcon(phase: store.activeTunnel?.phase)
        }
        .menuBarExtraStyle(.menu)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NotificationCenter.default.addObserver(self, selector: #selector(windowBecameKey(_:)), name: NSWindow.didBecomeKeyNotification, object: nil)
        NotificationCenter.default.addObserver(self, selector: #selector(windowWillClose(_:)), name: NSWindow.willCloseNotification, object: nil)
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    @objc private func windowBecameKey(_ notification: Notification) {
        guard let window = notification.object as? NSWindow, window.canBecomeMain, !(window is NSPanel) else { return }
        NSApp.setActivationPolicy(.regular)
    }
    @objc private func windowWillClose(_ notification: Notification) {
        guard let closing = notification.object as? NSWindow, closing.canBecomeMain, !(closing is NSPanel) else { return }
        DispatchQueue.main.async {
            let visible = NSApp.windows.contains { $0 !== closing && $0.canBecomeMain && !($0 is NSPanel) && $0.isVisible }
            NSApp.setActivationPolicy(visible ? .regular : .accessory)
        }
    }
}

private struct MainView: View {
    @EnvironmentObject private var store: ProfileStore
    @State private var selection: String?
    @State private var confirmRemove = false

    private var selectedProfile: ProfileSummary? { store.profiles.first { $0.name == selection } }

    var body: some View {
        List(selection: $selection) {
            ForEach(store.profiles) { profile in
                ProfileRow(profile: profile)
                    .tag(profile.name)
                    .contextMenu {
                        Button("Edit…") { store.beginEdit(profile) }
                            .disabled(store.networkBusy || store.isActive(profile))
                        Divider()
                        Button("Delete…", role: .destructive) {
                            selection = profile.name
                            confirmRemove = true
                        }
                        .disabled(store.networkBusy)
                    }
            }
        }
        .listStyle(.inset)
        .overlay {
            if store.profiles.isEmpty {
                ContentUnavailableView("No Profiles", systemImage: "shield",
                                       description: Text("Add a profile. Its complete configuration will be stored in Keychain."))
            }
        }
        .navigationTitle("WireGuard")
        .toolbar {
            ToolbarItemGroup {
                Button { store.newProfile() } label: { Label("Add Profile", systemImage: "plus") }
                    .disabled(store.networkBusy)
                Button { confirmRemove = true } label: { Label("Delete Profile", systemImage: "minus") }
                    .disabled(selectedProfile == nil || store.networkBusy)
                Menu {
                    Toggle("Launch at Login", isOn: Binding(get: { store.launchAtLogin }, set: { store.setLaunchAtLogin($0) }))
                } label: { Label("Settings", systemImage: "gearshape") }
            }
        }
        .safeAreaInset(edge: .top) {
            if let error = store.lastError {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                    Text(error).font(.callout).textSelection(.enabled)
                    Spacer(minLength: 8)
                    Button("Dismiss") { store.lastError = nil }
                        .controlSize(.small)
                }
                .padding(10)
                .background(.red.opacity(0.10))
            }
        }
        .safeAreaInset(edge: .bottom) { ConnectionStatusBar() }
        .sheet(item: $store.profileEditor) { editor in
            ProfileEditorView(editor: editor)
                .environmentObject(store)
        }
        .sheet(item: $store.pendingConnection) { pending in
            ConnectionSheet(profile: pending.profile)
                .environmentObject(store)
        }
        .onDeleteCommand { if selectedProfile != nil { confirmRemove = true } }
        .confirmationDialog(selectedProfile?.isStored == true ? "Delete this Keychain profile?" : "Discard this unsaved profile?",
                            isPresented: $confirmRemove, titleVisibility: .visible) {
            if let selectedProfile {
                Button(selectedProfile.isStored ? "Delete Profile" : "Discard Unsaved Profile", role: .destructive) {
                    store.remove(selectedProfile)
                    selection = nil
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            if selectedProfile?.isStored == true {
                Text("Touch ID is required. The complete profile will be removed from this Mac.")
            } else {
                Text("This unsaved profile exists only in app memory and will be discarded.")
            }
        }
    }
}

private struct ProfileEditorView: View {
    @EnvironmentObject private var store: ProfileStore
    @Environment(\.dismiss) private var dismiss
    @State private var draft: WGProfile
    @State private var allowedIPs: String
    @State private var proxyConfigured: Bool
    @State private var proxyDomain: String
    @State private var proxyUsername: String
    @State private var proxyPassword: String
    private let isNew: Bool

    init(editor: ProfileEditor) {
        _draft = State(initialValue: editor.profile)
        _allowedIPs = State(initialValue: editor.profile.allowedIPs.joined(separator: ", "))
        _proxyConfigured = State(initialValue: editor.profile.proxy != nil)
        _proxyDomain = State(initialValue: editor.profile.proxy?.domain ?? "")
        _proxyUsername = State(initialValue: editor.profile.proxy?.username ?? "relay-user")
        _proxyPassword = State(initialValue: editor.profile.proxy?.password ?? "")
        isNew = editor.isNew
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                if let error = store.editorError {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                            .textSelection(.enabled)
                    }
                }
                Section("Profile") {
                    TextField("Name", text: $draft.name)
                        .disabled(!isNew)
                    TextField("Interface IP address", text: $draft.address)
                    TextField("Allowed IPs", text: $allowedIPs)
                    TextField("DNS server", text: $draft.dns)
                }
                Section("WireGuard keys") {
                    SecureField("Private key", text: $draft.privateKey)
                        .textContentType(.password)
                    SecureField("Optional preshared key", text: Binding(
                        get: { draft.presharedKey ?? "" },
                        set: { draft.presharedKey = $0.isEmpty ? nil : $0 }))
                        .textContentType(.password)
                    SecureField("Peer public key", text: $draft.peerPublicKey)
                        .textContentType(.password)
                    Text("Keys stay masked and are sent directly to the biometric Keychain helper.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Direct endpoints") {
                    TextField("IPv4 hostname", text: $draft.endpointIPv4)
                    TextField("IPv6 hostname", text: $draft.endpointIPv6)
                    TextField("UDP port", value: $draft.endpointPort, format: .number)
                }
                Section("Fly.io proxy") {
                    Toggle("Configure proxy for this profile", isOn: $proxyConfigured)
                    if proxyConfigured {
                        TextField("Proxy domain (relay.example.com)", text: $proxyDomain)
                        TextField("GOST username", text: $proxyUsername)
                        SecureField("GOST password", text: $proxyPassword)
                        Text("Copy WGPROXY_USERNAME and WGPROXY_PASSWORD from .env. This password is separate from the optional WireGuard preshared key.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            Divider()
            HStack {
                Button("Cancel") {
                    store.editorError = nil
                    store.profileEditor = nil
                    dismiss()
                }
                Spacer()
                Button(isNew ? "Add Profile" : "Save Profile") {
                    draft.allowedIPs = allowedIPs.split(separator: ",").map {
                        $0.trimmingCharacters(in: .whitespacesAndNewlines)
                    }.filter { !$0.isEmpty }
                    draft.proxy = proxyConfigured ? ProxySettings(domain: proxyDomain, username: proxyUsername, password: proxyPassword) : nil
                    store.saveProfile(ProfileEditor(profile: draft, isNew: isNew))
                }
                .keyboardShortcut(.defaultAction)
                .disabled(store.networkBusy)
            }
            .padding()
        }
        .frame(width: 560, height: 740)
    }
}

private struct ConnectionSheet: View {
    @EnvironmentObject private var store: ProfileStore
    @Environment(\.dismiss) private var dismiss
    let profile: WGProfile
    @State private var options = ConnectionOptions()

    private var endpoint: String {
        let host = options.family == .ipv4 ? profile.endpointIPv4 : profile.endpointIPv6
        return "\(host):\(profile.endpointPort)"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Connect \(profile.name)").font(.title2).fontWeight(.semibold)
            Toggle("Use Fly.io proxy", isOn: $options.useProxy)
                .disabled(profile.proxy == nil)
            if let proxy = profile.proxy, options.useProxy {
                LabeledContent("Relay", value: "\(proxy.domain):443")
            } else if profile.proxy == nil {
                Text("Configure a proxy domain, username and password in Edit.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Picker("Endpoint family", selection: $options.family) {
                ForEach(EndpointFamily.allCases) { family in Text(family.title).tag(family) }
            }
            .pickerStyle(.segmented)
            Toggle("Replace macOS DNS with \(profile.dns)", isOn: $options.replaceDNS)
            Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 8) {
                GridRow { Text("Endpoint").foregroundStyle(.secondary); Text(endpoint).textSelection(.enabled) }
                GridRow {
                    Text("MTU").foregroundStyle(.secondary)
                    Text(options.useProxy ? "1280 · proxy mode" : (options.family == .ipv4 ? "Automatic · physical MTU − 60" : "Automatic · physical MTU − 80"))
                }
                GridRow { Text("Keepalive").foregroundStyle(.secondary); Text("25 seconds") }
            }
            Text("The profile is held in memory only for this connection attempt.")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Button("Cancel") {
                    store.pendingConnection = nil
                    dismiss()
                }
                Spacer()
                Button("Connect") {
                    store.connect(profile, options: options)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 500)
    }
}

private struct ProfileRow: View {
    @EnvironmentObject private var store: ProfileStore
    @State private var showingCounters = false
    let profile: ProfileSummary

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Text(profile.name).fontWeight(.medium).lineLimit(1)
                if profile.isInvalid {
                    Label("Not saved", systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.red)
                }
                Spacer(minLength: 8)
                if store.isActive(profile) {
                    Text(store.activeTunnel?.phase.rawValue ?? "")
                        .font(.caption).foregroundStyle(statusColor(store.activeTunnel?.phase))
                }
                Toggle("Enable \(profile.name)", isOn: Binding(
                    get: { store.isActive(profile) },
                    set: { _ in store.toggle(profile) }))
                    .toggleStyle(.switch).tint(.green).controlSize(.small).labelsHidden().fixedSize()
                    .disabled(profile.isInvalid || store.networkBusy || (store.activeTunnel != nil && !store.isActive(profile)))
                Button {
                    withAnimation(.easeInOut(duration: 0.15)) { showingCounters.toggle() }
                } label: {
                    Text(showingCounters ? "<<" : ">>").font(.system(.body, design: .monospaced))
                }
                .buttonStyle(.bordered).controlSize(.small)
            }
            if showingCounters { ProfileCounters(profile: profile) }
            if profile.isInvalid && !showingCounters {
                Text("Edit this in-memory draft to retry saving it.")
                    .font(.caption).foregroundStyle(.red)
            }
        }
        .padding(.vertical, 6)
        .contentShape(Rectangle())
    }
}

private struct ProfileCounters: View {
    @EnvironmentObject private var store: ProfileStore
    let profile: ProfileSummary

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Divider()
            if profile.isInvalid {
                Text(profile.issue ?? "Not saved. Edit this profile to retry.")
                    .font(.caption).foregroundStyle(.red)
            } else if let active = store.activeTunnel, active.profileName == profile.name {
                Grid(alignment: .leading, horizontalSpacing: 22, verticalSpacing: 6) {
                    GridRow { Text("Status").foregroundStyle(.secondary); Text(active.phase.rawValue).foregroundStyle(statusColor(active.phase)) }
                    GridRow { Text("Mode").foregroundStyle(.secondary); Text("\(active.usesProxy ? "Proxy" : "Direct") · \(active.recovered ? "recovered session" : active.family.title)") }
                    if let proxy = active.proxyDomain {
                        GridRow { Text("Relay").foregroundStyle(.secondary); Text(proxy) }
                    }
                    GridRow { Text("Uptime").foregroundStyle(.secondary); TimelineView(.periodic(from: .now, by: 1)) { _ in Text(formatDuration(Date().timeIntervalSince(active.connectedAt))).monospacedDigit() } }
                    GridRow { Text("Last handshake").foregroundStyle(.secondary); Text(formatHandshake(active.latestHandshake)) }
                    GridRow { Text("Interface").foregroundStyle(.secondary); Text(active.interfaceName) }
                    GridRow { Text("MTU").foregroundStyle(.secondary); Text("\(active.mtu)") }
                    GridRow { Text("Endpoint").foregroundStyle(.secondary); Text(active.endpointDisplay).textSelection(.enabled) }
                    GridRow { Text("Resolved address").foregroundStyle(.secondary); Text(active.endpointAddress).textSelection(.enabled) }
                    GridRow { Text("Physical path").foregroundStyle(.secondary); Text("\(active.physicalInterface) via \(active.gateway)") }
                    GridRow { Text("DNS").foregroundStyle(.secondary); Text(active.dnsApplied ? "Applied" : "Unchanged") }
                }
                .font(.caption)
                Divider()
                Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 5) {
                    GridRow { Text(""); Text("Received"); Text("Sent") }.foregroundStyle(.secondary)
                    GridRow {
                        Text("WireGuard total")
                        Text(formatBytes(active.wireGuardReceivedBytes))
                        Text(formatBytes(active.wireGuardSentBytes))
                    }
                    GridRow {
                        Text("Rate")
                        Text("\(formatBytes(store.rate.rxBytesPerSecond))/s")
                        Text("\(formatBytes(store.rate.txBytesPerSecond))/s")
                    }
                    GridRow { Text("Packets"); Text("\(store.counters.rxPackets)"); Text("\(store.counters.txPackets)") }
                    GridRow { Text("Errors"); Text("\(store.counters.rxErrors)"); Text("\(store.counters.txErrors)") }
                }
                .font(.caption.monospacedDigit())
            } else {
                Text("Disconnected").font(.caption).foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct ConnectionStatusBar: View {
    @EnvironmentObject private var store: ProfileStore
    var body: some View {
        HStack(spacing: 7) {
            Circle().fill(statusColor(store.activeTunnel?.phase)).frame(width: 7, height: 7)
            Text(store.statusText).font(.caption).foregroundStyle(.secondary)
            if store.networkBusy { ProgressView().controlSize(.small) }
            Spacer()
        }
        .padding(.horizontal, 14).padding(.vertical, 8).background(.bar)
    }
}

private struct MenuBarView: View {
    @EnvironmentObject private var store: ProfileStore
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        ForEach(store.profiles) { profile in
            Button {
                if store.isActive(profile) {
                    store.disconnect()
                } else {
                    showMainWindow()
                    store.prepareConnection(profile)
                }
            } label: {
                HStack {
                    Text(profile.name)
                    Spacer()
                    if store.isActive(profile) {
                        Text("↓ \(formatBytes(store.rate.rxBytesPerSecond))/s · ↑ \(formatBytes(store.rate.txBytesPerSecond))/s")
                        Image(systemName: "checkmark.circle.fill")
                    } else { Image(systemName: "circle") }
                }
            }
            .disabled(profile.isInvalid || store.networkBusy || (store.activeTunnel != nil && !store.isActive(profile)))
        }
        Divider()
        Button("Open Window") { showMainWindow() }
        if store.activeTunnel != nil { Text("Disconnect before quitting").foregroundStyle(.secondary) }
        Button("Quit") { NSApp.terminate(nil) }.disabled(store.activeTunnel != nil)
    }

    private func showMainWindow() {
        NSApp.setActivationPolicy(.regular)
        openWindow(id: "main")
        DispatchQueue.main.async {
            if let window = NSApp.windows.first(where: { $0.canBecomeMain && !($0 is NSPanel) }) {
                if window.isMiniaturized { window.deminiaturize(nil) }
                window.makeKeyAndOrderFront(nil)
            }
            NSApp.activate(ignoringOtherApps: true)
        }
    }
}

private struct StatusIcon: View {
    let phase: TunnelPhase?
    var body: some View {
        Image(systemName: "shield.lefthalf.filled")
            .symbolRenderingMode(.palette)
            .foregroundStyle(statusColor(phase))
    }
}

private func statusColor(_ phase: TunnelPhase?) -> Color {
    switch phase {
    case .connected: return .green
    case .connecting: return .orange
    case .stale: return .yellow
    case nil: return .gray
    }
}

private func formatBytes(_ bytes: UInt64) -> String {
    ByteCountFormatter.string(fromByteCount: Int64(clamping: bytes), countStyle: .file)
}

private func formatDuration(_ interval: TimeInterval) -> String {
    let seconds = max(0, Int(interval))
    return String(format: "%02d:%02d:%02d", seconds / 3600, (seconds / 60) % 60, seconds % 60)
}

private func formatHandshake(_ date: Date?) -> String {
    guard let date else { return "Waiting" }
    let seconds = max(0, Int(Date().timeIntervalSince(date)))
    if seconds < 2 { return "just now" }
    return "\(seconds) seconds ago"
}
