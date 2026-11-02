import Foundation
import Darwin

struct ProxySettings: Codable, Equatable {
    var domain: String
    var username: String
    var password: String

    init(domain: String, username: String = "relay-user", password: String) {
        self.domain = domain
        self.username = username
        self.password = password
    }

    private enum CodingKeys: String, CodingKey { case domain, username, password, accessKey }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        domain = try values.decode(String.self, forKey: .domain)
        username = try values.decodeIfPresent(String.self, forKey: .username) ?? "relay-user"
        password = try values.decodeIfPresent(String.self, forKey: .password)
            ?? values.decode(String.self, forKey: .accessKey)
    }

    func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(domain, forKey: .domain)
        try values.encode(username, forKey: .username)
        try values.encode(password, forKey: .password)
    }
}

struct WGProfile: Codable, Equatable, Identifiable {
    static let currentVersion = 1

    var version: Int = currentVersion
    var name: String
    var privateKey: String
    var presharedKey: String?
    var peerPublicKey: String
    var address: String
    var allowedIPs: [String]
    var dns: String
    var endpointIPv4: String
    var endpointIPv6: String
    var endpointPort: UInt16 = 51820
    var proxy: ProxySettings?

    var id: String { name }
}

enum EndpointFamily: String, Codable, CaseIterable, Identifiable {
    case ipv4
    case ipv6

    var id: String { rawValue }
    var title: String { self == .ipv4 ? "IPv4" : "IPv6" }
    var addressFamily: Int32 { self == .ipv4 ? AF_INET : AF_INET6 }
    var directOverhead: Int { self == .ipv4 ? 60 : 80 }
}

struct RootUpRequest: Codable {
    var logicalName: String
    var privateKey: String
    var presharedKey: String?
    var peerPublicKey: String
    var address: String
    var allowedIPs: [String]
    var dns: String?
    var endpointHost: String
    var endpointPort: UInt16
    var endpointFamily: EndpointFamily
    var persistentKeepalive: UInt16
    var proxy: ProxySettings? = nil
}

struct DNSServiceState: Codable, Equatable {
    var name: String
    var servers: [String]
}

struct SupervisorState: Codable {
    var logicalName: String
    var interfaceName: String
    var endpointAddress: String
    var endpointRouteAdded: Bool
    var routes: [String]
    var dnsBaseline: [DNSServiceState]
    var transportRoutes: [String]? = nil
    var proxyPID: Int32? = nil
    var physicalFamily: EndpointFamily? = nil
    var physicalInterface: String? = nil
    var physicalGateway: String? = nil
}

struct RootUpResult: Codable {
    var logicalName: String
    var interfaceName: String
    var endpointAddress: String
    var endpointDisplay: String
    var physicalInterface: String
    var gateway: String
    var mtu: Int
    var dnsApplied: Bool
}

struct RootNameRequest: Codable {
    var logicalName: String
}

struct RootStatusResult: Codable {
    var active: Bool
    var interfaceName: String?
    var endpoint: String?
    var latestHandshake: Int64
    var receivedBytes: UInt64
    var sentBytes: UInt64
    var mtu: Int?
    var launcherVersion: Int? = 3
}

enum ProfileValidationError: LocalizedError {
    case message(String)

    var errorDescription: String? {
        switch self { case .message(let message): return message }
    }
}

enum ProfileValidator {
    static func validate(_ profile: WGProfile) throws {
        guard profile.version == WGProfile.currentVersion else {
            throw ProfileValidationError.message("Unsupported profile version: \(profile.version).")
        }
        let name = profile.name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty && name.count <= 80 && !name.contains("\n") else {
            throw ProfileValidationError.message("Profile name must contain 1 to 80 characters.")
        }
        try validateKey(profile.privateKey, field: "Private key")
        if let presharedKey = profile.presharedKey?.trimmingCharacters(in: .whitespacesAndNewlines), !presharedKey.isEmpty {
            try validateKey(presharedKey, field: "Preshared key")
        }
        try validateKey(profile.peerPublicKey, field: "Peer public key")
        try validateIPAddress(profile.address, field: "Interface IP address")
        guard !profile.allowedIPs.isEmpty else {
            throw ProfileValidationError.message("Enter at least one AllowedIPs network.")
        }
        for allowedIP in profile.allowedIPs {
            let network = try parseNetwork(allowedIP, field: "AllowedIPs", requireHost: false)
            if network.prefix == 0 {
                throw ProfileValidationError.message("Default routes 0.0.0.0/0 and ::/0 are not allowed.")
            }
        }
        try validateIPAddress(profile.dns, field: "DNS")
        try validateEndpointHost(profile.endpointIPv4, field: "IPv4 endpoint")
        try validateEndpointHost(profile.endpointIPv6, field: "IPv6 endpoint")
        guard profile.endpointPort > 0 else {
            throw ProfileValidationError.message("Endpoint port must be between 1 and 65535.")
        }
        if let proxy = profile.proxy { try validateProxy(proxy) }
    }

    static func normalized(_ profile: WGProfile) throws -> WGProfile {
        var copy = profile
        copy.name = copy.name.trimmingCharacters(in: .whitespacesAndNewlines)
        copy.privateKey = copy.privateKey.trimmingCharacters(in: .whitespacesAndNewlines)
        copy.presharedKey = copy.presharedKey?.trimmingCharacters(in: .whitespacesAndNewlines)
        if copy.presharedKey?.isEmpty == true { copy.presharedKey = nil }
        copy.peerPublicKey = copy.peerPublicKey.trimmingCharacters(in: .whitespacesAndNewlines)
        copy.address = copy.address.trimmingCharacters(in: .whitespacesAndNewlines)
        copy.allowedIPs = copy.allowedIPs.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        copy.dns = copy.dns.trimmingCharacters(in: .whitespacesAndNewlines)
        copy.endpointIPv4 = copy.endpointIPv4.trimmingCharacters(in: .whitespacesAndNewlines)
        copy.endpointIPv6 = copy.endpointIPv6.trimmingCharacters(in: .whitespacesAndNewlines)
        if let proxy = copy.proxy {
            copy.proxy = ProxySettings(domain: proxy.domain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
                                       username: proxy.username.trimmingCharacters(in: .whitespacesAndNewlines),
                                       password: proxy.password.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        try validate(copy)
        return copy
    }

    static func validateKey(_ value: String, field: String) throws {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let decoded = Data(base64Encoded: trimmed), decoded.count == 32 else {
            throw ProfileValidationError.message("\(field) must be a WireGuard base64 key.")
        }
    }

    static func validateProxy(_ proxy: ProxySettings) throws {
        guard proxy.domain.count <= 253,
              proxy.domain.range(of: #"^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$"#, options: .regularExpression) != nil,
              proxy.domain.contains("."), !proxy.domain.contains("..") else {
            throw ProfileValidationError.message("Proxy domain must be a hostname, such as relay.example.com, without a scheme or port.")
        }
        guard proxy.username.range(of: #"^[a-zA-Z0-9_.-]{1,64}$"#, options: .regularExpression) != nil else {
            throw ProfileValidationError.message("Proxy username must contain 1 to 64 letters, digits, underscores, dots or hyphens.")
        }
        guard proxy.password.range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil else {
            throw ProfileValidationError.message("Proxy password must contain the 64 hexadecimal characters generated by publish_flyio.")
        }
    }

    static func validateIPAddress(_ value: String, field: String) throws {
        var ipv4 = in_addr()
        var ipv6 = in6_addr()
        let valid = value.withCString {
            inet_pton(AF_INET, $0, &ipv4) == 1 || inet_pton(AF_INET6, $0, &ipv6) == 1
        }
        guard valid else { throw ProfileValidationError.message("\(field) must be one IPv4 or IPv6 address.") }
    }

    static func validateEndpointHost(_ value: String, field: String) throws {
        let host = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty, host.count <= 253, !host.contains(where: { $0.isWhitespace || $0 == "/" }) else {
            throw ProfileValidationError.message("\(field) must be a hostname or address without a port.")
        }
    }

    private struct ParsedNetwork { let family: Int32; let prefix: Int }

    private static func parseNetwork(_ value: String, field: String, requireHost: Bool) throws -> ParsedNetwork {
        let parts = value.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let prefix = Int(parts[1]) else {
            throw ProfileValidationError.message("\(field) must use CIDR notation.")
        }
        let address = String(parts[0])
        var ipv4 = in_addr()
        if address.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            guard (0...32).contains(prefix), !requireHost || prefix > 0 else {
                throw ProfileValidationError.message("Invalid IPv4 prefix in \(field).")
            }
            return ParsedNetwork(family: AF_INET, prefix: prefix)
        }
        var ipv6 = in6_addr()
        if address.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
            guard (0...128).contains(prefix), !requireHost || prefix > 0 else {
                throw ProfileValidationError.message("Invalid IPv6 prefix in \(field).")
            }
            return ParsedNetwork(family: AF_INET6, prefix: prefix)
        }
        throw ProfileValidationError.message("Invalid address in \(field): \(address)")
    }
}
