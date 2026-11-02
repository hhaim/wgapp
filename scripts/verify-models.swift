import Foundation

@main
struct VerifyModels {
    static func main() throws {
        // Synthetic key bytes are made in memory; no real profile is loaded.
        let placeholder = Data(repeating: 0, count: 32).base64EncodedString()
        var profile = WGProfile(name: "model-check", privateKey: placeholder, presharedKey: nil,
                                peerPublicKey: placeholder, address: "10.0.0.1",
                                allowedIPs: ["10.13.13.0/24", "10.0.0.0/24"], dns: "10.0.0.53",
                                endpointIPv4: "ipv4.example.net", endpointIPv6: "ipv6.example.net",
                                endpointPort: 51820, proxy: nil)
        try ProfileValidator.validate(profile)
        let direct = try JSONDecoder().decode(WGProfile.self, from: JSONEncoder().encode(profile))
        precondition(direct.proxy == nil && direct.address == "10.0.0.1")
        print("PASS existing direct profile and multiple AllowedIPs remain compatible")

        profile.proxy = ProxySettings(domain: "relay.example.com", username: "test-user", password: String(repeating: "a", count: 64))
        let proxy = try JSONDecoder().decode(WGProfile.self, from: JSONEncoder().encode(profile))
        try ProfileValidator.validate(proxy)
        precondition(proxy.privateKey == direct.privateKey && proxy.endpointIPv6 == direct.endpointIPv6)
        precondition(proxy.proxy?.username == "test-user" && proxy.proxy?.password == String(repeating: "a", count: 64))
        print("PASS one profile retains the same WG keys and both endpoints in proxy mode")

        for invalid in [ProxySettings(domain: "https://relay.example.com", password: String(repeating: "a", count: 64)),
                        ProxySettings(domain: "relay.example.com", password: "short"),
                        ProxySettings(domain: "relay.example.com", username: "bad\nname", password: String(repeating: "a", count: 64))] {
            do {
                try ProfileValidator.validateProxy(invalid)
                fatalError("Invalid proxy settings were accepted")
            } catch is ProfileValidationError { }
        }
        print("PASS invalid proxy domain, username and password are rejected")
        let legacyProxy = Data("{\"domain\":\"relay.example.com\",\"accessKey\":\"\(String(repeating: "a", count: 64))\"}".utf8)
        let migrated = try JSONDecoder().decode(ProxySettings.self, from: legacyProxy)
        precondition(migrated.username == "relay-user" && migrated.password == String(repeating: "a", count: 64))
        let fields = try JSONSerialization.jsonObject(with: JSONEncoder().encode(migrated)) as! [String: Any]
        precondition(fields["accessKey"] == nil && fields["username"] as? String == "relay-user")
        print("PASS old accessKey profiles migrate in memory to explicit username/password")

        // A pre-proxy root helper must not be mistaken for a proxy-capable one.
        let oldStatus = Data(#"{"active":false,"latestHandshake":0,"receivedBytes":0,"sentBytes":0}"#.utf8)
        let old = try JSONDecoder().decode(RootStatusResult.self, from: oldStatus)
        precondition(old.launcherVersion == nil)
        let current = RootStatusResult(active: false, interfaceName: nil, endpoint: nil, latestHandshake: 0,
                                       receivedBytes: 0, sentBytes: 0, mtu: nil)
        let roundTrip = try JSONDecoder().decode(RootStatusResult.self, from: JSONEncoder().encode(current))
        precondition(roundTrip.launcherVersion == 3)
        print("PASS old root helpers cannot advertise proxy capability; current helpers can")
    }
}
