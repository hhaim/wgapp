import Foundation

enum GOSTConfiguration {
    static func data(proxy: ProxySettings, localPort: UInt16, endpointHost: String,
                     endpointPort: UInt16, relayAddress: String) throws -> Data {
        func authority(_ host: String, _ port: UInt16) -> String {
            host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
        }
        let configuration: [String: Any] = [
            "log": ["level": "error", "output": "stderr"],
            "services": [[
                "name": "wireguard", "addr": "127.0.0.1:\(localPort)",
                "handler": ["type": "udp", "chain": "relay"],
                "listener": ["type": "udp", "metadata": ["keepAlive": true, "ttl": "2m", "readQueueSize": 128]],
                "forwarder": ["nodes": [["name": "home", "addr": authority(endpointHost, endpointPort)]]]
            ]],
            "chains": [["name": "relay", "hops": [["name": "fly", "nodes": [[
                "name": "proxy", "addr": authority(relayAddress, 443),
                "connector": ["type": "relay", "auth": ["username": proxy.username, "password": proxy.password]],
                "dialer": ["type": "wss", "metadata": ["host": proxy.domain, "path": "/ws",
                    "keepAlive": true, "ttl": "20s", "handshakeTimeout": "15s"],
                    "tls": ["secure": true, "serverName": proxy.domain]]
            ]]]]]]
        ]
        return try JSONSerialization.data(withJSONObject: configuration, options: [.sortedKeys])
    }
}
