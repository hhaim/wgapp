import Foundation

private struct TestInput: Decodable {
    var proxy: ProxySettings
    var localPort: UInt16
    var endpointHost: String
    var endpointPort: UInt16
    var relayAddress: String
}

@main
struct EmitGOSTTestConfiguration {
    static func main() throws {
        let request = try JSONDecoder().decode(TestInput.self, from: FileHandle.standardInput.readDataToEndOfFile())
        try ProfileValidator.validateProxy(request.proxy)
        try FileHandle.standardOutput.write(contentsOf: GOSTConfiguration.data(
            proxy: request.proxy, localPort: request.localPort, endpointHost: request.endpointHost,
            endpointPort: request.endpointPort, relayAddress: request.relayAddress))
    }
}
