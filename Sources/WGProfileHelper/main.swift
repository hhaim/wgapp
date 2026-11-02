import Foundation
import Security
import LocalAuthentication
import Darwin

enum HelperError: LocalizedError {
    case message(String)

    var errorDescription: String? {
        switch self { case .message(let message): return message }
    }
}

func requireGUIConsoleSession() throws {
    let attributes = try FileManager.default.attributesOfItem(atPath: "/dev/console")
    guard let owner = attributes[.ownerAccountID] as? NSNumber, owner.uint32Value == getuid() else {
        throw HelperError.message("WGProfileHelper must run as the logged-in local GUI user.")
    }
}

func keychainQuery(account: String? = nil, forAdd: Bool = false) throws -> [String: Any] {
    var keychain: SecKeychain?
    try checkStatus(SecKeychainCopyDefault(&keychain), operation: "open login Keychain")
    guard let keychain else { throw HelperError.message("macOS did not return the login Keychain.") }
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: wgAppKeychainService,
        (forAdd ? kSecUseKeychain : kSecMatchSearchList) as String: forAdd ? keychain : [keychain]
    ]
    if let account { query[kSecAttrAccount as String] = account }
    return query
}

func authenticationContext(reason: String) -> LAContext {
    let context = LAContext()
    context.localizedReason = reason
    context.localizedCancelTitle = "Cancel"
    context.localizedFallbackTitle = ""
    return context
}

func authenticate(reason: String) throws -> Data {
    let context = authenticationContext(reason: reason)
    var policyError: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &policyError) else {
        if (policyError as? LAError)?.code == .biometryLockout {
            throw HelperError.message("Touch ID is locked. Unlock your Mac with its login password, then retry Touch ID in WGApp.")
        }
        throw policyError ?? HelperError.message("Touch ID is not enrolled or available.") as NSError
    }
    let semaphore = DispatchSemaphore(value: 0)
    var accepted = false
    var authenticationError: Error?
    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
        accepted = success
        authenticationError = error
        semaphore.signal()
    }
    semaphore.wait()
    guard accepted else { throw authenticationError ?? HelperError.message("Touch ID was cancelled or failed.") }
    guard let state = context.evaluatedPolicyDomainState else {
        throw HelperError.message("macOS did not return the current Touch ID enrollment state.")
    }
    return state
}

func checkStatus(_ status: OSStatus, operation: String) throws {
    guard status == errSecSuccess else {
        if status == errSecUserCanceled || status == errSecAuthFailed {
            throw HelperError.message("Touch ID was cancelled or failed.")
        }
        if status == errSecItemNotFound {
            throw HelperError.message("Profile was not found.")
        }
        let detail = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
        throw HelperError.message("Keychain \(operation) failed: \(detail)")
    }
}

func profileDataFromStdin(expectedName: String) throws -> Data {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    guard !data.isEmpty else { throw HelperError.message("Expected one profile JSON object on stdin.") }
    // Business validation belongs to the app and root launcher. Keeping this
    // storage helper independent of profile fields preserves its signed identity
    // across ordinary app/model updates and avoids renewed Keychain ACL prompts.
    guard let profile = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          let version = profile["version"] as? NSNumber, version.doubleValue == 1,
          CFGetTypeID(version) != CFBooleanGetTypeID() else {
        throw HelperError.message("Expected a version 1 profile JSON object.")
    }
    guard !expectedName.isEmpty, expectedName.count <= 80, !expectedName.contains("\n"),
          profile["name"] as? String == expectedName else {
        throw HelperError.message("The profile JSON name must match the account name.")
    }
    return try JSONSerialization.data(withJSONObject: profile, options: [.sortedKeys])
}

func addProfile(account: String) throws {
    let data = try profileDataFromStdin(expectedName: account)
    let enrollmentState = try authenticate(reason: "Protect WireGuard profile \(account)")
    var query = try keychainQuery(account: account, forAdd: true)
    query[kSecValueData as String] = data
    query[kSecAttrGeneric as String] = enrollmentState
    query[kSecAttrLabel as String] = "WGApp profile: \(account)"
    try checkStatus(SecItemAdd(query as CFDictionary, nil), operation: "add")
}

func readProfile(account: String, enrollmentState: Data) throws -> Data {
    var query = try keychainQuery(account: account)
    query[kSecReturnData as String] = true
    query[kSecReturnAttributes as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    try checkStatus(SecItemCopyMatching(query as CFDictionary, &result), operation: "read")
    guard let row = result as? [String: Any],
          let data = row[kSecValueData as String] as? Data,
          let savedState = row[kSecAttrGeneric as String] as? Data else {
        throw HelperError.message("Keychain returned an invalid profile value.")
    }
    guard savedState == enrollmentState else {
        throw HelperError.message("The enrolled Touch ID set has changed. Delete and add this profile again.")
    }
    return data
}

func readProfile(account: String, reason: String) throws -> Data {
    try readProfile(account: account, enrollmentState: authenticate(reason: reason))
}

func editProfile(account: String) throws {
    let enrollmentState = try authenticate(reason: "Edit WireGuard profile \(account)")
    _ = try readProfile(account: account, enrollmentState: enrollmentState)
    let replacement = try profileDataFromStdin(expectedName: account)
    let status = SecItemUpdate(try keychainQuery(account: account) as CFDictionary,
                               [kSecValueData as String: replacement] as CFDictionary)
    try checkStatus(status, operation: "update")
}

func listProfiles() throws -> Data {
    var query = try keychainQuery()
    query[kSecReturnAttributes as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitAll
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { return try JSONEncoder().encode([String]()) }
    try checkStatus(status, operation: "list")
    let rows: [[String: Any]]
    if let many = result as? [[String: Any]] { rows = many }
    else if let one = result as? [String: Any] { rows = [one] }
    else { throw HelperError.message("Keychain returned invalid profile attributes.") }
    var names = rows.compactMap { $0[kSecAttrAccount as String] as? String }
    names.sort { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
    return try JSONEncoder().encode(names)
}

func deleteProfile(account: String) throws {
    let enrollmentState = try authenticate(reason: "Delete WireGuard profile \(account)")
    _ = try readProfile(account: account, enrollmentState: enrollmentState)
    try checkStatus(SecItemDelete(try keychainQuery(account: account) as CFDictionary), operation: "delete")
}

func writeStdout(_ data: Data) throws {
    try FileHandle.standardOutput.write(contentsOf: data)
}

@main
struct WGProfileHelper {
    static func main() {
        do {
            try requireGUIConsoleSession()
            let arguments = Array(CommandLine.arguments.dropFirst())
            guard let command = arguments.first else {
                throw HelperError.message("Usage: WGProfileHelper {add|edit|get|list|delete} [profile-name]")
            }
            switch command {
            case "list" where arguments.count == 1:
                try writeStdout(try listProfiles())
            case "add" where arguments.count == 2:
                try addProfile(account: arguments[1])
            case "edit" where arguments.count == 2:
                try editProfile(account: arguments[1])
            case "get" where arguments.count == 2:
                guard isatty(STDOUT_FILENO) == 0 else {
                    throw HelperError.message("Refusing to print a profile to a terminal; pipe stdout directly to the launcher.")
                }
                try writeStdout(try readProfile(account: arguments[1], reason: "Connect WireGuard profile \(arguments[1])"))
            case "delete" where arguments.count == 2:
                try deleteProfile(account: arguments[1])
            default:
                throw HelperError.message("Usage: WGProfileHelper {add|edit|get|list|delete} [profile-name]")
            }
        } catch {
            FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
            exit(1)
        }
    }
}
