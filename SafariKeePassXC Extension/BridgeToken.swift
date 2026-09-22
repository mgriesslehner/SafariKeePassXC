//
//  BridgeToken.swift
//  SafariKeePassXC Extension
//
//  Reads the per-launch bridge authentication token from the shared Keychain
//  access group so the extension can prove its identity to BridgeServer.
//

import Foundation
import Security

nonisolated enum BridgeToken {

    private static let service = "at.griesslehner.SafariKeePassXC.bridge-token"
    private static let account = "token"

    static func load() -> Data? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        if let group = sharedKeychainGroup() {
            query[kSecAttrAccessGroup as String] = group
        }
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return data
    }

    // Must match the implementation in the host app's BridgeToken.swift.
    static func sharedKeychainGroup() -> String? {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, [], &info) == errSecSuccess,
              let dict = info as? [String: Any],
              let teamID = dict[kSecCodeInfoTeamIdentifier as String] as? String,
              !teamID.isEmpty else { return nil }
        return "\(teamID).at.griesslehner.SafariKeePassXC"
    }
}

extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}
