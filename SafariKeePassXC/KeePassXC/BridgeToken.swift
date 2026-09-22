//
//  BridgeToken.swift
//  SafariKeePassXC
//
//  Generates and verifies the per-launch bridge token. Written to a shared
//  Keychain group so the extension can prove to BridgeServer that it's the
//  real extension process, not just something that found the socket path.
//
//  SETUP: both targets need "Keychain Sharing" in Xcode, group
//  "at.griesslehner.SafariKeePassXC".
//

import Foundation
import Security
import os.log

nonisolated enum BridgeToken {

    private static let service = "at.griesslehner.SafariKeePassXC.bridge-token"
    private static let account = "token"

    // Generates a fresh 32-byte random token, writes it to the shared Keychain
    // group, and returns it. Call once in BridgeServer.start() before accepting
    // connections.
    @discardableResult
    static func generate() -> Data? {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            os_log(.error, "BridgeToken: SecRandomCopyBytes failed")
            return nil
        }
        let token = Data(bytes)
        deleteExisting()

        var attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: token,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        if let group = sharedKeychainGroup() {
            attributes[kSecAttrAccessGroup as String] = group
        }

        let status = SecItemAdd(attributes as CFDictionary, nil)
        if status != errSecSuccess {
            os_log(.error, "BridgeToken: Keychain write failed (OSStatus %d)", status)
            return nil
        }
        return token
    }

    // Reads the current token from the Keychain.
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

    // Constant-time comparison to guard against timing side-channels.
    static func verify(_ incoming: Data) -> Bool {
        guard let expected = load(), incoming.count == expected.count else { return false }
        var diff: UInt8 = 0
        for (a, b) in zip(incoming, expected) { diff |= a ^ b }
        return diff == 0
    }

    private static func deleteExisting() {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if let group = sharedKeychainGroup() {
            query[kSecAttrAccessGroup as String] = group
        }
        SecItemDelete(query as CFDictionary)
    }

    // Derives the Keychain access group from the running process's Team ID via
    // code-signing info. Returns nil for unsigned / ad-hoc builds, in which
    // case the token is stored without an access group (development only).
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

    nonisolated init?(hexString: String) {
        guard hexString.count % 2 == 0 else { return nil }
        var data = Data(capacity: hexString.count / 2)
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let next = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        self = data
    }
}
