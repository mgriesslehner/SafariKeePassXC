//
//  AssociationStore.swift
//  SafariKeePassXC Extension
//
//  Stores the KeePassXC association (database id + id public key) in the
//  Keychain. No passwords ever end up here, just the public id key.
//

import Foundation
import Security

nonisolated struct Association: Codable, Sendable {
    let id: String
    let publicKey: String
}

nonisolated struct AssociationStore {

    private static let service = "at.griesslehner.SafariKeePassXC"
    private static let account = "keepassxc-association"

    func load() -> Association? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let association = try? JSONDecoder().decode(Association.self, from: data) else {
            return nil
        }
        return association
    }

    func save(_ association: Association) throws {
        let data = try JSONEncoder().encode(association)
        clear()
        let attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.account,
            kSecValueData as String: data,
        ]
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status),
                          userInfo: [NSLocalizedDescriptionKey: "keychain_save_failed"])
        }
    }

    func clear() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.account,
        ]
        SecItemDelete(query as CFDictionary)
    }
}
