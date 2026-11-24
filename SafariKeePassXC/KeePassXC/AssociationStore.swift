//
//  AssociationStore.swift
//  SafariKeePassXC Extension
//
//  Stores the KeePassXC association (database id + id public key) in the
//  Keychain.
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
        if let association = read(dataProtection: true) {
            return association
        }
        guard let legacy = read(dataProtection: false) else { return nil }
        guard (try? save(legacy)) != nil else { return legacy }
        deleteLegacy()
        return legacy
    }

    private func read(dataProtection: Bool) -> Association? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        if dataProtection {
            query[kSecUseDataProtectionKeychain as String] = true
        }
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let association = try? JSONDecoder().decode(Association.self, from: data) else {
            return nil
        }
        return association
    }

    private func deleteLegacy() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.account,
        ]
        SecItemDelete(query as CFDictionary)
    }

    func save(_ association: Association) throws {
        let data = try JSONEncoder().encode(association)
        deleteDataProtectionItem()
        let attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.account,
            kSecValueData as String: data,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status),
                          userInfo: [NSLocalizedDescriptionKey: "keychain_save_failed"])
        }
    }

    func clear() {
        deleteDataProtectionItem()
        deleteLegacy()
    }

    private func deleteDataProtectionItem() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.account,
            kSecUseDataProtectionKeychain as String: true,
        ]
        SecItemDelete(query as CFDictionary)
    }
}
