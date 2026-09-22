//
//  KeePassXCClient.swift
//  SafariKeePassXC Extension
//
//  Talks to KeePassXC over its browser integration protocol. Nothing else
//  in the extension touches sockets or encryption directly.
//

import Foundation
import Sodium
import os.log

// MARK: - Public result types

struct KeePassXCStatus: Sendable {
    let connected: Bool
    let associated: Bool
    let databaseHash: String?
    let keePassXCVersion: String?
    let error: String?
}

struct LoginEntry: Sendable {
    let name: String
    let login: String
    let password: String
    let uuid: String
    let group: String?
    let totp: String?
    let expired: Bool
}

struct DatabaseGroup: Sendable {
    let name: String
    let uuid: String
}

// MARK: - Errors

enum KeePassXCError: LocalizedError {
    case notReachable(String)
    case handshakeFailed
    case cryptoFailure
    case invalidResponse
    case responseTooLarge
    case notAssociated
    case keePassXC(code: Int, message: String)

    var errorDescription: String? {
        switch self {
        case .notReachable(let reason):
            return "keepassxc_not_reachable: \(reason)"
        case .handshakeFailed:
            return "handshake_failed"
        case .cryptoFailure:
            return "crypto_failure"
        case .invalidResponse:
            return "invalid_response"
        case .responseTooLarge:
            return "response_too_large"
        case .notAssociated:
            return "not_associated"
        case .keePassXC(let code, let message):
            return "keepassxc_error \(code): \(message)"
        }
    }
}

// MARK: - Client

actor KeePassXCClient {

    static let shared = KeePassXCClient()
    static let bridgeVersion = "0.1"

    private static let maxResponseSize = 1024 * 1024
    private static let maxReceiveChunks = 64

    private let socket = UnixSocketConnection()
    private let store = AssociationStore()
    private var crypto: KeePassXCCrypto?
    private var hostPublicKey: Bytes?
    private var clientID: String?

    // MARK: Public API

    func ping() -> [String: Any] {
        ["version": Self.bridgeVersion]
    }

    func status() async -> KeePassXCStatus {
        do {
            try await ensureSession()
        } catch {
            return KeePassXCStatus(
                connected: false,
                associated: false,
                databaseHash: nil,
                keePassXCVersion: nil,
                error: (error as? LocalizedError)?.errorDescription
                ?? String(describing: error)
            )
        }

        var hash: String?
        var version: String?
        var associated = false
        var reportedError: String?

        do {
            let response = try await sendEncrypted(
                action: "get-databasehash",
                payload: [:]
            )

            hash = response["hash"] as? String
            version = response["version"] as? String

            if let association = store.load() {
                let testResponse = try? await sendEncrypted(
                    action: "test-associate",
                    payload: [
                        "id": association.id,
                        "key": association.publicKey,
                    ]
                )

                associated = (testResponse?["success"] as? String) == "true"
            }
        } catch {
            reportedError = (error as? LocalizedError)?.errorDescription
            ?? String(describing: error)
        }

        return KeePassXCStatus(
            connected: true,
            associated: associated,
            databaseHash: hash,
            keePassXCVersion: version,
            error: reportedError
        )
    }

    func associate() async throws -> Association {
        try await ensureSession()

        guard let crypto else {
            throw KeePassXCError.handshakeFailed
        }

        guard let idKeyPair = Sodium().box.keyPair() else {
            throw KeePassXCError.cryptoFailure
        }

        let idPublicKeyBase64 = Data(idKeyPair.publicKey).base64EncodedString()

        let response = try await sendEncrypted(
            action: "associate",
            payload: [
                "key": crypto.publicKeyBase64,
                "idKey": idPublicKeyBase64,
            ]
        )

        guard let id = response["id"] as? String else {
            throw KeePassXCError.invalidResponse
        }

        let association = Association(
            id: id,
            publicKey: idPublicKeyBase64
        )

        try store.save(association)
        return association
    }

    func getLogins(
        for url: String,
        submitUrl: String? = nil
    ) async throws -> [LoginEntry] {
        guard let association = store.load() else {
            throw KeePassXCError.notAssociated
        }

        try await ensureSession()

        var payload: [String: Any] = [
            "url": url,
            "keys": [
                [
                    "id": association.id,
                    "key": association.publicKey,
                ]
            ],
        ]

        if let submitUrl {
            payload["submitUrl"] = submitUrl
        }

        let response = try await sendEncrypted(
            action: "get-logins",
            payload: payload
        )

        let rawEntries = response["entries"] as? [[String: Any]] ?? []

        return rawEntries.map { raw in
            LoginEntry(
                name: raw["name"] as? String ?? "",
                login: raw["login"] as? String ?? "",
                password: raw["password"] as? String ?? "",
                uuid: raw["uuid"] as? String ?? "",
                group: raw["group"] as? String,
                totp: raw["totp"] as? String,
                expired: (raw["expired"] as? String) == "true"
                || (raw["expired"] as? Bool) == true
            )
        }
    }

    func setLogin(
        url: String,
        submitUrl: String?,
        login: String,
        password: String,
        uuid: String?,
        group: String? = nil,
        groupUuid: String? = nil
    ) async throws {
        guard let association = store.load() else {
            throw KeePassXCError.notAssociated
        }

        try await ensureSession()

        var payload: [String: Any] = [
            "url": url,
            "submitUrl": submitUrl ?? url,
            "id": association.id,
            "login": login,
            "password": password,
        ]

        if let uuid {
            payload["uuid"] = uuid
        }

        if let group {
            payload["group"] = group
        }

        if let groupUuid {
            payload["groupUuid"] = groupUuid
        }

        let response = try await sendEncrypted(
            action: "set-login",
            payload: payload
        )

        guard (response["success"] as? String) == "true" else {
            throw KeePassXCError.invalidResponse
        }
    }

    func databaseGroups() async throws -> [DatabaseGroup] {
        try await ensureSession()

        let response = try await sendEncrypted(
            action: "get-database-groups",
            payload: [:]
        )

        guard
            let wrapper = response["groups"] as? [String: Any],
            let roots = wrapper["groups"] as? [[String: Any]]
        else {
            throw KeePassXCError.invalidResponse
        }

        var groups: [DatabaseGroup] = []

        func walk(_ nodes: [[String: Any]], path: String) {
            for node in nodes {
                guard
                    let name = node["name"] as? String,
                    let uuid = node["uuid"] as? String
                else {
                    continue
                }

                let fullPath = path.isEmpty
                ? name
                : path + "/" + name

                groups.append(
                    DatabaseGroup(
                        name: fullPath,
                        uuid: uuid
                    )
                )

                if let children = node["children"] as? [[String: Any]] {
                    walk(children, path: fullPath)
                }
            }
        }

        walk(roots, path: "")
        return groups
    }

    func generatePassword() async throws -> String {
        try await ensureSession()

        let response = try await sendEncrypted(
            action: "generate-password",
            payload: [:]
        )

        if let password = response["password"] as? String {
            return password
        }

        // KeePassXC < 2.7 wrapped the password in an entries array.
        if
            let entries = response["entries"] as? [[String: Any]],
            let password = entries.first?["password"] as? String
        {
            return password
        }

        throw KeePassXCError.invalidResponse
    }

    // MARK: Session / handshake

    private func ensureSession() async throws {
        if await socket.isConnected,
           crypto != nil,
           hostPublicKey != nil,
           clientID != nil {
            return
        }

        // Fresh session: new transport, new ephemeral keys, new clientID.
        await socket.disconnect()

        crypto = nil
        hostPublicKey = nil
        clientID = nil

        do {
            try await socket.connect(to: Self.socketPath())
        } catch {
            throw KeePassXCError.notReachable(
                (error as? LocalizedError)?.errorDescription
                ?? String(describing: error)
            )
        }

        guard let newCrypto = KeePassXCCrypto() else {
            throw KeePassXCError.cryptoFailure
        }

        guard let newClientID = newCrypto.newClientID(),
              let nonce = newCrypto.newNonce() else {
            throw KeePassXCError.cryptoFailure
        }

        let response = try await roundTrip(
            [
                "action": "change-public-keys",
                "publicKey": newCrypto.publicKeyBase64,
                "nonce": Data(nonce).base64EncodedString(),
                "clientID": newClientID,
            ],
            expecting: "change-public-keys"
        )

        guard
            (response["success"] as? String) == "true",
            let hostKeyBase64 = response["publicKey"] as? String,
            let hostKey = Data(base64Encoded: hostKeyBase64)
        else {
            throw KeePassXCError.handshakeFailed
        }

        crypto = newCrypto
        hostPublicKey = Bytes(hostKey)
        clientID = newClientID
    }

    private func sendEncrypted(
        action: String,
        payload: [String: Any]
    ) async throws -> [String: Any] {
        guard
            let crypto,
            let hostPublicKey,
            let clientID
        else {
            throw KeePassXCError.handshakeFailed
        }

        var inner = payload
        inner["action"] = action

        guard let nonce = crypto.newNonce() else {
            throw KeePassXCError.cryptoFailure
        }

        guard let message = crypto.encrypt(
            inner,
            nonce: nonce,
            hostPublicKey: hostPublicKey
        ) else {
            throw KeePassXCError.cryptoFailure
        }

        let envelope: [String: Any] = [
            "action": action,
            "message": message,
            "nonce": Data(nonce).base64EncodedString(),
            "clientID": clientID,
        ]

        let response: [String: Any]

        do {
            response = try await roundTrip(
                envelope,
                expecting: action
            )
        } catch let error as KeePassXCError {
            // A KeePassXC-level error (e.g. no logins found) doesn't mean the
            // session is broken, so only reset on actual transport failures.
            if case .keePassXC = error {
                throw error
            }
            self.crypto = nil
            self.hostPublicKey = nil
            self.clientID = nil
            await socket.disconnect()
            throw error
        } catch {
            self.crypto = nil
            self.hostPublicKey = nil
            self.clientID = nil
            await socket.disconnect()
            throw error
        }

        guard
            let responseNonceBase64 = response["nonce"] as? String,
            let responseNonce = Data(base64Encoded: responseNonceBase64),
            let encrypted = response["message"] as? String
        else {
            throw KeePassXCError.invalidResponse
        }

        guard Bytes(responseNonce) == KeePassXCCrypto.incremented(nonce) else {
            throw KeePassXCError.invalidResponse
        }

        guard let decrypted = crypto.decrypt(
            encrypted,
            nonce: Bytes(responseNonce),
            hostPublicKey: hostPublicKey
        ) else {
            throw KeePassXCError.cryptoFailure
        }

        if let error = Self.protocolError(in: decrypted) {
            throw error
        }

        return decrypted
    }

    private func roundTrip(
        _ body: [String: Any],
        expecting action: String
    ) async throws -> [String: Any] {
        let data = try JSONSerialization.data(withJSONObject: body)
        try await socket.send(data)

        var buffer = Data()

        for _ in 0..<Self.maxReceiveChunks {
            let chunk = try await socket.receive()

            // Protect against both a huge individual read and unbounded
            // accumulation of an incomplete JSON object.
            guard chunk.count <= Self.maxResponseSize else {
                throw KeePassXCError.responseTooLarge
            }

            guard buffer.count <= Self.maxResponseSize - chunk.count else {
                throw KeePassXCError.responseTooLarge
            }

            buffer.append(chunk)

            for messageData in try Self.completeJSONObjects(
                in: &buffer
            ) {
                guard let json = try? JSONSerialization.jsonObject(
                    with: messageData
                ) as? [String: Any] else {
                    continue
                }

                if (json["action"] as? String) == action {
                    // Unencrypted error responses surface here
                    // (e.g. locked DB).
                    if let error = Self.protocolError(in: json) {
                        throw error
                    }

                    return json
                }

                // Do not log the complete message: KeePassXC responses
                // may contain credentials or other sensitive information.
                os_log(
                    .default,
                    "Skipping unsolicited KeePassXC message: %{public}@",
                    (json["action"] as? String) ?? "unknown"
                )
            }
        }

        throw KeePassXCError.invalidResponse
    }

    // MARK: Helpers

    static func completeJSONObjects(
        in buffer: inout Data
    ) throws -> [Data] {
        var objects: [Data] = []
        var depth = 0
        var inString = false
        var escaped = false
        var start: Int?

        for (offset, byte) in buffer.enumerated() {
            if escaped {
                escaped = false
                continue
            }

            switch byte {
            case UInt8(ascii: "\\") where inString:
                escaped = true

            case UInt8(ascii: "\""):
                inString.toggle()

            case UInt8(ascii: "{") where !inString:
                if depth == 0 {
                    start = offset
                }

                depth += 1

            case UInt8(ascii: "}") where !inString:
                guard depth > 0 else {
                    throw KeePassXCError.invalidResponse
                }

                depth -= 1

                if depth == 0, let objectStart = start {
                    let startIndex = buffer.index(
                        buffer.startIndex,
                        offsetBy: objectStart
                    )

                    let endIndex = buffer.index(
                        buffer.startIndex,
                        offsetBy: offset + 1
                    )

                    objects.append(
                        buffer.subdata(in: startIndex..<endIndex)
                    )

                    start = nil
                }

            default:
                break
            }
        }

        if let objectStart = start {
            // Keep the incomplete tail for the next read.
            let startIndex = buffer.index(
                buffer.startIndex,
                offsetBy: objectStart
            )

            buffer = buffer.subdata(
                in: startIndex..<buffer.endIndex
            )
        } else if !objects.isEmpty {
            buffer.removeAll(keepingCapacity: true)
        }

        return objects
    }

    static func protocolError(
        in json: [String: Any]
    ) -> KeePassXCError? {
        let message = json["error"] as? String ?? ""

        let codeString =
            (json["errorCode"] as? String)
            ?? (json["errorCode"] as? Int).map(String.init)
            ?? ""

        let failureMessage =
            message.isEmpty || message == "success"
            ? nil
            : message

        guard
            failureMessage != nil
                || (!codeString.isEmpty && codeString != "0")
        else {
            return nil
        }

        return .keePassXC(
            code: Int(codeString) ?? -1,
            message: failureMessage ?? "unknown_error"
        )
    }

    static func socketPath() -> String {
        var buffer = [CChar](
            repeating: 0,
            count: Int(PATH_MAX)
        )

        let length = confstr(
            _CS_DARWIN_USER_TEMP_DIR,
            &buffer,
            buffer.count
        )

        let directory =
        length > 0
        ? String(cString: buffer)
        : NSTemporaryDirectory()

        return (directory as NSString)
            .appendingPathComponent(
                "org.keepassxc.KeePassXC.BrowserServer"
            )
    }
}
