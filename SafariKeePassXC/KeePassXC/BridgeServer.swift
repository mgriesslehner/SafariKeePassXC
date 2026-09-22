//
//  BridgeServer.swift
//  SafariKeePassXC
//
//  Bridges the sandboxed Safari extension to the KeePassXC client layer.
//  The appex can't reach KeePassXC's socket directly (sandbox), so this
//  listens on a Unix socket placed inside the extension's own container.
//
//  Wire format both ways: UInt32 LE length prefix + one UTF-8 JSON object,
//  same {id, action, …} shape the JS side uses.
//

import Foundation
import Network
import os.log

nonisolated enum BridgeSocket {
    static let extensionBundleID = "at.griesslehner.SafariKeePassXC.Extension"
    static let socketName = "kpxc-bridge.sock"

    static func pathFromHostApp() -> String {
        (NSHomeDirectory() as NSString)
            .appendingPathComponent("Library/Containers/\(extensionBundleID)/Data/\(socketName)")
    }
}

actor BridgeServer {

    private static let maxMessageLength = 1024 * 1024

    private var listener: NWListener?

    func start() {
        guard listener == nil else { return }

        if BridgeToken.generate() == nil {
            os_log(.error, "BridgeServer: token generation failed; all connections will be rejected")
        }

        let path = BridgeSocket.pathFromHostApp()
        // Remove a stale socket from a previous run; bind fails otherwise.
        try? FileManager.default.removeItem(atPath: path)

        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.unix(path: path)

        do {
            let listener = try NWListener(using: parameters)
            listener.newConnectionHandler = { connection in
                Task { await Self.serve(connection) }
            }
            listener.start(queue: .global(qos: .userInitiated))
            self.listener = listener
            os_log(.default, "BridgeServer listening at %{public}@", path)
        } catch {
            os_log(.error, "BridgeServer failed to start: %{public}@", String(describing: error))
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
        try? FileManager.default.removeItem(atPath: BridgeSocket.pathFromHostApp())
    }

    // MARK: Connection handling
    
    private static func serve(_ connection: NWConnection) async {
        connection.start(queue: .global(qos: .userInitiated))
        defer { connection.cancel() }

        // Every connection must present the current bridge token before any
        // requests are processed. This prevents other processes that can reach
        // the socket path from querying KeePassXC.
        do {
            let handshake = try await receiveMessage(on: connection)
            guard handshake["action"] as? String == "bridge-auth",
                  let tokenHex = handshake["token"] as? String,
                  let incoming = Data(hexString: tokenHex),
                  BridgeToken.verify(incoming) else {
                os_log(.error, "BridgeServer: rejected unauthorized connection")
                return
            }
            try await sendMessage(["success": true], on: connection)
        } catch {
            return
        }

        while true {
            do {
                let request = try await receiveMessage(on: connection)
                let response = await BridgeRouter.handle(request)
                try await sendMessage(response, on: connection)
            } catch {
                // Normal end of connection, or a protocol error - either way
                // this connection is done; the extension reconnects as needed.
                return
            }
        }
    }

    private static func receiveMessage(on connection: NWConnection) async throws -> [String: Any] {
        let header = try await receive(exactly: 4, on: connection)
        let length = header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }.littleEndian
        guard length > 0 && length <= maxMessageLength else {
            throw BridgeWireError.invalidMessageLength(Int(length))
        }
        let body = try await receive(exactly: Int(length), on: connection)
        guard let json = try JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            throw BridgeWireError.invalidFrame
        }
        return json
    }

    private static func sendMessage(_ message: [String: Any], on connection: NWConnection) async throws {
        let body = try JSONSerialization.data(withJSONObject: message)
        var frame = withUnsafeBytes(of: UInt32(body.count).littleEndian) { Data($0) }
        frame.append(body)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: frame, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            })
        }
    }

    private static func receive(exactly count: Int, on connection: NWConnection) async throws -> Data {
        var buffer = Data()
        while buffer.count < count {
            let chunk: Data = try await withCheckedThrowingContinuation { continuation in
                connection.receive(minimumIncompleteLength: 1, maximumLength: count - buffer.count) { data, _, _, error in
                    if let data, !data.isEmpty {
                        continuation.resume(returning: data)
                    } else if let error {
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume(throwing: BridgeWireError.closed)
                    }
                }
            }
            buffer.append(chunk)
        }
        return buffer
    }

    enum BridgeWireError: Error {
        case invalidMessageLength(Int)
        case invalidFrame
        case closed
    }
}

// MARK: - Router

enum BridgeRouter {

    static func handle(_ request: [String: Any]) async -> [String: Any] {
        let id = request["id"] as? Int
        guard let action = request["action"] as? String else {
            return failure(id: id, error: "invalid_request")
        }

        let client = KeePassXCClient.shared
        do {
            switch action {
            case "ping":
                return success(id: id, result: await client.ping())

            case "status":
                let status = await client.status()
                var result: [String: Any] = [
                    "connected": status.connected,
                    "associated": status.associated,
                ]
                if let hash = status.databaseHash { result["databaseHash"] = hash }
                if let version = status.keePassXCVersion { result["keePassXCVersion"] = version }
                if let error = status.error { result["error"] = error }
                return success(id: id, result: result)

            case "associate":
                let association = try await client.associate()
                return success(id: id, result: ["id": association.id])

            case "get-logins":
                guard let url = request["url"] as? String, !url.isEmpty else {
                    return failure(id: id, error: "missing_url")
                }
                let entries = try await client.getLogins(for: url,
                                                         submitUrl: request["submitUrl"] as? String)
                return success(id: id, result: [
                    "count": entries.count,
                    "entries": entries.map { entry -> [String: Any] in
                        var dict: [String: Any] = [
                            "name": entry.name,
                            "login": entry.login,
                            "password": entry.password,
                            "uuid": entry.uuid,
                            "expired": entry.expired,
                        ]
                        if let group = entry.group { dict["group"] = group }
                        if let totp = entry.totp { dict["totp"] = totp }
                        return dict
                    },
                ])

            case "set-login":
                guard let url = request["url"] as? String, !url.isEmpty,
                      let login = request["login"] as? String,
                      let password = request["password"] as? String, !password.isEmpty else {
                    return failure(id: id, error: "missing_fields")
                }
                try await client.setLogin(url: url,
                                          submitUrl: request["submitUrl"] as? String,
                                          login: login,
                                          password: password,
                                          uuid: request["uuid"] as? String,
                                          group: request["group"] as? String,
                                          groupUuid: request["groupUuid"] as? String)
                return success(id: id, result: [:])

            case "get-database-groups":
                let groups = try await client.databaseGroups()
                return success(id: id, result: [
                    "groups": groups.map { ["name": $0.name, "uuid": $0.uuid] },
                ])

            case "generate-password":
                let password = try await client.generatePassword()
                return success(id: id, result: ["password": password])

            default:
                return failure(id: id, error: "unknown_action: \(action)")
            }
        } catch {
            let message = (error as? LocalizedError)?.errorDescription ?? String(describing: error)
            os_log(.error, "BridgeRouter: action %{public}@ failed: %{public}@", action, message)
            return failure(id: id, error: message)
        }
    }

    private static func success(id: Int?, result: [String: Any]) -> [String: Any] {
        var response: [String: Any] = ["success": true, "result": result]
        if let id { response["id"] = id }
        return response
    }

    private static func failure(id: Int?, error: String) -> [String: Any] {
        var response: [String: Any] = ["success": false, "error": error]
        if let id { response["id"] = id }
        return response
    }
}
