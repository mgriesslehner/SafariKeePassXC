//
//  HostBridgeConnection.swift
//  SafariKeePassXC Extension
//
//  Connects to the host app's BridgeServer over a Unix socket inside this
//  extension's sandbox container - the only place a sandboxed appex can
//  reach. One connection per request; the process can get killed anytime.
//
//  Wire format: UInt32 LE length prefix + UTF-8 JSON, matches BridgeServer.
//

import Foundation
import Network

enum HostBridgeError: LocalizedError {
    case hostAppNotRunning
    case bridgeAuthFailed
    case transportFailed(String)

    var errorDescription: String? {
        switch self {
        case .hostAppNotRunning:
            return "host_app_not_running"
        case .bridgeAuthFailed:
            return "bridge_auth_failed"
        case .transportFailed(let reason):
            return "bridge_transport_failed: \(reason)"
        }
    }
}

enum HostBridgeConnection {

    private static var socketPath: String {
        (NSHomeDirectory() as NSString).appendingPathComponent("kpxc-bridge.sock")
    }

    static func roundTrip(_ request: [String: Any]) async throws -> [String: Any] {
        let connection = NWConnection(to: .unix(path: socketPath), using: .tcp)
        defer { connection.cancel() }

        try await connect(connection)

        // Authenticate before sending any request. The token was written to
        // the shared Keychain access group by the host app on launch.
        guard let token = BridgeToken.load() else {
            throw HostBridgeError.hostAppNotRunning
        }
        let handshakeBody = try JSONSerialization.data(
            withJSONObject: ["action": "bridge-auth", "token": token.hexString]
        )
        var handshakeFrame = withUnsafeBytes(of: UInt32(handshakeBody.count).littleEndian) { Data($0) }
        handshakeFrame.append(handshakeBody)
        try await send(handshakeFrame, on: connection)

        let ackHeader = try await receive(exactly: 4, on: connection)
        let ackLength = ackHeader.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }.littleEndian
        guard ackLength > 0, ackLength < 1024 else {
            throw HostBridgeError.transportFailed("invalid_handshake_frame")
        }
        let ackBody = try await receive(exactly: Int(ackLength), on: connection)
        guard let ack = try JSONSerialization.jsonObject(with: ackBody) as? [String: Any],
              ack["success"] as? Bool == true else {
            throw HostBridgeError.bridgeAuthFailed
        }

        let body = try JSONSerialization.data(withJSONObject: request)
        var frame = withUnsafeBytes(of: UInt32(body.count).littleEndian) { Data($0) }
        frame.append(body)
        try await send(frame, on: connection)

        let header = try await receive(exactly: 4, on: connection)
        let length = header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }.littleEndian
        guard length > 0, length < 1024 * 1024 else {
            throw HostBridgeError.transportFailed("invalid_frame")
        }
        let responseBody = try await receive(exactly: Int(length), on: connection)

        guard let json = try JSONSerialization.jsonObject(with: responseBody) as? [String: Any] else {
            throw HostBridgeError.transportFailed("invalid_json")
        }
        return json
    }

    // MARK: Primitives

    private static func connect(_ connection: NWConnection) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    connection.stateUpdateHandler = nil
                    continuation.resume()
                case .failed, .waiting:
                    connection.stateUpdateHandler = nil
                    connection.cancel()
                    continuation.resume(throwing: HostBridgeError.hostAppNotRunning)
                default:
                    break
                }
            }
            connection.start(queue: .global(qos: .userInitiated))
        }
    }

    private static func send(_ data: Data, on connection: NWConnection) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: HostBridgeError.transportFailed(error.localizedDescription))
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
                        continuation.resume(throwing: HostBridgeError.transportFailed(error.localizedDescription))
                    } else {
                        continuation.resume(throwing: HostBridgeError.transportFailed("connection_closed"))
                    }
                }
            }
            buffer.append(chunk)
        }
        return buffer
    }
}
