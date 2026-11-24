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
//  Raw POSIX sockets instead of Network.framework: NWConnection was unreliable on macOS 27.0.
//
//  Timeouts: short for connect/send and the auth handshake; long for the
//  actual response, since the host may be waiting on KeePassXC (and the user).

import Foundation
import Darwin

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

    private static let connectTimeout: TimeInterval = 5
    private static let sendTimeout: TimeInterval = 5
    private static let handshakeTimeout: TimeInterval = 5
    private static let responseTimeout: TimeInterval = 130

    private static var socketPath: String {
        (NSHomeDirectory() as NSString).appendingPathComponent("kpxc-bridge.sock")
    }

    static func roundTrip(_ request: [String: Any]) async throws -> [String: Any] {
        let fd = try await connect(to: socketPath)
        defer { close(fd) }
        setTimeout(fd, option: SO_SNDTIMEO, seconds: sendTimeout)
        setTimeout(fd, option: SO_RCVTIMEO, seconds: handshakeTimeout)

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
        try await send(handshakeFrame, to: fd)

        let ackHeader = try await receive(exactly: 4, from: fd)
        let ackLength = ackHeader.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }.littleEndian
        guard ackLength > 0, ackLength < 1024 else {
            throw HostBridgeError.transportFailed("invalid_handshake_frame")
        }
        let ackBody = try await receive(exactly: Int(ackLength), from: fd)
        guard let ack = try JSONSerialization.jsonObject(with: ackBody) as? [String: Any],
              ack["success"] as? Bool == true else {
            throw HostBridgeError.bridgeAuthFailed
        }

        setTimeout(fd, option: SO_RCVTIMEO, seconds: responseTimeout)
        let body = try JSONSerialization.data(withJSONObject: request)
        var frame = withUnsafeBytes(of: UInt32(body.count).littleEndian) { Data($0) }
        frame.append(body)
        try await send(frame, to: fd)

        let header = try await receive(exactly: 4, from: fd)
        let length = header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }.littleEndian
        guard length > 0, length < 1024 * 1024 else {
            throw HostBridgeError.transportFailed("invalid_frame")
        }
        let responseBody = try await receive(exactly: Int(length), from: fd)

        guard let json = try JSONSerialization.jsonObject(with: responseBody) as? [String: Any] else {
            throw HostBridgeError.transportFailed("invalid_json")
        }
        return json
    }

    // MARK: Primitives

    private static let cwdLock = NSLock()

    private static func connect(to path: String) async throws -> Int32 {
        try await performBlocking {
            let fd = socket(AF_UNIX, SOCK_STREAM, 0)
            guard fd >= 0 else {
                throw HostBridgeError.hostAppNotRunning
            }

            // Without this, writing to a socket whose peer already closed
            // raises SIGPIPE, which kills the process instead of surfacing
            // as a catchable error.
            var noSigPipe: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))

            let directory = (path as NSString).deletingLastPathComponent
            let name = (path as NSString).lastPathComponent

            cwdLock.lock()
            defer { cwdLock.unlock() }

            let savedCwd = open(".", O_RDONLY)
            guard savedCwd >= 0 else {
                close(fd)
                throw HostBridgeError.transportFailed(String(cString: strerror(errno)))
            }
            defer { close(savedCwd) }

            guard chdir(directory) == 0 else {
                close(fd)
                throw HostBridgeError.hostAppNotRunning
            }
            defer { fchdir(savedCwd) }

            var addr = sockaddr_un()
            addr.sun_family = sa_family_t(AF_UNIX)

            let nameBytes = Array(name.utf8)
            let capacity = MemoryLayout.size(ofValue: addr.sun_path)
            guard nameBytes.count < capacity else {
                close(fd)
                throw HostBridgeError.transportFailed("path_too_long")
            }
            withUnsafeMutableBytes(of: &addr.sun_path) { rawBuffer in
                let buffer = rawBuffer.bindMemory(to: UInt8.self)
                for (index, byte) in nameBytes.enumerated() {
                    buffer[index] = byte
                }
                buffer[nameBytes.count] = 0
            }

            // Non-blocking connect so a full listen backlog can't hang us;
            // poll bounds the wait.
            let flags = fcntl(fd, F_GETFL)
            _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
            var result = withUnsafePointer(to: &addr) { ptr -> Int32 in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    Darwin.connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            if result != 0, errno == EAGAIN || errno == EINPROGRESS {
                var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
                let ready = Darwin.poll(&pfd, 1, Int32(connectTimeout * 1000))
                var soError: Int32 = 0
                var length = socklen_t(MemoryLayout<Int32>.size)
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &length)
                if ready > 0, soError == 0 {
                    result = 0
                }
            }
            _ = fcntl(fd, F_SETFL, flags)
            guard result == 0 else {
                close(fd)
                throw HostBridgeError.hostAppNotRunning
            }

            return fd
        }
    }

    private static func setTimeout(_ fd: Int32, option: Int32, seconds: TimeInterval) {
        var value = timeval(tv_sec: Int(seconds), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, option, &value, socklen_t(MemoryLayout<timeval>.size))
    }

    private static func send(_ data: Data, to fd: Int32) async throws {
        try await performBlocking {
            try data.withUnsafeBytes { (rawBuffer: UnsafeRawBufferPointer) in
                var offset = 0
                let total = rawBuffer.count
                while offset < total {
                    let n = Darwin.write(fd, rawBuffer.baseAddress!.advanced(by: offset), total - offset)
                    if n < 0 {
                        if errno == EINTR { continue }
                        if errno == EAGAIN { throw HostBridgeError.transportFailed("timeout") }
                        throw HostBridgeError.transportFailed(String(cString: strerror(errno)))
                    }
                    if n == 0 {
                        throw HostBridgeError.transportFailed("connection_closed")
                    }
                    offset += n
                }
            }
        }
    }

    private static func receive(exactly count: Int, from fd: Int32) async throws -> Data {
        var buffer = Data()
        while buffer.count < count {
            let remaining = count - buffer.count
            let chunk = try await performBlocking { () -> Data in
                var readBuffer = [UInt8](repeating: 0, count: remaining)
                let n = readBuffer.withUnsafeMutableBytes { rawBuffer in
                    Darwin.read(fd, rawBuffer.baseAddress, rawBuffer.count)
                }
                if n < 0 {
                    if errno == EINTR {
                        return Data()
                    }
                    if errno == EAGAIN { throw HostBridgeError.transportFailed("timeout") }
                    throw HostBridgeError.transportFailed(String(cString: strerror(errno)))
                }
                if n == 0 {
                    throw HostBridgeError.transportFailed("connection_closed")
                }
                return Data(readBuffer[0..<n])
            }
            buffer.append(chunk)
        }
        return buffer
    }

    private static func performBlocking<T: Sendable>(
        _ body: @escaping @Sendable () throws -> T
    ) async throws -> T {
        try await Task.detached(priority: .userInitiated) {
            try body()
        }.value
    }
}
