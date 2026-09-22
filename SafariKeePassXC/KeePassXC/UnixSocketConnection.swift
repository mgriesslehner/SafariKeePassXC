//
//  UnixSocketConnection.swift
//  SafariKeePassXC Extension
//
//  Async Unix domain socket transport to reach KeePassXC. No protocol
//  knowledge here, just bytes in and out.
//
//  Raw POSIX sockets instead of Network.framework: NWConnection was unreliable on macOS 27.0.
//

import Foundation
import Darwin

actor UnixSocketConnection {

    enum SocketError: LocalizedError {
        case connectionFailed(String)
        case disconnected

        var errorDescription: String? {
            switch self {
            case .connectionFailed(let reason):
                return "socket_connection_failed: \(reason)"
            case .disconnected:
                return "socket_disconnected"
            }
        }
    }

    private var fileDescriptor: Int32 = -1

    var isConnected: Bool {
        fileDescriptor >= 0
    }

    func connect(to path: String) async throws {
        if fileDescriptor >= 0 {
            return
        }

        let newFd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard newFd >= 0 else {
            throw SocketError.connectionFailed(Self.lastErrorDescription())
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)

        let pathBytes = Array(path.utf8)
        let capacity = MemoryLayout.size(ofValue: addr.sun_path)
        guard pathBytes.count < capacity else {
            close(newFd)
            throw SocketError.connectionFailed("path_too_long")
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { rawBuffer in
            let buffer = rawBuffer.bindMemory(to: UInt8.self)
            for (index, byte) in pathBytes.enumerated() {
                buffer[index] = byte
            }
            buffer[pathBytes.count] = 0
        }

        do {
            try await Self.performBlocking {
                var addrCopy = addr
                let result = withUnsafePointer(to: &addrCopy) { ptr -> Int32 in
                    ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                        Darwin.connect(newFd, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
                    }
                }
                guard result == 0 else {
                    throw SocketError.connectionFailed(Self.lastErrorDescription())
                }
            }
        } catch {
            close(newFd)
            throw error
        }

        fileDescriptor = newFd
    }

    func send(_ data: Data) async throws {
        let fd = fileDescriptor
        guard fd >= 0 else {
            throw SocketError.disconnected
        }

        try await Self.performBlocking {
            try data.withUnsafeBytes { (rawBuffer: UnsafeRawBufferPointer) in
                var offset = 0
                let total = rawBuffer.count
                while offset < total {
                    let n = Darwin.write(fd, rawBuffer.baseAddress!.advanced(by: offset), total - offset)
                    if n < 0 {
                        if errno == EINTR { continue }
                        throw SocketError.connectionFailed(Self.lastErrorDescription())
                    }
                    if n == 0 {
                        throw SocketError.disconnected
                    }
                    offset += n
                }
            }
        }
    }

    func receive() async throws -> Data {
        let fd = fileDescriptor
        guard fd >= 0 else {
            throw SocketError.disconnected
        }

        return try await Self.performBlocking {
            var buffer = [UInt8](repeating: 0, count: 64 * 1024)
            let n: Int = buffer.withUnsafeMutableBytes { rawBuffer in
                Darwin.read(fd, rawBuffer.baseAddress, rawBuffer.count)
            }
            if n < 0 {
                if errno == EINTR {
                    return Data()
                }
                throw SocketError.connectionFailed(Self.lastErrorDescription())
            }
            if n == 0 {
                throw SocketError.disconnected
            }
            return Data(buffer[0..<n])
        }
    }

    func disconnect() {
        if fileDescriptor >= 0 {
            close(fileDescriptor)
            fileDescriptor = -1
        }
    }

    // MARK: Helpers

    private static func lastErrorDescription() -> String {
        String(cString: strerror(errno))
    }

    // Runs a blocking POSIX call off the actor's executor so it can't stall
    // cooperative-pool threads, then hops back via the continuation.
    private static func performBlocking<T: Sendable>(
        _ body: @escaping @Sendable () throws -> T
    ) async throws -> T {
        try await Task.detached(priority: .userInitiated) {
            try body()
        }.value
    }
}
