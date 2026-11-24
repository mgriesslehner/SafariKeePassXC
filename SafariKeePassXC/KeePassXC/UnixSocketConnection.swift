//
//  UnixSocketConnection.swift
//  SafariKeePassXC Extension
//
//  Async Unix domain socket transport to reach KeePassXC. No protocol
//  knowledge here, just bytes in and out.
//
//  Raw POSIX sockets instead of Network.framework: NWConnection was unreliable on macOS 27.0.
//
//  Timeouts: connect and send are short; receive is long because KeePassXC
//  can wait on the user (unlock prompt, association dialog). A timeout drops
//  the connection so a hung KeePassXC can't block the shared actor forever.

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

    private static let connectTimeout: TimeInterval = 5
    private static let sendTimeout: TimeInterval = 5
    private static let receiveTimeout: TimeInterval = 120

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

        // Without this, writing to a socket whose peer already closed
        // raises SIGPIPE, which kills the process instead of surfacing
        // as a catchable error.
        var noSigPipe: Int32 = 1
        setsockopt(newFd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))

        Self.setTimeout(newFd, option: SO_SNDTIMEO, seconds: Self.sendTimeout)
        Self.setTimeout(newFd, option: SO_RCVTIMEO, seconds: Self.receiveTimeout)

        let pathBytes = Array(path.utf8)
        let capacity = MemoryLayout.size(ofValue: sockaddr_un().sun_path)
        guard pathBytes.count < capacity else {
            close(newFd)
            throw SocketError.connectionFailed("path_too_long")
        }

        do {
            try await Self.performBlocking {
                var addr = sockaddr_un()
                addr.sun_family = sa_family_t(AF_UNIX)
                withUnsafeMutableBytes(of: &addr.sun_path) { rawBuffer in
                    let buffer = rawBuffer.bindMemory(to: UInt8.self)
                    for (index, byte) in pathBytes.enumerated() {
                        buffer[index] = byte
                    }
                    buffer[pathBytes.count] = 0
                }
                let flags = fcntl(newFd, F_GETFL)
                _ = fcntl(newFd, F_SETFL, flags | O_NONBLOCK)
                var result = withUnsafePointer(to: &addr) { ptr -> Int32 in
                    ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                        Darwin.connect(newFd, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
                    }
                }
                if result != 0, errno == EAGAIN || errno == EINPROGRESS {
                    var pfd = pollfd(fd: newFd, events: Int16(POLLOUT), revents: 0)
                    let ready = Darwin.poll(&pfd, 1, Int32(Self.connectTimeout * 1000))
                    if ready == 0 {
                        throw SocketError.connectionFailed("timeout")
                    }
                    var soError: Int32 = 0
                    var length = socklen_t(MemoryLayout<Int32>.size)
                    getsockopt(newFd, SOL_SOCKET, SO_ERROR, &soError, &length)
                    if ready > 0, soError == 0 {
                        result = 0
                    } else if soError != 0 {
                        errno = soError
                    }
                }
                _ = fcntl(newFd, F_SETFL, flags)
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

        do {
            try await Self.performBlocking {
            try data.withUnsafeBytes { (rawBuffer: UnsafeRawBufferPointer) in
                var offset = 0
                let total = rawBuffer.count
                while offset < total {
                    let n = Darwin.write(fd, rawBuffer.baseAddress!.advanced(by: offset), total - offset)
                    if n < 0 {
                        if errno == EINTR { continue }
                        if errno == EAGAIN { throw SocketError.connectionFailed("timeout") }
                        throw SocketError.connectionFailed(Self.lastErrorDescription())
                    }
                    if n == 0 {
                        throw SocketError.disconnected
                    }
                    offset += n
                }
            }
            }
        } catch {
            disconnect()
            throw error
        }
    }

    func receive() async throws -> Data {
        let fd = fileDescriptor
        guard fd >= 0 else {
            throw SocketError.disconnected
        }

        do {
            return try await Self.performBlocking {
            var buffer = [UInt8](repeating: 0, count: 64 * 1024)
            let n: Int = buffer.withUnsafeMutableBytes { rawBuffer in
                Darwin.read(fd, rawBuffer.baseAddress, rawBuffer.count)
            }
            if n < 0 {
                if errno == EINTR {
                    return Data()
                }
                if errno == EAGAIN { throw SocketError.connectionFailed("timeout") }
                throw SocketError.connectionFailed(Self.lastErrorDescription())
            }
            if n == 0 {
                throw SocketError.disconnected
            }
            return Data(buffer[0..<n])
            }
        } catch {
            disconnect()
            throw error
        }
    }

    func disconnect() {
        if fileDescriptor >= 0 {
            close(fileDescriptor)
            fileDescriptor = -1
        }
    }

    // MARK: Helpers

    private static func setTimeout(_ fd: Int32, option: Int32, seconds: TimeInterval) {
        var value = timeval(tv_sec: Int(seconds), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, option, &value, socklen_t(MemoryLayout<timeval>.size))
    }

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
