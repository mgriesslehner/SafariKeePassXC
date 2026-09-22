//
//  SafariKeePassXCTests.swift
//  SafariKeePassXCTests
//

import Testing
@testable import SafariKeePassXC
import Foundation
import Darwin

// MARK: - UnixSocketConnection

// Minimal POSIX echo listener so the test doesn't depend on KeePassXC being
// installed, and doesn't go through Network.framework itself (that's the
// thing being replaced - see UnixSocketConnection.swift).
private struct EchoListener {
    let fd: Int32

    static func start(at path: String) -> EchoListener? {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8)
        withUnsafeMutableBytes(of: &addr.sun_path) { rawBuffer in
            let buffer = rawBuffer.bindMemory(to: UInt8.self)
            for (index, byte) in pathBytes.enumerated() {
                buffer[index] = byte
            }
            buffer[pathBytes.count] = 0
        }

        let bindResult = withUnsafePointer(to: &addr) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                bind(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindResult == 0, listen(fd, 1) == 0 else {
            close(fd)
            return nil
        }
        return EchoListener(fd: fd)
    }

    func acceptAndEcho() {
        let clientFd = accept(fd, nil, nil)
        guard clientFd >= 0 else { return }
        defer { Darwin.close(clientFd) }
        var buffer = [UInt8](repeating: 0, count: 1024)
        let n = read(clientFd, &buffer, buffer.count)
        guard n > 0 else { return }
        _ = write(clientFd, buffer, n)
    }

    func stop() {
        Darwin.close(fd)
    }
}

@Suite("UnixSocketConnection") struct UnixSocketConnectionTests {

    private static func makeSocketPath() -> String {
        (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("kpxc-test-\(UUID().uuidString).sock")
    }

    @Test func sendAndReceiveRoundTrip() async throws {
        let path = Self.makeSocketPath()
        let listener = try #require(EchoListener.start(at: path))
        defer {
            listener.stop()
            try? FileManager.default.removeItem(atPath: path)
        }

        Task.detached { listener.acceptAndEcho() }

        let connection = UnixSocketConnection()
        try await connection.connect(to: path)
        #expect(await connection.isConnected)

        let message = Data("ping".utf8)
        try await connection.send(message)
        let received = try await connection.receive()
        #expect(received == message)

        await connection.disconnect()
        #expect(await connection.isConnected == false)
    }

    @Test func connectToMissingSocketFails() async {
        let connection = UnixSocketConnection()
        do {
            try await connection.connect(to: Self.makeSocketPath())
            Issue.record("Expected connect to a non-existent socket to fail")
        } catch {
            // expected
        }
    }
}

// MARK: - KeePassXCCrypto

@Suite("KeePassXCCrypto") struct KeePassXCCryptoTests {

    // KeePassXC expects the response nonce to equal incremented(requestNonce).

    @Test func nonceIncrementBasic() {
        #expect(KeePassXCCrypto.incremented([0, 0, 0, 0]) == [1, 0, 0, 0])
    }

    @Test func nonceIncrementCarryIntoSecondByte() {
        #expect(KeePassXCCrypto.incremented([0xFF, 0, 0, 0]) == [0, 1, 0, 0])
    }

    @Test func nonceIncrementChainedCarry() {
        #expect(KeePassXCCrypto.incremented([0xFF, 0xFF, 0, 0]) == [0, 0, 1, 0])
    }

    @Test func nonceIncrementFullOverflowWrapsToZero() {
        let allFF: [UInt8] = [0xFF, 0xFF, 0xFF, 0xFF]
        #expect(KeePassXCCrypto.incremented(allFF) == [0, 0, 0, 0])
    }

    @Test func nonceIncrementDoesNotMutateInput() {
        let nonce: [UInt8] = [5, 6, 7, 8]
        _ = KeePassXCCrypto.incremented(nonce)
        #expect(nonce == [5, 6, 7, 8])
    }

    @Test func encryptDecryptRoundTrip() throws {
        let alice = try #require(KeePassXCCrypto())
        let bob   = try #require(KeePassXCCrypto())

        let payload: [String: Any] = ["action": "test", "value": "hello"]
        let nonce  = try #require(alice.newNonce())
        let bobKey = try #require(Data(base64Encoded: bob.publicKeyBase64))

        let ciphertext = try #require(
            alice.encrypt(payload, nonce: nonce, hostPublicKey: [UInt8](bobKey))
        )

        let aliceKey = try #require(Data(base64Encoded: alice.publicKeyBase64))
        let decrypted = try #require(
            bob.decrypt(ciphertext, nonce: nonce, hostPublicKey: [UInt8](aliceKey))
        )

        #expect(decrypted["action"] as? String == "test")
        #expect(decrypted["value"]  as? String == "hello")
    }

    @Test func decryptWithWrongKeyFails() throws {
        let alice = try #require(KeePassXCCrypto())
        let bob   = try #require(KeePassXCCrypto())
        let eve   = try #require(KeePassXCCrypto())

        let nonce  = try #require(alice.newNonce())
        let bobKey = try #require(Data(base64Encoded: bob.publicKeyBase64))
        let ciphertext = try #require(
            alice.encrypt(["secret": "data"], nonce: nonce, hostPublicKey: [UInt8](bobKey))
        )

        let aliceKey = try #require(Data(base64Encoded: alice.publicKeyBase64))
        #expect(eve.decrypt(ciphertext, nonce: nonce, hostPublicKey: [UInt8](aliceKey)) == nil)
    }

    @Test func decryptWithWrongNonceFails() throws {
        let alice = try #require(KeePassXCCrypto())
        let bob   = try #require(KeePassXCCrypto())

        let nonce  = try #require(alice.newNonce())
        let bobKey = try #require(Data(base64Encoded: bob.publicKeyBase64))
        let ciphertext = try #require(
            alice.encrypt(["k": "v"], nonce: nonce, hostPublicKey: [UInt8](bobKey))
        )

        let wrongNonce = try #require(alice.newNonce())
        let aliceKey   = try #require(Data(base64Encoded: alice.publicKeyBase64))
        #expect(bob.decrypt(ciphertext, nonce: wrongNonce, hostPublicKey: [UInt8](aliceKey)) == nil)
    }
}

// MARK: - KeePassXCClient: completeJSONObjects

@Suite("completeJSONObjects") struct CompleteJSONObjectsTests {

    private func parse(_ string: String) throws -> ([Data], Data) {
        var buf = Data(string.utf8)
        let objects = try KeePassXCClient.completeJSONObjects(in: &buf)
        return (objects, buf)
    }

    private func json(_ data: Data) -> [String: Any]? {
        try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    }

    @Test func singleCompleteObject() throws {
        let (objects, remaining) = try parse(#"{"action":"test"}"#)
        #expect(objects.count == 1)
        #expect(json(objects[0])?["action"] as? String == "test")
        #expect(remaining.isEmpty)
    }

    @Test func twoConsecutiveObjects() throws {
        let (objects, remaining) = try parse(#"{"a":1}{"b":2}"#)
        #expect(objects.count == 2)
        #expect(remaining.isEmpty)
    }

    @Test func incompleteObjectIsRetainedInBuffer() throws {
        let (objects, remaining) = try parse(#"{"action":"tes"#)
        #expect(objects.isEmpty)
        #expect(!remaining.isEmpty)
    }

    @Test func completeObjectFollowedByIncomplete() throws {
        let (objects, remaining) = try parse(#"{"a":1}{"b":"incom"#)
        #expect(objects.count == 1)
        #expect(json(objects[0])?["a"] as? Int == 1)
        // incomplete tail kept for next read
        #expect(String(data: remaining, encoding: .utf8)?.hasPrefix("{") == true)
    }

    @Test func emptyBufferReturnsNothing() throws {
        let (objects, remaining) = try parse("")
        #expect(objects.isEmpty)
        #expect(remaining.isEmpty)
    }

    @Test func nestedObjectsAreHandledCorrectly() throws {
        let input = #"{"outer":{"inner":42}}"#
        let (objects, _) = try parse(input)
        #expect(objects.count == 1)
        let outer = json(objects[0])
        let inner = outer?["outer"] as? [String: Any]
        #expect(inner?["inner"] as? Int == 42)
    }

    @Test func bracesInsideStringsAreIgnored() throws {
        // The value "{not an object}" must not confuse the depth counter.
        let input = #"{"key":"{not an object}"}"#
        let (objects, remaining) = try parse(input)
        #expect(objects.count == 1)
        #expect(remaining.isEmpty)
        #expect(json(objects[0])?["key"] as? String == "{not an object}")
    }

    @Test func escapedQuoteInsideStringDoesNotCloseIt() throws {
        // "say \"hi\"" — the escaped quotes must not toggle inString prematurely.
        let input = #"{"msg":"say \"hi\""}"#
        let (objects, remaining) = try parse(input)
        #expect(objects.count == 1)
        #expect(remaining.isEmpty)
    }

    @Test func escapedBackslashBeforeQuoteDoesNotEscapeIt() throws {
        // "\\" followed by " — the backslash escapes itself, not the quote.
        let input = "{\"k\":\"\\\\\"}"
        let (objects, remaining) = try parse(input)
        #expect(objects.count == 1)
        #expect(remaining.isEmpty)
    }

    @Test func strayClosingBraceThrows() {
        var buf = Data("}".utf8)
        do {
            _ = try KeePassXCClient.completeJSONObjects(in: &buf)
            Issue.record("Expected invalidResponse to be thrown")
        } catch KeePassXCError.invalidResponse {
            // expected
        } catch {
            Issue.record("Expected invalidResponse, got \(error)")
        }
    }

    @Test func prefixGarbageBeforeObjectIsSkipped() throws {
        // Bytes before the first '{' are not part of any object.
        let (objects, _) = try parse(#"garbage{"a":1}"#)
        #expect(objects.count == 1)
    }

    @Test func bufferIsClearedAfterFullConsumption() throws {
        var buf = Data(#"{"x":1}"#.utf8)
        _ = try KeePassXCClient.completeJSONObjects(in: &buf)
        #expect(buf.isEmpty)
    }
}

// MARK: - KeePassXCClient: protocolError

@Suite("protocolError") struct ProtocolErrorTests {

    @Test func noErrorFieldsReturnsNil() {
        #expect(KeePassXCClient.protocolError(in: ["action": "get-logins"]) == nil)
    }

    @Test func successMessageReturnsNil() {
        #expect(KeePassXCClient.protocolError(in: ["error": "success"]) == nil)
    }

    @Test func emptyErrorStringReturnsNil() {
        #expect(KeePassXCClient.protocolError(in: ["error": ""]) == nil)
    }

    @Test func errorCodeZeroReturnsNil() {
        #expect(KeePassXCClient.protocolError(in: ["errorCode": "0"]) == nil)
    }

    @Test func errorMessageWithoutCodeGivesCodeMinusOne() {
        guard case .keePassXC(let code, let message) =
            KeePassXCClient.protocolError(in: ["error": "Database locked"])
        else {
            Issue.record("Expected keePassXC error")
            return
        }
        #expect(code == -1)
        #expect(message == "Database locked")
    }

    @Test func errorCodeWithoutMessageGivesUnknownError() {
        guard case .keePassXC(let code, let message) =
            KeePassXCClient.protocolError(in: ["errorCode": "6"])
        else {
            Issue.record("Expected keePassXC error")
            return
        }
        #expect(code == 6)
        #expect(message == "unknown_error")
    }

    @Test func errorCodeAsIntegerIsHandled() {
        guard case .keePassXC(let code, _) =
            KeePassXCClient.protocolError(in: ["errorCode": 15])
        else {
            Issue.record("Expected keePassXC error")
            return
        }
        #expect(code == 15)
    }

    @Test func bothCodeAndMessageAreCaptured() {
        guard case .keePassXC(let code, let message) =
            KeePassXCClient.protocolError(in: ["errorCode": "6", "error": "No logins found"])
        else {
            Issue.record("Expected keePassXC error")
            return
        }
        #expect(code == 6)
        #expect(message == "No logins found")
    }
}

// MARK: - BridgeToken.verify

@Suite("BridgeToken.verify") struct BridgeTokenVerifyTests {

    @Test func generatedTokenVerifiesItself() {
        guard let token = BridgeToken.generate() else { return }
        #expect(BridgeToken.verify(token))
    }

    @Test func flippedFirstByteIsRejected() {
        guard var token = BridgeToken.generate() else { return }
        token[0] ^= 0xFF
        #expect(!BridgeToken.verify(token))
    }

    @Test func flippedLastByteIsRejected() {
        guard var token = BridgeToken.generate() else { return }
        token[token.count - 1] ^= 0x01
        #expect(!BridgeToken.verify(token))
    }

    @Test func shorterDataIsRejected() {
        _ = BridgeToken.generate()
        #expect(!BridgeToken.verify(Data(repeating: 0, count: 16)))
    }

    @Test func emptyDataIsRejected() {
        _ = BridgeToken.generate()
        #expect(!BridgeToken.verify(Data()))
    }
}

// MARK: - AssociationStore (Keychain integration)

@Suite("AssociationStore", .serialized) struct AssociationStoreTests {

    @Test func saveAndLoad() throws {
        let store = AssociationStore()
        store.clear()
        defer { store.clear() }

        let association = Association(id: "testDB", publicKey: "testKey==")
        try store.save(association)

        let loaded = try #require(store.load())
        #expect(loaded.id == association.id)
        #expect(loaded.publicKey == association.publicKey)
    }

    @Test func loadReturnsNilWhenEmpty() {
        let store = AssociationStore()
        store.clear()
        defer { store.clear() }
        #expect(store.load() == nil)
    }

    @Test func clearRemovesStoredItem() throws {
        let store = AssociationStore()
        store.clear()
        defer { store.clear() }

        try store.save(Association(id: "x", publicKey: "y"))
        store.clear()
        #expect(store.load() == nil)
    }

    @Test func saveOverwritesPreviousEntry() throws {
        let store = AssociationStore()
        store.clear()
        defer { store.clear() }

        try store.save(Association(id: "first",  publicKey: "key1"))
        try store.save(Association(id: "second", publicKey: "key2"))

        let loaded = try #require(store.load())
        #expect(loaded.id == "second")
    }
}

// MARK: - Data hex extensions

@Suite("Data hex extensions") struct DataHexExtensionTests {

    @Test func knownBytesToHex() {
        #expect(Data([0x00, 0xFF, 0xAB]).hexString == "00ffab")
    }

    @Test func hexRoundTrip() {
        let original = Data([0xDE, 0xAD, 0xBE, 0xEF])
        #expect(Data(hexString: original.hexString) == original)
    }

    @Test func uppercaseHexIsAccepted() {
        #expect(Data(hexString: "DEADBEEF") == Data(hexString: "deadbeef"))
    }

    @Test func oddLengthReturnsNil() {
        #expect(Data(hexString: "abc") == nil)
    }

    @Test func invalidCharactersReturnNil() {
        #expect(Data(hexString: "zz") == nil)
    }

    @Test func emptyStringReturnsEmptyData() {
        #expect(Data(hexString: "") == Data())
    }
}
