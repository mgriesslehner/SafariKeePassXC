//
//  KeePassXCCrypto.swift
//  SafariKeePassXC Extension
//
//  crypto_box (X25519 + XSalsa20-Poly1305) via libsodium, for the KeePassXC
//  browser protocol.
//

import Foundation
import Sodium

nonisolated struct KeePassXCCrypto {

    private let sodium: Sodium
    private let keyPair: Box.KeyPair

    init?() {
        let sodium = Sodium()
        guard let keyPair = sodium.box.keyPair() else {
            return nil
        }
        self.sodium = sodium
        self.keyPair = keyPair
    }

    var publicKeyBase64: String {
        Data(keyPair.publicKey).base64EncodedString()
    }

    func newNonce() -> Bytes? {
        sodium.randomBytes.buf(length: sodium.box.NonceBytes)
    }

    func newClientID() -> String? {
        guard let bytes = sodium.randomBytes.buf(length: 24) else { return nil }
        return Data(bytes).base64EncodedString()
    }

    func encrypt(_ payload: [String: Any], nonce: Bytes, hostPublicKey: Bytes) -> String? {
        guard let json = try? JSONSerialization.data(withJSONObject: payload),
              let cipher = sodium.box.seal(message: Bytes(json),
                                           recipientPublicKey: hostPublicKey,
                                           senderSecretKey: keyPair.secretKey,
                                           nonce: nonce) else {
            return nil
        }
        return Data(cipher).base64EncodedString()
    }

    func decrypt(_ base64: String, nonce: Bytes, hostPublicKey: Bytes) -> [String: Any]? {
        guard let cipher = Data(base64Encoded: base64),
              let plain = sodium.box.open(authenticatedCipherText: Bytes(cipher),
                                          senderPublicKey: hostPublicKey,
                                          recipientSecretKey: keyPair.secretKey,
                                          nonce: nonce),
              let json = try? JSONSerialization.jsonObject(with: Data(plain)) as? [String: Any] else {
            return nil
        }
        return json
    }

    static func incremented(_ nonce: Bytes) -> Bytes {
        var result = nonce
        var carry: UInt16 = 1
        for index in result.indices {
            carry += UInt16(result[index])
            result[index] = UInt8(carry & 0xff)
            carry >>= 8
        }
        return result
    }
}
