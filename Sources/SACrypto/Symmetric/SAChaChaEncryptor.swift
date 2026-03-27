//
//  SAChaChaEncryptor.swift
//  SACrypto
//
//  ChaCha20-Poly1305 authenticated encryption via CryptoKit.
//

import CryptoKit
import Foundation

/// ChaCha20-Poly1305 authenticated encryption.
///
/// A modern stream cipher combined with the Poly1305 MAC.
/// Preferred over AES-GCM on devices without hardware AES acceleration,
/// and specified in TLS 1.3 as a mandatory cipher suite.
public enum SAChaChaEncryptor: Sendable {

    // MARK: Key Management

    /// Generates a new random 256-bit ChaCha20-Poly1305 key.
    public static func generateKey() -> Data {
        SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
    }

    // MARK: Encrypt

    /// Encrypts `plaintext` with ChaCha20-Poly1305.
    ///
    /// A fresh random 96-bit nonce is generated for every call.
    ///
    /// - Parameters:
    ///   - plaintext: The data to encrypt.
    ///   - key: A 256-bit (32-byte) key.
    public static func encrypt(_ plaintext: Data, key: Data) throws -> SASealedData {
        let symmetricKey = SymmetricKey(data: key)
        let sealedBox = try ChaChaPoly.seal(plaintext, using: symmetricKey)
        return SASealedData(
            nonce: Data(sealedBox.nonce),
            ciphertext: sealedBox.ciphertext,
            tag: sealedBox.tag
        )
    }

    // MARK: Decrypt

    /// Decrypts and verifies a `SASealedData` packet.
    ///
    /// - Parameters:
    ///   - sealed: The sealed data produced by `encrypt`.
    ///   - key: The same 256-bit key used to encrypt.
    public static func decrypt(_ sealed: SASealedData, key: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let nonce = try ChaChaPoly.Nonce(data: sealed.nonce)
        let sealedBox = try ChaChaPoly.SealedBox(
            nonce: nonce,
            ciphertext: sealed.ciphertext,
            tag: sealed.tag
        )
        return try ChaChaPoly.open(sealedBox, using: symmetricKey)
    }

    /// Decrypts from a combined `nonce || ciphertext || tag` blob.
    public static func decrypt(combined: Data, key: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let sealedBox = try ChaChaPoly.SealedBox(combined: combined)
        return try ChaChaPoly.open(sealedBox, using: symmetricKey)
    }
}
