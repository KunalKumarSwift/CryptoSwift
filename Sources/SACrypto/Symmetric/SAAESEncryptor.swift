//
//  SAAESEncryptor.swift
//  SACrypto
//
//  AES-256-GCM authenticated encryption via CryptoKit.
//

import CryptoKit
import Foundation

/// Errors thrown by symmetric encryption operations.
public enum SASymmetricEncryptionError: Error, Sendable {
    /// The provided key is not a valid size for this algorithm.
    case invalidKeySize
    /// Decryption failed — ciphertext was tampered with, or the wrong key was used.
    case decryptionFailed
}

/// AES-256-GCM authenticated encryption.
///
/// AES-GCM provides both **confidentiality** (only the key holder can read the message)
/// and **authenticity** (any tampering is detected before decryption proceeds).
/// The 96-bit nonce is generated randomly on every call to `encrypt`.
public enum SAAESEncryptor: Sendable {

    // MARK: Key Management

    /// Generates a new random 256-bit AES key.
    public static func generateKey() -> Data {
        SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
    }

    // MARK: Encrypt

    /// Encrypts `plaintext` with AES-256-GCM.
    ///
    /// A fresh random 96-bit nonce is generated for every call.
    /// You must store the returned `SASealedData` to decrypt later.
    ///
    /// - Parameters:
    ///   - plaintext: The data to encrypt.
    ///   - key: A 256-bit (32-byte) AES key.
    /// - Throws: `CryptoKitError` if the key size is invalid.
    public static func encrypt(_ plaintext: Data, key: Data) throws -> SASealedData {
        let symmetricKey = SymmetricKey(data: key)
        let sealedBox = try AES.GCM.seal(plaintext, using: symmetricKey)
        return SASealedData(
            nonce: Data(sealedBox.nonce),
            ciphertext: sealedBox.ciphertext,
            tag: sealedBox.tag
        )
    }

    // MARK: Decrypt

    /// Decrypts and verifies a `SASealedData` packet.
    ///
    /// Decryption fails if the key is wrong or the ciphertext has been modified.
    ///
    /// - Parameters:
    ///   - sealed: The sealed data produced by `encrypt`.
    ///   - key: The same 256-bit key used to encrypt.
    public static func decrypt(_ sealed: SASealedData, key: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let nonce = try AES.GCM.Nonce(data: sealed.nonce)
        let sealedBox = try AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: sealed.ciphertext,
            tag: sealed.tag
        )
        return try AES.GCM.open(sealedBox, using: symmetricKey)
    }

    /// Decrypts from a combined `nonce || ciphertext || tag` blob.
    ///
    /// - Parameters:
    ///   - combined: The serialised representation from `SASealedData.combined`.
    ///   - key: The 256-bit key used to encrypt.
    public static func decrypt(combined: Data, key: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let sealedBox = try AES.GCM.SealedBox(combined: combined)
        return try AES.GCM.open(sealedBox, using: symmetricKey)
    }
}
