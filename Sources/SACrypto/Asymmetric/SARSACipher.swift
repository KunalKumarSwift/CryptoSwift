//
//  SARSACipher.swift
//  SACrypto
//
//  RSA-OAEP encryption and decryption via Security.framework.
//

import Foundation
import Security

/// RSA key size.
public enum SARSAKeySize: Sendable {
    /// 2048-bit key. Minimum acceptable for new applications.
    case bits2048
    /// 3072-bit key. Equivalent security to 128-bit symmetric.
    case bits3072
    /// 4096-bit key. Highest RSA security level commonly used.
    case bits4096

    var intValue: Int {
        switch self {
        case .bits2048: return 2048
        case .bits3072: return 3072
        case .bits4096: return 4096
        }
    }
}

/// A raw-bytes RSA key pair in PKCS#1 DER format.
public struct SARSAKeyPair: Sendable {
    /// PKCS#1 DER-encoded RSA private key.
    public let privateKeyData: Data
    /// PKCS#1 DER-encoded RSA public key.
    public let publicKeyData: Data
}

/// Errors thrown by RSA operations.
public enum SARSAError: Error, Sendable {
    case keyGenerationFailed(String)
    case encryptionFailed(String)
    case decryptionFailed(String)
    case invalidKey
}

/// RSA-OAEP-SHA256 public-key encryption and decryption.
///
/// RSA is primarily used to encrypt small payloads (e.g. a symmetric key)
/// or to verify identity via a shared public key.
/// For bulk data, use RSA to encrypt an AES key, then AES for the data.
public enum SARSACipher: Sendable {

    // MARK: Key Generation

    /// Generates a new RSA key pair.
    ///
    /// - Parameter keySize: The RSA modulus size. Minimum recommended: 2048.
    public static func generateKeyPair(keySize: SARSAKeySize = .bits2048) throws -> SARSAKeyPair {
        let parameters: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: keySize.intValue
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(parameters as CFDictionary, &error) else {
            throw SARSAError.keyGenerationFailed(
                error?.takeRetainedValue().localizedDescription ?? "SecKeyCreateRandomKey returned nil"
            )
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SARSAError.keyGenerationFailed("Could not derive public key from private key")
        }

        var exportError: Unmanaged<CFError>?
        guard let privateData = SecKeyCopyExternalRepresentation(privateKey, &exportError) as Data? else {
            throw SARSAError.keyGenerationFailed("Could not export private key")
        }
        guard let publicData = SecKeyCopyExternalRepresentation(publicKey, &exportError) as Data? else {
            throw SARSAError.keyGenerationFailed("Could not export public key")
        }

        return SARSAKeyPair(privateKeyData: privateData, publicKeyData: publicData)
    }

    // MARK: Encrypt

    /// Encrypts `plaintext` with the recipient's RSA public key using OAEP-SHA256.
    ///
    /// Maximum plaintext size = (keySize / 8) - 66 bytes.
    /// For a 2048-bit key that is 190 bytes max.
    ///
    /// - Parameters:
    ///   - plaintext: Data to encrypt.
    ///   - publicKeyData: PKCS#1 DER-encoded RSA public key.
    ///   - keySize: Size of the key in bits (must match the provided key).
    public static func encrypt(
        _ plaintext: Data,
        publicKeyData: Data,
        keySize: SARSAKeySize = .bits2048
    ) throws -> Data {
        let key = try importPublicKey(publicKeyData, keySize: keySize)
        var error: Unmanaged<CFError>?
        guard let encrypted = SecKeyCreateEncryptedData(
            key, .rsaEncryptionOAEPSHA256, plaintext as CFData, &error
        ) as Data? else {
            throw SARSAError.encryptionFailed(
                error?.takeRetainedValue().localizedDescription ?? "SecKeyCreateEncryptedData returned nil"
            )
        }
        return encrypted
    }

    // MARK: Decrypt

    /// Decrypts RSA-OAEP-SHA256 ciphertext using the private key.
    ///
    /// - Parameters:
    ///   - ciphertext: The encrypted data produced by `encrypt`.
    ///   - privateKeyData: PKCS#1 DER-encoded RSA private key.
    ///   - keySize: Size of the key in bits (must match the provided key).
    public static func decrypt(
        _ ciphertext: Data,
        privateKeyData: Data,
        keySize: SARSAKeySize = .bits2048
    ) throws -> Data {
        let key = try importPrivateKey(privateKeyData, keySize: keySize)
        var error: Unmanaged<CFError>?
        guard let decrypted = SecKeyCreateDecryptedData(
            key, .rsaEncryptionOAEPSHA256, ciphertext as CFData, &error
        ) as Data? else {
            throw SARSAError.decryptionFailed(
                error?.takeRetainedValue().localizedDescription ?? "SecKeyCreateDecryptedData returned nil"
            )
        }
        return decrypted
    }

    // MARK: Private Helpers

    private static func importPublicKey(_ data: Data, keySize: SARSAKeySize) throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: keySize.intValue
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error) else {
            throw SARSAError.invalidKey
        }
        return key
    }

    private static func importPrivateKey(_ data: Data, keySize: SARSAKeySize) throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: keySize.intValue
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error) else {
            throw SARSAError.invalidKey
        }
        return key
    }
}
