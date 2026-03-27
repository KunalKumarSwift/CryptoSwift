//
//  SAX25519Agreement.swift
//  SACrypto
//
//  X25519 (Curve25519) key agreement via CryptoKit.
//

import CryptoKit
import Foundation

/// A Curve25519 key pair for X25519 key agreement (raw 32-byte representations).
public struct SAX25519KeyPair: Sendable {
    /// 32-byte raw private key scalar.
    public let privateKeyData: Data
    /// 32-byte Curve25519 public key.
    public let publicKeyData: Data
}

/// Errors thrown by key agreement operations.
public enum SAKeyAgreementError: Error, Sendable {
    /// The provided key bytes could not be parsed.
    case invalidKey
}

/// X25519 Elliptic Curve Diffie-Hellman key agreement.
///
/// X25519 is the recommended key agreement algorithm.
/// It is faster and safer than ECDH-P256 (no special-case point issues).
/// Specified as mandatory in TLS 1.3.
public enum SAX25519Agreement: Sendable {

    // MARK: Key Generation

    /// Generates a fresh X25519 key pair.
    public static func generateKeyPair() -> SAX25519KeyPair {
        let key = Curve25519.KeyAgreement.PrivateKey()
        return SAX25519KeyPair(
            privateKeyData: key.rawRepresentation,
            publicKeyData: key.publicKey.rawRepresentation
        )
    }

    // MARK: Key Agreement

    /// Derives a shared symmetric key from your private key and the peer's public key.
    ///
    /// Both parties call this with their own private key and the other's public key.
    /// The result is identical on both sides without any communication of the secret.
    ///
    /// The shared secret is passed through HKDF-SHA256 to produce a uniformly
    /// distributed symmetric key suitable for use with AES-GCM or ChaCha20.
    ///
    /// - Parameters:
    ///   - myPrivateKeyData: Your 32-byte raw private key.
    ///   - peerPublicKeyData: The peer's 32-byte raw public key.
    ///   - salt: Optional salt for HKDF (can be public; makes output context-specific).
    ///   - info: Optional context info for HKDF (e.g. app name or session identifier).
    ///   - outputByteCount: Desired key length in bytes. Default is 32 (256-bit AES key).
    /// - Returns: Derived symmetric key bytes.
    public static func sharedSymmetricKey(
        myPrivateKeyData: Data,
        peerPublicKeyData: Data,
        salt: Data = Data(),
        info: Data = Data(),
        outputByteCount: Int = 32
    ) throws -> Data {
        let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: myPrivateKeyData)
        let publicKey  = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKeyData)
        let secret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let derived = secret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: info,
            outputByteCount: outputByteCount
        )
        return derived.withUnsafeBytes { Data($0) }
    }
}
