//
//  SAEd25519Signer.swift
//  SACrypto
//
//  Ed25519 digital signatures via CryptoKit (Curve25519.Signing).
//

import CryptoKit
import Foundation

/// An Ed25519 key pair (raw 32-byte representations).
public struct SAEd25519KeyPair: Sendable {
    /// 32-byte raw private key scalar.
    public let privateKeyData: Data
    /// 32-byte compressed public key point.
    public let publicKeyData: Data
}

/// Errors thrown by signing operations.
public enum SASigningError: Error, Sendable {
    /// The key data could not be parsed.
    case invalidKey
    /// Signing failed unexpectedly.
    case signingFailed
}

/// Ed25519 digital signatures using Curve25519.
///
/// Ed25519 is the recommended algorithm for new applications.
/// It is fast, small (32-byte keys and signatures), deterministic,
/// and immune to several fault attacks that affect ECDSA.
public enum SAEd25519Signer: Sendable {

    // MARK: Key Generation

    /// Generates a fresh Ed25519 key pair.
    public static func generateKeyPair() -> SAEd25519KeyPair {
        let privateKey = Curve25519.Signing.PrivateKey()
        return SAEd25519KeyPair(
            privateKeyData: privateKey.rawRepresentation,
            publicKeyData: privateKey.publicKey.rawRepresentation
        )
    }

    // MARK: Sign

    /// Signs `data` with the raw Ed25519 private key.
    ///
    /// - Parameters:
    ///   - data: The message to sign. CryptoKit hashes it internally with SHA-512.
    ///   - privateKeyData: 32-byte raw private key.
    /// - Returns: 64-byte signature.
    public static func sign(_ data: Data, privateKeyData: Data) throws -> Data {
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData)
        return try key.signature(for: data)
    }

    // MARK: Verify

    /// Verifies an Ed25519 signature.
    ///
    /// - Parameters:
    ///   - signature: The 64-byte signature produced by `sign`.
    ///   - data: The original message.
    ///   - publicKeyData: 32-byte raw public key.
    /// - Returns: `true` if the signature is valid.
    public static func verify(
        _ signature: Data,
        for data: Data,
        publicKeyData: Data
    ) throws -> Bool {
        let key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)
        return key.isValidSignature(signature, for: data)
    }
}
