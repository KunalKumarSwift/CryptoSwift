//
//  SAECDSASigner.swift
//  SACrypto
//
//  ECDSA digital signatures over NIST P-256, P-384, P-521 via CryptoKit.
//

import CryptoKit
import Foundation

/// ECDSA digital signatures over NIST elliptic curves.
///
/// Prefer `SAEd25519Signer` for new code — Ed25519 is simpler and harder to misuse.
/// Use ECDSA when you need compatibility with systems that require NIST P-curves
/// (e.g. FIPS 140, TLS client certificates, certain government requirements).
public enum SAECDSASigner: Sendable {

    // MARK: Sign

    /// Signs `data` using ECDSA with a DER-encoded NIST curve private key.
    ///
    /// The signature is returned in DER format.
    ///
    /// - Parameters:
    ///   - data: The message to sign. CryptoKit hashes it with SHA-256/384/512.
    ///   - privateKeyDER: PKCS#8 DER-encoded private key (from `SAECKeyGenerator`).
    ///   - curve: The elliptic curve the key is on.
    public static func sign(_ data: Data, privateKeyDER: Data, curve: ECCurve) throws -> Data {
        switch curve {
        case .p256:
            let key = try P256.Signing.PrivateKey(derRepresentation: privateKeyDER)
            return try key.signature(for: data).derRepresentation
        case .p384:
            let key = try P384.Signing.PrivateKey(derRepresentation: privateKeyDER)
            return try key.signature(for: data).derRepresentation
        case .p521:
            let key = try P521.Signing.PrivateKey(derRepresentation: privateKeyDER)
            return try key.signature(for: data).derRepresentation
        }
    }

    // MARK: Verify

    /// Verifies a DER-encoded ECDSA signature.
    ///
    /// - Parameters:
    ///   - signature: DER-encoded ECDSA signature (produced by `sign`).
    ///   - data: The original message that was signed.
    ///   - publicKeyDER: SubjectPublicKeyInfo DER-encoded public key.
    ///   - curve: The elliptic curve the key is on.
    /// - Returns: `true` if the signature is valid.
    public static func verify(
        _ signature: Data,
        for data: Data,
        publicKeyDER: Data,
        curve: ECCurve
    ) throws -> Bool {
        switch curve {
        case .p256:
            let key = try P256.Signing.PublicKey(derRepresentation: publicKeyDER)
            let sig = try P256.Signing.ECDSASignature(derRepresentation: signature)
            return key.isValidSignature(sig, for: data)
        case .p384:
            let key = try P384.Signing.PublicKey(derRepresentation: publicKeyDER)
            let sig = try P384.Signing.ECDSASignature(derRepresentation: signature)
            return key.isValidSignature(sig, for: data)
        case .p521:
            let key = try P521.Signing.PublicKey(derRepresentation: publicKeyDER)
            let sig = try P521.Signing.ECDSASignature(derRepresentation: signature)
            return key.isValidSignature(sig, for: data)
        }
    }
}
