//
//  SAECDHAgreement.swift
//  SACrypto
//
//  ECDH key agreement over NIST P-256, P-384, P-521 via CryptoKit.
//

import CryptoKit
import Foundation

/// ECDH key agreement over NIST elliptic curves.
///
/// Use this when you need NIST P-curve compatibility (e.g. FIPS environments).
/// For new code without such constraints, prefer `SAX25519Agreement`.
public enum SAECDHAgreement: Sendable {

    // MARK: Key Agreement

    /// Derives a shared symmetric key from your DER-encoded private key and the peer's public key.
    ///
    /// The raw Diffie-Hellman shared secret is passed through HKDF-SHA256 before being returned,
    /// ensuring uniform distribution and domain separation.
    ///
    /// - Parameters:
    ///   - myPrivateKeyDER: PKCS#8 DER-encoded ECDH private key (from `SAECKeyGenerator`).
    ///   - peerPublicKeyDER: SubjectPublicKeyInfo DER-encoded peer public key.
    ///   - curve: The elliptic curve both keys are on.
    ///   - salt: Optional HKDF salt (public; adds context separation).
    ///   - info: Optional HKDF context info.
    ///   - outputByteCount: Output key length in bytes. Default 32 (256-bit).
    public static func sharedSymmetricKey(
        myPrivateKeyDER: Data,
        peerPublicKeyDER: Data,
        curve: ECCurve,
        salt: Data = Data(),
        info: Data = Data(),
        outputByteCount: Int = 32
    ) throws -> Data {
        switch curve {
        case .p256:
            let priv = try P256.KeyAgreement.PrivateKey(derRepresentation: myPrivateKeyDER)
            let pub  = try P256.KeyAgreement.PublicKey(derRepresentation: peerPublicKeyDER)
            let secret = try priv.sharedSecretFromKeyAgreement(with: pub)
            return secret.hkdfDerivedSymmetricKey(
                using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: outputByteCount
            ).withUnsafeBytes { Data($0) }

        case .p384:
            let priv = try P384.KeyAgreement.PrivateKey(derRepresentation: myPrivateKeyDER)
            let pub  = try P384.KeyAgreement.PublicKey(derRepresentation: peerPublicKeyDER)
            let secret = try priv.sharedSecretFromKeyAgreement(with: pub)
            return secret.hkdfDerivedSymmetricKey(
                using: SHA384.self, salt: salt, sharedInfo: info, outputByteCount: outputByteCount
            ).withUnsafeBytes { Data($0) }

        case .p521:
            let priv = try P521.KeyAgreement.PrivateKey(derRepresentation: myPrivateKeyDER)
            let pub  = try P521.KeyAgreement.PublicKey(derRepresentation: peerPublicKeyDER)
            let secret = try priv.sharedSecretFromKeyAgreement(with: pub)
            return secret.hkdfDerivedSymmetricKey(
                using: SHA512.self, salt: salt, sharedInfo: info, outputByteCount: outputByteCount
            ).withUnsafeBytes { Data($0) }
        }
    }
}
