//
//  SAECKeyPair.swift
//  SACrypto
//
//  Elliptic curve key pair generation for signing and key agreement.
//

import CryptoKit
import Foundation

/// An elliptic curve.
public enum ECCurve: Sendable {
    /// NIST P-256 (secp256r1) — 128-bit security level. Most widely supported.
    case p256
    /// NIST P-384 (secp384r1) — 192-bit security level.
    case p384
    /// NIST P-521 (secp521r1) — 260-bit security level.
    case p521
}

/// A DER-encoded elliptic curve key pair for use with ECDSA signing.
public struct SAECSigningKeyPair: Sendable {
    /// PKCS#8 DER-encoded private key.
    public let privateKeyDER: Data
    /// SubjectPublicKeyInfo DER-encoded public key.
    public let publicKeyDER: Data
    /// The curve this key pair is on.
    public let curve: ECCurve

    public init(privateKeyDER: Data, publicKeyDER: Data, curve: ECCurve) {
        self.privateKeyDER = privateKeyDER
        self.publicKeyDER = publicKeyDER
        self.curve = curve
    }
}

/// A DER-encoded elliptic curve key pair for use with ECDH key agreement.
public struct SAECKeyAgreementPair: Sendable {
    /// PKCS#8 DER-encoded private key.
    public let privateKeyDER: Data
    /// SubjectPublicKeyInfo DER-encoded public key.
    public let publicKeyDER: Data
    /// The curve this key pair is on.
    public let curve: ECCurve

    public init(privateKeyDER: Data, publicKeyDER: Data, curve: ECCurve) {
        self.privateKeyDER = privateKeyDER
        self.publicKeyDER = publicKeyDER
        self.curve = curve
    }
}

/// Errors thrown when working with EC key pairs.
public enum SAECKeyError: Error, Sendable {
    /// The provided DER data could not be parsed as a key on the specified curve.
    case invalidKey
}

/// Generates elliptic curve key pairs over NIST P-256, P-384, and P-521.
public enum SAECKeyGenerator: Sendable {

    /// Generates a random signing key pair (for use with `SAECDSASigner`).
    public static func generateSigningKeyPair(curve: ECCurve) -> SAECSigningKeyPair {
        switch curve {
        case .p256:
            let k = P256.Signing.PrivateKey()
            return SAECSigningKeyPair(privateKeyDER: k.derRepresentation,
                                      publicKeyDER: k.publicKey.derRepresentation,
                                      curve: .p256)
        case .p384:
            let k = P384.Signing.PrivateKey()
            return SAECSigningKeyPair(privateKeyDER: k.derRepresentation,
                                      publicKeyDER: k.publicKey.derRepresentation,
                                      curve: .p384)
        case .p521:
            let k = P521.Signing.PrivateKey()
            return SAECSigningKeyPair(privateKeyDER: k.derRepresentation,
                                      publicKeyDER: k.publicKey.derRepresentation,
                                      curve: .p521)
        }
    }

    /// Generates a random key agreement pair (for use with `SAECDHAgreement`).
    public static func generateKeyAgreementPair(curve: ECCurve) -> SAECKeyAgreementPair {
        switch curve {
        case .p256:
            let k = P256.KeyAgreement.PrivateKey()
            return SAECKeyAgreementPair(privateKeyDER: k.derRepresentation,
                                        publicKeyDER: k.publicKey.derRepresentation,
                                        curve: .p256)
        case .p384:
            let k = P384.KeyAgreement.PrivateKey()
            return SAECKeyAgreementPair(privateKeyDER: k.derRepresentation,
                                        publicKeyDER: k.publicKey.derRepresentation,
                                        curve: .p384)
        case .p521:
            let k = P521.KeyAgreement.PrivateKey()
            return SAECKeyAgreementPair(privateKeyDER: k.derRepresentation,
                                        publicKeyDER: k.publicKey.derRepresentation,
                                        curve: .p521)
        }
    }
}
