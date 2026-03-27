//
//  SAKeyDerivation.swift
//  SACrypto
//
//  Password-Based Key Derivation Function 2 (PBKDF2) via CommonCrypto.
//

import CommonCrypto
import Foundation

/// The pseudo-random function used inside PBKDF2.
public enum KDFAlgorithm: Sendable {
    /// PBKDF2 with HMAC-SHA256 (recommended for most use cases).
    case pbkdf2SHA256
    /// PBKDF2 with HMAC-SHA512 (higher output entropy).
    case pbkdf2SHA512
}

/// Errors thrown during key derivation.
public enum SAKeyDerivationError: Error, Sendable, Equatable {
    /// The password string is empty.
    case emptyPassword
    /// CommonCrypto returned a non-success status code.
    case derivationFailed(status: Int32)
}

/// Derives cryptographic keys from passwords using PBKDF2.
public enum SAKeyDerivation: Sendable {

    /// Derives a symmetric key from a human-readable password.
    ///
    /// - Parameters:
    ///   - password: The user's password. Must not be empty.
    ///   - salt: A unique random salt. Generate with `SASaltGenerator.generate()`.
    ///   - iterations: Work factor. Higher = slower brute-force, slower derive.
    ///     Recommended: ≥100,000 for SHA-256; NIST recommends ≥600,000 for SHA-256 (2023).
    ///   - keyByteCount: Length of the output key in bytes. Default is 32 (256 bits).
    ///   - algorithm: The pseudo-random function to use inside PBKDF2.
    /// - Returns: Derived key as raw bytes.
    public static func deriveKey(
        fromPassword password: String,
        salt: Data,
        iterations: Int = 100_000,
        keyByteCount: Int = 32,
        algorithm: KDFAlgorithm = .pbkdf2SHA256
    ) throws -> Data {
        guard !password.isEmpty else { throw SAKeyDerivationError.emptyPassword }

        let prf: CCPseudoRandomAlgorithm
        switch algorithm {
        case .pbkdf2SHA256: prf = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
        case .pbkdf2SHA512: prf = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
        }

        var derivedKey = [UInt8](repeating: 0, count: keyByteCount)
        let saltBytes = [UInt8](salt)

        let status: Int32 = password.withCString { passwordPtr in
            CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                passwordPtr, password.utf8.count,
                saltBytes, saltBytes.count,
                prf,
                UInt32(iterations),
                &derivedKey, keyByteCount
            )
        }

        guard status == kCCSuccess else {
            throw SAKeyDerivationError.derivationFailed(status: status)
        }

        return Data(derivedKey)
    }
}
