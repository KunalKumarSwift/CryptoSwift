//
//  SAHasher.swift
//  SACrypto
//
//  Secure cryptographic hashing using SHA-2 via CryptoKit.
//

import CryptoKit
import Foundation

/// The SHA-2 algorithm variant to use.
public enum HashAlgorithm: Sendable {
    /// SHA-256: 32-byte digest. Good general-purpose choice.
    case sha256
    /// SHA-384: 48-byte digest. Stronger; common in TLS certificates.
    case sha384
    /// SHA-512: 64-byte digest. Maximum SHA-2 strength.
    case sha512
}

/// Cryptographic hashing using the SHA-2 family of algorithms.
///
/// All methods are infallible — hashing always succeeds.
public enum SAHasher: Sendable {

    // MARK: Raw Data → Data

    /// Returns the hash of `data` using the specified algorithm.
    public static func hash(_ data: Data, using algorithm: HashAlgorithm = .sha256) -> Data {
        switch algorithm {
        case .sha256: return Data(SHA256.hash(data: data))
        case .sha384: return Data(SHA384.hash(data: data))
        case .sha512: return Data(SHA512.hash(data: data))
        }
    }

    /// Returns the hash of a UTF-8 encoded string.
    public static func hash(_ string: String, using algorithm: HashAlgorithm = .sha256) -> Data {
        hash(Data(string.utf8), using: algorithm)
    }

    // MARK: Raw Data → Hex String

    /// Returns a lowercase hex digest of `data`.
    public static func hexString(_ data: Data, using algorithm: HashAlgorithm = .sha256) -> String {
        hash(data, using: algorithm).hexString
    }

    /// Returns a lowercase hex digest of a UTF-8 string.
    public static func hexString(_ string: String, using algorithm: HashAlgorithm = .sha256) -> String {
        hash(string, using: algorithm).hexString
    }
}
