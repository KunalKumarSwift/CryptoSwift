//
//  SASaltGenerator.swift
//  SACrypto
//
//  Cryptographically secure salt generation.
//

import Foundation

/// Generates cryptographically secure random salts for use with key derivation functions.
///
/// A salt must be:
/// - **Random** — never reuse a salt across different passwords.
/// - **Long enough** — 16 bytes (128 bits) minimum; 32 bytes recommended.
/// - **Stored alongside the derived key** — it is not secret, but it is required for verification.
public enum SASaltGenerator: Sendable {

    /// Generates a random salt of the given byte length.
    ///
    /// - Parameter byteCount: Number of random bytes to generate. Default is 32 (256 bits).
    public static func generate(byteCount: Int = 32) -> Data {
        SASecureRandom.bytes(count: byteCount)
    }
}
