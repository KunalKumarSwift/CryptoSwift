//
//  SASecureRandom.swift
//  SACrypto
//
//  Cryptographically secure random byte generation via SecRandomCopyBytes.
//

import Foundation
import Security

/// Cryptographically secure random number generation.
///
/// All methods use `SecRandomCopyBytes` which reads from the OS entropy pool
/// (/dev/random equivalent). This is suitable for generating keys, nonces,
/// salts, and any other security-sensitive random values.
public enum SASecureRandom: Sendable {

    /// Returns `count` cryptographically secure random bytes.
    public static func bytes(count: Int) -> Data {
        var buffer = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &buffer)
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed — entropy source unavailable")
        return Data(buffer)
    }

    /// Returns a random `UInt32`.
    public static func uint32() -> UInt32 {
        var value: UInt32 = 0
        withUnsafeMutableBytes(of: &value) {
            _ = SecRandomCopyBytes(kSecRandomDefault, MemoryLayout<UInt32>.size, $0.baseAddress!)
        }
        return value
    }

    /// Returns a random `UInt64`.
    public static func uint64() -> UInt64 {
        var value: UInt64 = 0
        withUnsafeMutableBytes(of: &value) {
            _ = SecRandomCopyBytes(kSecRandomDefault, MemoryLayout<UInt64>.size, $0.baseAddress!)
        }
        return value
    }

    /// Returns a uniformly random integer in the range `[0, upperBound)`.
    /// Uses rejection sampling to avoid modulo bias.
    public static func uniformRandom(upperBound: UInt32) -> UInt32 {
        precondition(upperBound > 0, "upperBound must be > 0")
        // Calculate the smallest multiple of upperBound that fits in UInt32
        let threshold = UInt32.max - (UInt32.max % upperBound)
        var candidate: UInt32
        repeat {
            candidate = uint32()
        } while candidate >= threshold
        return candidate % upperBound
    }
}
