//
//  SAInsecureHasher.swift
//  SACrypto
//
//  MD5 and SHA-1 — legacy algorithms for interoperability only.
//  DO NOT use these for new security-sensitive features.
//

import CryptoKit
import Foundation

/// Legacy hash algorithms.
///
/// ⚠️ **MD5 and SHA-1 are cryptographically broken.**
/// They are provided solely for interoperability with older systems.
/// Use `SAHasher` (SHA-256/384/512) for any new work.
public enum SAInsecureHasher: Sendable {

    // MARK: MD5

    /// MD5 digest of `data`. NOT suitable for security purposes.
    public static func md5(_ data: Data) -> Data {
        Data(Insecure.MD5.hash(data: data))
    }

    /// MD5 digest of a UTF-8 string, returned as raw bytes.
    public static func md5(_ string: String) -> Data {
        md5(Data(string.utf8))
    }

    /// MD5 digest of `data` as a lowercase hex string.
    public static func md5HexString(_ data: Data) -> String {
        md5(data).hexString
    }

    /// MD5 digest of a UTF-8 string as a lowercase hex string.
    public static func md5HexString(_ string: String) -> String {
        md5(string).hexString
    }

    // MARK: SHA-1

    /// SHA-1 digest of `data`. NOT suitable for digital signatures or new security code.
    public static func sha1(_ data: Data) -> Data {
        Data(Insecure.SHA1.hash(data: data))
    }

    /// SHA-1 digest of a UTF-8 string, returned as raw bytes.
    public static func sha1(_ string: String) -> Data {
        sha1(Data(string.utf8))
    }

    /// SHA-1 digest of `data` as a lowercase hex string.
    public static func sha1HexString(_ data: Data) -> String {
        sha1(data).hexString
    }

    /// SHA-1 digest of a UTF-8 string as a lowercase hex string.
    public static func sha1HexString(_ string: String) -> String {
        sha1(string).hexString
    }
}
