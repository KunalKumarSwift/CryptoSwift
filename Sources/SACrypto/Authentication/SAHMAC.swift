//
//  SAHMAC.swift
//  SACrypto
//
//  Hash-Based Message Authentication Code via CryptoKit.
//

import CryptoKit
import Foundation

/// The hash function to use inside HMAC.
public enum HMACAlgorithm: Sendable {
    case sha256
    case sha384
    case sha512
}

/// Errors thrown by HMAC operations.
public enum SAHMACError: Error, Sendable {
    /// The provided key is empty.
    case emptyKey
}

/// Hash-Based Message Authentication Code (HMAC).
///
/// HMAC combines a hash function with a secret key to produce a MAC —
/// a short tag that proves both the integrity and authenticity of a message.
/// Unlike a plain hash, only someone who holds the key can produce or verify the tag.
public enum SAHMAC: Sendable {

    // MARK: Authenticate

    /// Returns the HMAC authentication code for `data` under `key`.
    ///
    /// - Parameters:
    ///   - data: The message to authenticate.
    ///   - key: The secret key (any length; internally hashed if longer than block size).
    ///   - algorithm: Hash algorithm to use (default: SHA-256).
    public static func authenticate(
        _ data: Data,
        key: Data,
        using algorithm: HMACAlgorithm = .sha256
    ) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        switch algorithm {
        case .sha256:
            return Data(HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey))
        case .sha384:
            return Data(HMAC<SHA384>.authenticationCode(for: data, using: symmetricKey))
        case .sha512:
            return Data(HMAC<SHA512>.authenticationCode(for: data, using: symmetricKey))
        }
    }

    // MARK: Verify

    /// Verifies a MAC in constant time to prevent timing attacks.
    ///
    /// - Parameters:
    ///   - data: The original message.
    ///   - mac: The MAC to verify.
    ///   - key: The secret key used to produce the MAC.
    ///   - algorithm: Hash algorithm (must match the one used to produce `mac`).
    /// - Returns: `true` if the MAC is valid.
    public static func verify(
        _ data: Data,
        mac: Data,
        key: Data,
        using algorithm: HMACAlgorithm = .sha256
    ) -> Bool {
        let symmetricKey = SymmetricKey(data: key)
        switch algorithm {
        case .sha256:
            return HMAC<SHA256>.isValidAuthenticationCode(mac, authenticating: data, using: symmetricKey)
        case .sha384:
            return HMAC<SHA384>.isValidAuthenticationCode(mac, authenticating: data, using: symmetricKey)
        case .sha512:
            return HMAC<SHA512>.isValidAuthenticationCode(mac, authenticating: data, using: symmetricKey)
        }
    }
}
