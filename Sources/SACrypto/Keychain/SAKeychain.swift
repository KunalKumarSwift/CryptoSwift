//
//  SAKeychain.swift
//  SACrypto
//
//  Secure storage for keys and sensitive data via Security.framework Keychain Services.
//

import Foundation
import Security

/// Errors thrown by keychain operations.
public enum SAKeychainError: Error, Sendable {
    /// `SecItemAdd` returned a non-success status.
    case storeFailed(OSStatus)
    /// `SecItemCopyMatching` returned a non-success status.
    case retrieveFailed(OSStatus)
    /// `SecItemDelete` returned a non-success, non-notFound status.
    case deleteFailed(OSStatus)
    /// The item was not found in the keychain.
    case itemNotFound
    /// The returned value could not be cast to `Data`.
    case dataConversionFailed
}

/// Secure storage of raw data (keys, tokens, credentials) in the iOS Keychain.
///
/// Items are stored with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` —
/// readable only while the device is unlocked and never backed up to iCloud.
public enum SAKeychain: Sendable {

    // MARK: Store

    /// Stores `data` under `key`. Overwrites any existing value for the same key.
    ///
    /// - Parameters:
    ///   - data: Raw bytes to store (e.g. a symmetric key or token).
    ///   - key: An application-specific identifier string (e.g. `"com.myapp.aes-key"`).
    public static func store(_ data: Data, forKey key: String) throws {
        // Remove any existing item first to allow overwrite
        try? delete(forKey: key)

        let query: [String: Any] = [
            kSecClass as String:            kSecClassGenericPassword,
            kSecAttrAccount as String:      key,
            kSecValueData as String:        data,
            kSecAttrAccessible as String:   kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw SAKeychainError.storeFailed(status)
        }
    }

    // MARK: Retrieve

    /// Retrieves the data stored under `key`.
    ///
    /// - Parameter key: The identifier used when storing.
    /// - Throws: `SAKeychainError.itemNotFound` if no item exists for `key`.
    public static func retrieve(forKey key: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String:        kSecClassGenericPassword,
            kSecAttrAccount as String:  key,
            kSecReturnData as String:   true,
            kSecMatchLimit as String:   kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let data = result as? Data else {
                throw SAKeychainError.dataConversionFailed
            }
            return data
        case errSecItemNotFound:
            throw SAKeychainError.itemNotFound
        default:
            throw SAKeychainError.retrieveFailed(status)
        }
    }

    // MARK: Delete

    /// Deletes the item stored under `key`.
    ///
    /// Succeeds silently if no item exists for `key`.
    public static func delete(forKey key: String) throws {
        let query: [String: Any] = [
            kSecClass as String:        kSecClassGenericPassword,
            kSecAttrAccount as String:  key
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SAKeychainError.deleteFailed(status)
        }
    }

    // MARK: Existence Check

    /// Returns `true` if an item exists for `key`.
    public static func exists(forKey key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String:        kSecClassGenericPassword,
            kSecAttrAccount as String:  key
        ]
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }
}
