//
//  SASealedData.swift
//  SACrypto
//
//  Value type representing the output of authenticated symmetric encryption.
//

import Foundation

/// The output of authenticated symmetric encryption (AES-GCM or ChaCha20-Poly1305).
///
/// Contains everything the receiver needs to decrypt and verify the message:
/// the nonce, the ciphertext, and the authentication tag.
///
/// The `combined` property serialises all three fields as `nonce + ciphertext + tag`
/// — the same layout used by CryptoKit's own `.combined` representation.
public struct SASealedData: Sendable, Equatable {

    /// The nonce (or IV) used during encryption. Must be unique per message.
    public let nonce: Data

    /// The encrypted ciphertext. Same length as the original plaintext.
    public let ciphertext: Data

    /// The authentication tag (16 bytes for both AES-GCM and ChaCha20-Poly1305).
    /// Verifying this tag during decryption detects any tampering.
    public let tag: Data

    public init(nonce: Data, ciphertext: Data, tag: Data) {
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag
    }

    /// Serialised as `nonce || ciphertext || tag`.
    /// Compatible with CryptoKit's own `.combined` SealedBox representation.
    public var combined: Data {
        nonce + ciphertext + tag
    }
}
