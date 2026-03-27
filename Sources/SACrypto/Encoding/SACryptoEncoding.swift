//
//  SACryptoEncoding.swift
//  SACrypto
//
//  Hex and Base64-URL encoding/decoding helpers used throughout the library.
//

import Foundation

public extension Data {

    // MARK: Hex

    /// Lowercase hex string representation, e.g. "deadbeef".
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }

    /// Initialise Data from a hex string. Returns nil if the string is malformed.
    init?(hexString: String) {
        guard hexString.count % 2 == 0 else { return nil }
        var data = Data(capacity: hexString.count / 2)
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let next = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        self = data
    }

    // MARK: Base64-URL

    /// Base64-URL encoded string (RFC 4648 §5) — uses `-` and `_`, no padding.
    var base64URLEncoded: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Decode a standard Base64 or Base64-URL encoded string into Data.
    init?(base64URLEncoded string: String) {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder != 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        guard let decoded = Data(base64Encoded: base64) else { return nil }
        self = decoded
    }
}
