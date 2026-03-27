import XCTest
@testable import SACrypto

final class CryptoEncodingTests: XCTestCase {

    // MARK: Hex Encoding

    func test_hexString_knownValues() {
        XCTAssertEqual(Data([0x00]).hexString, "00")
        XCTAssertEqual(Data([0xFF]).hexString, "ff")
        XCTAssertEqual(Data([0xDE, 0xAD, 0xBE, 0xEF]).hexString, "deadbeef")
    }

    func test_hexString_empty() {
        XCTAssertEqual(Data().hexString, "")
    }

    func test_hexString_isLowercase() {
        let hex = Data([0xAB, 0xCD, 0xEF]).hexString
        XCTAssertEqual(hex, hex.lowercased())
    }

    func test_hexString_is2xDataLength() {
        let data = SASecureRandom.bytes(count: 32)
        XCTAssertEqual(data.hexString.count, 64)
    }

    // MARK: Hex Decoding

    func test_hexInit_roundTrip() {
        let original = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let hex      = original.hexString
        let decoded  = Data(hexString: hex)
        XCTAssertEqual(decoded, original)
    }

    func test_hexInit_emptyString_returnsEmptyData() {
        XCTAssertEqual(Data(hexString: ""), Data())
    }

    func test_hexInit_oddLength_returnsNil() {
        XCTAssertNil(Data(hexString: "abc"))
    }

    func test_hexInit_invalidCharacters_returnsNil() {
        XCTAssertNil(Data(hexString: "zz"))
    }

    func test_hexInit_uppercaseAccepted() {
        XCTAssertEqual(Data(hexString: "DEADBEEF"), Data([0xDE, 0xAD, 0xBE, 0xEF]))
    }

    func test_hexInit_mixedCase() {
        XCTAssertEqual(Data(hexString: "DeAdBeEf"), Data([0xDE, 0xAD, 0xBE, 0xEF]))
    }

    // MARK: Base64-URL Encoding

    func test_base64URL_encodesDifferentlyFromStandardBase64() {
        // Force a value that would produce + or / in standard base64
        let data = Data([0xFB, 0xFF, 0xFF])  // standard: "+///"  base64url: "-___"
        let base64Std = data.base64EncodedString()
        let base64URL = data.base64URLEncoded
        XCTAssertNotEqual(base64Std, base64URL)
        XCTAssertFalse(base64URL.contains("+"))
        XCTAssertFalse(base64URL.contains("/"))
        XCTAssertFalse(base64URL.contains("="))
    }

    func test_base64URL_roundTrip() {
        let original = SASecureRandom.bytes(count: 32)
        let encoded  = original.base64URLEncoded
        let decoded  = Data(base64URLEncoded: encoded)
        XCTAssertEqual(decoded, original)
    }

    func test_base64URL_roundTrip_variousLengths() {
        for length in [1, 2, 3, 15, 16, 17, 32, 100] {
            let data    = SASecureRandom.bytes(count: length)
            let encoded = data.base64URLEncoded
            let decoded = Data(base64URLEncoded: encoded)
            XCTAssertEqual(decoded, data, "Round-trip failed for length \(length)")
        }
    }

    func test_base64URL_noPaddingInOutput() {
        for _ in 0..<10 {
            let data    = SASecureRandom.bytes(count: Int(SASecureRandom.uniformRandom(upperBound: 50) + 1))
            let encoded = data.base64URLEncoded
            XCTAssertFalse(encoded.contains("="), "Base64-URL must not contain padding")
        }
    }

    func test_base64URL_acceptsStandardBase64() {
        // Standard Base64 with padding should also decode
        let data    = Data([1, 2, 3])
        let std     = data.base64EncodedString()         // "AQID"
        let decoded = Data(base64URLEncoded: std)
        XCTAssertEqual(decoded, data)
    }

    func test_base64URL_emptyData() {
        XCTAssertEqual(Data().base64URLEncoded, "")
        XCTAssertEqual(Data(base64URLEncoded: ""), Data())
    }

    // MARK: Integration with hashing

    func test_hexString_hashOutput_matches_knownSHA256() {
        // SHA-256("") known vector
        let hash = SAHasher.hexString("", using: .sha256)
        XCTAssertEqual(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }
}
