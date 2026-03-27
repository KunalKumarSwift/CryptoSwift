import XCTest
@testable import SACrypto

final class HMACTests: XCTestCase {

    private let key  = Data("super-secret-key".utf8)
    private let data = Data("important message".utf8)

    // MARK: Authenticate

    func test_hmacSHA256_isDeterministic() {
        let mac1 = SAHMAC.authenticate(data, key: key)
        let mac2 = SAHMAC.authenticate(data, key: key)
        XCTAssertEqual(mac1, mac2)
    }

    func test_hmacSHA256_outputIs32Bytes() {
        XCTAssertEqual(SAHMAC.authenticate(data, key: key, using: .sha256).count, 32)
    }

    func test_hmacSHA384_outputIs48Bytes() {
        XCTAssertEqual(SAHMAC.authenticate(data, key: key, using: .sha384).count, 48)
    }

    func test_hmacSHA512_outputIs64Bytes() {
        XCTAssertEqual(SAHMAC.authenticate(data, key: key, using: .sha512).count, 64)
    }

    func test_hmac_differentKeys_produceDifferentMACs() {
        let key2 = Data("different-key".utf8)
        XCTAssertNotEqual(
            SAHMAC.authenticate(data, key: key),
            SAHMAC.authenticate(data, key: key2)
        )
    }

    func test_hmac_differentData_produceDifferentMACs() {
        let other = Data("different message".utf8)
        XCTAssertNotEqual(
            SAHMAC.authenticate(data, key: key),
            SAHMAC.authenticate(other, key: key)
        )
    }

    func test_hmac_knownVector_sha256() {
        // RFC 4231 Test Case 1:
        // key  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)
        // data = "Hi There"
        // expected HMAC-SHA256 = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
        let k = Data([0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                      0x0b, 0x0b, 0x0b, 0x0b])
        let d = Data("Hi There".utf8)
        let mac = SAHMAC.authenticate(d, key: k, using: .sha256)
        XCTAssertEqual(mac.hexString, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    }

    // MARK: Verify

    func test_verify_validMAC_returnsTrue() {
        let mac = SAHMAC.authenticate(data, key: key)
        XCTAssertTrue(SAHMAC.verify(data, mac: mac, key: key))
    }

    func test_verify_tamperedData_returnsFalse() {
        let mac     = SAHMAC.authenticate(data, key: key)
        let tampered = Data("tampered message".utf8)
        XCTAssertFalse(SAHMAC.verify(tampered, mac: mac, key: key))
    }

    func test_verify_wrongKey_returnsFalse() {
        let mac  = SAHMAC.authenticate(data, key: key)
        let key2 = Data("wrong-key".utf8)
        XCTAssertFalse(SAHMAC.verify(data, mac: mac, key: key2))
    }

    func test_verify_truncatedMAC_returnsFalse() {
        let mac     = SAHMAC.authenticate(data, key: key)
        let partial = mac.prefix(16)
        XCTAssertFalse(SAHMAC.verify(data, mac: partial, key: key))
    }

    func test_verify_allAlgorithmsRoundTrip() {
        for algo in [HMACAlgorithm.sha256, .sha384, .sha512] {
            let mac = SAHMAC.authenticate(data, key: key, using: algo)
            XCTAssertTrue(SAHMAC.verify(data, mac: mac, key: key, using: algo),
                          "Verification failed for \(algo)")
        }
    }
}
