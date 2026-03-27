import XCTest
@testable import SACrypto

final class HashingTests: XCTestCase {

    // MARK: SAHasher — SHA-256

    func test_sha256_knownVector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let digest = SAHasher.hexString("", using: .sha256)
        XCTAssertEqual(digest, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    func test_sha256_string() {
        let digest = SAHasher.hexString("hello world", using: .sha256)
        XCTAssertEqual(digest, "b94d27b9934d3e08a52e52d7da7dabfac484efe04294e576fae2e9a2c2a1c86a")
    }

    func test_sha256_dataMatchesString() {
        let data = Data("hello".utf8)
        let fromData   = SAHasher.hash(data, using: .sha256)
        let fromString = SAHasher.hash("hello", using: .sha256)
        XCTAssertEqual(fromData, fromString)
    }

    func test_sha256_outputIs32Bytes() {
        XCTAssertEqual(SAHasher.hash(Data("x".utf8), using: .sha256).count, 32)
    }

    func test_sha256_avalancheEffect() {
        let a = SAHasher.hash("password",  using: .sha256)
        let b = SAHasher.hash("Password",  using: .sha256)
        XCTAssertNotEqual(a, b, "One-bit change must produce a completely different digest")
    }

    // MARK: SAHasher — SHA-384 / SHA-512

    func test_sha384_outputIs48Bytes() {
        XCTAssertEqual(SAHasher.hash(Data("x".utf8), using: .sha384).count, 48)
    }

    func test_sha512_outputIs64Bytes() {
        XCTAssertEqual(SAHasher.hash(Data("x".utf8), using: .sha512).count, 64)
    }

    func test_sha384_knownVector() {
        // SHA-384("") = 38b060a751ac9638...
        let digest = SAHasher.hexString("", using: .sha384)
        XCTAssertTrue(digest.hasPrefix("38b060a751ac9638"), "SHA-384 of empty string should match known vector")
    }

    func test_sha512_knownVector() {
        // SHA-512("") = cf83e1357eef8...
        let digest = SAHasher.hexString("", using: .sha512)
        XCTAssertTrue(digest.hasPrefix("cf83e1357eef8"), "SHA-512 of empty string should match known vector")
    }

    func test_hashing_isDeterministic() {
        let data = Data("deterministic".utf8)
        XCTAssertEqual(SAHasher.hash(data), SAHasher.hash(data))
    }

    // MARK: SAInsecureHasher — MD5

    func test_md5_knownVector() {
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        let hex = SAInsecureHasher.md5HexString(Data())
        XCTAssertEqual(hex, "d41d8cd98f00b204e9800998ecf8427e")
    }

    func test_md5_string_knownVector() {
        // MD5("hello world") = 5eb63bbbe01eeed093cb22bb8f5acdc3
        let hex = SAInsecureHasher.md5HexString("hello world")
        XCTAssertEqual(hex, "5eb63bbbe01eeed093cb22bb8f5acdc3")
    }

    func test_md5_outputIs16Bytes() {
        XCTAssertEqual(SAInsecureHasher.md5(Data("x".utf8)).count, 16)
    }

    // MARK: SAInsecureHasher — SHA-1

    func test_sha1_knownVector() {
        // SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        let hex = SAInsecureHasher.sha1HexString(Data())
        XCTAssertEqual(hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709")
    }

    func test_sha1_outputIs20Bytes() {
        XCTAssertEqual(SAInsecureHasher.sha1(Data("x".utf8)).count, 20)
    }
}
