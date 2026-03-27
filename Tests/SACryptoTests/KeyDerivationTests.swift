import XCTest
@testable import SACrypto

final class KeyDerivationTests: XCTestCase {

    // MARK: SASaltGenerator

    func test_salt_hasCorrectLength() {
        XCTAssertEqual(SASaltGenerator.generate(byteCount: 16).count, 16)
        XCTAssertEqual(SASaltGenerator.generate(byteCount: 32).count, 32)
        XCTAssertEqual(SASaltGenerator.generate(byteCount: 64).count, 64)
    }

    func test_salt_isRandom() {
        let a = SASaltGenerator.generate()
        let b = SASaltGenerator.generate()
        XCTAssertNotEqual(a, b, "Two independently generated salts should not be equal")
    }

    func test_salt_defaultIs32Bytes() {
        XCTAssertEqual(SASaltGenerator.generate().count, 32)
    }

    // MARK: SAKeyDerivation — Basic

    func test_deriveKey_isDeterministic() throws {
        let salt = SASaltGenerator.generate()
        let k1 = try SAKeyDerivation.deriveKey(fromPassword: "password", salt: salt)
        let k2 = try SAKeyDerivation.deriveKey(fromPassword: "password", salt: salt)
        XCTAssertEqual(k1, k2)
    }

    func test_deriveKey_defaultOutputIs32Bytes() throws {
        let k = try SAKeyDerivation.deriveKey(fromPassword: "pw", salt: SASaltGenerator.generate())
        XCTAssertEqual(k.count, 32)
    }

    func test_deriveKey_customOutputLength() throws {
        let k = try SAKeyDerivation.deriveKey(fromPassword: "pw",
                                               salt: SASaltGenerator.generate(),
                                               keyByteCount: 64)
        XCTAssertEqual(k.count, 64)
    }

    func test_deriveKey_differentPasswords_differentKeys() throws {
        let salt = SASaltGenerator.generate()
        let k1 = try SAKeyDerivation.deriveKey(fromPassword: "password1", salt: salt)
        let k2 = try SAKeyDerivation.deriveKey(fromPassword: "password2", salt: salt)
        XCTAssertNotEqual(k1, k2)
    }

    func test_deriveKey_differentSalts_differentKeys() throws {
        let k1 = try SAKeyDerivation.deriveKey(fromPassword: "password", salt: SASaltGenerator.generate())
        let k2 = try SAKeyDerivation.deriveKey(fromPassword: "password", salt: SASaltGenerator.generate())
        XCTAssertNotEqual(k1, k2, "Different salts must produce different keys")
    }

    func test_deriveKey_differentIterations_differentKeys() throws {
        let salt = SASaltGenerator.generate()
        let k1 = try SAKeyDerivation.deriveKey(fromPassword: "pw", salt: salt, iterations: 1000)
        let k2 = try SAKeyDerivation.deriveKey(fromPassword: "pw", salt: salt, iterations: 2000)
        XCTAssertNotEqual(k1, k2)
    }

    // MARK: SAKeyDerivation — Algorithm Variants

    func test_deriveKey_sha256AndSha512_differ() throws {
        let salt = SASaltGenerator.generate()
        let k256 = try SAKeyDerivation.deriveKey(fromPassword: "pw", salt: salt, algorithm: .pbkdf2SHA256)
        let k512 = try SAKeyDerivation.deriveKey(fromPassword: "pw", salt: salt, algorithm: .pbkdf2SHA512)
        XCTAssertNotEqual(k256, k512)
    }

    // MARK: SAKeyDerivation — Error Handling

    func test_deriveKey_emptyPassword_throws() {
        XCTAssertThrowsError(
            try SAKeyDerivation.deriveKey(fromPassword: "", salt: SASaltGenerator.generate())
        ) { error in
            XCTAssertEqual(error as? SAKeyDerivationError, .emptyPassword)
        }
    }

    // MARK: Integration: derived key usable for AES

    func test_derivedKeyUsableForAES() throws {
        let salt       = SASaltGenerator.generate()
        let key        = try SAKeyDerivation.deriveKey(fromPassword: "hunter2", salt: salt)
        let plaintext  = Data("secret data".utf8)
        let sealed     = try SAAESEncryptor.encrypt(plaintext, key: key)
        let decrypted  = try SAAESEncryptor.decrypt(sealed, key: key)
        XCTAssertEqual(decrypted, plaintext)
    }
}
