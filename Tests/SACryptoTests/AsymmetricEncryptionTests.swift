import XCTest
@testable import SACrypto

final class AsymmetricEncryptionTests: XCTestCase {

    // MARK: SAECKeyGenerator

    func test_ecSigningKeyPair_p256_hasDERData() {
        let pair = SAECKeyGenerator.generateSigningKeyPair(curve: .p256)
        XCTAssertFalse(pair.privateKeyDER.isEmpty)
        XCTAssertFalse(pair.publicKeyDER.isEmpty)
        XCTAssertEqual(pair.curve, .p256)
    }

    func test_ecSigningKeyPair_isRandom() {
        let a = SAECKeyGenerator.generateSigningKeyPair(curve: .p256)
        let b = SAECKeyGenerator.generateSigningKeyPair(curve: .p256)
        XCTAssertNotEqual(a.privateKeyDER, b.privateKeyDER)
    }

    func test_ecKeyAgreementPair_allCurves() {
        for curve in [ECCurve.p256, .p384, .p521] {
            let pair = SAECKeyGenerator.generateKeyAgreementPair(curve: curve)
            XCTAssertFalse(pair.privateKeyDER.isEmpty, "privateKeyDER should not be empty for \(curve)")
            XCTAssertFalse(pair.publicKeyDER.isEmpty, "publicKeyDER should not be empty for \(curve)")
        }
    }

    // MARK: SARSACipher — Key Generation

    func test_rsa_generateKeyPair_producesNonEmptyKeys() throws {
        let pair = try SARSACipher.generateKeyPair(keySize: .bits2048)
        XCTAssertFalse(pair.privateKeyData.isEmpty)
        XCTAssertFalse(pair.publicKeyData.isEmpty)
    }

    func test_rsa_generateKeyPair_isRandom() throws {
        let a = try SARSACipher.generateKeyPair()
        let b = try SARSACipher.generateKeyPair()
        XCTAssertNotEqual(a.publicKeyData, b.publicKeyData)
    }

    // MARK: SARSACipher — Encrypt / Decrypt

    func test_rsa_encryptDecrypt_roundTrip() throws {
        let pair      = try SARSACipher.generateKeyPair(keySize: .bits2048)
        let plaintext = Data("secret message".utf8)
        let encrypted = try SARSACipher.encrypt(plaintext, publicKeyData: pair.publicKeyData)
        let decrypted = try SARSACipher.decrypt(encrypted, privateKeyData: pair.privateKeyData)
        XCTAssertEqual(decrypted, plaintext)
    }

    func test_rsa_encrypt_isNonDeterministic() throws {
        let pair      = try SARSACipher.generateKeyPair()
        let plaintext = Data("same message".utf8)
        let c1 = try SARSACipher.encrypt(plaintext, publicKeyData: pair.publicKeyData)
        let c2 = try SARSACipher.encrypt(plaintext, publicKeyData: pair.publicKeyData)
        XCTAssertNotEqual(c1, c2, "OAEP padding randomises ciphertext")
    }

    func test_rsa_wrongPrivateKey_throwsOnDecrypt() throws {
        let pair1     = try SARSACipher.generateKeyPair()
        let pair2     = try SARSACipher.generateKeyPair()
        let plaintext = Data("message".utf8)
        let encrypted = try SARSACipher.encrypt(plaintext, publicKeyData: pair1.publicKeyData)
        XCTAssertThrowsError(
            try SARSACipher.decrypt(encrypted, privateKeyData: pair2.privateKeyData)
        )
    }

    // MARK: Integration: RSA wraps AES key

    func test_rsa_wrapsAESKey_roundTrip() throws {
        let rsaPair   = try SARSACipher.generateKeyPair()
        let aesKey    = SAAESEncryptor.generateKey()             // 32 bytes
        let wrapped   = try SARSACipher.encrypt(aesKey, publicKeyData: rsaPair.publicKeyData)
        let unwrapped = try SARSACipher.decrypt(wrapped, privateKeyData: rsaPair.privateKeyData)
        XCTAssertEqual(unwrapped, aesKey)
    }
}
