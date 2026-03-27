import XCTest
@testable import SACrypto

final class SymmetricEncryptionTests: XCTestCase {

    private let plaintext = Data("the quick brown fox jumps over the lazy dog".utf8)

    // MARK: SAAESEncryptor

    func test_aes_generateKey_is32Bytes() {
        XCTAssertEqual(SAAESEncryptor.generateKey().count, 32)
    }

    func test_aes_generateKey_isRandom() {
        XCTAssertNotEqual(SAAESEncryptor.generateKey(), SAAESEncryptor.generateKey())
    }

    func test_aes_encryptDecrypt_roundTrip() throws {
        let key      = SAAESEncryptor.generateKey()
        let sealed   = try SAAESEncryptor.encrypt(plaintext, key: key)
        let recovered = try SAAESEncryptor.decrypt(sealed, key: key)
        XCTAssertEqual(recovered, plaintext)
    }

    func test_aes_nonce_isUniquePerEncryption() throws {
        let key  = SAAESEncryptor.generateKey()
        let s1   = try SAAESEncryptor.encrypt(plaintext, key: key)
        let s2   = try SAAESEncryptor.encrypt(plaintext, key: key)
        XCTAssertNotEqual(s1.nonce, s2.nonce, "A fresh nonce must be generated each time")
    }

    func test_aes_ciphertext_sameLength_asPlaintext() throws {
        let key    = SAAESEncryptor.generateKey()
        let sealed = try SAAESEncryptor.encrypt(plaintext, key: key)
        XCTAssertEqual(sealed.ciphertext.count, plaintext.count)
    }

    func test_aes_tag_is16Bytes() throws {
        let key    = SAAESEncryptor.generateKey()
        let sealed = try SAAESEncryptor.encrypt(plaintext, key: key)
        XCTAssertEqual(sealed.tag.count, 16)
    }

    func test_aes_nonce_is12Bytes() throws {
        let key    = SAAESEncryptor.generateKey()
        let sealed = try SAAESEncryptor.encrypt(plaintext, key: key)
        XCTAssertEqual(sealed.nonce.count, 12)
    }

    func test_aes_combined_hasCorrectLength() throws {
        let key    = SAAESEncryptor.generateKey()
        let sealed = try SAAESEncryptor.encrypt(plaintext, key: key)
        XCTAssertEqual(sealed.combined.count, 12 + plaintext.count + 16)
    }

    func test_aes_decryptFromCombined_roundTrip() throws {
        let key      = SAAESEncryptor.generateKey()
        let sealed   = try SAAESEncryptor.encrypt(plaintext, key: key)
        let recovered = try SAAESEncryptor.decrypt(combined: sealed.combined, key: key)
        XCTAssertEqual(recovered, plaintext)
    }

    func test_aes_wrongKey_throwsOnDecrypt() throws {
        let key    = SAAESEncryptor.generateKey()
        let sealed = try SAAESEncryptor.encrypt(plaintext, key: key)
        let wrong  = SAAESEncryptor.generateKey()
        XCTAssertThrowsError(try SAAESEncryptor.decrypt(sealed, key: wrong))
    }

    func test_aes_tamperedTag_throwsOnDecrypt() throws {
        let key    = SAAESEncryptor.generateKey()
        let sealed = try SAAESEncryptor.encrypt(plaintext, key: key)
        var badTag = sealed.tag
        badTag[0] ^= 0xFF
        let tampered = SASealedData(nonce: sealed.nonce, ciphertext: sealed.ciphertext, tag: badTag)
        XCTAssertThrowsError(try SAAESEncryptor.decrypt(tampered, key: key))
    }

    func test_aes_emptyPlaintext_roundTrip() throws {
        let key      = SAAESEncryptor.generateKey()
        let sealed   = try SAAESEncryptor.encrypt(Data(), key: key)
        let recovered = try SAAESEncryptor.decrypt(sealed, key: key)
        XCTAssertEqual(recovered, Data())
    }

    // MARK: SAChaChaEncryptor

    func test_chacha_generateKey_is32Bytes() {
        XCTAssertEqual(SAChaChaEncryptor.generateKey().count, 32)
    }

    func test_chacha_encryptDecrypt_roundTrip() throws {
        let key      = SAChaChaEncryptor.generateKey()
        let sealed   = try SAChaChaEncryptor.encrypt(plaintext, key: key)
        let recovered = try SAChaChaEncryptor.decrypt(sealed, key: key)
        XCTAssertEqual(recovered, plaintext)
    }

    func test_chacha_nonce_isUniquePerEncryption() throws {
        let key = SAChaChaEncryptor.generateKey()
        let s1  = try SAChaChaEncryptor.encrypt(plaintext, key: key)
        let s2  = try SAChaChaEncryptor.encrypt(plaintext, key: key)
        XCTAssertNotEqual(s1.nonce, s2.nonce)
    }

    func test_chacha_nonce_is12Bytes() throws {
        let key    = SAChaChaEncryptor.generateKey()
        let sealed = try SAChaChaEncryptor.encrypt(plaintext, key: key)
        XCTAssertEqual(sealed.nonce.count, 12)
    }

    func test_chacha_tag_is16Bytes() throws {
        let key    = SAChaChaEncryptor.generateKey()
        let sealed = try SAChaChaEncryptor.encrypt(plaintext, key: key)
        XCTAssertEqual(sealed.tag.count, 16)
    }

    func test_chacha_decryptFromCombined_roundTrip() throws {
        let key      = SAChaChaEncryptor.generateKey()
        let sealed   = try SAChaChaEncryptor.encrypt(plaintext, key: key)
        let recovered = try SAChaChaEncryptor.decrypt(combined: sealed.combined, key: key)
        XCTAssertEqual(recovered, plaintext)
    }

    func test_chacha_wrongKey_throwsOnDecrypt() throws {
        let key    = SAChaChaEncryptor.generateKey()
        let sealed = try SAChaChaEncryptor.encrypt(plaintext, key: key)
        XCTAssertThrowsError(try SAChaChaEncryptor.decrypt(sealed, key: SAChaChaEncryptor.generateKey()))
    }

    func test_chacha_tamperedCiphertext_throwsOnDecrypt() throws {
        let key    = SAChaChaEncryptor.generateKey()
        let sealed = try SAChaChaEncryptor.encrypt(plaintext, key: key)
        var badCt  = sealed.ciphertext
        badCt[0] ^= 0xFF
        let tampered = SASealedData(nonce: sealed.nonce, ciphertext: badCt, tag: sealed.tag)
        XCTAssertThrowsError(try SAChaChaEncryptor.decrypt(tampered, key: key))
    }

    // MARK: Cross-cipher compatibility

    func test_aesAndChaCha_produceDifferentCiphertexts() throws {
        let aesKey    = SAAESEncryptor.generateKey()
        let chachaKey = SAChaChaEncryptor.generateKey()
        let aesSealed    = try SAAESEncryptor.encrypt(plaintext, key: aesKey)
        let chachaSealed = try SAChaChaEncryptor.encrypt(plaintext, key: chachaKey)
        XCTAssertNotEqual(aesSealed.ciphertext, chachaSealed.ciphertext)
    }
}
