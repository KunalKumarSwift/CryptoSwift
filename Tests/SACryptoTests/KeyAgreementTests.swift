import XCTest
@testable import SACrypto

final class KeyAgreementTests: XCTestCase {

    // MARK: SAX25519Agreement

    func test_x25519_generateKeyPair_correctLengths() {
        let pair = SAX25519Agreement.generateKeyPair()
        XCTAssertEqual(pair.privateKeyData.count, 32)
        XCTAssertEqual(pair.publicKeyData.count, 32)
    }

    func test_x25519_generateKeyPair_isRandom() {
        XCTAssertNotEqual(
            SAX25519Agreement.generateKeyPair().privateKeyData,
            SAX25519Agreement.generateKeyPair().privateKeyData
        )
    }

    func test_x25519_bothSidesDeriveSameKey() throws {
        let alice = SAX25519Agreement.generateKeyPair()
        let bob   = SAX25519Agreement.generateKeyPair()

        let aliceShared = try SAX25519Agreement.sharedSymmetricKey(
            myPrivateKeyData: alice.privateKeyData,
            peerPublicKeyData: bob.publicKeyData
        )
        let bobShared = try SAX25519Agreement.sharedSymmetricKey(
            myPrivateKeyData: bob.privateKeyData,
            peerPublicKeyData: alice.publicKeyData
        )

        XCTAssertEqual(aliceShared, bobShared, "ECDH must produce identical keys on both sides")
    }

    func test_x25519_sharedKey_is32Bytes() throws {
        let a = SAX25519Agreement.generateKeyPair()
        let b = SAX25519Agreement.generateKeyPair()
        let key = try SAX25519Agreement.sharedSymmetricKey(
            myPrivateKeyData: a.privateKeyData,
            peerPublicKeyData: b.publicKeyData
        )
        XCTAssertEqual(key.count, 32)
    }

    func test_x25519_sharedKey_variesWithDifferentPeers() throws {
        let alice = SAX25519Agreement.generateKeyPair()
        let bob   = SAX25519Agreement.generateKeyPair()
        let carol = SAX25519Agreement.generateKeyPair()

        let ab = try SAX25519Agreement.sharedSymmetricKey(
            myPrivateKeyData: alice.privateKeyData,
            peerPublicKeyData: bob.publicKeyData
        )
        let ac = try SAX25519Agreement.sharedSymmetricKey(
            myPrivateKeyData: alice.privateKeyData,
            peerPublicKeyData: carol.publicKeyData
        )
        XCTAssertNotEqual(ab, ac)
    }

    func test_x25519_saltAffectsOutput() throws {
        let a = SAX25519Agreement.generateKeyPair()
        let b = SAX25519Agreement.generateKeyPair()
        let k1 = try SAX25519Agreement.sharedSymmetricKey(
            myPrivateKeyData: a.privateKeyData,
            peerPublicKeyData: b.publicKeyData,
            salt: Data("session-1".utf8)
        )
        let k2 = try SAX25519Agreement.sharedSymmetricKey(
            myPrivateKeyData: a.privateKeyData,
            peerPublicKeyData: b.publicKeyData,
            salt: Data("session-2".utf8)
        )
        XCTAssertNotEqual(k1, k2)
    }

    func test_x25519_customOutputLength() throws {
        let a = SAX25519Agreement.generateKeyPair()
        let b = SAX25519Agreement.generateKeyPair()
        let key = try SAX25519Agreement.sharedSymmetricKey(
            myPrivateKeyData: a.privateKeyData,
            peerPublicKeyData: b.publicKeyData,
            outputByteCount: 64
        )
        XCTAssertEqual(key.count, 64)
    }

    // MARK: Integration: X25519 + AES-GCM

    func test_x25519_sharedKeyUsableForEncryption() throws {
        let alice = SAX25519Agreement.generateKeyPair()
        let bob   = SAX25519Agreement.generateKeyPair()

        let aliceKey = try SAX25519Agreement.sharedSymmetricKey(
            myPrivateKeyData: alice.privateKeyData,
            peerPublicKeyData: bob.publicKeyData
        )
        let bobKey = try SAX25519Agreement.sharedSymmetricKey(
            myPrivateKeyData: bob.privateKeyData,
            peerPublicKeyData: alice.publicKeyData
        )

        let plaintext = Data("secret from Alice to Bob".utf8)
        let sealed    = try SAAESEncryptor.encrypt(plaintext, key: aliceKey)
        let recovered = try SAAESEncryptor.decrypt(sealed, key: bobKey)
        XCTAssertEqual(recovered, plaintext)
    }

    // MARK: SAECDHAgreement

    func test_ecdh_p256_bothSidesDeriveSameKey() throws {
        let alice = SAECKeyGenerator.generateKeyAgreementPair(curve: .p256)
        let bob   = SAECKeyGenerator.generateKeyAgreementPair(curve: .p256)

        let aliceShared = try SAECDHAgreement.sharedSymmetricKey(
            myPrivateKeyDER: alice.privateKeyDER,
            peerPublicKeyDER: bob.publicKeyDER,
            curve: .p256
        )
        let bobShared = try SAECDHAgreement.sharedSymmetricKey(
            myPrivateKeyDER: bob.privateKeyDER,
            peerPublicKeyDER: alice.publicKeyDER,
            curve: .p256
        )

        XCTAssertEqual(aliceShared, bobShared)
    }

    func test_ecdh_p384_bothSidesDeriveSameKey() throws {
        let alice = SAECKeyGenerator.generateKeyAgreementPair(curve: .p384)
        let bob   = SAECKeyGenerator.generateKeyAgreementPair(curve: .p384)

        let aliceShared = try SAECDHAgreement.sharedSymmetricKey(
            myPrivateKeyDER: alice.privateKeyDER,
            peerPublicKeyDER: bob.publicKeyDER,
            curve: .p384
        )
        let bobShared = try SAECDHAgreement.sharedSymmetricKey(
            myPrivateKeyDER: bob.privateKeyDER,
            peerPublicKeyDER: alice.publicKeyDER,
            curve: .p384
        )

        XCTAssertEqual(aliceShared, bobShared)
    }

    func test_ecdh_p521_bothSidesDeriveSameKey() throws {
        let alice = SAECKeyGenerator.generateKeyAgreementPair(curve: .p521)
        let bob   = SAECKeyGenerator.generateKeyAgreementPair(curve: .p521)

        let aliceShared = try SAECDHAgreement.sharedSymmetricKey(
            myPrivateKeyDER: alice.privateKeyDER,
            peerPublicKeyDER: bob.publicKeyDER,
            curve: .p521
        )
        let bobShared = try SAECDHAgreement.sharedSymmetricKey(
            myPrivateKeyDER: bob.privateKeyDER,
            peerPublicKeyDER: alice.publicKeyDER,
            curve: .p521
        )

        XCTAssertEqual(aliceShared, bobShared)
    }

    func test_ecdh_differentCurves_produceDifferentLengthKeys() throws {
        let aliceP256 = SAECKeyGenerator.generateKeyAgreementPair(curve: .p256)
        let bobP256   = SAECKeyGenerator.generateKeyAgreementPair(curve: .p256)
        let aliceP384 = SAECKeyGenerator.generateKeyAgreementPair(curve: .p384)
        let bobP384   = SAECKeyGenerator.generateKeyAgreementPair(curve: .p384)

        let k256 = try SAECDHAgreement.sharedSymmetricKey(
            myPrivateKeyDER: aliceP256.privateKeyDER, peerPublicKeyDER: bobP256.publicKeyDER, curve: .p256
        )
        let k384 = try SAECDHAgreement.sharedSymmetricKey(
            myPrivateKeyDER: aliceP384.privateKeyDER, peerPublicKeyDER: bobP384.publicKeyDER,
            curve: .p384, outputByteCount: 48
        )

        XCTAssertEqual(k256.count, 32)
        XCTAssertEqual(k384.count, 48)
    }
}
