import XCTest
@testable import SACrypto

final class SignatureTests: XCTestCase {

    private let message = Data("sign this message".utf8)

    // MARK: SAEd25519Signer

    func test_ed25519_generateKeyPair_correctLengths() {
        let pair = SAEd25519Signer.generateKeyPair()
        XCTAssertEqual(pair.privateKeyData.count, 32)
        XCTAssertEqual(pair.publicKeyData.count, 32)
    }

    func test_ed25519_generateKeyPair_isRandom() {
        XCTAssertNotEqual(
            SAEd25519Signer.generateKeyPair().privateKeyData,
            SAEd25519Signer.generateKeyPair().privateKeyData
        )
    }

    func test_ed25519_signVerify_roundTrip() throws {
        let pair      = SAEd25519Signer.generateKeyPair()
        let signature = try SAEd25519Signer.sign(message, privateKeyData: pair.privateKeyData)
        let valid     = try SAEd25519Signer.verify(signature, for: message, publicKeyData: pair.publicKeyData)
        XCTAssertTrue(valid)
    }

    func test_ed25519_signature_is64Bytes() throws {
        let pair = SAEd25519Signer.generateKeyPair()
        let sig  = try SAEd25519Signer.sign(message, privateKeyData: pair.privateKeyData)
        XCTAssertEqual(sig.count, 64)
    }

    func test_ed25519_isDeterministic() throws {
        let pair = SAEd25519Signer.generateKeyPair()
        let sig1 = try SAEd25519Signer.sign(message, privateKeyData: pair.privateKeyData)
        let sig2 = try SAEd25519Signer.sign(message, privateKeyData: pair.privateKeyData)
        XCTAssertEqual(sig1, sig2, "Ed25519 signatures are deterministic")
    }

    func test_ed25519_tamperedMessage_failsVerification() throws {
        let pair      = SAEd25519Signer.generateKeyPair()
        let signature = try SAEd25519Signer.sign(message, privateKeyData: pair.privateKeyData)
        let tampered  = Data("sign THIS message".utf8)
        let valid     = try SAEd25519Signer.verify(signature, for: tampered, publicKeyData: pair.publicKeyData)
        XCTAssertFalse(valid)
    }

    func test_ed25519_wrongPublicKey_failsVerification() throws {
        let pair      = SAEd25519Signer.generateKeyPair()
        let wrongPair = SAEd25519Signer.generateKeyPair()
        let signature = try SAEd25519Signer.sign(message, privateKeyData: pair.privateKeyData)
        let valid     = try SAEd25519Signer.verify(signature, for: message, publicKeyData: wrongPair.publicKeyData)
        XCTAssertFalse(valid)
    }

    func test_ed25519_tamperedSignature_failsVerification() throws {
        let pair = SAEd25519Signer.generateKeyPair()
        var sig  = try SAEd25519Signer.sign(message, privateKeyData: pair.privateKeyData)
        sig[0] ^= 0xFF
        XCTAssertThrowsError(
            try SAEd25519Signer.verify(sig, for: message, publicKeyData: pair.publicKeyData)
        )
    }

    // MARK: SAECDSASigner — P-256

    func test_ecdsa_p256_roundTrip() throws {
        let pair = SAECKeyGenerator.generateSigningKeyPair(curve: .p256)
        let sig  = try SAECDSASigner.sign(message, privateKeyDER: pair.privateKeyDER, curve: .p256)
        let ok   = try SAECDSASigner.verify(sig, for: message, publicKeyDER: pair.publicKeyDER, curve: .p256)
        XCTAssertTrue(ok)
    }

    func test_ecdsa_p256_tamperedMessage_failsVerification() throws {
        let pair     = SAECKeyGenerator.generateSigningKeyPair(curve: .p256)
        let sig      = try SAECDSASigner.sign(message, privateKeyDER: pair.privateKeyDER, curve: .p256)
        let tampered = Data("tampered".utf8)
        let ok       = try SAECDSASigner.verify(sig, for: tampered, publicKeyDER: pair.publicKeyDER, curve: .p256)
        XCTAssertFalse(ok)
    }

    func test_ecdsa_p256_wrongKey_failsVerification() throws {
        let pair  = SAECKeyGenerator.generateSigningKeyPair(curve: .p256)
        let other = SAECKeyGenerator.generateSigningKeyPair(curve: .p256)
        let sig   = try SAECDSASigner.sign(message, privateKeyDER: pair.privateKeyDER, curve: .p256)
        let ok    = try SAECDSASigner.verify(sig, for: message, publicKeyDER: other.publicKeyDER, curve: .p256)
        XCTAssertFalse(ok)
    }

    // MARK: SAECDSASigner — P-384 / P-521

    func test_ecdsa_p384_roundTrip() throws {
        let pair = SAECKeyGenerator.generateSigningKeyPair(curve: .p384)
        let sig  = try SAECDSASigner.sign(message, privateKeyDER: pair.privateKeyDER, curve: .p384)
        XCTAssertTrue(try SAECDSASigner.verify(sig, for: message, publicKeyDER: pair.publicKeyDER, curve: .p384))
    }

    func test_ecdsa_p521_roundTrip() throws {
        let pair = SAECKeyGenerator.generateSigningKeyPair(curve: .p521)
        let sig  = try SAECDSASigner.sign(message, privateKeyDER: pair.privateKeyDER, curve: .p521)
        XCTAssertTrue(try SAECDSASigner.verify(sig, for: message, publicKeyDER: pair.publicKeyDER, curve: .p521))
    }

    func test_ecdsa_crossCurve_keysAreIncompatible() throws {
        let p256pair = SAECKeyGenerator.generateSigningKeyPair(curve: .p256)
        let p384pair = SAECKeyGenerator.generateSigningKeyPair(curve: .p384)
        let sig = try SAECDSASigner.sign(message, privateKeyDER: p256pair.privateKeyDER, curve: .p256)
        XCTAssertThrowsError(
            try SAECDSASigner.verify(sig, for: message, publicKeyDER: p384pair.publicKeyDER, curve: .p384),
            "Using a P-384 key to verify a P-256 signature should throw"
        )
    }
}
