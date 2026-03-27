import XCTest
@testable import SACrypto

final class KeychainTests: XCTestCase {

    private let testKey  = "com.sacrypto.tests.keychain.\(UUID().uuidString)"
    private let testData = Data("keychain test value".utf8)

    override func tearDown() {
        try? SAKeychain.delete(forKey: testKey)
        super.tearDown()
    }

    // MARK: Store / Retrieve

    func test_store_andRetrieve_roundTrip() throws {
        try SAKeychain.store(testData, forKey: testKey)
        let retrieved = try SAKeychain.retrieve(forKey: testKey)
        XCTAssertEqual(retrieved, testData)
    }

    func test_store_overwritesExistingValue() throws {
        let first  = Data("first".utf8)
        let second = Data("second".utf8)
        try SAKeychain.store(first,  forKey: testKey)
        try SAKeychain.store(second, forKey: testKey)
        let retrieved = try SAKeychain.retrieve(forKey: testKey)
        XCTAssertEqual(retrieved, second)
    }

    func test_retrieve_missingKey_throwsItemNotFound() {
        let missingKey = "com.sacrypto.tests.does-not-exist.\(UUID().uuidString)"
        XCTAssertThrowsError(try SAKeychain.retrieve(forKey: missingKey)) { error in
            XCTAssertEqual(error as? SAKeychainError, .itemNotFound)
        }
    }

    // MARK: Delete

    func test_delete_removesItem() throws {
        try SAKeychain.store(testData, forKey: testKey)
        try SAKeychain.delete(forKey: testKey)
        XCTAssertThrowsError(try SAKeychain.retrieve(forKey: testKey)) { error in
            XCTAssertEqual(error as? SAKeychainError, .itemNotFound)
        }
    }

    func test_delete_nonExistentKey_doesNotThrow() {
        let missing = "com.sacrypto.tests.missing.\(UUID().uuidString)"
        XCTAssertNoThrow(try SAKeychain.delete(forKey: missing))
    }

    // MARK: Exists

    func test_exists_afterStore_returnsTrue() throws {
        try SAKeychain.store(testData, forKey: testKey)
        XCTAssertTrue(SAKeychain.exists(forKey: testKey))
    }

    func test_exists_beforeStore_returnsFalse() {
        let freshKey = "com.sacrypto.tests.fresh.\(UUID().uuidString)"
        XCTAssertFalse(SAKeychain.exists(forKey: freshKey))
    }

    func test_exists_afterDelete_returnsFalse() throws {
        try SAKeychain.store(testData, forKey: testKey)
        try SAKeychain.delete(forKey: testKey)
        XCTAssertFalse(SAKeychain.exists(forKey: testKey))
    }

    // MARK: Integration: store and recover AES key

    func test_storeAndRecover_aesKey() throws {
        let aesKey = SAAESEncryptor.generateKey()
        try SAKeychain.store(aesKey, forKey: testKey)
        let recovered = try SAKeychain.retrieve(forKey: testKey)
        XCTAssertEqual(recovered, aesKey)

        // Verify it still works for encryption
        let plaintext = Data("hello".utf8)
        let sealed    = try SAAESEncryptor.encrypt(plaintext, key: recovered)
        let decrypted = try SAAESEncryptor.decrypt(sealed, key: recovered)
        XCTAssertEqual(decrypted, plaintext)
    }
}
