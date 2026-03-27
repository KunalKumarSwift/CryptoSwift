import XCTest
@testable import SACrypto

final class SecureRandomTests: XCTestCase {

    // MARK: SASecureRandom.bytes

    func test_bytes_returnsCorrectCount() {
        for count in [1, 16, 32, 64, 256] {
            XCTAssertEqual(SASecureRandom.bytes(count: count).count, count,
                           "bytes(count: \(count)) should return exactly \(count) bytes")
        }
    }

    func test_bytes_isRandom() {
        let a = SASecureRandom.bytes(count: 32)
        let b = SASecureRandom.bytes(count: 32)
        XCTAssertNotEqual(a, b, "Two independent calls must produce different bytes")
    }

    func test_bytes_emptyRequest_returnsEmptyData() {
        XCTAssertEqual(SASecureRandom.bytes(count: 0).count, 0)
    }

    // MARK: SASecureRandom.uint32

    func test_uint32_isRandom() {
        // Very unlikely (1/2^32) that 5 consecutive calls all return the same value
        let values = (0..<5).map { _ in SASecureRandom.uint32() }
        let unique = Set(values)
        XCTAssertGreaterThan(unique.count, 1)
    }

    // MARK: SASecureRandom.uint64

    func test_uint64_isRandom() {
        let a = SASecureRandom.uint64()
        let b = SASecureRandom.uint64()
        // 1/2^64 chance of collision
        XCTAssertNotEqual(a, b)
    }

    // MARK: SASecureRandom.uniformRandom

    func test_uniformRandom_isWithinBounds() {
        for _ in 0..<1000 {
            let value = SASecureRandom.uniformRandom(upperBound: 6)
            XCTAssertLessThan(value, 6)
        }
    }

    func test_uniformRandom_upperBound1_alwaysReturns0() {
        for _ in 0..<100 {
            XCTAssertEqual(SASecureRandom.uniformRandom(upperBound: 1), 0)
        }
    }

    func test_uniformRandom_coversAllValues() {
        // With 1000 trials over [0,5], expect all 6 values to appear
        var seen = Set<UInt32>()
        for _ in 0..<1000 {
            seen.insert(SASecureRandom.uniformRandom(upperBound: 6))
        }
        XCTAssertEqual(seen, [0, 1, 2, 3, 4, 5])
    }

    // MARK: Statistical sanity — chi-square uniformity

    func test_bytes_distributionIsReasonablyUniform() {
        // Generate 25,600 bytes and check byte-value frequencies
        let data = SASecureRandom.bytes(count: 25_600)
        var counts = [Int](repeating: 0, count: 256)
        data.forEach { counts[Int($0)] += 1 }

        let expected = Double(data.count) / 256.0  // 100 per bucket
        var chiSquare = 0.0
        for count in counts {
            let diff = Double(count) - expected
            chiSquare += (diff * diff) / expected
        }
        // For 255 df, chi-square > 310 would be suspicious at p < 0.001
        XCTAssertLessThan(chiSquare, 350, "Byte distribution looks non-uniform — chi-square = \(chiSquare)")
    }
}
