// swift-tools-version:6.0

import PackageDescription

let package = Package(
    name: "Crypto",
    platforms: [
        .iOS(.v15),
    ],
    products: [
        .library(
            name: "SACrypto",
            targets: ["SACrypto"]),
    ],
    targets: [
        .target(
            name: "SACrypto",
            dependencies: [],
            path: "Sources/SACrypto"
        ),
        .testTarget(
            name: "SACryptoTests",
            dependencies: ["SACrypto"],
            path: "Tests/SACryptoTests"
        ),
    ]
)
