// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "TestAlgoChat",
    platforms: [
        .macOS(.v12)
    ],
    dependencies: [
        .package(url: "https://github.com/CorvidLabs/swift-algochat.git", from: "0.0.1"),
        .package(url: "https://github.com/CorvidLabs/swift-algokit.git", from: "0.0.2")
    ],
    targets: [
        .executableTarget(
            name: "TestAlgoChat",
            dependencies: [
                .product(name: "AlgoChat", package: "swift-algochat"),
                .product(name: "AlgoKit", package: "swift-algokit")
            ],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency"),
                .unsafeFlags(["-parse-as-library"])
            ]
        )
    ]
)
