// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ZcashNameSDK",
    platforms: [.macOS(.v12), .iOS(.v15)],
    products: [
        .library(name: "ZcashNameSDK", targets: ["ZcashNameSDK"]),
    ],
    targets: [
        .target(name: "ZcashNameSDK"),
    ]
)
