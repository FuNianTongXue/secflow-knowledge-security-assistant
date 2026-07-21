// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "SecFlowMac",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "SecFlowMac", targets: ["SecFlowMac"]),
    ],
    targets: [
        .executableTarget(
            name: "SecFlowMac",
            resources: [
                .copy("Resources")
            ]
        ),
        .testTarget(name: "SecFlowMacTests", dependencies: ["SecFlowMac"]),
    ]
)
