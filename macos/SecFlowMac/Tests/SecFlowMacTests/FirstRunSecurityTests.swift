import AppKit
import SwiftUI
import XCTest
@testable import SecFlowMac

final class FirstRunSecurityTests: XCTestCase {
    @MainActor
    func testEmbeddedBackendDoesNotInheritDeveloperLLMEnvironment() {
        var source = [
            "PATH": "/usr/bin",
            "HOME": "/tmp/example-home",
        ]
        for key in LocalBackendManager.isolatedLLMEnvironmentKeys {
            source[key] = "developer-secret-or-setting"
        }

        let isolated = LocalBackendManager.isolatedBackendEnvironment(from: source)

        XCTAssertEqual(isolated["PATH"], "/usr/bin")
        XCTAssertEqual(isolated["HOME"], "/tmp/example-home")
        for key in LocalBackendManager.isolatedLLMEnvironmentKeys {
            XCTAssertNil(isolated[key], "\(key) must not reach the packaged backend")
        }
    }

    @MainActor
    func testFirstRunWizardRendersProviderStep() throws {
        let size = NSSize(width: 1100, height: 720)
        let hostingView = NSHostingView(
            rootView: LLMOnboardingView()
                .environmentObject(AppModel())
                .frame(width: size.width, height: size.height)
        )
        hostingView.frame = NSRect(origin: .zero, size: size)
        hostingView.layoutSubtreeIfNeeded()
        let bitmap = try XCTUnwrap(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))
        XCTAssertGreaterThan(nonWhitePixelCount(bitmap), 20_000)

        if let snapshotPath = ProcessInfo.processInfo.environment["SECFLOW_ONBOARDING_SNAPSHOT"] {
            try png.write(to: URL(fileURLWithPath: snapshotPath), options: .atomic)
        }
    }

    private func nonWhitePixelCount(_ bitmap: NSBitmapImageRep) -> Int {
        var count = 0
        for y in stride(from: 0, to: bitmap.pixelsHigh, by: 4) {
            for x in stride(from: 0, to: bitmap.pixelsWide, by: 4) {
                guard let color = bitmap.colorAt(x: x, y: y)?.usingColorSpace(.deviceRGB) else { continue }
                if color.redComponent < 0.97 || color.greenComponent < 0.97 || color.blueComponent < 0.97 {
                    count += 16
                }
            }
        }
        return count
    }
}
