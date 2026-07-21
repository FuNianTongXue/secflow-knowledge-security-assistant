import AppKit
import SwiftUI

private enum WeChatLikeWindowMetrics {
    static let defaultSize = CGSize(width: 1100, height: 720)
    static let minSize = CGSize(width: 960, height: 620)
    static let cornerRadius: CGFloat = 12
}

@MainActor
final class SecFlowAppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.appearance = NSAppearance(named: .aqua)
    }

    func applicationWillTerminate(_ notification: Notification) {
        LocalBackendManager.shared.stop()
    }
}

@main
struct SecFlowMacApp: App {
    @NSApplicationDelegateAdaptor(SecFlowAppDelegate.self) private var appDelegate
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup("") {
            RootView()
                .environmentObject(model)
                .preferredColorScheme(.light)
                .environment(\.colorScheme, .light)
                .environment(\.locale, model.appLanguage.locale)
                .tint(AppPalette.primary)
                .frame(
                    minWidth: WeChatLikeWindowMetrics.minSize.width,
                    minHeight: WeChatLikeWindowMetrics.minSize.height
                )
                .background(WeChatLikeWindowConfigurator())
        }
        .defaultSize(
            width: WeChatLikeWindowMetrics.defaultSize.width,
            height: WeChatLikeWindowMetrics.defaultSize.height
        )
        .commands {
            CommandGroup(after: .appInfo) {
                Button(model.text(.refreshData)) {
                    Task { await model.refreshAll() }
                }
                .keyboardShortcut("r", modifiers: .command)
            }
        }

        Settings {
            SettingsView()
                .environmentObject(model)
                .overlay {
                    TrialStatusBlocker(status: model.trialStatus)
                }
                .preferredColorScheme(.light)
                .environment(\.colorScheme, .light)
                .environment(\.locale, model.appLanguage.locale)
                .tint(AppPalette.primary)
                .frame(width: 1080, height: 760)
        }
    }
}

private struct WeChatLikeWindowConfigurator: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async {
            configure(view.window)
        }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        DispatchQueue.main.async {
            configure(nsView.window)
        }
    }

    private func configure(_ window: NSWindow?) {
        guard let window else { return }
        window.styleMask.insert(.resizable)
        window.styleMask.insert(.fullSizeContentView)
        clearNativeWindowTitle(window)
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.isOpaque = false
        window.backgroundColor = .clear
        window.hasShadow = true
        window.isMovableByWindowBackground = false
        window.minSize = NSSize(
            width: WeChatLikeWindowMetrics.minSize.width,
            height: WeChatLikeWindowMetrics.minSize.height
        )
        window.resizeIncrements = NSSize(width: 1, height: 1)
        window.collectionBehavior.insert(.fullScreenPrimary)
        window.contentView?.wantsLayer = true
        window.contentView?.layer?.backgroundColor = NSColor.clear.cgColor
        window.contentView?.layer?.cornerRadius = WeChatLikeWindowMetrics.cornerRadius
        window.contentView?.layer?.cornerCurve = .continuous
        window.contentView?.layer?.masksToBounds = true

        DispatchQueue.main.async {
            clearNativeWindowTitle(window)
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
            clearNativeWindowTitle(window)
        }
    }
}

private func clearNativeWindowTitle(_ window: NSWindow) {
    window.title = ""
    window.subtitle = ""
    window.representedURL = nil

    if let titlebarView = window.standardWindowButton(.closeButton)?.superview {
        hideTitleTextFields(in: titlebarView)
    }

    if let frameView = window.contentView?.superview {
        for subview in frameView.subviews where String(describing: type(of: subview)).contains("Titlebar") {
            hideTitleTextFields(in: subview)
        }
    }
}

private func hideTitleTextFields(in view: NSView) {
    if let textField = view as? NSTextField {
        textField.stringValue = ""
        textField.isHidden = true
        textField.alphaValue = 0
    }
    view.subviews.forEach(hideTitleTextFields)
}
