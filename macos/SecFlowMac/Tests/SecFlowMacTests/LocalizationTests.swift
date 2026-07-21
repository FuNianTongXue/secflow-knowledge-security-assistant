import XCTest
@testable import SecFlowMac

@MainActor
final class LocalizationTests: XCTestCase {
    override func tearDown() {
        UserDefaults.standard.removeObject(forKey: "secflow.appLanguage")
        super.tearDown()
    }

    func testLanguageSelectionIsPersisted() {
        UserDefaults.standard.set(AppLanguage.en.rawValue, forKey: "secflow.appLanguage")

        XCTAssertEqual(AppLanguage.storedValue(), .en)
        XCTAssertEqual(localized(.navReports, language: .en), "Reports")
        XCTAssertEqual(localized(.navReports, language: .zhHans), "报告中心")
    }

    func testSupportedSettingsLanguagesExposeApiCodes() {
        XCTAssertEqual(AppLanguage.allCases.map(\.apiCode), [
            "zh-Hans",
            "zh-Hant",
            "en",
            "ko",
            "ja",
            "es",
            "fr",
            "de",
            "it",
            "ru",
        ])
        XCTAssertEqual(AppLanguage(apiCode: "zh-Hant"), .zhHant)
        XCTAssertEqual(AppLanguage(apiCode: "fr-FR"), .fr)
        XCTAssertEqual(AppLanguage(apiCode: "ru_RU"), .ru)
    }

    func testAppVersionUsesSharedBundleValue() {
        XCTAssertEqual(localized(.appVersion, language: .zhHans), AppBrand.versionLabel)
        XCTAssertEqual(localized(.appVersion, language: .en), AppBrand.versionLabel)
    }

    func testAppModelStoresSelectedLanguage() {
        let model = AppModel()

        model.setLanguage(.es)

        XCTAssertEqual(model.appLanguage, .es)
        XCTAssertEqual(UserDefaults.standard.string(forKey: "secflow.appLanguage"), AppLanguage.es.rawValue)
        XCTAssertEqual(model.text(.settings), "Settings")
    }
}
