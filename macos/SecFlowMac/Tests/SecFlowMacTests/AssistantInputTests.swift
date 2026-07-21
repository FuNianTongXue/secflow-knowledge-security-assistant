import XCTest
@testable import SecFlowMac

final class AssistantInputTests: XCTestCase {
    func testPunctuationOnlyQuestionIsNotMeaningful() {
        XCTAssertFalse(isMeaningfulAssistantQuestion("?"))
        XCTAssertFalse(isMeaningfulAssistantQuestion("？"))
        XCTAssertFalse(isMeaningfulAssistantQuestion("..."))
    }

    func testSecurityQuestionWithTextOrIdentifierIsMeaningful() {
        XCTAssertTrue(isMeaningfulAssistantQuestion("这个漏洞怎么修复？"))
        XCTAssertTrue(isMeaningfulAssistantQuestion("CVE-2026-55576"))
    }
}
