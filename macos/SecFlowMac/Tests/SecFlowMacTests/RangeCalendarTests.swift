import XCTest
@testable import SecFlowMac

final class RangeCalendarTests: XCTestCase {
    func testJuly2026MatchesFiveWeekReferenceLayout() throws {
        let calendar = RangeCalendarLayout.calendar
        let july = try XCTUnwrap(calendar.date(from: DateComponents(year: 2026, month: 7, day: 16)))
        let days = RangeCalendarLayout.days(in: july)

        XCTAssertEqual(days.count, 35)
        XCTAssertEqual(calendar.dateComponents([.year, .month, .day], from: days.first!.date), DateComponents(year: 2026, month: 6, day: 28))
        XCTAssertEqual(calendar.dateComponents([.year, .month, .day], from: days.last!.date), DateComponents(year: 2026, month: 8, day: 1))
        XCTAssertFalse(days.first!.isInDisplayedMonth)
        XCTAssertTrue(days[3].isInDisplayedMonth)
        XCTAssertFalse(days.last!.isInDisplayedMonth)
    }

    func testCalendarExpandsToSixWeeksWhenRequired() throws {
        let calendar = RangeCalendarLayout.calendar
        let august = try XCTUnwrap(calendar.date(from: DateComponents(year: 2026, month: 8, day: 1)))

        XCTAssertEqual(RangeCalendarLayout.days(in: august).count, 42)
    }
}
