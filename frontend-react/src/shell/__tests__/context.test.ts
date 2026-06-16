import { describe, expect, it } from "vitest";
import { formatTimestampValue, shiftTimeZoneInputValue, timeZoneDisplayLabel, toUtcQueryValue } from "../context";

describe("shell timezone helpers", () => {
  it("converts operator local input into UTC query values", () => {
    expect(toUtcQueryValue("2026-03-20T15:30", "Europe/Moscow")).toBe("2026-03-20 12:30:00");
    expect(toUtcQueryValue("2026-03-20T08:15", "America/New_York")).toBe("2026-03-20 12:15:00");
  });

  it("keeps the same instant when switching timezone input shells", () => {
    expect(shiftTimeZoneInputValue("2026-03-20T15:30", "Europe/Moscow", "UTC")).toBe("2026-03-20T12:30");
    expect(shiftTimeZoneInputValue("2026-03-20T12:30", "UTC", "Europe/Moscow")).toBe("2026-03-20T15:30");
  });

  it("formats UTC-backed timestamps in the selected operator timezone", () => {
    expect(formatTimestampValue("2026-03-20 12:30:00", "Europe/Moscow", "ru", "time")).toContain("15:30");
    expect(formatTimestampValue("2026-03-20 12:30:00", "UTC", "en", "time")).toContain("12:30");
  });

  it("provides an explicit timezone label for operator-facing timestamps", () => {
    expect(timeZoneDisplayLabel("Europe/Moscow", "ru")).toBe("МСК (UTC+3)");
    expect(timeZoneDisplayLabel("UTC", "en")).toBe("UTC");
    expect(timeZoneDisplayLabel("Europe/Berlin", "en")).toBe("Berlin");
  });
});
