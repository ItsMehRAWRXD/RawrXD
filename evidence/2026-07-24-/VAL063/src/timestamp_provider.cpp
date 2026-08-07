#include "timestamp_provider.hpp"
#include <iomanip>
#include <sstream>
#include <string>

namespace val063 {

TimestampProvider::TimestampProvider() = default;
TimestampProvider::~TimestampProvider() = default;

Timestamp TimestampProvider::now() const {
    return Timestamp::now();
}

Timestamp::TimePoint TimestampProvider::monotonic_now() {
    return Timestamp::Clock::now();
}

Timestamp::WallTimePoint TimestampProvider::wall_now() {
    return Timestamp::WallClock::now();
}

std::string TimestampProvider::to_iso8601(Timestamp::WallTimePoint tp) {
    auto time_t = Timestamp::WallClock::to_time_t(tp);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        tp.time_since_epoch()
    ) % 1000;
    
    std::tm utc{};
    gmtime_s(&utc, &time_t);
    
    std::ostringstream oss;
    oss << std::put_time(&utc, "%Y-%m-%dT%H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    oss << 'Z';
    
    return oss.str();
}

std::optional<Timestamp::WallTimePoint> TimestampProvider::from_iso8601(std::string_view str) {
    // Parse ISO 8601 format: YYYY-MM-DDTHH:MM:SS.sssZ
    if (str.length() < 20) {
        return std::nullopt;
    }
    
    std::tm tm{};
    int year, month, day, hour, minute, second, millis;
    
    // Parse date and time components
    if (sscanf_s(str.data(), "%d-%d-%dT%d:%d:%d.%dZ", 
                 &year, &month, &day, &hour, &minute, &second, &millis) < 6) {
        // Try without milliseconds
        if (sscanf_s(str.data(), "%d-%d-%dT%d:%d:%dZ",
                     &year, &month, &day, &hour, &minute, &second) < 6) {
            return std::nullopt;
        }
        millis = 0;
    }
    
    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_sec = second;
    tm.tm_isdst = 0;
    
    auto time_t = _mkgmtime(&tm);
    if (time_t == -1) {
        return std::nullopt;
    }
    
    auto tp = Timestamp::WallClock::from_time_t(time_t);
    tp += std::chrono::milliseconds(millis);
    
    return tp;
}

std::chrono::nanoseconds TimestampProvider::duration(
    const Timestamp& start, 
    const Timestamp& end
) {
    return end.elapsed_since(start);
}

bool TimestampProvider::is_monotonic(const Timestamp& earlier, const Timestamp& later) {
    return later.monotonic >= earlier.monotonic;
}

int64_t TimestampProvider::to_ns_since_epoch(Timestamp::WallTimePoint tp) {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        tp.time_since_epoch()
    ).count();
}

int64_t TimestampProvider::to_ns_since_epoch(Timestamp::TimePoint tp) {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        tp.time_since_epoch()
    ).count();
}

// ============================================================================
// Convenience namespace
// ============================================================================

namespace timestamp {

Timestamp now() {
    return Timestamp::now();
}

std::string iso8601_now() {
    return TimestampProvider::to_iso8601(TimestampProvider::wall_now());
}

bool is_ordered(const Timestamp& t1, const Timestamp& t2) {
    return TimestampProvider::is_monotonic(t1, t2);
}

} // namespace timestamp

} // namespace val063
