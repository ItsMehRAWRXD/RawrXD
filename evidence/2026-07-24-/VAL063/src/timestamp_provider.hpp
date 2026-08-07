#pragma once

#include "execution_types.hpp"

namespace val063 {

// High-resolution timestamp capture
// Provides both monotonic (for duration) and wall-clock (for correlation) timestamps
class TimestampProvider {
public:
    TimestampProvider();
    ~TimestampProvider() = default;

    // Capture current timestamp from both clocks
    Timestamp now() const;

    // Get monotonic time only (for intervals)
    static Timestamp::TimePoint monotonic_now();

    // Get wall clock time only (for logging/correlation)
    static Timestamp::WallTimePoint wall_now();

    // Convert wall time to ISO 8601 string
    static std::string to_iso8601(Timestamp::WallTimePoint tp);

    // Parse ISO 8601 string to wall time
    static std::optional<Timestamp::WallTimePoint> from_iso8601(std::string_view str);

    // Duration between two timestamps
    static std::chrono::nanoseconds duration(
        const Timestamp& start, 
        const Timestamp& end
    );

    // Check if timestamps are monotonically ordered
    static bool is_monotonic(const Timestamp& earlier, const Timestamp& later);

    // Convert to nanoseconds since epoch
    static int64_t to_ns_since_epoch(Timestamp::WallTimePoint tp);
    static int64_t to_ns_since_epoch(Timestamp::TimePoint tp);
};

// Convenience functions
namespace timestamp {
    // Capture now
    Timestamp now();
    
    // Current time in ISO 8601
    std::string iso8601_now();
    
    // Check monotonic ordering
    bool is_ordered(const Timestamp& t1, const Timestamp& t2);
}

} // namespace val063
