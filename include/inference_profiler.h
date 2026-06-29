// =============================================================================
// RawrXD Inference Profiler — C++ Header / Integration Bridge
// Zero deps, inline hooks into existing inference pipeline
// =============================================================================
#pragma once
#include <cstdint>
#include <cstring>

// MASM exports
extern "C" {
    int  Profiler_Initialize();
    int  Profiler_BeginRegion(const char* name);
    void Profiler_EndRegion(int region_idx);
    uint64_t Profiler_Report(char* buffer, uint64_t buf_size);
    void Profiler_Reset();
}

namespace rxdn {

// RAII region scoper — zero overhead when profiler inactive
struct ProfileScope {
    int idx = -1;
    explicit ProfileScope(const char* name) {
        idx = Profiler_BeginRegion(name);
    }
    ~ProfileScope() {
        if (idx >= 0) Profiler_EndRegion(idx);
    }
    // No copy/move — strict RAII
    ProfileScope(const ProfileScope&) = delete;
    ProfileScope& operator=(const ProfileScope&) = delete;
};

// Static inline helpers for manual begin/end (rare cases)
inline int  prof_begin(const char* name) { return Profiler_BeginRegion(name); }
inline void prof_end(int idx)            { Profiler_EndRegion(idx); }

// Convenience: profile a full function body
#define PROFILE_FUNC() rxdn::ProfileScope _prof(__FUNCTION__)

// Convenience: profile a named block
#define PROFILE_BLOCK(name) rxdn::ProfileScope _prof_##__LINE__(name)

// Report to stdout (or telemetry log)
inline void prof_dump() {
    char buf[4096];
    uint64_t n = Profiler_Report(buf, sizeof(buf));
    if (n) {
        buf[n < sizeof(buf) ? n : sizeof(buf)-1] = '\0';
        // Write to your telemetry sink here
        // Telemetry::LogRaw(buf);
    }
}

} // namespace rxdn
