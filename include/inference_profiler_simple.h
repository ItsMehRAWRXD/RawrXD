// ============================================================================
// Simple C++ Profiler — Replacement for MASM version (stability first)
// ============================================================================
#pragma once
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <windows.h>

// Simple RDTSC inline function
inline uint64_t rdtsc() {
    return __rdtsc();
}

// Global profiler state
struct ProfileRegion {
    const char* name;
    uint64_t total_cycles;
    uint64_t call_count;
    uint64_t max_cycles;
    uint64_t t0;  // scratch for current timing
};

static const int MAX_REGIONS = 16;
static ProfileRegion g_regions[MAX_REGIONS];
static int g_region_count = 0;
static bool g_profiler_active = false;
static uint64_t g_rdtsc_overhead = 50;

// Initialize profiler
inline void Profiler_Initialize() {
    memset(g_regions, 0, sizeof(g_regions));
    g_region_count = 0;
    g_profiler_active = true;
    g_rdtsc_overhead = 50;  // Estimated overhead
}

// Begin region
inline int Profiler_BeginRegion(const char* name) {
    if (!g_profiler_active) return -1;
    
    // Find existing region
    for (int i = 0; i < g_region_count; i++) {
        if (strcmp(g_regions[i].name, name) == 0) {
            g_regions[i].t0 = rdtsc();
            return i;
        }
    }
    
    // Create new region
    if (g_region_count >= MAX_REGIONS) return -1;
    int idx = g_region_count++;
    g_regions[idx].name = name;
    g_regions[idx].t0 = rdtsc();
    return idx;
}

// End region
inline void Profiler_EndRegion(int idx) {
    if (!g_profiler_active || idx < 0 || idx >= MAX_REGIONS) return;
    
    uint64_t t1 = rdtsc();
    uint64_t delta = t1 - g_regions[idx].t0;
    if (delta > g_rdtsc_overhead) {
        delta -= g_rdtsc_overhead;
    }
    
    g_regions[idx].total_cycles += delta;
    g_regions[idx].call_count++;
    if (delta > g_regions[idx].max_cycles) {
        g_regions[idx].max_cycles = delta;
    }
}

// Report results
inline uint64_t Profiler_Report(char* buffer, uint64_t buf_size) {
    if (!g_profiler_active || buf_size == 0) return 0;
    
    uint64_t written = 0;
    for (int i = 0; i < g_region_count; i++) {
        if (g_regions[i].call_count == 0) continue;
        
        int n = snprintf(buffer + written, buf_size - written,
            "%s,%llu,%llu,%llu,%llu\n",
            g_regions[i].name,
            g_regions[i].total_cycles,
            g_regions[i].call_count,
            g_regions[i].total_cycles / g_regions[i].call_count,
            g_regions[i].max_cycles);
        
        if (n > 0) {
            written += n;
        }
    }
    
    return written;
}

// C++ RAII wrapper
namespace rxdn {
struct ProfileScope {
    int idx = -1;
    explicit ProfileScope(const char* name) {
        idx = Profiler_BeginRegion(name);
    }
    ~ProfileScope() {
        if (idx >= 0) Profiler_EndRegion(idx);
    }
    ProfileScope(const ProfileScope&) = delete;
    ProfileScope& operator=(const ProfileScope&) = delete;
};

inline void prof_dump() {
    char buf[4096];
    uint64_t n = Profiler_Report(buf, sizeof(buf));
    if (n) {
        buf[n < sizeof(buf) ? n : sizeof(buf)-1] = '\0';
        printf("\n=== INFERENCE PROFILER REPORT ===\n%s", buf);
    }
}
} // namespace rxdn

#define PROFILE_FUNC() rxdn::ProfileScope _prof(__FUNCTION__)
#define PROFILE_BLOCK(name) rxdn::ProfileScope _prof_##__LINE__(name)
