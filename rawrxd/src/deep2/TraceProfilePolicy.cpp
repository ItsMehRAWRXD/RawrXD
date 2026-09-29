// TraceProfilePolicy.cpp — RAWRXD_TRACE_PROFILE_POLICY_001
#include "TraceProfilePolicy.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <atomic>
#include <string>

namespace rawrxd { namespace trace {

static std::atomic<RawrTraceProfile> g_profile{RawrTraceProfile::Perf};
static std::atomic<bool> g_initialized{false};
static std::atomic<bool> g_debugContaminated{false};
static std::atomic<uint64_t> g_traceSpamLines{0};

static void initializeProfile() {
    bool expected = false;
    if (!g_initialized.compare_exchange_strong(expected, true)) return;

    const char* env = std::getenv("RAWRXD_TRACE_PROFILE");
    if (env && env[0]) {
        if (std::strcmp(env, "debug") == 0) { g_profile.store(RawrTraceProfile::Debug); return; }
        if (std::strcmp(env, "ide") == 0) { g_profile.store(RawrTraceProfile::Ide); return; }
        if (std::strcmp(env, "receipt") == 0) { g_profile.store(RawrTraceProfile::Receipt); return; }
        if (std::strcmp(env, "perf") == 0) { g_profile.store(RawrTraceProfile::Perf); return; }
    }
    // Legacy env vars force debug
    auto on = [](const char* name) -> bool {
        const char* v = std::getenv(name);
        return v && v[0] && v[0] != '0';
    };
    if (on("DEEP2_TRACE_FORWARD") || on("RAWRXD_VERBOSE") || on("RAWRXD_TRACE_TOKEN")) {
        g_profile.store(RawrTraceProfile::Debug);
        g_debugContaminated.store(true);
        return;
    }
    // Default: perf (clean TPS, no hotpath spam)
    g_profile.store(RawrTraceProfile::Perf);
}

RawrTraceProfile currentProfile() {
    if (!g_initialized.load()) initializeProfile();
    return g_profile.load();
}

bool enabled(RawrTraceChannel channel) {
    RawrTraceProfile p = currentProfile();
    // Receipt mode: no stderr traces at all
    if (p == RawrTraceProfile::Receipt) return false;

    // Perf mode: only summaries + failures (no hotpath spam)
    if (p == RawrTraceProfile::Perf) {
        switch (channel) {
            case RawrTraceChannel::Stream:    return true;  // [STREAM] RESULT = TPS receipt
            case RawrTraceChannel::Generate:  return true;  // [GENERATE] EXIT = TPS summary
            default: return false;  // suppress all hotpath in perf
        }
    }

    // IDE mode: stage events + summaries + failures, but no per-token flood
    if (p == RawrTraceProfile::Ide) {
        switch (channel) {
            case RawrTraceChannel::Init:       return true;
            case RawrTraceChannel::Alloc:      return true;
            case RawrTraceChannel::Tokenize:   return true;
            case RawrTraceChannel::Stream:     return true;
            case RawrTraceChannel::Generate:   return true;
            case RawrTraceChannel::Forward:    return true;  // [FWD_ALL] entry only (not per-layer)
            case RawrTraceChannel::Embed:      return true;  // failures only
            // Suppress per-token hotpath in IDE mode:
            case RawrTraceChannel::LinearW:    return false;
            case RawrTraceChannel::GpuForward: return false;
            case RawrTraceChannel::Logits:     return false;
            case RawrTraceChannel::Sampler:    return false;
            case RawrTraceChannel::Decode:     return false;
            default: return true;  // stage-level events
        }
    }

    // Debug mode: everything on
    // (all channels enabled)
    (void)channel;
    return true;
}

void markDebugContaminated(const char* reason) {
    g_debugContaminated.store(true);
    if (reason) {
        std::fprintf(stderr, "[TRACE_PROFILE] DEBUG_CONTAMINATED reason=%s\n", reason);
        std::fflush(stderr);
    }
}

bool isTpsBaselineValid() {
    return !g_debugContaminated.load();
}

uint64_t traceSpamLines() {
    return g_traceSpamLines.load();
}

void incrementTraceSpam() {
    g_traceSpamLines.fetch_add(1, std::memory_order_relaxed);
}

void writeTraceProfileReceipt(const std::string& path) {
    RawrTraceProfile p = currentProfile();
    FILE* f = nullptr;
    fopen_s(&f, path.c_str(), "w");
    if (!f) return;

    std::fprintf(f, "GATE=RAWRXD_TRACE_PROFILE_POLICY_001\n");
    std::fprintf(f, "TRACE_PROFILE=%s\n", profileName(p));
    std::fprintf(f, "TRACE_SPAM_LINES=%llu\n", (unsigned long long)traceSpamLines());
    std::fprintf(f, "TPS_VALID_FOR_BASELINE=%d\n", isTpsBaselineValid() ? 1 : 0);
    std::fprintf(f, "DEBUG_CONTAMINATED=%d\n", g_debugContaminated.load() ? 1 : 0);
    std::fprintf(f, "STRUCTURED_DIAG_ENABLED=%d\n", (p == RawrTraceProfile::Ide) ? 1 : 0);
    std::fprintf(f, "UNCONDITIONAL_HOTPATH_SPAM=%d\n", (p == RawrTraceProfile::Debug) ? 1 : 0);
    std::fprintf(f, "VERDICT=%s\n", isTpsBaselineValid() ? "PASS" : "DIAG_PASS");
    std::fclose(f);
}

const char* profileName(RawrTraceProfile p) {
    switch (p) {
        case RawrTraceProfile::Perf:    return "perf";
        case RawrTraceProfile::Ide:     return "ide";
        case RawrTraceProfile::Debug:   return "debug";
        case RawrTraceProfile::Receipt: return "receipt";
        default: return "unknown";
    }
}

const char* channelName(RawrTraceChannel c) {
    switch (c) {
        case RawrTraceChannel::Init:        return "Init";
        case RawrTraceChannel::Alloc:       return "Alloc";
        case RawrTraceChannel::Tokenize:    return "Tokenize";
        case RawrTraceChannel::Embed:       return "Embed";
        case RawrTraceChannel::Forward:     return "Forward";
        case RawrTraceChannel::LinearW:     return "LinearW";
        case RawrTraceChannel::GpuForward:  return "GpuForward";
        case RawrTraceChannel::Logits:      return "Logits";
        case RawrTraceChannel::Sampler:     return "Sampler";
        case RawrTraceChannel::Decode:      return "Decode";
        case RawrTraceChannel::Stream:      return "Stream";
        case RawrTraceChannel::Generate:    return "Generate";
        case RawrTraceChannel::Speculative: return "Speculative";
        case RawrTraceChannel::MoE:         return "MoE";
        case RawrTraceChannel::SSM:         return "SSM";
        case RawrTraceChannel::KernelRoute: return "KernelRoute";
        default: return "Unknown";
    }
}

}} // namespace rawrxd::trace