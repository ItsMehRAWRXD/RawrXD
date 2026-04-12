// rawrengine_asm_dispatch_stubs.cpp
// RawrEngine headless lane: satisfy MASM dispatch bridge symbols.
// These are intentionally minimal; real dispatch is provided by SSOT/unified dispatch in other targets.

#include <atomic>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>

namespace {
std::atomic<unsigned long long> g_cliDispatchCount{0};
std::atomic<unsigned long long> g_commandDispatchCount{0};
std::atomic<unsigned long long> g_featureDispatchCount{0};
std::atomic<unsigned long long> g_featureCount{0};
std::atomic<bool> g_featuresInitialized{false};
std::atomic<unsigned long long> g_dispatchMode{0};
std::atomic<unsigned long long> g_modeParseFallbackCount{0};
std::atomic<unsigned long long> g_dispatchTotal{0};
std::atomic<unsigned long long> g_lastDispatchChannel{0};

unsigned long long parseModeToken(const char* m)
{
    if (!m) {
        return 0;
    }
    if (std::strcmp(m, "strict") == 0) {
        return 1;
    }
    if (std::strcmp(m, "balanced") == 0) {
        return 2;
    }
    if (std::strcmp(m, "burst") == 0) {
        return 3;
    }
    if (std::strcmp(m, "0") == 0) {
        return 0;
    }
    return 0xFFFFFFFFFFFFFFFFULL;
}

unsigned long long parseFeatureCountFromEnv()
{
    if (const char* v = std::getenv("RAWRXD_FEATURE_COUNT")) {
        char* end = nullptr;
        const unsigned long long n = std::strtoull(v, &end, 10);
        if (end != v) {
            return n;
        }
    }

    if (const char* features = std::getenv("RAWRXD_FEATURES")) {
        unsigned long long count = 0;
        bool inToken = false;
        for (const char* p = features; *p; ++p) {
            const char c = *p;
            const bool sep = (c == ',' || c == ';' || c == '|');
            if (!sep && c != ' ' && c != '\t' && c != '\r' && c != '\n') {
                if (!inToken) {
                    ++count;
                    inToken = true;
                }
            } else {
                inToken = false;
            }
        }
        return count;
    }

    return 0ULL;
}

void ensureFeatureCountInitialized()
{
    bool expected = false;
    if (g_featuresInitialized.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        g_featureCount.store(parseFeatureCountFromEnv(), std::memory_order_release);

        if (const char* m = std::getenv("RAWRXD_DISPATCH_MODE")) {
            const unsigned long long mode = parseModeToken(m);
            if (mode == 0xFFFFFFFFFFFFFFFFULL) {
                g_dispatchMode.store(0, std::memory_order_release);
                g_modeParseFallbackCount.fetch_add(1, std::memory_order_relaxed);
            } else {
                g_dispatchMode.store(mode, std::memory_order_release);
            }
        }
    }
}
} // namespace

extern "C" void rawrxd_dispatch_cli()
{
    ensureFeatureCountInitialized();
    g_dispatchTotal.fetch_add(1, std::memory_order_relaxed);
    g_lastDispatchChannel.store(1, std::memory_order_relaxed);
    const auto n = g_cliDispatchCount.fetch_add(1, std::memory_order_relaxed) + 1;
    std::fprintf(stderr,
                 "[RawrEngine] rawrxd_dispatch_cli fallback dispatch=%llu mode=%llu\n",
                 n,
                 g_dispatchMode.load(std::memory_order_acquire));
}

extern "C" void rawrxd_dispatch_command()
{
    ensureFeatureCountInitialized();
    g_dispatchTotal.fetch_add(1, std::memory_order_relaxed);
    g_lastDispatchChannel.store(2, std::memory_order_relaxed);
    const auto n = g_commandDispatchCount.fetch_add(1, std::memory_order_relaxed) + 1;
    std::fprintf(stderr,
                 "[RawrEngine] rawrxd_dispatch_command fallback dispatch=%llu mode=%llu\n",
                 n,
                 g_dispatchMode.load(std::memory_order_acquire));
}

extern "C" void rawrxd_dispatch_feature()
{
    ensureFeatureCountInitialized();
    g_dispatchTotal.fetch_add(1, std::memory_order_relaxed);
    g_lastDispatchChannel.store(3, std::memory_order_relaxed);
    const auto n = g_featureDispatchCount.fetch_add(1, std::memory_order_relaxed) + 1;
    std::fprintf(stderr,
                 "[RawrEngine] rawrxd_dispatch_feature fallback dispatch=%llu available_features=%llu\n",
                 n,
                 g_featureCount.load(std::memory_order_acquire));
}

extern "C" unsigned __int64 rawrxd_get_feature_count()
{
    ensureFeatureCountInitialized();
    return g_featureCount.load(std::memory_order_acquire);
}

extern "C" unsigned __int64 rawrxd_get_dispatch_stub_stats()
{
    // [63:56] last_channel, [55:48] mode, [47:40] parse_fallback,
    // [39:32] feature_dispatch, [31:24] command_dispatch,
    // [23:16] cli_dispatch, [15:8] dispatch_total, [7:0] feature_count.
    const unsigned long long lastChannel = g_lastDispatchChannel.load(std::memory_order_relaxed) & 0xFFULL;
    const unsigned long long mode = g_dispatchMode.load(std::memory_order_relaxed) & 0xFFULL;
    const unsigned long long parseFallback = g_modeParseFallbackCount.load(std::memory_order_relaxed) & 0xFFULL;
    const unsigned long long featureDispatch = g_featureDispatchCount.load(std::memory_order_relaxed) & 0xFFULL;
    const unsigned long long commandDispatch = g_commandDispatchCount.load(std::memory_order_relaxed) & 0xFFULL;
    const unsigned long long cliDispatch = g_cliDispatchCount.load(std::memory_order_relaxed) & 0xFFULL;
    const unsigned long long dispatchTotal = g_dispatchTotal.load(std::memory_order_relaxed) & 0xFFULL;
    const unsigned long long featureCount = g_featureCount.load(std::memory_order_relaxed) & 0xFFULL;
    return (lastChannel << 56) | (mode << 48) | (parseFallback << 40) | (featureDispatch << 32) |
           (commandDispatch << 24) | (cliDispatch << 16) | (dispatchTotal << 8) | featureCount;
}

extern "C" unsigned __int64 rawrxd_set_dispatch_stub_mode(unsigned __int64 mode)
{
    // Allowed modes: 0=default, 1=strict, 2=balanced, 3=burst.
    if (mode > 3ULL) {
        g_modeParseFallbackCount.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
    g_dispatchMode.store(mode, std::memory_order_release);
    return mode;
}

extern "C" void rawrxd_reset_dispatch_stub_stats()
{
    g_cliDispatchCount.store(0, std::memory_order_relaxed);
    g_commandDispatchCount.store(0, std::memory_order_relaxed);
    g_featureDispatchCount.store(0, std::memory_order_relaxed);
    g_dispatchTotal.store(0, std::memory_order_relaxed);
    g_lastDispatchChannel.store(0, std::memory_order_relaxed);
    g_modeParseFallbackCount.store(0, std::memory_order_relaxed);
}
