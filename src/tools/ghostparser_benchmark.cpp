// ============================================================================
// ghostparser_benchmark.cpp — GhostParser SIMD vs Scalar TPS Micro-benchmark
// ============================================================================
// Measures tokens-per-second (TPS) ceiling for completion marker scanning.
// Compares AVX2/AVX-512 MASM fast-path against scalar wcsstr fallback.
//
// Build: cmake --build . --target RawrXD-GhostParserBench
// Run:   .\bin\RawrXD-GhostParserBench.exe
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <chrono>
#include <intrin.h>

// MASM fast-path exports
extern "C" {
    size_t GhostParser_ScanVectorized(
        const wchar_t* buffer, size_t bufferLen,
        void* outPayloads, size_t maxPayloads);
    size_t GhostParser_ScanVectorized_AVX512(
        const wchar_t* buffer, size_t bufferLen,
        void* outPayloads, size_t maxPayloads);
}

// Payload layout (must match MASM exactly)
#pragma pack(push, 1)
struct GhostCompletionPayload {
    const wchar_t* text;
    int startPos;
    int endPos;
    float confidence;
};
#pragma pack(pop)

// ── CPU Feature Detection ────────────────────────────────────────────────
static bool g_hasAVX2 = false;
static bool g_hasAVX512F = false;

static void detectCPUFeatures() {
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    bool osxsave = (cpuInfo[2] & (1 << 27)) != 0;
    bool avx = (cpuInfo[2] & (1 << 28)) != 0;

    if (osxsave && avx) {
        unsigned long long xcr0 = _xgetbv(0);
        bool ymmState = (xcr0 & 0x06) == 0x06;  // YMM state enabled
        if (ymmState) {
            int cpuInfo7[4] = {0};
            __cpuidex(cpuInfo7, 7, 0);
            g_hasAVX2 = (cpuInfo7[1] & (1 << 5)) != 0;  // AVX2 (bit 5 of EBX)
            bool avx512f = (cpuInfo7[1] & (1 << 16)) != 0;
            bool zmmState = (xcr0 & 0xE0) == 0xE0;  // ZMM state enabled
            g_hasAVX512F = avx512f && zmmState;
        }
    }
}

// ── High-resolution timer ────────────────────────────────────────────────
static double qpcToUs(uint64_t start, uint64_t end) {
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    return (double)(end - start) * 1e6 / freq.QuadPart;
}

// ── Test buffer generator ────────────────────────────────────────────────
static std::wstring generateBuffer(size_t wcharCount, size_t markerCount) {
    std::wstring buf;
    buf.reserve(wcharCount);

    // Fill with ASCII text
    const wchar_t filler[] = L"// This is a typical code completion context buffer used by the IDE ghost text renderer. ";
    size_t fillerLen = wcslen(filler);

    size_t markersPlaced = 0;
    size_t step = wcharCount / (markerCount + 1);

    for (size_t i = 0; i < wcharCount; ) {
        // Add filler text
        size_t chunk = std::min(fillerLen, wcharCount - i);
        buf.append(filler, chunk);
        i += chunk;

        // Inject marker at regular intervals
        if (markersPlaced < markerCount && i + 20 < wcharCount) {
            buf += L"[[COMPLETION:result";
            buf += std::to_wstring(markersPlaced);
            buf += L"]]";
            i += 20;
            ++markersPlaced;
        }
    }

    // Pad to exact size
    while (buf.size() < wcharCount) buf += L' ';
    if (buf.size() > wcharCount) buf.resize(wcharCount);
    return buf;
}

// ── Scalar reference scan (same logic as ghost_completion_parse.cpp) ────
static size_t scalarScan(const wchar_t* buf, size_t len,
                         std::vector<GhostCompletionPayload>& out) {
    size_t found = 0;
    const wchar_t* p = buf;
    const wchar_t* end = buf + len;
    const wchar_t marker[] = L"[[COMPLETION:";
    size_t markerLen = wcslen(marker);

    while (p < end) {
        const wchar_t* hit = wcsstr(p, marker);
        if (!hit) break;
        const wchar_t* contentStart = hit + markerLen;
        const wchar_t* contentEnd = wcsstr(contentStart, L"]]");
        if (!contentEnd) break;

        GhostCompletionPayload pl{};
        pl.text = contentStart;
        pl.startPos = static_cast<int>(hit - buf);
        pl.endPos = static_cast<int>(contentEnd + 2 - buf);
        pl.confidence = 0.85f;
        out.push_back(pl);
        ++found;
        p = contentEnd + 2;
    }
    return found;
}

// ── Benchmark runner ─────────────────────────────────────────────────────
struct BenchResult {
    const char* name;
    size_t bufSize;
    size_t markersFound;
    double usPerScan;
    double scansPerSec;
    double tpsEquivalent;  // tokens/sec if each marker = 1 token
    double speedupVsScalar;
};

static BenchResult benchScalar(const std::wstring& buf, size_t iterations) {
    std::vector<GhostCompletionPayload> out;
    out.reserve(64);

    LARGE_INTEGER t0, t1;
    QueryPerformanceCounter(&t0);
    size_t totalFound = 0;
    for (size_t i = 0; i < iterations; ++i) {
        out.clear();
        totalFound += scalarScan(buf.c_str(), buf.length(), out);
    }
    QueryPerformanceCounter(&t1);

    double totalUs = qpcToUs(t0.QuadPart, t1.QuadPart);
    double usPerScan = totalUs / iterations;
    BenchResult r{};
    r.name = "Scalar (wcsstr)";
    r.bufSize = buf.length() * sizeof(wchar_t);
    r.markersFound = totalFound / iterations;
    r.usPerScan = usPerScan;
    r.scansPerSec = 1e6 / usPerScan;
    r.tpsEquivalent = r.scansPerSec;  // 1 scan = 1 token opportunity
    r.speedupVsScalar = 1.0;
    return r;
}

static BenchResult benchAVX2(const std::wstring& buf, size_t iterations) {
    alignas(32) GhostCompletionPayload payloads[64];

    LARGE_INTEGER t0, t1;
    QueryPerformanceCounter(&t0);
    size_t totalFound = 0;
    for (size_t i = 0; i < iterations; ++i) {
        totalFound += GhostParser_ScanVectorized(
            buf.c_str(), buf.length(), payloads, 64);
    }
    QueryPerformanceCounter(&t1);

    double totalUs = qpcToUs(t0.QuadPart, t1.QuadPart);
    double usPerScan = totalUs / iterations;
    BenchResult r{};
    r.name = "AVX2 MASM";
    r.bufSize = buf.length() * sizeof(wchar_t);
    r.markersFound = totalFound / iterations;
    r.usPerScan = usPerScan;
    r.scansPerSec = 1e6 / usPerScan;
    r.tpsEquivalent = r.scansPerSec;
    return r;
}

static BenchResult benchAVX512(const std::wstring& buf, size_t iterations) {
    alignas(64) GhostCompletionPayload payloads[64];

    LARGE_INTEGER t0, t1;
    QueryPerformanceCounter(&t0);
    size_t totalFound = 0;
    for (size_t i = 0; i < iterations; ++i) {
        totalFound += GhostParser_ScanVectorized_AVX512(
            buf.c_str(), buf.length(), payloads, 64);
    }
    QueryPerformanceCounter(&t1);

    double totalUs = qpcToUs(t0.QuadPart, t1.QuadPart);
    double usPerScan = totalUs / iterations;
    BenchResult r{};
    r.name = "AVX-512 MASM";
    r.bufSize = buf.length() * sizeof(wchar_t);
    r.markersFound = totalFound / iterations;
    r.usPerScan = usPerScan;
    r.scansPerSec = 1e6 / usPerScan;
    r.tpsEquivalent = r.scansPerSec;
    return r;
}

// ── Main ─────────────────────────────────────────────────────────────────
int main() {
    detectCPUFeatures();

    printf("GhostParser SIMD Micro-benchmark\n");
    printf("CPU Features: AVX2=%s  AVX-512F=%s\n",
           g_hasAVX2 ? "YES" : "NO",
           g_hasAVX512F ? "YES" : "NO");
    printf("================================\n\n");

    // Quick test
    printf("Quick test AVX2 with 32-wchar buffer... ");
    {
        std::wstring w = generateBuffer(32, 1);
        alignas(32) GhostCompletionPayload pl[64];
        size_t n = GhostParser_ScanVectorized(w.c_str(), w.length(), pl, 64);
        printf("found %zu markers\n", n);
    }

    printf("Quick test AVX-512 with 32-wchar buffer... ");
    {
        std::wstring w = generateBuffer(32, 1);
        alignas(64) GhostCompletionPayload pl[64];
        size_t n = GhostParser_ScanVectorized_AVX512(w.c_str(), w.length(), pl, 64);
        printf("found %zu markers\n", n);
    }

    // Warmup
    printf("[Warmup] ...\n");
    {
        std::wstring w = generateBuffer(1024, 4);
        alignas(32) GhostCompletionPayload pl[64];
        if (g_hasAVX2) {
            GhostParser_ScanVectorized(w.c_str(), w.length(), pl, 64);
        }
    }

    // Test sizes: small (typical completion), medium (file), large (batch)
    const size_t sizes[] = { 1024, 4096, 16384, 65536, 262144 };
    const size_t markers[] = { 4, 8, 16, 32, 64 };
    const size_t iterations[] = { 10000, 5000, 2000, 500, 100 };

    for (int s = 0; s < 5; ++s) {
        size_t sz = sizes[s];
        size_t mk = markers[s];
        size_t iter = iterations[s];

        std::wstring buf = generateBuffer(sz, mk);
        printf("Buffer: %zu wchar_t (%zu bytes), %zu markers, %zu iters\n",
               sz, sz * sizeof(wchar_t), mk, iter);

        BenchResult scalar = benchScalar(buf, iter);
        printf("  %-16s  %8.2f us/scan  %10.0f scans/s\n",
               scalar.name, scalar.usPerScan, scalar.scansPerSec);

        if (g_hasAVX2) {
            BenchResult avx2 = benchAVX2(buf, iter);
            avx2.speedupVsScalar = scalar.usPerScan / avx2.usPerScan;
            printf("  %-16s  %8.2f us/scan  %10.0f scans/s  %8.1fx\n",
                   avx2.name, avx2.usPerScan, avx2.scansPerSec, avx2.speedupVsScalar);
        } else {
            printf("  AVX2             SKIPPED (buggy)\n");
        }

        if (g_hasAVX512F) {
            BenchResult avx512 = benchAVX512(buf, iter);
            avx512.speedupVsScalar = scalar.usPerScan / avx512.usPerScan;
            printf("  %-16s  %8.2f us/scan  %10.0f scans/s  %8.1fx\n",
                   avx512.name, avx512.usPerScan, avx512.scansPerSec, avx512.speedupVsScalar);
        } else {
            printf("  AVX-512          SKIPPED (not supported)\n");
        }
        printf("\n");
    }

    printf("Benchmark complete.\n");
    return 0;
}
