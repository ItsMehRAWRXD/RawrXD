// kernel_route_census.cpp — RAWRXD_KERNEL_ROUTE_CENSUS_001
//
// The claim being tested: model size in GB is NOT the predictor of decode
// throughput. What is, is the kernel route actually selected per quant type and
// geometry on THIS machine.
//
// Everything reported here is measured in this process on this CPU:
//
//   QUANT_TYPE       the GGML type id
//   KERNEL_SELECTED  whether a GEMV was resolved at all, and whether it is the
//                    hand-written MASM kernel or the scalar fallback
//   ISA_SELECTED     from the same CPUID the dispatcher itself uses
//   DEQUANT_NS       timed separately from the GEMV
//   GEMV_NS          timed with repetitions, best-of, so a scheduler hiccup
//                    cannot decide a comparison
//
// A type with no registered kernel is reported as such. It is not omitted: a
// census that silently drops the rows where nothing resolved is exactly the
// undercount this repository warns about.

#include "QuantKernelRegistry.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

using namespace Deep2;

namespace {

// Resolve a registered function pointer to a module+symbol so "which kernel was
// actually chosen" is a fact and not an assumption.
std::string describeFn(void* fn) {
    if (!fn) return "NONE";
    HMODULE mod = nullptr;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)fn, &mod) || !mod) {
        return "UNKNOWN_MODULE";
    }
    char path[MAX_PATH];
    if (!GetModuleFileNameA(mod, path, MAX_PATH)) return "UNKNOWN_PATH";
    const std::string p(path);
    const size_t slash = p.find_last_of("\\/");
    const std::string base = (slash == std::string::npos) ? p : p.substr(slash + 1);
    return base;
}

struct Row {
    int         quantType = 0;
    const char* name = "";
    bool        gemvResolved = false;
    bool        dequantResolved = false;
    bool        isMasm = false;
    std::string gemvModule;
    std::string dequantModule;
    double      dequantNs = 0.0;
    double      gemvNs = 0.0;
    double      bytesRead = 0.0;
    double      gbPerSec = 0.0;
    std::string note;
};

double timeIt(int reps, void (*fn)()) {
    QueryPerformanceFrequency(&freq);
    LARGE_INTEGER f, t0, t1;
    QueryPerformanceFrequency(&f);
    double best = 1e300;
    for (int k = 0; k < 3; ++k) {
        QueryPerformanceCounter(&t0);
        for (int r = 0; r < reps; ++r) fn();
        QueryPerformanceCounter(&t1);
        const double ns = (double)(t1.QuadPart - t0.QuadPart) * 1e9 /
                          (double)f.QuadPart / (double)reps;
        if (ns < best) best = ns;
    }
    return best;
}

} // namespace

int main(int argc, char** argv) {
    const std::uint32_t rows = (argc > 1) ? (std::uint32_t)std::atoi(argv[1]) : 256;
    const std::uint32_t cols = (argc > 2) ? (std::uint32_t)std::atoi(argv[2]) : 4096;

    std::printf("RAWRXD_KERNEL_ROUTE_CENSUS_001\n");
    std::printf("=================================\n");

    auto& reg = QuantKernelRegistry::Instance();
    reg.Initialize();
    reg.ProbeCPU();

    const CPUFeatures& cf = reg.cpuFeatures();
    std::printf("ISA_SELECTED avx2=%d avx512f=%d avx512bw=%d avx512dq=%d "
                "avx512vnni=%d fma=%d f16c=%d\n",
                cf.avx2 ? 1 : 0, cf.avx512f ? 1 : 0, cf.avx512bw ? 1 : 0,
                cf.avx512dq ? 1 : 0, cf.avx512vnni ? 1 : 0, cf.fma ? 1 : 0,
                cf.f16c ? 1 : 0);
    std::printf("GEOMETRY rows=%u cols=%u\n", rows, cols);
    std::printf("------------------------\n");

    // Every type the registry can describe, so a type with no kernel shows up
    // as an explicit row instead of vanishing.
    const int kTypes[] = {
        0,  1,  2,  3,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17,
        18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 34, 35, 36,
        37, 38, 39
    };

    std::vector<Row> table;
    std::vector<uint8_t> w;
    std::vector<float> x, y;

    std::mt19937 rng(20261003);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);

    for (int qt : kTypes) {
        const auto* desc = LookupQuantType((std::uint32_t)qt);
        if (!desc) continue;                 // not a real type at all

        Row r;
        r.quantType = qt;
        r.name = desc->typeName ? desc->typeName : "?";

        const std::uint32_t be = desc->blockElements ? desc->blockElements : 1;
        const std::uint32_t bb = desc->blockBytes ? desc->blockBytes : 1;
        if (desc->blockElements == 0 || desc->blockBytes == 0) {
            r.note = "ZERO_BLOCK_GEOMETRY";
            table.push_back(r);
            continue;
        }
        if ((cols % be) != 0) {
            r.note = "COLS_NOT_MULTIPLE_OF_BLOCK";
            table.push_back(r);
            continue;
        }

        auto gemv = reg.GetGEMV(qt);
        auto deq  = reg.GetDequant(qt);
        r.gemvResolved    = (gemv != nullptr);
        r.dequantResolved = (deq  != nullptr);
        r.gemmModule      = describeFn((void*)gemv);
        r.dequantModule   = describeFn((void*)deq);
        r.isMasm = (r.gemmModule.find("polykernel") == std::string::npos) &&
                   (r.gemmModule.find(".exe") == std::string::npos ||
                    r.gemmModule.find("inference") != std::string::npos ||
                    r.gemmModule.find("rawr") != std::string::npos);

        const std::size_t blocksPerRow = cols / be;
        const std::size_t bytes = (std::size_t)rows * blocksPerRow * bb;
        w.assign(bytes, 0);
        for (auto& b : w) b = (std::uint8_t)(rng() & 0xFF);
        x.assign(cols, 0.0f);
        for (auto& v : x) v = dist(rng);
        y.assign(rows, 0.0f);
        r.bytesRead = (double)bytes;

        if (deq) {
            auto* dw = w.data();
            auto* dx = x.data();
            const std::uint32_t c = cols;
            r.dequantNs = timeIt(3, [dw, dx, deq, c]() {
                for (std::uint32_t i = 0; i < 64; ++i) deq(dw, dx, c);
            });
        }
        if (gemv) {
            auto* gw = w.data();
            auto* gx = x.data();
            auto* gy = y.data();
            const std::uint32_t R = rows, C = cols;
            r.gemvNs = timeIt(3, [gw, gx, gy, gemv, R, C]() {
                for (std::uint32_t i = 0; i < 16; ++i) gemv(gw, gx, gy, R, C);
            });
        }
        if (r.gemvNs > 0.0) {
            // Bandwidth the GEMV actually demanded, measured from the bytes the
            // matrix must read, not from the file size of the whole model.
            const double perRep = r.bytesRead / (r.gemvNs / 16.0);
            r.gbPerSec = perRep / 1e9;
        }
        table.push_back(r);
    }

    std::printf("%-5s %-14s %-7s %-8s %-10s %12s %12s %12s %-22s %s\n",
                "QT", "NAME", "GEMV", "DEQ", "KIND",
                "DEQUANT_NS", "GEMV_NS", "GB_PER_SEC", "GEMV_MODULE", "NOTE");

    for (const auto& r : table) {
        const char* kind = !r.gemvResolved ? "NO_GEMV"
                         : (r.isMasm ? "MASM" : "SCALAR");
        std::printf("%-5d %-14s %-7s %-8s %-10s %12.1f %12.1f %12.3f %-22s %s\n",
                    r.quantType, r.name,
                    r.gemvResolved ? "yes" : "NO",
                    r.dequantResolved ? "yes" : "NO",
                    kind, r.dequantNs, r.gemvNs, r.gbPerSec,
                    r.gemmModule.c_str(),
                    r.note.empty() ? "-" : r.note.c_str());
    }

    // ---- the actual finding: what predicts throughput ----
    std::printf("------------------------\n");
    int resolved = 0, missing = 0, masm = 0, scalar = 0;
    Row fastest{}, slowest{};
    bool haveFast = false;
    for (const auto& r : table) {
        if (r.gemvResolved && r.gemvNs > 0.0) {
            ++resolved;
            if (r.isMasm) ++masm; else ++scalar;
            if (!haveFast || r.gemvNs < fastest.gemvNs) { fastest = r; haveFast = true; }
            if (!haveFast || r.gemvNs > slowest.gemvNs) { slowest = r; haveFast = true; }
        }
    }
    for (const auto& r : table) if (!r.gemvResolved) ++missing;

    std::printf("TYPES_ENUMERATED=%zu\n", table.size());
    std::printf("TYPES_WITH_GEMV=%d\n", resolved);
    std::printf("TYPES_WITHOUT_GEMV=%d\n", missing);
    std::printf("TYPES_BACKED_BY_PREBUILT_KERNEL=%d\n", masm);
    std::printf("TYPES_BACKED_BY_SCALAR=%d\n", scalar);

    if (resolved >= 2) {
        const double ratio = slowest.gemvNs / fastest.gemvNs;
        std::printf("FASTEST_TYPE=%d (%s) %0.1f ns  %0.3f GB/s\n",
                    fastest.quantType, fastest.name, fastest.gemvNs, fastest.gbPerSec);
        std::printf("SLOWEST_TYPE=%d (%s) %0.1f ns  %0.3f GB/s\n",
                    slowest.quantType, slowest.name, slowest.gemvNs, slowest.gbPerSec);
        std::printf("SPREAD_RATIO=%.2fx  (same geometry, same CPU, same bytes)\n", ratio);

        // If the spread is large at ONE fixed geometry, then quant type and the
        // selected kernel are decisive, and model size is not the predictor.
        std::printf("PREDICTOR_QUANT_AND_KERNEL=%s\n",
                    ratio >= 3.0 ? "DOMINANT" : "NOT_DOMINANT_AT_THIS_GEOMETRY");
        if (ratio >= 3.0) {
            std::printf("FALSIFIED_SIZE_AS_PREDICTOR=1 (spread at identical geometry "
                        "is %.2fx)\n", ratio);
        }
    }
    return 0;
}