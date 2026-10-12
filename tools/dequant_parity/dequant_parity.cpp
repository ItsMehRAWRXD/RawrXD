// Bit-exact validation of the loader's GGUF dequantiser against ggml.
//
// ggml is the authoritative reference: if this passes bit-for-bit on real
// model bytes, the dequantiser in rawrxd_model_loader.cpp is not approximating
// the weights - it is reproducing exactly what ggml would compute.
//
// The previous loader filled every quantised tensor with ((i % 16) * 0.001f),
// a synthetic pattern. This test is what proves that is gone.
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <cmath>
#include <string>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#endif
#include "ggml.h"

// ---- the code under test, included verbatim from rawrxd_model_loader.cpp ----
#include "tmp_frag.inc"

// Minimal GGUF reader: just enough to get real tensor bytes.
struct Blob {
    const uint8_t* base = nullptr; size_t size = 0, pos = 0;
    uint32_t u32() { uint32_t v; std::memcpy(&v, base + pos, 4); pos += 4; return v; }
    uint64_t u64() { uint64_t v; std::memcpy(&v, base + pos, 8); pos += 8; return v; }
    std::string str() { uint64_t n = u64(); std::string s((const char*)(base + pos), (size_t)n); pos += (size_t)n; return s; }
    bool skipScalar(uint32_t t) {
        switch (t) { case 0: case 1: pos += 1; return true;
                     case 2: case 3: pos += 2; return true;
                     case 4: case 5: case 6: case 7: if (t == 7) pos += 1; else pos += 4; return true;
                     case 10: case 11: case 12: pos += 8; return true;
                     case 8: str(); return true; default: return false; }
    }
    bool skipVal(uint32_t t, int d) {
        if (d > 6) return false;
        if (t == 8) { str(); return true; }
        if (t == 9) { uint32_t et = u32(); uint64_t n = u64();
                      for (uint64_t i = 0; i < n; ++i) if (!skipVal(et, d + 1)) return false; return true; }
        return skipScalar(t);
    }
};

struct Rec { std::string name; uint32_t type; uint64_t off; std::vector<uint64_t> dims; size_t bytes; };

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc < 2) { std::printf("usage: dequant_parity <model.gguf>\n"); return 1; }

#ifdef _WIN32
    HANDLE h = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { std::printf("open fail\n"); return 1; }
    LARGE_INTEGER sz{}; GetFileSizeEx(h, &sz);
    HANDLE m = CreateFileMappingA(h, nullptr, PAGE_READONLY, 0, 0, nullptr);
    Blob b; b.base = (const uint8_t*)MapViewOfFile(m, FILE_MAP_READ, 0, 0, (SIZE_T)sz.QuadPart);
    b.size = (size_t)sz.QuadPart;
#else
    int fd = ::open(argv[1], O_RDONLY);
    struct stat st{}; ::fstat(fd, &st);
    Blob b; b.size = (size_t)st.st_size;
    b.base = (const uint8_t*)::mmap(nullptr, b.size, PROT_READ, MAP_PRIVATE, fd, 0);
#endif
    if (!b.base) { std::printf("map fail\n"); return 1; }

    b.u32();                       // magic
    b.u32();                       // version
    const uint64_t tc = b.u64(), kv = b.u64();
    for (uint64_t i = 0; i < kv; ++i) { b.str(); if (!b.skipVal(b.u32(), 0)) { std::printf("meta fail\n"); return 1; } }

    std::vector<Rec> recs(tc);
    for (uint64_t i = 0; i < tc; ++i) {
        recs[i].name = b.str();
        const uint32_t nd = b.u32();
        recs[i].dims.resize(nd);
        for (auto& d : recs[i].dims) d = b.u64();
        recs[i].type = b.u32();
        recs[i].off = b.u64();
    }
    const size_t dataStart = (b.pos + 31) & ~size_t(31);
    std::printf("parsed %llu tensors, data starts at %zu\n", (unsigned long long)tc, dataStart);

    // Pick a bounded, representative set across every type present.
    struct Want { uint32_t type; const char* nameSubstr; };
    const Want wants[] = {
        {2, nullptr},  // Q4_0
        {12, nullptr}, // Q4_K
        {14, nullptr}, // Q6_K
        {0, nullptr},  // F32
    };
    int pass = 0, fail = 0, tested = 0;

    for (const auto& w : wants) {
        if (tested >= 5) break;
        // Find a tensor of this type whose dims[0] is a multiple of the block.
        const Rec* pick = nullptr;
        uint64_t pickBest = 0;
        for (const auto& r : recs) {
            if (r.type != w.type) continue;
            const ggml_type_traits* tr = ggml_get_type_traits((ggml_type)r.type);
            if (!tr || r.dims.empty()) continue;
            const size_t blk = (size_t)tr->blck_size;
            if ((r.dims[0] % blk) != 0) continue;
            // keep the test small
            uint64_t n = 1; for (auto d : r.dims) n *= d;
            if (n > 8000000) continue;
            // Prefer the LARGEST qualifying tensor of this type, so a
            // small tensor (e.g. a router row) does not stand in for a real
            // weight matrix.
            if (!pick || n > pickBest) { pick = &r; pickBest = n; }
            // keep scanning: the LARGEST qualifying tensor is the real test.
        }
        if (!pick) { std::printf("  type %-3u : no small tensor found (skipped)\n", w.type); continue; }

        const ggml_type_traits* tr = ggml_get_type_traits((ggml_type)pick->type);
        const size_t blk = (size_t)tr->blck_size;
        const size_t tsz = (size_t)tr->type_size;
        uint64_t n = 1; for (auto d : pick->dims) n *= d;
        const size_t blocks = (size_t)(n / blk);
        const size_t nbytes = blocks * tsz;

        std::printf("  candidate %s type=%u n=%llu off=%llu nbytes=%zu size=%zu\n",
                    pick->name.c_str(), pick->type, (unsigned long long)n,
                    (unsigned long long)pick->off, nbytes, b.size);
        const uint8_t* raw = b.base + dataStart + pick->off;
        if ((size_t)(raw - b.base) + nbytes > b.size) { std::printf("  OOB for %s\n", pick->name.c_str()); continue; }

        // Compare a bounded prefix (real bytes, bounded RSS).
        const size_t nCmp = n;
        std::vector<float> mine(nCmp, 0.0f), theirs(nCmp, 0.0f);
        if (!DequantizeGguf(pick->type, raw, mine.data(), nCmp)) {
            std::printf("  [FAIL] %-34s type=%-3u DequantizeGguf REFUSED\n", pick->name.c_str(), pick->type);
            ++fail; ++tested; continue;
        }
        // ggml exposes NO to_float for F32 (nothing to dequantise); a direct
        // memcpy is the reference for that type.
        if (pick->type == 0) {
            std::memcpy(theirs.data(), raw, nCmp * sizeof(float));
        } else if (tr->to_float) {
            tr->to_float(raw, theirs.data(), (int)n);
        } else {
            std::printf("  [SKIP] %-34s type=%-3u ggml has no reference dequantiser\n",
                        pick->name.c_str(), pick->type);
            continue;
        }

        size_t exact = 0, diff = 0, nonfinite = 0;
        double maxAbs = 0.0;
        for (size_t i = 0; i < nCmp; ++i) {
            if (!std::isfinite(mine[i])) { ++nonfinite; continue; }
            if (std::memcmp(&mine[i], &theirs[i], sizeof(float)) == 0) ++exact;
            else {
                ++diff;
                maxAbs = std::max(maxAbs, std::fabs(double(mine[i]) - double(theirs[i])));
            }
        }
        // First divergence, with the raw block bytes, so the cause is visible.
        if (diff > 0) {
            for (size_t i = 0; i < n; ++i) {
                if (std::memcmp(&mine[i], &theirs[i], sizeof(float)) == 0) continue;
                const size_t blk = i / 32;
                const uint8_t* bb = raw + blk * 18;
                std::printf("       first divergence at i=%zu (block %zu, j=%zu)\n", i, blk, i % 32);
                std::printf("       block bytes:");
                for (int q = 0; q < 18; ++q) std::printf(" %02X", bb[q]);
                std::printf("\n       mine=%.9g theirs=%.9g\n", mine[i], theirs[i]);
                break;
            }
        }
        const bool ok = (diff == 0 && nonfinite == 0);
        std::printf("  [%s] %-34s type=%-3u n=%-8llu exact=%zu diff=%zu nonfinite=%zu maxAbs=%.3e\n",
                    ok ? "PASS" : "FAIL", pick->name.c_str(), pick->type,
                    (unsigned long long)nCmp, exact, diff, nonfinite, maxAbs);
        if (ok) ++pass; else ++fail;
        ++tested;
    }

    std::printf("\n=== dequantiser vs ggml: %d passed, %d failed ===\n", pass, fail);
    std::printf("VERDICT=%s\n", fail == 0 ? "PASS" : "FAIL");
    return fail == 0 ? 0 : 1;
}
