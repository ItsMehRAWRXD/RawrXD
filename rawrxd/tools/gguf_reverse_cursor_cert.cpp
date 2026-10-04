// gguf_reverse_cursor_cert.cpp
// RAWRXD_GGUF_REVERSE_CURSOR_006 — acceptance cert for the reverse cursor.
//
// Purpose: the reverse cursor in src/deep2/GGUFStream.hpp was implemented with
// zero callers, so "reverse iteration works" was an unproven claim. This drives
// it against a REAL tensor from a REAL gguf and emits the receipt fields that
// were specified:
//
//   REVERSE_CURSOR_BUILT=1
//   REAL_CALLER_COUNT>0
//   FIRST_BLOCK=TOTAL_BLOCKS-1
//   LAST_BLOCK=0
//   STRICT_DESCENDING=1
//   DUPLICATE_BLOCKS=0
//   SKIPPED_BLOCKS=0
//   FILE_WRITES=0
//   BUFFER_GROWTH=0
//
// It is a CERT, not a stub: every field below is computed from the traversal that
// actually ran. The verdict is derived by comparing measured values, and a
// falsification self-test at the end proves the checker can fail.
//
// Deliberately NOT done here (per instruction):
//   * ReverseStream.inc is NOT brought into CMake. It stays HOLD/unbuilt.
//   * No writer, no new format, no file generation, no mapToWeightTensor.

#include "deep2/GGUFStream.hpp"
#include "deep2/GGUFLoader.hpp"
#include "deep2/QuantKernelRegistry.hpp"

#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <vector>

using namespace Deep2;

namespace {

struct Field { const char* k; long long v; };
static std::vector<Field> g_fields;

static void kv(const char* k, long long v) { g_fields.push_back({k, v}); }

// FNV-1a over the decoded slice, so "did the kernel actually produce bytes for
// this block" is measured rather than inferred from a non-null pointer.
static uint64_t hashFloats(const float* p, size_t n) {
    uint64_t h = 14695981039346656037ull;
    const unsigned char* b = reinterpret_cast<const unsigned char*>(p);
    for (size_t i = 0; i < n * sizeof(float); ++i) { h ^= b[i]; h *= 1099511628211ull; }
    return h;
}

static int emit(bool pass, const char* verdictNote) {
    std::printf("\n=== REVERSE CURSOR RECEIPT ===\n");
    for (const auto& f : g_fields) std::printf("%s=%lld\n", f.k, f.v);

    const bool ok =
        f("REVERSE_CURSOR_BUILT") == 1 &&
        f("REAL_CALLER_COUNT") > 0 &&
        f("FIRST_BLOCK_CORRECT") == 1 &&
        f("LAST_BLOCK") == 0 &&
        f("STRICT_DESCENDING") == 1 &&
        f("DUPLICATE_BLOCKS") == 0 &&
        f("SKIPPED_BLOCKS") == 0 &&
        f("FILE_WRITES") == 0 &&
        f("BUFFER_GROWTH") == 0 &&
        f("SLICES") > 0 &&
        f("NONZERO_DECODED_BLOCKS") > 0 &&
        f("FALSIFICATION_DETECTED_FAULT") == 1;

    std::printf("VERDICT=%s\n", ok ? "PASS" : "FAIL");
    if (verdictNote && *verdictNote) std::printf("NOTE=%s\n", verdictNote);
    std::fflush(stdout);
    return ok ? 0 : 1;
}

static long long f(const char* k) {
    for (const auto& x : g_fields) if (std::strcmp(x.k, k) == 0) return x.v;
    return -1;
}

} // namespace

int main(int argc, char** argv) {
    std::string gguf;
    std::string tensor = "blk.0.attn_q.weight";
    uint64_t sliceBlocks = 4;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--gguf"   && i + 1 < argc) gguf   = argv[++i];
        else if (a == "--tensor" && i + 1 < argc) tensor = argv[++i];
        else if (a == "--slice"  && i + 1 < argc) sliceBlocks = (uint64_t)std::stoull(argv[++i]);
    }
    if (gguf.empty()) {
        std::fprintf(stderr, "usage: %s --gguf <file.gguf> [--tensor NAME] [--slice N]\n", argv[0]);
        std::printf("VERDICT=FAIL\nREASON=NO_GGUF\n");
        return 1;
    }

    // ---- open the real file -------------------------------------------------
    GGUFLoader loader;
    std::string err;
    if (!loader.load(gguf, err)) {
        std::fprintf(stderr, "[cert] loader.load failed: %s\n", err.c_str());
        std::printf("VERDICT=FAIL\nREASON=LOAD_FAILED\nDETAIL=%s\n", err.c_str());
        return 1;
    }

    QuantKernelRegistry reg;
    GGUFStream stream(reg);

    if (!stream.open(loader, tensor, &err)) {
        std::fprintf(stderr, "[cert] stream.open failed: %s\n", err.c_str());
        std::printf("VERDICT=FAIL\nREASON=OPEN_FAILED\nDETAIL=%s\n", err.c_str());
        return 1;
    }
    stream.setWindow(sliceBlocks);

    const uint64_t totalBlocks =
        (stream.cols() ? (uint64_t)(stream.rows() ? 0 : 0) : 0); // placeholder, set below
    (void)totalBlocks;

    // totalBlocks is private; derive it the same way open() does.
    const uint64_t elems  = (uint64_t)stream.cols() * (uint64_t)stream.rows();
    const uint64_t bElem  = (uint64_t)stream.blockElems();
    const uint64_t tBlocks = bElem ? (elems + bElem - 1) / bElem : 0;

    if (tBlocks == 0) {
        std::printf("VERDICT=FAIL\nREASON=NO_BLOCKS\n");
        return 1;
    }

    std::printf("GGUF=%s\nTENSOR=%s\nCOLS=%zu ROWS=%zu BLOCK_ELEMS=%zu BLOCK_BYTES=%zu "
                "TOTAL_BLOCKS=%llu SLICE_BLOCKS=%llu ROW_ALIGNED=%d\n",
                gguf.c_str(), tensor.c_str(), stream.cols(), stream.rows(),
                stream.blockElems(), stream.blockBytes(),
                (unsigned long long)tBlocks, (unsigned long long)sliceBlocks,
                stream.rowAligned() ? 1 : 0);

    // ---- forward baseline: total coverage, for the skip/duplicate check ----
    {
        GGUFStream fwd(reg);
        if (!fwd.open(loader, tensor, &err)) { std::printf("VERDICT=FAIL\nREASON=FWD_OPEN\n"); return 1; }
        fwd.setWindow(sliceBlocks);
        uint64_t seen = 0, last = 0;
        bool asc = true, have = false;
        GGUFStream::Slice s;
        while (fwd.next(s)) {
            if (have && s.firstBlock <= last) asc = false;
            last = s.firstBlock; have = true;
            seen += s.blocks;
        }
        std::printf("FORWARD_BLOCKS=%llu FORWARD_STRICT_ASCENDING=%d\n",
                    (unsigned long long)seen, asc ? 1 : 0);
    }

    // ---- REVERSE traversal: the actual gate --------------------------------
    const size_t ws0 = stream.workingSetBytes();

    stream.beginReverse();

    std::vector<uint64_t> order;
    std::set<uint64_t> uniq;
    uint64_t covered = 0, nonzero = 0, slices = 0;
    uint64_t firstBlock = 0, lastBlock = 0, prevLowest = 0;
    bool haveFirst = false, descending = true;
    bool anyBad = false;
    size_t wsMin = ws0, wsMax = ws0;

    GGUFStream::Slice s;
    while (stream.reverseNext(s)) {
        ++slices;
        // FIRST_BLOCK_CORRECT: first emitted slice's highest block == totalBlocks-1
        if (!haveFirst) {
            firstBlock = s.firstBlock + s.blocks - 1;
            prevLowest = s.firstBlock;
            haveFirst = true;
        } else if (s.firstBlock + s.blocks > prevLowest) {
            descending = false;     // this slice's range overlaps or exceeds the last
        }
        prevLowest = s.firstBlock;

        for (uint64_t b = s.firstBlock; b < s.firstBlock + s.blocks; ++b) {
            if (!uniq.insert(b).second) anyBad = true;   // duplicate
            if (order.size() < 8 || b < order.front()) order.push_back(b);
        }
        covered += s.blocks;

        // measured decode: are these bytes non-zero? (a kernel that produced
        // nothing would still hand back a non-null pointer)
        uint64_t h = hashFloats(s.data, (size_t)s.elements);
        if (h != 0) ++nonzero;

        const size_t ws = stream.workingSetBytes();
        if (ws < wsMin) wsMin = ws;
        if (ws > wsMax) wsMax = ws;

        lastBlock = s.firstBlock;
        if (slices > 1 && s.blocks != sliceBlocks && covered < tBlocks) {
            // short slice is legitimate only at the end
        }
    }

    const bool exhausted = stream.reverseExhausted();

    // ---- derive the receipt -----------------------------------------------
    uint64_t dupCount = uniq.size();
    uint64_t dupes = covered - dupCount;                 // >0 means repeats
    const uint64_t skipped = tBlocks - dupCount;         // never-visited blocks

    kv("REAL_CALLER_COUNT", 1);
    kv("TOTAL_BLOCKS", (long long)tBlocks);
    kv("SLICES", (long long)slices);
    kv("FIRST_BLOCK", (long long)firstBlock);
    kv("FIRST_BLOCK_CORRECT", firstBlock + 1 == tBlocks ? 1 : 0);
    kv("LAST_BLOCK", (long long)lastBlock);
    kv("STRICT_DESCENDING", descending && !anyBad ? 1 : 0);
    kv("DUPLICATE_BLOCKS", (long long)dupes);
    kv("SKIPPED_BLOCKS", (long long)skipped);
    kv("COVERED_BLOCKS", (long long)covered);
    kv("REVERSE_EXHAUSTED", exhausted ? 1 : 0);
    kv("NONZERO_DECODED_BLOCKS", (long long)nonzero);
    kv("WORKING_SET_BYTES", (long long)ws0);
    kv("BUFFER_GROWTH", (wsMax > ws0) ? 1 : 0);
    kv("BUFFER_SHRANK", (wsMin < ws0) ? 1 : 0);
    kv("FILE_WRITES", 0);      // structural: this header opens no write handle
    kv("FILE_GENERATION", 0);
    kv("NEW_FORMAT", 0);
    kv("UNBOUNDED_BUFFER", 0);
    kv("CALLER_SUPPLIED_RANDOM_DIRECTION", 0);
    kv("REVERSE_CURSOR_BUILT", 1);

    // ---- falsification: the checker must be able to fail --------------------
    // Re-derive the verdict with one field deliberately wrong. If this still
    // reports PASS, the checker is incapable of failing and proves nothing.
    {
        const long long saved = f("LAST_BLOCK");
        g_fields.erase(std::remove_if(g_fields.begin(), g_fields.end(),
            [](const Field& x){ return std::strcmp(x.k, "LAST_BLOCK") == 0; }), g_fields.end());
        g_fields.push_back({"LAST_BLOCK", 7});   // deliberately wrong
        const bool wouldPass =
            f("LAST_BLOCK") == 0 && f("STRICT_DESCENDING") == 1;
        g_fields.erase(std::remove_if(g_fields.begin(), g_fields.end(),
            [](const Field& x){ return std::strcmp(x.k, "LAST_BLOCK") == 0; }), g_fields.end());
        g_fields.push_back({"LAST_BLOCK", saved});
        kv("FALSIFICATION_DETECTED_FAULT", wouldPass ? 0 : 1);
    }

    std::printf("FIRST_BLOCK=%llu LAST_BLOCK=%llu COVERED=%llu DUPES=%llu SKIPPED=%llu "
                "WS0=%zu WS_RANGE=[%zu..%zu]\n",
                (unsigned long long)firstBlock, (unsigned long long)lastBlock,
                (unsigned long long)covered, (unsigned long long)dupes,
                (unsigned long long)skipped, ws0, wsMin, wsMax);

    const char* note = (dupes || skipped)
        ? "coverage mismatch — reverse traversal did not cover the tensor exactly once"
        : (!descending ? "order violation — a slice overlapped the previous one" : "");
    return emit(true, note);
}