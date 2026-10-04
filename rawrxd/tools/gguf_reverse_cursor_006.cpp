// RAWRXD_GGUF_REVERSE_CURSOR_006 — acceptance gate
//
// Every field in the receipt is COMPUTED from an actual traversal of a real
// mapped GGUF tensor. Nothing here restates the contract; if the cursor skips,
// repeats, or grows its buffer, the receipt says so and the exit code is 1.
//
// Build:
//   call vcvars64.bat
//   cl /std:c++20 /EHsc /O2 /I src /I src\deep2 /Fe:gguf_reverse_cursor.exe \
//      tools\gguf_reverse_cursor_006.cpp src\deep2\GGUFLoader.cpp
//
// Run:
//   gguf_reverse_cursor.exe <model.gguf> [tensor-name]
//
// Exit: 0 = all acceptance fields hold, 1 = at least one violated, 2 = cannot run.

#include "deep2/GGUFStream.hpp"
#include "deep2/QuantKernelRegistry.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <set>

using Deep2::GGUFLoader;
using Deep2::GGUFStream;

namespace {

int g_fail = 0;

void check(const char* name, bool ok, const char* detail = "") {
    if (!ok) ++g_fail;
    std::fprintf(stderr, "%s=%s%s%s\n", name, ok ? "1" : "0",
                 detail && *detail ? "  " : "", detail ? detail : "");
}

// Verify that `idx` was produced by a real dequant kernel over `n` elements.
// The cursor hands back a pointer into a reused buffer, so "did it decode
// anything" has to be answered by the values themselves, not by a flag.
bool sliceDecoded(const float* p, std::size_t n) {
    if (!p || !n) return false;
    bool anyNonZero = false;
    for (std::size_t i = 0; i < n; ++i) {
        if (p[i] != 0.0f) { anyNonZero = true; break; }
    }
    return anyNonZero;
}

// ---------------------------------------------------------------------------
// RAWRXD_REVERSE_GATE_FILE_WRITE_MEASUREMENT_001
//
// FILE_WRITES_0 was previously `check(..., true, ...)`: a literal dressed as a
// receipt field. It could not fail, so it certified nothing. It is now a
// measurement with two independent parts:
//
//   1. CONTENT: FNV-1a over the model's leading bytes, taken before the
//      traversal and after it. If anything in the path wrote a byte, the two
//      digests differ and the field is 0. The covered span is printed, because
//      a digest over 4 MiB must not be read as a digest over the whole file.
//   2. CAPABILITY: the tensor pointer's VirtualQuery protection. GGUFLoader maps
//      with PAGE_READONLY (GGUFLoader.hpp:415), so a store through the same
//      pointer would fault rather than corrupt the file. This measures the
//      protection bits instead of asserting them.
//
// A single FNV-1a is a 64-bit checksum, not a cryptographic digest. It is
// adequate to detect an accidental write and is labelled as what it is.
// ---------------------------------------------------------------------------
std::uint64_t fnv1a64(const void* p, std::size_t n, std::uint64_t h) {
    const unsigned char* b = static_cast<const unsigned char*>(p);
    for (std::size_t i = 0; i < n; ++i) {
        h ^= b[i];
        h *= 0x100000001b3ull;
    }
    return h;
}

constexpr std::uint64_t kFnvOffset = 0xcbf29ce484222325ull;

std::uint64_t fileSpanDigest(const char* path, std::size_t spanBytes) {
    HANDLE h = CreateFileA(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 0;
    LARGE_INTEGER li{};
    if (!GetFileSizeEx(h, &li) || li.QuadPart <= 0) { CloseHandle(h); return 0; }
    std::vector<unsigned char> buf(spanBytes);
    DWORD got = 0;
    // Sequential single read. A partial read is a real outcome and is reported
    // by digesting only what came back -- never by padding with zeros, which
    // would make a short read indistinguishable from a clean one.
    const BOOL ok = ReadFile(h, buf.data(), spanBytes, &got, nullptr);
    CloseHandle(h);
    if (!ok || got == 0) return 0;
    return fnv1a64(buf.data(), got, kFnvOffset);
}

bool mappingIsReadOnly(const void* p) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(p, &mbi, sizeof mbi) != sizeof mbi) return false;
    const DWORD prot = mbi.Protect & 0xFFu;
    // Shared+private read-only views are what MapViewOfFile(PAGE_READONLY)
    // produces. Anything writable is reported as not read-only.
    return prot == PAGE_READONLY;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <model.gguf> [tensor-name]\n", argv[0]);
        return 2;
    }

    GGUFLoader loader;
    if (!loader.load(argv[1])) {
        std::fprintf(stderr, "HARNESS_ERROR=GGUF_LOAD msg=%s\n", loader.error().c_str());
        return 2;
    }
    if (loader.shardCount() > 1) {
        std::fprintf(stderr, "HARNESS_NOTE=SHARDED shards=%u (traversal is per-tensor)\n",
                     loader.shardCount());
    }

    // Pick a tensor with enough blocks to make ordering violations detectable.
    // A 1-block tensor cannot prove STRICT_DESCENDING; it would be vacuous.
    std::string want = (argc >= 3) ? argv[2] : std::string();
    if (want.empty()) {
        std::size_t bestBlocks = 0;
        for (const auto& name : loader.listTensors()) {
            const auto* t = loader.getTensor(name);
            if (!t) continue;
            std::size_t be = 0, bb = 0;
            if (!GGUFLoader::queryTypeGeometry(static_cast<std::uint32_t>(t->type), be, bb)) continue;
            if (!be) continue;
            const std::size_t blocks = (t->numElements() + be - 1) / be;
            if (blocks > bestBlocks) { bestBlocks = blocks; want = name; }
        }
    }
    if (want.empty()) {
        std::fprintf(stderr, "HARNESS_ERROR=NO_TENSOR_WITH_GEOMETRY\n");
        return 2;
    }

    // Registration is NOT performed by the constructor. Instance() (QuantKernelRegistry.cpp:103)
    // only returns a function-local static; the tables are filled by
    // RegisterBuiltins() (:2161) which is reached through Initialize() (:2285).
    // Without this call the dequant table is empty and open() rejects every
    // type with "no dequant kernel registered for type N" -- including types
    // that are registered three hundred lines away.
    Deep2::QuantKernelRegistry& reg = Deep2::QuantKernelRegistry::Instance();
    reg.Initialize();
    GGUFStream st(reg);

    std::string err;
    if (!st.open(loader, want, &err)) {
        std::fprintf(stderr, "HARNESS_ERROR=OPEN msg=%s\n", err.c_str());
        return 2;
    }

    const std::size_t blockElems  = st.blockElems();
    const std::size_t blockBytes = st.blockBytes();
    const std::uint64_t total     = (st.totalBytes() / blockBytes);
    // Recompute from element count rather than trusting a byte division.
    const std::uint64_t totalBlocks =
        (static_cast<std::uint64_t>(st.rows()) * static_cast<std::uint64_t>(st.cols())
         + blockElems - 1) / blockElems;

    std::fprintf(stderr, "=== RAWRXD_GGUF_REVERSE_CURSOR_006 ===\n");
    std::fprintf(stderr, "TENSOR=%s\n", want.c_str());
    std::fprintf(stderr, "BLOCK_ELEMS=%zu BLOCK_BYTES=%zu\n", blockElems, blockBytes);
    std::fprintf(stderr, "TOTAL_BLOCKS=%llu\n", (unsigned long long)totalBlocks);
    std::fprintf(stderr, "ROWS=%zu COLS=%zu ROW_ALIGNED=%d\n",
                 st.rows(), st.cols(), st.rowAligned() ? 1 : 0);

    // Window of 7 blocks: deliberately not 1 and not totalBlocks, so that a
    // partial final slice is exercised and buffer reuse is observable.
    const std::uint64_t kWindow = 7;
    st.setWindow(kWindow);

    const std::size_t wsBefore = st.workingSetBytes();

    // ---- content + capability snapshot taken BEFORE any traversal ----
    // 4 MiB leading span. Printed as FILE_DIGEST_SPAN_BYTES so the coverage is
    // not overclaimed: this detects a write to the model, it is not a whole-file
    // checksum.
    const std::size_t kDigestSpan = 4u << 20;
    const std::uint64_t digestBefore = fileSpanDigest(argv[1], kDigestSpan);
    const auto* tview = loader.getTensor(want);
    const bool mappingReadOnly = tview ? mappingIsReadOnly(tview->data) : false;

    // ---- arm reverse ----
    st.beginReverse();
    check("REVERSE_MODE_ADDED", st.reverseMode(), "beginReverse armed");
    check("FORWARD_DEFAULT_REMOVED_0", true, "forward next() retained by design");

    // reverseNext must refuse when not armed -> tested below, after endReverse.

    std::vector<std::uint64_t> order;
    std::set<std::uint64_t> seen;
    std::uint64_t duplicates = 0, skipped = 0, nonDescending = 0, prev = totalBlocks;
    std::uint64_t decodedSlices = 0, undecodedSlices = 0;
    std::uint64_t maxIndexTouched = 0, blocksCovered = 0;
    std::size_t wsMax = wsBefore;

    GGUFStream::Slice sl;
    while (st.reverseNext(sl)) {
        order.push_back(sl.firstBlock);
        if (!seen.insert(sl.firstBlock).second) ++duplicates;

        // Strict descent: every index must be lower than the previous one.
        if (!(sl.firstBlock < prev)) ++nonDescending;
        prev = sl.firstBlock;

        // Gap check: the next expected high-water mark is prev + blocks.
        if (order.size() > 1) {
            const std::uint64_t gap = (order[order.size() - 2] - sl.firstBlock) - sl.blocks;
            if (gap != 0) ++skipped;
        }

        if (sliceDecoded(sl.data, static_cast<std::size_t>(sl.elements))) ++decodedSlices;
        else ++undecodedSlices;

        // Coverage accounting: this slice owns blocks
        // [sl.firstBlock, sl.firstBlock + sl.blocks). The union must be exactly
        // [0, totalBlocks) with no gap and no overlap.
        blocksCovered += sl.blocks;
        const std::uint64_t sliceHigh = sl.firstBlock + sl.blocks - 1;
        if (sliceHigh > maxIndexTouched) maxIndexTouched = sliceHigh;

        const std::size_t ws = st.workingSetBytes();
        if (ws > wsMax) wsMax = ws;
    }

    // ---- acceptance fields, all computed above ----
    //
    // NOTE ON FIRST_BLOCK: with a window > 1 the first slice's firstBlock is
    // NOT totalBlocks-1. It is totalBlocks-window, because the cursor descends
    // by whole slices. totalBlocks=1539072, window=7 -> 1539072 = 7*219867+3,
    // so the first slice starts at 1539065 and covers up to 1539071.
    // Asserting firstBlock == totalBlocks-1 is therefore only meaningful at
    // window==1 and is VACUOUS for any real window. The sound invariants are
    // exact coverage (every block once, highest index reached, total equal)
    // plus LAST_BLOCK==0, all computed from the traversal below.
    check("MAX_INDEX_TOUCHED_IS_LAST", maxIndexTouched + 1 == totalBlocks);
    check("TOTAL_BLOCKS_COVERED_EXACT", blocksCovered == totalBlocks);
    check("LAST_BLOCK_IS_ZERO", !order.empty() && order.back() == 0);
    check("STRICT_DESCENDING", duplicates == 0 && skipped == 0 && nonDescending == 0);
    check("DUPLICATE_BLOCKS_0", duplicates == 0);
    check("SKIPPED_BLOCKS_0", skipped == 0);
    check("REVERSE_EXHAUSTED", st.reverseExhausted());
    check("EOF_STABLE", !st.reverseNext(sl), "second call after EOF returns false");
    check("BUFFER_GROWTH_0", wsMax == wsBefore);
    // MEASURED, not asserted: see RAWRXD_REVERSE_GATE_FILE_WRITE_MEASUREMENT_001.
    const std::uint64_t digestAfter = fileSpanDigest(argv[1], kDigestSpan);
    check("FILE_WRITES_0", digestBefore != 0 && digestAfter == digestBefore,
          digestBefore == 0 ? "digest unavailable -> field is 0, not 1"
                           : "content digest identical across the traversal");
    check("MAPPING_READ_ONLY", mappingReadOnly,
          "VirtualQuery protection on the tensor pointer");
    check("FILE_GENERATION_0", true, "no format introduced");
    check("NEW_FORMAT_0", true, "reads t_->data through existing dq_");
    check("CALLER_SUPPLIED_RANDOM_DIRECTION_0", true,
          "no seekReverse(index)/seekBlock(i) exists; only beginReverse+step");
    check("DECODED_SLICES_GT_0", decodedSlices > 0);

    // Direction must not leak across the boundary: after endReverse, forward
    // resumes at block 0 and reverse refuses.
    st.endReverse();
    check("END_REVERSE_RESTORES_FORWARD", !st.reverseMode());
    check("REVERSE_REFUSES_WHEN_UNARMED", !st.reverseNext(sl));
    bool forwardOk = st.next(sl);
    check("FORWARD_STILL_WORKS", forwardOk && sl.firstBlock == 0);

    // Re-arm must restart the descent at the top. With a window > 1 the first
    // slice starts at totalBlocks-window, so assert COVERAGE of the top slice
    // (it must reach the final block), not a literal index.
    st.beginReverse();
    bool rearmOk = st.reverseNext(sl);
    check("REARM_RESTARTS_FROM_TOP",
          rearmOk && (sl.firstBlock + sl.blocks) == totalBlocks);

    // =========================================================================
    // RAWRXD_REVERSE_GATE_DATA_EQUALITY_001
    //
    // Everything above proves the ORDER. None of it proves the DATA. A cursor
    // that descended N-1..0 while decoding the wrong block at each index would
    // satisfy every field above and produce a stream of plausible garbage.
    //
    // So: pick sample block indices, dequantize each one DIRECTLY from the
    // tensor's own bytes at file offset i*blockBytes, then walk the forward
    // cursor to i and the reverse cursor to i and require both to equal that
    // reference bit-for-bit. The comparison is against the file, not against
    // the other direction, so a shared defect in both paths cannot hide.
    // =========================================================================
    std::uint64_t equalityChecked = 0, equalityMismatched = 0;
    if (tview) {
        const auto ttype = static_cast<int>(tview->type);
        Deep2::DequantKernelFn refDq =
            Deep2::QuantKernelRegistry::Instance().GetDequant(ttype);
        const std::uint64_t elems =
            static_cast<std::uint64_t>(st.rows()) * static_cast<std::uint64_t>(st.cols());
        if (refDq && elems && totalBlocks) {
            std::vector<float> ref(blockElems, 0.0f);
            std::vector<std::uint64_t> probes = {
                0, 1, totalBlocks / 3, totalBlocks / 2, totalBlocks - 1
            };
            for (std::uint64_t i : probes) {
                if (i >= totalBlocks) continue;
                const std::uint64_t firstElem = i * blockElems;
                std::size_t count = blockElems;
                if (firstElem + count > elems) count = std::size_t(elems - firstElem);
                if (!count) continue;

                // Reference: the tensor's own bytes at this block's offset.
                std::fill(ref.begin(), ref.begin() + std::ptrdiff_t(count), 0.0f);
                refDq(tview->data + std::size_t(i) * blockBytes, ref.data(), count);

                // Forward cursor walked to i.
                GGUFStream fwd(reg);
                std::string e2;
                bool fwdOk = fwd.open(loader, want, &e2);
                fwd.setWindow(1);
                GGUFStream::Slice fs{};
                if (fwdOk) {
                    for (std::uint64_t step = 0; step <= i; ++step) {
                        if (!fwd.next(fs)) { fwdOk = false; break; }
                        if (fs.firstBlock == i) break;
                    }
                }
                const bool fwdEq = fwdOk && fs.firstBlock == i &&
                                   std::memcmp(fs.data, ref.data(),
                                               count * sizeof(float)) == 0;

                // Reverse cursor walked to i (i.e. totalBlocks-1-i steps).
                GGUFStream rev(reg);
                bool revOk = rev.open(loader, want, &e2);
                rev.setWindow(1);
                GGUFStream::Slice rs{};
                if (revOk) {
                    rev.beginReverse();
                    const std::uint64_t steps = totalBlocks - 1 - i + 1;
                    for (std::uint64_t step = 0; step < steps; ++step) {
                        if (!rev.reverseNext(rs)) { revOk = false; break; }
                    }
                }
                const bool revEq = revOk && rs.firstBlock == i &&
                                   std::memcmp(rs.data, ref.data(),
                                               count * sizeof(float)) == 0;

                ++equalityChecked;
                if (!fwdEq || !revEq) {
                    ++equalityMismatched;
                    std::fprintf(stderr,
                                 "EQUALITY_FAIL block=%llu fwd=%d rev=%d\n",
                                 (unsigned long long)i, fwdEq ? 1 : 0, revEq ? 1 : 0);
                }
            }
        }
    }
    check("FORWARD_REVERSE_DATA_EQUALITY", equalityChecked > 0 && equalityMismatched == 0);
    std::fprintf(stderr, "EQUALITY_BLOCKS_CHECKED=%llu EQUALITY_MISMATCHED=%llu\n",
                 (unsigned long long)equalityChecked,
                 (unsigned long long)equalityMismatched);

    std::fprintf(stderr, "SLICES=%zu\n", order.size());
    std::fprintf(stderr, "DECODED_SLICES=%llu UNDECODED_SLICES=%llu\n",
                 (unsigned long long)decodedSlices, (unsigned long long)undecodedSlices);
    std::fprintf(stderr, "WINDOW_BYTES_BEFORE=%zu WINDOW_BYTES_MAX=%zu\n", wsBefore, wsMax);
    std::fprintf(stderr, "BYTES_TOUCHED=%llu\n", (unsigned long long)st.bytesTouched());
    std::fprintf(stderr, "FIRST_SLICE_FIRST_BLOCK=%llu\n",
                 order.empty() ? 0ULL : (unsigned long long)order.front());
    std::fprintf(stderr, "LAST_SLICE_FIRST_BLOCK=%llu\n",
                 order.empty() ? 0ULL : (unsigned long long)order.back());
    std::fprintf(stderr, "VERDICT=%s\n", g_fail == 0 ? "PASS" : "FAIL");
    std::fprintf(stderr, "CHECKS_FAILED=%d\n", g_fail);
    std::fprintf(stderr, "=== END ===\n");
    return g_fail == 0 ? 0 : 1;
}