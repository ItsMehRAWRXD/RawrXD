// ============================================================================
// test_compression_core.cpp -- validation matrix for rawrxd::compression.
// ============================================================================
// Exercises the Qt-free compression core against the acceptance criteria:
// empty input, small/large payloads, incompressible data, corrupt and truncated
// streams, the decompression ceiling (decompression-bomb protection), and
// concurrent use.
//
// Build: see the command in the handoff; links rawrxd_compression_core.lib.
// Exit code 0 only if every check passes.
// ============================================================================
#include "codec/compression_core.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <thread>
#include <vector>

using rawrxd::compression::compress;
using rawrxd::compression::decompress;
using rawrxd::compression::MaxOneShotBytes;
using rawrxd::compression::Status;

static int g_failures = 0;
static int g_checks = 0;

static void check(bool cond, const char* name, const char* detail = "") {
    ++g_checks;
    if (cond) {
        std::printf("  PASS  %s %s\n", name, detail);
    } else {
        ++g_failures;
        std::printf("  FAIL  %s %s\n", name, detail);
    }
}

static std::vector<std::uint8_t> makeRandom(std::size_t n, std::uint32_t seed) {
    std::mt19937 rng(seed);
    std::vector<std::uint8_t> v(n);
    for (auto& b : v) b = static_cast<std::uint8_t>(rng() & 0xFF);
    return v;
}

static std::vector<std::uint8_t> makeText(std::size_t n) {
    static const char* words[] = {
        "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog",
        "rawrxd", "native", "compression", "zlib", "gguf", "tensor"
    };
    std::vector<std::uint8_t> v;
    v.reserve(n * 2);
    std::mt19937 rng(7);
    while (v.size() < n) {
        const char* w = words[rng() % (sizeof(words) / sizeof(words[0]))];
        v.insert(v.end(), w, w + std::strlen(w));
        v.push_back(' ');
    }
    v.resize(n);
    return v;
}

static bool roundTrip(const std::vector<std::uint8_t>& in, const char* name) {
    auto c = compress(in.data(), in.size());
    if (!c) {
        check(false, name, "compress failed");
        return false;
    }
    auto d = decompress(c.bytes.data(), c.bytes.size(), MaxOneShotBytes);
    if (!d) {
        check(false, name, "decompress failed");
        return false;
    }
    bool same = (d.bytes == in);
    check(same, name, same ? "" : "round-trip mismatch");
    return same;
}

int main() {
    std::printf("=== rawrxd compression core validation ===\n");

    // 1. Empty input: must succeed, produce a valid stream, decode to empty.
    {
        auto c = compress(nullptr, 0);
        check(static_cast<bool>(c), "empty/compress-ok");
        auto d = decompress(c.bytes.data(), c.bytes.size(), MaxOneShotBytes);
        check(static_cast<bool>(d) && d.bytes.empty(), "empty/round-trip-empty");
    }

    // 2. Empty input to decompress: legacy adapter returned success + empty.
    {
        auto d = decompress(nullptr, 0, MaxOneShotBytes);
        check(static_cast<bool>(d) && d.bytes.empty(), "empty/decompress-noop");
    }

    // 3. Small payload.
    roundTrip(makeText(64), "small/64B-roundtrip");

    // 4. Typical payload.
    roundTrip(makeText(100 * 1024), "medium/100KB-roundtrip");

    // 5. Large compressible payload.
    roundTrip(makeText(4 * 1024 * 1024), "large/4MB-roundtrip");

    // 6. Random incompressible data: must still round-trip exactly.
    roundTrip(makeRandom(1024 * 1024, 12345), "random/1MB-incompressible-roundtrip");

    // 7. Highly compressible data should actually shrink.
    {
        auto in = makeText(1024 * 1024);
        auto c = compress(in.data(), in.size());
        check(static_cast<bool>(c) && c.bytes.size() < in.size(),
              "compressible/shrinks");
    }

    // 8. Corrupt stream: flip bytes in the middle of a valid stream.
    {
        auto in = makeText(64 * 1024);
        auto c = compress(in.data(), in.size());
        auto bad = c.bytes;
        for (std::size_t i = bad.size() / 2; i < bad.size() && i < bad.size() / 2 + 16; ++i)
            bad[i] ^= 0xFF;
        auto d = decompress(bad.data(), bad.size(), MaxOneShotBytes);
        check(!d, "corrupt/rejected");
    }

    // 9. Truncated stream: cut the tail (adler32 + final block).
    {
        auto in = makeText(64 * 1024);
        auto c = compress(in.data(), in.size());
        auto trunc = c.bytes;
        trunc.resize(trunc.size() / 2);
        auto d = decompress(trunc.data(), trunc.size(), MaxOneShotBytes);
        check(!d, "truncated/rejected");
    }

    // 10. Decompression ceiling: advertised expansion beyond the limit.
    //     Compress 1 MB, then demand a 4 KB ceiling.
    {
        auto in = makeText(1024 * 1024);
        auto c = compress(in.data(), in.size());
        auto d = decompress(c.bytes.data(), c.bytes.size(), 4096);
        check(!d && d.bytes.size() <= 4096,
              "ceiling/limits-small-output",
              "must reject without over-allocating");
    }

    // 11. Decompression bomb: tiny compressed input, huge expansion, tiny cap.
    {
        std::vector<std::uint8_t> zeros(1024 * 1024, 0); // compresses to ~1 KB
        auto c = compress(zeros.data(), zeros.size());
        std::printf("  info  bomb: %zu zeros -> %zu compressed bytes\n",
                    zeros.size(), c.bytes.size());
        check(c.bytes.size() < 16 * 1024, "bomb/high-ratio-achieved");
        auto d = decompress(c.bytes.data(), c.bytes.size(), 64 * 1024);
        check(!d, "bomb/rejected-at-64KB-ceiling");
    }

    // 12. Exact-fit ceiling should succeed (boundary correctness).
    {
        auto in = makeText(100 * 1024);
        auto c = compress(in.data(), in.size());
        auto d = decompress(c.bytes.data(), c.bytes.size(), in.size());
        check(static_cast<bool>(d) && d.bytes == in, "ceiling/exact-fit-succeeds");
    }

    // 13. MaxOneShotBytes guard: oversize request must be rejected, not truncated.
    {
        // Do not actually allocate; a null pointer with an oversize length must
        // be rejected before any work.
        auto c = compress(nullptr, MaxOneShotBytes + 1);
        check(!c, "limit/oversize-rejected");
    }

    // 14. Concurrent use: no corruption or races across threads.
    {
        const int kThreads = 4;
        std::vector<std::thread> ts;
        std::vector<int> ok(kThreads, 0);
        for (int t = 0; t < kThreads; ++t) {
            ts.emplace_back([&, t]() {
                for (int i = 0; i < 20; ++i) {
                    auto in = makeText(50 * 1024 + t * 4096 + i);
                    auto c = compress(in.data(), in.size());
                    if (!c) continue;
                    auto d = decompress(c.bytes.data(), c.bytes.size(), MaxOneShotBytes);
                    if (d && d.bytes == in) ok[t]++;
                }
            });
        }
        for (auto& th : ts) th.join();
        int total = 0;
        for (int v : ok) total += v;
        check(total == kThreads * 20, "concurrent/4-threads-no-corruption");
    }

    std::printf("\n=== %d checks, %d failures ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}