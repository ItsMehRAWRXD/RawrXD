// ============================================================================
// compressed_residency_test.cpp -- end-to-end compressed-weight residency.
// ============================================================================
// Proves the Native Universal Compression Expansion on a SYNTHETIC model:
//
//   1. Weights are stored compressed in memory and the resident footprint is
//      measured to be far below the uncompressed size (compressible tensors)
//      while incompressible tensors stay ~raw (fp16-style "only shrink what is
//      shrinkable").
//   2. read() is byte-exact against the original for full and partial ranges.
//   3. A single small read decompresses exactly ONE block, not the whole tensor
//      (partial decompression -- the whole point of compressed residency).
//   4. A corrupted block is rejected (integrity check), never silently served.
//   5. A synthetic 2-layer MLP runs its forward pass by streaming rows out of
//      the compressed store and matches an independent dense reference computed
//      from the original uncompressed weights (numerical parity).
//
// Exit code 0 iff every check passes, so CTest can gate on it. Works with the
// zlib provider or the dependency-free RXDN codec (RAWRXD_HAVE_ZLIB 0/1).
// ============================================================================
#include "deep2/CompressedWeightResidency.hpp"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

namespace {

int g_failures = 0;

void Check(bool cond, const char* what) {
    if (!cond) {
        std::printf("FAIL: %s\n", what);
        ++g_failures;
    }
}

// Deterministic, run-heavy data that the RLE-based native codec shrinks well,
// mimicking the repeated/zero-heavy byte patterns of real quantized weights.
std::vector<std::uint8_t> MakeStructured(std::size_t n, std::uint32_t seed) {
    std::mt19937 rng(seed);
    std::vector<std::uint8_t> v(n);
    std::size_t pos = 0;
    while (pos < n) {
        const std::uint8_t value = static_cast<std::uint8_t>(rng() % 12);
        std::size_t run = 8 + (rng() % 120);
        if (run > n - pos) run = n - pos;
        std::memset(v.data() + pos, value, run);
        pos += run;
    }
    return v;
}

std::vector<std::uint8_t> MakeRandom(std::size_t n, std::uint32_t seed) {
    std::mt19937 rng(seed);
    std::vector<std::uint8_t> v(n);
    for (auto& b : v) b = static_cast<std::uint8_t>(rng());
    return v;
}

bool BytesEqual(const std::uint8_t* a, const std::uint8_t* b, std::size_t n) {
    return std::memcmp(a, b, n) == 0;
}

} // namespace

int main() {
    using rawrxd::residency::CompressedTensor;
    using rawrxd::residency::CompressedWeightStore;

    const std::size_t kBlock = 4096; // 4 KiB blocks: amortise per-block header cost

    // ---- 1. Build a synthetic model: compressible + incompressible tensors. --
    const std::size_t nStruct = 256 * 1024; // 256 KiB, compressible
    const std::size_t nRandom = 256 * 1024; // 256 KiB, incompressible
    const std::vector<std::uint8_t> structured = MakeStructured(nStruct, 1234);
    const std::vector<std::uint8_t> randomData = MakeRandom(nRandom, 5678);

    CompressedWeightStore store;
    Check(store.add("embed.weight", structured.data(), structured.size(), kBlock),
          "add compressible tensor");
    Check(store.add("attn.wq.weight", randomData.data(), randomData.size(), kBlock),
          "add incompressible tensor");
    Check(store.tensor_count() == 2, "tensor count == 2");

    // ---- 2. Resident footprint vs raw -------------------------------------
    const std::uint64_t rawTotal = store.total_raw_bytes();
    const std::uint64_t resTotal = store.total_resident_bytes();
    const double ratio = store.overall_resident_ratio();
    Check(rawTotal == nStruct + nRandom, "raw total size correct");
    Check(resTotal < rawTotal, "resident footprint is below raw");
    std::printf("footprint: raw=%llu resident=%llu ratio=%.1f%%\n",
                (unsigned long long)rawTotal, (unsigned long long)resTotal,
                ratio * 100.0);

    CompressedTensor* embed = store.get("embed.weight");
    CompressedTensor* attn = store.get("attn.wq.weight");
    Check(embed && embed->resident_ratio() < 0.50,
          "compressible tensor resident < 50% of raw");
    // Incompressible data must NOT expand: stored raw + tiny index only.
    Check(attn && attn->resident_ratio() < 1.10,
          "incompressible tensor resident <= ~raw (+index), no expansion");
    std::printf("  embed.weight: raw=%zu blocks=%zu resident=%llu ratio=%.1f%%\n",
                structured.size(), embed->block_count(),
                (unsigned long long)embed->resident_bytes(),
                embed->resident_ratio() * 100.0);
    std::printf("  attn.wq.weight: raw=%zu blocks=%zu resident=%llu ratio=%.1f%%\n",
                randomData.size(), attn->block_count(),
                (unsigned long long)attn->resident_bytes(),
                attn->resident_ratio() * 100.0);

    // ---- 3. Full read is byte-exact ---------------------------------------
    std::vector<std::uint8_t> out;
    Check(embed->read_all(out), "embed read_all ok");
    Check(out.size() == structured.size() &&
              BytesEqual(out.data(), structured.data(), structured.size()),
          "embed full read byte-exact");
    Check(attn->read_all(out), "attn read_all ok");
    Check(out.size() == randomData.size() &&
              BytesEqual(out.data(), randomData.data(), randomData.size()),
          "attn full read byte-exact");

    // ---- 4. Partial range reads are byte-exact ----------------------------
    {
        const std::uint64_t rng_cases[][2] = {
            {0, 1}, {0, 64}, {1, 4095}, {255, 257}, {4096, 8192}, {250000, 1000}};
        bool all_ok = true;
        for (auto& c : rng_cases) {
            std::uint64_t off = c[0], len = c[1];
            if (off >= structured.size()) continue;      // skip out-of-range start
            if (off + len > structured.size()) len = structured.size() - off;
            std::vector<std::uint8_t> got(len);
            if (!embed->read(off, len, got) ||
                !BytesEqual(got.data(), structured.data() + off, len)) {
                all_ok = false;
                std::printf("  range mismatch off=%llu len=%llu\n",
                            (unsigned long long)off, (unsigned long long)len);
            }
        }
        Check(all_ok, "partial range reads byte-exact");
    }

    // ---- 5. Partial decompression: one small read touches ONE block -------
    {
        embed->reset_counters();
        const std::size_t blocksBefore = embed->block_count();
        std::vector<std::uint8_t> tmp(64);
        Check(embed->read(0, 64, tmp), "small read ok");
        Check(BytesEqual(tmp.data(), structured.data(), 64), "small read bytes");
        Check(embed->blocks_touched() == 1,
              "single 64B read touches exactly 1 block");
        Check(embed->blocks_touched() < blocksBefore,
              "single read decompresses a strict subset of blocks");
        std::printf("partial: 1 read touched %llu/%zu blocks, decompressed %llu bytes\n",
                    (unsigned long long)embed->blocks_touched(), blocksBefore,
                    (unsigned long long)embed->decompressed_bytes());
    }

    // ---- 6. Corruption is rejected ----------------------------------------
    {
        CompressedTensor t;
        Check(t.build(structured.data(), structured.size(), kBlock), "build for corruption");
        Check(t.corrupt_block_byte_for_testing(0), "corrupt block 0");
        std::vector<std::uint8_t> sink(structured.size());
        Check(!t.read_all(sink), "corrupted block must fail read, not serve bad bytes");
    }

    // ---- 7. Synthetic 2-layer MLP forward via compressed residency --------
    //        W1[out1 x in] , b1[out1] ; W2[out2 x out1] , b2[out2] ; ReLU.
    {
        const std::size_t IN = 32, H = 64, OUT = 16;
        std::mt19937 rng(99);
        std::vector<float> W1(H * IN), b1(H), W2(OUT * H), b2(OUT), x(IN);
        for (auto& v : W1) v = (float)(rng() % 2000 - 1000) / 1000.0f;
        for (auto& v : b1) v = (float)(rng() % 200 - 100) / 100.0f;
        for (auto& v : W2) v = (float)(rng() % 2000 - 1000) / 1000.0f;
        for (auto& v : b2) v = (float)(rng() % 200 - 100) / 100.0f;
        for (auto& v : x)  v = (float)(rng() % 2000 - 1000) / 1000.0f;

        auto asBytes = [](const std::vector<float>& v) {
            return reinterpret_cast<const std::uint8_t*>(v.data());
        };

        // Dense reference (independent of the residency path).
        std::vector<float> ref1(H), ref2(OUT);
        for (std::size_t o = 0; o < H; ++o) {
            float acc = b1[o];
            for (std::size_t i = 0; i < IN; ++i) acc += W1[o * IN + i] * x[i];
            ref1[o] = acc > 0.0f ? acc : 0.0f;
        }
        for (std::size_t o = 0; o < OUT; ++o) {
            float acc = b2[o];
            for (std::size_t i = 0; i < H; ++i) acc += W2[o * H + i] * ref1[i];
            ref2[o] = acc;
        }

        CompressedWeightStore mlp;
        const std::size_t MB = 1024; // amortise index overhead on these tensors
        Check(mlp.add("W1", asBytes(W1), W1.size() * sizeof(float), MB), "mlp W1");
        Check(mlp.add("b1", asBytes(b1), b1.size() * sizeof(float), MB), "mlp b1");
        Check(mlp.add("W2", asBytes(W2), W2.size() * sizeof(float), MB), "mlp W2");
        Check(mlp.add("b2", asBytes(b2), b2.size() * sizeof(float), MB), "mlp b2");

        // Storage self-check: the compressed store must round-trip W1 exactly.
        std::vector<std::uint8_t> w1back(W1.size() * sizeof(float));
        Check(mlp.get("W1")->read_all(w1back) &&
                  std::memcmp(w1back.data(), W1.data(), W1.size() * sizeof(float)) == 0,
              "mlp W1 storage roundtrip");

        auto* cW1 = mlp.get("W1");
        auto* cW2 = mlp.get("W2");
        std::vector<std::uint8_t> b1raw(b1.size() * sizeof(float));
        std::vector<std::uint8_t> b2raw(b2.size() * sizeof(float));
        Check(mlp.get("b1")->read_all(b1raw), "mlp b1 read");
        Check(mlp.get("b2")->read_all(b2raw), "mlp b2 read");

        // Forward pass reading each row straight out of compressed residency.
        std::vector<float> h1(H), h2(OUT);
        std::vector<std::uint8_t> row(IN * sizeof(float));
        for (std::size_t o = 0; o < H; ++o) {
            if (!cW1->read(o * IN * sizeof(float), row.size(), row)) { Check(false, "W1 row read"); break; }
            float acc;
            std::memcpy(&acc, b1raw.data() + o * sizeof(float), sizeof(float));
            const float* wr = reinterpret_cast<const float*>(row.data());
            for (std::size_t i = 0; i < IN; ++i) acc += wr[i] * x[i];
            h1[o] = acc > 0.0f ? acc : 0.0f;
        }
        std::vector<std::uint8_t> row2(H * sizeof(float));
        for (std::size_t o = 0; o < OUT; ++o) {
            if (!cW2->read(o * H * sizeof(float), row2.size(), row2)) { Check(false, "W2 row read"); break; }
            float acc;
            std::memcpy(&acc, b2raw.data() + o * sizeof(float), sizeof(float));
            const float* wr = reinterpret_cast<const float*>(row2.data());
            for (std::size_t i = 0; i < H; ++i) acc += wr[i] * h1[i];
            h2[o] = acc;
        }

        float maxDiff = 0.0f;
        for (std::size_t o = 0; o < OUT; ++o)
            maxDiff = std::max(maxDiff, std::fabs(h2[o] - ref2[o]));
        Check(maxDiff == 0.0f, "MLP forward matches dense reference (bit-exact)");

        const std::uint64_t mlpRaw = mlp.total_raw_bytes();
        const std::uint64_t mlpRes = mlp.total_resident_bytes();
        std::printf("mlp: raw=%llu resident=%llu ratio=%.1f%% maxDiff=%g\n",
                    (unsigned long long)mlpRaw, (unsigned long long)mlpRes,
                    mlpRaw ? 100.0 * mlpRes / mlpRaw : 0.0, maxDiff);
        // f32 weights are incompressible for the RLE codec, so resident ~= raw +
        // tiny block index; allow modest overhead rather than demanding savings.
        Check(mlpRes <= mlpRaw + mlpRaw / 10, "mlp resident within index overhead of raw");
    }

    if (g_failures == 0) {
        std::printf("RESULT=PASS\n");
        return 0;
    }
    std::printf("RESULT=FAIL failures=%d\n", g_failures);
    return 1;
}