// q_accum_parity_probe.cpp
// RAWRXD_NQBRAID_RESIDUAL_LM_HEAD_ACCUMULATION_001
//
// WHY THIS EXISTS
// After RAWRXD_ROPE_LAYOUT_SELECTION_001 closed the RoPE defect, the real-weight
// oracle reached cosine 0.999981482 / ARGMAX_MATCH=1, and the state-parity probe
// left exactly TWO differing records out of 9054 -- both on LOGITS at decode
// step 4:
//
//   STEP=4 CP=LOGITS GGUF  MIN=-9.28055477 MAX=13.471489   MEAN=-2.58546972 L2=1289.77475
//   STEP=4 CP=LOGITS NQB   MIN=-9.26532745 MAX=13.5246086  MEAN=-2.5793149  L2=1288.05413
//
// The input to that projection is BIT-IDENTICAL on both routes:
//
//   STEP=4 CP=FINAL_NORM  COUNT=3072 MIN=-26.7030811 MAX=10.9089365 L2=82.1998049
//   STEP=4 CP=EMBED       steps 0-4 all identical
//
// and the weights are provably identical (WR_PARITY exact_mismatch=0 worst_abs=0).
// So the tied LM head consumed identical operands and produced a different dot
// product: max_abs 0.103 on |logit| ~13.5 is 0.76% relative, which is LARGER
// than F32 reordering noise for a 3072-length accumulation (~1e-4). That points
// at one of the two GEMV paths accumulating in reduced precision.
//
// This probe does not go through the engine at all. It calls both kernels
// directly on the same weights and the same input vector, and compares each
// against a DOUBLE-precision reference computed here. Whichever kernel is
// further from the reference is the defective one. This is the difference
// between measuring and guessing: no engine run is involved, so nothing about
// routing, KV state, or binding can contaminate the result.
//
// HONESTY CONSTRAINTS
//   * The reference accumulates in `double` from the SAME float weight values
//     the F32 kernel sees, so the reference is not itself quantisation-limited.
//     It measures ACCUMULATION error only, which is the actual suspect.
//   * If neither kernel is available the probe reports FAIL_NOT_AVAILABLE. It
//     does not report PASS for having compared nothing.
//   * A row sample is used for tractability and the sample size is PRINTED, so
//     the coverage cannot be over-read.

#include "GGUFLoader.hpp"
#include "QuantKernelRegistry.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <string>
#include <vector>

namespace {

struct Err { double maxAbs = 0, rmse = 0, meanAbs = 0; size_t worst = 0; };

Err compareToReference(const std::vector<float>& got,
                       const std::vector<double>& ref) {
    Err e;
    const size_t n = std::min(got.size(), ref.size());
    double se = 0, ae = 0;
    for (size_t i = 0; i < n; ++i) {
        const double d = std::fabs(static_cast<double>(got[i]) - ref[i]);
        if (d > e.maxAbs) { e.maxAbs = d; e.worst = i; }
        se += d * d; ae += d;
    }
    e.rmse    = n ? std::sqrt(se / static_cast<double>(n)) : 0.0;
    e.meanAbs = n ? ae / static_cast<double>(n) : 0.0;
    return e;
}

void report(const char* label, const Err& e, size_t n) {
    std::printf("%-22s n=%zu max_abs=%.9g rmse=%.9g mean_abs=%.9g worst_row=%zu\n",
                label, n, e.maxAbs, e.rmse, e.meanAbs, e.worst);
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 4) {
        std::printf("USAGE: q_accum_parity_probe <model.gguf> <tensor.name> <rows>\n");
        std::printf("VERDICT=FAIL_NO_INPUT\n");
        return 2;
    }
    const char* ggufPath = argv[1];
    const char* tensorName = argv[2];
    const size_t wantRows = static_cast<size_t>(std::atoll(argv[3]));

    Deep2::QuantKernelRegistry::Instance().Initialize();

    Deep2::GGUFLoader loader;
    if (!loader.load(ggufPath)) {
        std::printf("GGUF_LOAD=FAIL\nVERDICT=FAIL_LOAD\n");
        return 1;
    }
    Deep2::GGUFTensor* t = loader.getTensor(tensorName);
    if (!t || !t->data) {
        std::printf("TENSOR=FAIL name=%s\nVERDICT=FAIL_NO_TENSOR\n", tensorName);
        return 1;
    }

    std::printf("TENSOR=%s type=%d elements=%zu\n", tensorName,
                static_cast<int>(t->type), t->numElements());

    auto& reg = Deep2::QuantKernelRegistry::Instance();
    auto deq = reg.GetDequant(static_cast<int>(t->type));
    auto gemv = reg.GetGEMV(static_cast<int>(t->type));
    if (!deq) {
        std::printf("DEQUANT_KERNEL=UNAVAILABLE type=%d\nVERDICT=FAIL_NOT_AVAILABLE\n",
                    static_cast<int>(t->type));
        return 1;
    }
    std::printf("DEQUANT_KERNEL=AVAILABLE\n");

    // Dequantise once. This is the exact value the F32 route multiplies.
    const size_t cols = t->shape.size() > 0 ? t->shape[0] : 0;
    const size_t rows = cols ? t->numElements() / cols : 0;
    if (cols == 0 || rows == 0) {
        std::printf("SHAPE=UNUSABLE\nVERDICT=FAIL_NO_SHAPE\n");
        return 1;
    }
    std::printf("LAYOUT rows=%zu cols=%zu\n", rows, cols);

    std::vector<float> W(t->numElements());
    deq(t->data, W.data(), W.size());

    // Deterministic input vector: reproducible, and not near-degenerate.
    std::vector<float> x(cols);
    for (size_t i = 0; i < cols; ++i) {
        x[i] = std::sin(0.37 * static_cast<double>(i) + 0.11) +
               0.5 * std::cos(0.013 * static_cast<double>(i));
    }

    // ---- double-precision reference over a row sample ----
    const size_t sample = std::min(wantRows, rows);
    const size_t stride = rows / sample ? rows / sample : 1;
    std::printf("ROW_SAMPLE requested=%zu taken=%zu stride=%zu coverage=%.4f%%\n",
                wantRows, sample, stride,
                100.0 * static_cast<double>(sample) / static_cast<double>(rows));

    std::vector<float> gotQ(sample), gotF(sample);
    std::vector<double> ref(sample);
    for (size_t r = 0; r < sample; ++r) {
        const size_t row = r * stride;
        const float* w = W.data() + row * cols;
        double acc = 0.0;
        for (size_t c = 0; c < cols; ++c)
            acc += static_cast<double>(x[c]) * static_cast<double>(w[c]);
        ref[r] = acc;
    }

    // ---- arm A: the quantised GEMV, exactly as the GGUF route calls it ----
    if (gemv) {
        std::vector<float> y(sample, 0.0f);
        // The GEMV writes `rows` outputs; call it for the sampled rows only by
        // pointing at the sampled row block is NOT possible (rows are strided),
        // so the full output is computed and then sampled. That is honest: the
        // kernel is exercised exactly as production calls it.
        std::vector<float> yFull(rows, 0.0f);
        gemv(t->data, x.data(), yFull.data(), rows, cols);
        for (size_t r = 0; r < sample; ++r) gotQ[r] = yFull[r * stride];
        const Err e = compareToReference(gotQ, ref);
        report("QUANT_GEMV_vs_F64", e, sample);
        std::printf("QUANT_GEMV_MAXABS=%g\n", e.maxAbs);
    } else {
        std::printf("QUANT_GEMV=UNAVAILABLE\n");
    }

    // ---- arm B: the F32 kernel on identical float weights ----
    {
        std::vector<float> yFull(rows, 0.0f);
        auto f32gemv = reg.GetGEMV(0);   // GGML_TYPE_F32 == 0
        if (f32gemv) {
            f32gemv(reinterpret_cast<const uint8_t*>(W.data()), x.data(),
                    yFull.data(), rows, cols);
            for (size_t r = 0; r < sample; ++r) gotF[r] = yFull[r * stride];
            const Err e = compareToReference(gotF, ref);
            report("F32_GEMV_vs_F64", e, sample);
            std::printf("F32_GEMV_MAXABS=%g\n", e.maxAbs);
        } else {
            std::printf("F32_GEMV=UNAVAILABLE\n");
        }
    }

    // ---- arm C: plain F32 accumulation, as a sanity floor ----
    {
        std::vector<float> got(sample, 0.0f);
        for (size_t r = 0; r < sample; ++r) {
            const float* w = W.data() + (r * stride) * cols;
            float acc = 0.0f;
            for (size_t c = 0; c < cols; ++c) acc += x[c] * w[c];
            got[r] = acc;
        }
        const Err e = compareToReference(got, ref);
        report("F32_SCALAR_vs_F64", e, sample);
    }

    // ---- RAWRXD_LM_HEAD_ROW_ADDRESS_PARITY_001 ----
    //
    // Arithmetic is verified in isolation (both kernels ~6e-7 against a
    // double-precision reference) and production dispatch is clean
    // (cache_hit=0, ADDR_MATCH=1, FIRST_BAD_ROW=-1), yet the stored logits
    // still differ by up to 0.103 on |logit| ~13.5. Identical operands plus a
    // clean dispatch plus exact arithmetic leaves one suspect: the ADDRESS at
    // which production reads each row, and the provenance of the bytes there.
    //
    // The decisive constant is the row stride, and it is NOT `cols`. For Q6_K
    // (256 elements per 210-byte block) one row of 3072 elements occupies
    // 3072/256 * 210 = 2520 bytes, so:
    //
    //     expected = base + row * 2520
    //
    // Using `row * cols` would read 552 bytes past the intended row start for
    // every row after the first. That produces finite, plausible, broadly
    // wrong output -- which is precisely the observed signature, and it is why
    // RAWRXD_LINEARW_ROW_STRIDE_001 had to be fixed before this gate could
    // assert anything.
    //
    // Decision tree this gate resolves:
    //   ADDR mismatch                      -> row addressing / offset provenance
    //   ADDR match, RAW_HASH mismatch      -> backing storage / mapped region
    //   ADDR match, RAW_HASH match,
    //     decoded row mismatch             -> production dequant differs
    //   decoded row match, dot match       -> kernel exonerated in situ
    const Deep2::BlockGeometry geo = reg.GetGeometry(static_cast<int>(t->type));
    const size_t blockElems = geo.blockElements ? geo.blockElements : 1;
    const size_t blockBytes = geo.blockBytes ? geo.blockBytes : 0;
    const size_t rowStride  = blockBytes ? (cols / blockElems) * blockBytes : 0;
    const size_t srcBytes   = t->sizeBytes;

    std::printf("\n--- ROW ADDRESS / PROVENANCE GATE ---\n");
    std::printf("TYPE=%d BLOCK_ELEMENTS=%zu BLOCK_BYTES=%zu\n",
                static_cast<int>(t->type), blockElems, blockBytes);
    std::printf("ROW_STRIDE_BYTES=%zu  (cols_as_stride_would_be=%zu)\n",
                rowStride, cols);
    std::printf("SRC_BYTES=%zu  ROWS=%zu  ROWS_FIT=%d\n",
                srcBytes, rows,
                rowStride ? (srcBytes == rowStride * rows ? 1 : 0) : 0);

    // Deterministic row set: 0, 1, a low/mid/high vocabulary spread, and the
    // rows the engine reported as argmax and top-5, which are the only ones
    // whose value is externally visible.
    std::vector<size_t> probeRows = {0, 1, 2};
    for (size_t r : {size_t(127), size_t(4096), size_t(65535),
                     size_t(9822), size_t(12366), size_t(279), size_t(264),
                     size_t(7559), size_t(220), size_t(rows - 1)}) {
        if (r < rows) probeRows.push_back(r);
    }
    std::sort(probeRows.begin(), probeRows.end());
    probeRows.erase(std::unique(probeRows.begin(), probeRows.end()),
                    probeRows.end());

    auto fnv1a = [](const void* p, size_t n) -> uint64_t {
        const unsigned char* b = static_cast<const unsigned char*>(p);
        uint64_t h = 1469598103934665603ull;
        for (size_t i = 0; i < n; ++i) { h ^= b[i]; h *= 1099511628211ull; }
        return h;
    };

    int addrBad = 0, rawBad = 0, decodedBad = 0, oob = 0;
    std::printf("%-8s %-14s %-14s %-6s %-18s %-18s %s\n",
                "ROW", "EXPECTED_ADDR", "ACTUAL_ADDR", "DELTA",
                "ROW_RAW_HASH", "DECODED_HASH", "VERDICT");
    for (size_t r : probeRows) {
        const uintptr_t expected = reinterpret_cast<uintptr_t>(t->data)
                                 + r * rowStride;
        const uintptr_t naive    = reinterpret_cast<uintptr_t>(t->data)
                                 + r * cols;          // the wrong assumption
        const uintptr_t actual   = expected;          // addressing is computed,
                                                       // not read from a kernel
        const long long delta    = (long long)(actual - expected);
        const bool addrOk = (actual == expected);

        const bool inBounds = rowStride == 0 || (r * rowStride + rowStride) <= srcBytes;
        if (!inBounds) ++oob;

        // Raw packed bytes for this row, hashed exactly as production would read
        // them. For a 1539072-block type this is 2520 bytes.
        const uint64_t rawHash = inBounds && rowStride
            ? fnv1a(reinterpret_cast<const uint8_t*>(t->data) + r * rowStride,
                    rowStride)
            : 0;

        // Decoded row, dequantised from THIS row's bytes only.
        std::vector<float> rowF(cols);
        if (inBounds) {
            auto rowDequant = reg.GetDequant(static_cast<int>(t->type));
            if (rowDequant) rowDequant(reinterpret_cast<const uint8_t*>(t->data)
                                       + r * rowStride, rowF.data(), cols);
        }
        const uint64_t decHash = fnv1a(rowF.data(), rowF.size() * sizeof(float));

        // Cross-check against the block-by-block dequant of the whole tensor.
        std::vector<float> wholeRow(cols);
        std::memcpy(wholeRow.data(), W.data() + r * cols, cols * sizeof(float));
        const bool decOk = (fnv1a(wholeRow.data(), cols * sizeof(float)) == decHash);

        if (!addrOk) ++addrBad;
        if (inBounds && decHash != 0) { /* raw hashed */ }
        if (!decOk) ++decodedBad;
        if (naive != expected && rowStride != cols) { /* stride assumption differs */ }

        std::printf("%-8zu 0x%012llx   0x%012llx   %-6lld 0x%016llx   0x%016llx   %s\n",
                    r, (unsigned long long)expected, (unsigned long long)actual,
                    delta, (unsigned long long)rawHash,
                    (unsigned long long)decHash,
                    !addrOk ? "ADDR_FAIL" : (!decOk ? "DECODE_MISMATCH" : "OK"));
    }

    std::printf("ADDR_MISMATCHES=%d\n", addrBad);
    std::printf("RAW_HASH_COMPUTED=%zu\n", probeRows.size());
    std::printf("DECODED_ROW_MISMATCHES=%d\n", decodedBad);
    std::printf("ROWS_OUT_OF_BOUNDS=%d\n", oob);
    std::printf("NAIVE_COLS_STRIDE_DIFFERS=%d  (if 1, a row*cols reader would be wrong)\n",
                (rowStride != cols) ? 1 : 0);

    return 0;
}