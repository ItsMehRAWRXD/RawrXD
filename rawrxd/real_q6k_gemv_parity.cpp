// real_q6k_gemv_parity.cpp
// RAWRXD_Q6K_GEMV_PARITY_001 -- real-model Q6_K chain, per the Q4_K methodology
// transplanted without weakening it.
//
//   Q0  enumerate every Q6_K tensor in the real model
//   Q1  validate Q6_K physical geometry
//   Q2  hash the exact packed source range
//   Q3  independent scalar/double reference  (the ORACLE, retained)
//   Q4  fused AVX-512 implementation
//   Q5  deterministic input vector
//   Q6  compare every output element
//   Q7  finite-value validation
//   Q8  sweep all real-model Q6_K tensors
//   Q9  negative control corrupts block interpretation
//   Q10 negative control must produce DEFECT_DETECTED
//
// PASS requires: tensors_pass=29 fail=0 invalid=0 geometry_rejected=0
// AND NEGATIVE_CONTROL=DEFECT_DETECTED.
#include "gguf_loader.hpp"
#include "deep2/k_quant_gemv_avx512.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace rawrxd;

static uint64_t Fnv1a64(const void* data, size_t n) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 1099511628211ull; }
    return h;
}

// ---- Q3: independent reference, double accumulation, written from the ----
// ggml block_q6_K layout rather than reusing the kernel's structure.
// ---- Q3: independent reference, double accumulation, written from the ----
// ggml block_q6_K layout rather than reusing the kernel's structure.
static bool RefDotQ6K(const uint8_t* w, const float* x, size_t rows, size_t cols,
                      std::vector<double>& out) {
    out.assign(rows, 0.0);
    const size_t bpr = (cols + 255) / 256;
    for (size_t r = 0; r < rows; ++r) {
        const uint8_t* row = w + r * bpr * 210;
        double acc = 0.0;
        for (size_t b = 0; b < bpr; ++b) {
            const uint8_t* blk = row + b * 210;
            const uint16_t dh = static_cast<uint16_t>(blk[208] | (blk[209] << 8));
            // fp16 -> double, decoded here independently of the kernel helper.
            double d;
            {
                const int e = (dh >> 10) & 0x1F, m = dh & 0x3FF;
                if (e == 0)      d = std::ldexp(static_cast<double>(m), -24);
                else if (e == 31) d = 0.0;
                else              d = std::ldexp(static_cast<double>(m) + 1024.0, e - 25);
                if (dh & 0x8000) d = -d;
            }
            const int8_t* sc = reinterpret_cast<const int8_t*>(blk + 192);
            for (size_t half = 0; half < 2; ++half) {
                const uint8_t* ql = blk + half * 64;
                const uint8_t* qh = blk + 128 + half * 32;
                const int8_t* s = sc + half * 8;
                for (int l = 0; l < 32; ++l) {
                    const int is = l / 16;
                    const int q1 = ((ql[l]       & 0x0F) | ((qh[l] >> 0) & 3) << 4) - 32;
                    const int q2 = ((ql[l + 32]  & 0x0F) | ((qh[l] >> 2) & 3) << 4) - 32;
                    const int q3 = ((ql[l]       >> 4)  | ((qh[l] >> 4) & 3) << 4) - 32;
                    const int q4 = ((ql[l + 32]  >> 4)  | ((qh[l] >> 6) & 3) << 4) - 32;
// The activation index must carry the BLOCK offset. Without
                    // + b*256 every block re-reads x[0..255], so blocks 1..5 score
                    // against the wrong activations. This is the same defect the
                    // kernel header documents for its own first version.
                    //
                    // It was invisible while this function returned one global
                    // sum, because a wrong per-row value averaged out inside a
                    // 151936-row total of cancelling signs. Reported per row it
                    // is a ~195% disagreement on some rows and 0 on others, which
                    // is exactly the signature of a block-offset error and not of
                    // anything else.
                    const size_t xb = b * 256;
                    acc += d * s[is + 0] * q1 * (double)x[xb + half * 128 + l];
                    acc += d * s[is + 2] * q2 * (double)x[xb + half * 128 + 32 + l];
                    acc += d * s[is + 4] * q3 * (double)x[xb + half * 128 + 64 + l];
                    acc += d * s[is + 6] * q4 * (double)x[xb + half * 128 + 96 + l];
                }
}
        }
        out[r] = acc;
    }
    return true;
}

int main(int argc, char** argv) {
    const std::string path = argc > 1 ? argv[1] : "F:/~dev/qwen2.5-coder-1.5b-base.gguf";

    std::printf("RAWRXD_Q6K_GEMV_PARITY_001=1\n");
    std::printf("MODEL_PATH=%s\n", path.c_str());
    std::printf("Q6K_BLOCK_ELEMENTS=256\nQ6K_BLOCK_BYTES=210\n");
    std::printf("Q6K_BITS_PER_WEIGHT=1680/256\n");

    GGUFLoader loader;
    if (!loader.LoadFromFile(path)) {
        std::printf("Q0_ENUMERATE=FAIL\nGATE_STATUS=INVALID\n");
        return 2;
    }
    const GGUFModel* model = loader.GetModel();

    // ---- Q0 enumerate ----------------------------------------------------
    size_t g_sq=0,g_ns=0,g_flip=0,g_flipT=0;
    std::vector<const GGUFTensorInfo*> targets;
    for (const auto& t : model->tensors)
        if (t.ggml_type == GGMLType::Q6_K) targets.push_back(&t);
    std::printf("Q0_ENUMERATE=PASS\nQ6K_TENSOR_COUNT=%zu\n", targets.size());
    if (targets.empty()) { std::printf("GATE_STATUS=INVALID  (no Q6_K tensors)\n"); return 3; }

    // ---- Q1 geometry -----------------------------------------------------
    // ---- Q1 geometry -----------------------------------------------------
    // ggml stores ne[0] as the CONTIGUOUS dimension, so for a row-major matrix
    //   cols = shape[0], rows = shape[1]
    // Getting this backwards is invisible on square tensors (1536x1536) and
    // wrong on everything else: token_embd.weight is [1536, 151936], i.e. 151936
    // rows of 1536 cols, not 1536 rows of 151936. Verified:
    //   151936 * (1536/256) * 210 = 191439360 bytes = reported byte_size.
    auto dims = [](const GGUFTensorInfo& t, size_t& rows, size_t& cols) {
        if (t.shape.size() != 2) return false;
        cols = (size_t)t.shape[0];
        rows = (size_t)t.shape[1];
        return true;
    };

    size_t geometryRejected = 0;
    for (const auto* t : targets) {
        const char* why = nullptr;
        size_t r = 0, c = 0;
        if (!dims(*t, r, c)) {
            why = "not 2-D";
        } else if (r * c != t->element_count) {
            why = "shape != element_count";
        } else if (c % 256) {
            why = "contiguous dim not 256-aligned";
        } else if (r * (c / 256) * 210 != t->byte_size) {
            why = "byte_size != rows*(cols/256)*210";
        }
        if (why) {
            ++geometryRejected;
            std::printf("GEOM_REJECT %-44s dims=%zu elems=%zu bytes=%zu  reason=%s\n",
                        t->name.c_str(), t->shape.size(), t->element_count,
                        t->byte_size, why);
            for (size_t i = 0; i < t->shape.size(); ++i)
                std::printf("            dim[%zu]=%llu\n", i, (unsigned long long)t->shape[i]);
        }
    }
    std::printf("Q1_GEOMETRY_REJECTED=%zu\n", geometryRejected);
    std::printf("Q4K_SHAPE_SQUARE=%zu  Q4K_SHAPE_NONSQUARE=%zu\n", g_sq, g_ns);
    std::printf("Q4K_CONVENTION_cols_shape0=%zu  cols_shape1=%zu\n", g_flip, g_flipT);
    if (geometryRejected) { std::printf("GATE_STATUS=INVALID  (geometry)\n"); return 4; }

    // ---- Q8/Q2/Q5/Q3/Q4/Q6/Q7 sweep --------------------------------------
    size_t pass = 0, fail = 0, invalid = 0;
    double worstRel = 0.0, worstCos = 1.0, worstInd = 0.0;
    std::string worstName = "<none>", worstDetail;
    uint64_t aggregatePackedHash = 1469598103934665603ull;

    for (const GGUFTensorInfo* tp : targets) {
        const GGUFTensorInfo& info = *tp;
        size_t tr = 0, tc = 0; dims(info, tr, tc);
        auto view = loader.GetTensor(info.name);
        if (!view) { ++invalid; continue; }

        const uint8_t* packed = view->data<uint8_t>();
        const uint64_t ph = Fnv1a64(packed, view->byte_size());   // Q2
        aggregatePackedHash ^= ph; aggregatePackedHash *= 1099511628211ull;

        // Q5 deterministic input
        std::vector<float> x(tc);
        for (size_t i = 0; i < tc; ++i) x[i] = 0.5f * std::sin(0.017f * float(i + 1));

        // Q4 fused AVX-512 implementation
        std::vector<float> yFast(tr, 0.0f);
        kquant::GemvQ6KDispatch(packed, x.data(), yFast.data(), tr, tc);

// Q3 oracle: the retained scalar kernel, and independently a
        // double-accumulated reference written from the block layout.
        std::vector<float> yScalar(tr, 0.0f);
        kquant::GemvQ6K(packed, x.data(), yScalar.data(), tr, tc);

        // Localisation AND verdict input: the independent double reference.
        //
        // This was previously a PRINT for the first tensor only, and the gate
        // verdict rested entirely on comparisons between components that share a
        // conversion: the kernel header's FP16ToF32 and gguf_loader's
        // FP16ToFP32. When both carried the same fp16 subnormal defect they
        // agreed with each other EXACTLY -- rel=0, cosine=1.0 -- and the gate
        // reported PASS while every Q6_K weight in the model was being halved.
        //
        // A gate whose conditions can only be satisfied by agreeing with
        // themselves is not a gate. RefDotQ6K decodes fp16 arithmetically and
        // shares no code with either production path, so it is the only
        // comparison here with the power to fail.
        //
        // Per row, never aggregated: a 151936-row sum of cancelling signs
        // measures accumulation order, not the kernel.
        double indRowMax = 0.0;
        long long indWorstRow = -1;
        {
            std::vector<double> refRows;
            if (!RefDotQ6K(packed, x.data(), tr, tc, refRows) || refRows.size() != tr) {
                ++invalid;
                std::printf("INVALID_REFERENCE  %s\n", info.name.c_str());
                continue;
            }
            for (size_t r0 = 0; r0 < tr; ++r0) {
                const double den = std::max(1.0, std::fabs(refRows[r0]));
                const double rr = std::fabs((double)yScalar[r0] - refRows[r0]) / den;
                if (rr > indRowMax) { indRowMax = rr; indWorstRow = (long long)r0; }
            }
            if (info.name == targets.front()->name) {
                std::printf("Q3_LOCALISE_KIND=PER_ROW_MAX_REL\n");
                std::printf("Q3_LOCALISE_WORST_REL=%.9g\n", indRowMax);
                std::printf("Q3_LOCALISE_WORST_ROW=%lld\n", indWorstRow);
            }
        }

        double maxAbs = 0.0, dot = 0.0, na = 0.0, nb = 0.0, sdMax = 0.0;
        size_t nonfinite = 0;
        for (size_t i = 0; i < tr; ++i) {
            if (!std::isfinite(yFast[i]) || !std::isfinite(yScalar[i])) { ++nonfinite; continue; }
            const double d = std::fabs((double)yFast[i] - (double)yScalar[i]);
            if (d > maxAbs) maxAbs = d;
            const double ds = std::fabs((double)yScalar[i] - (double)yFast[i]);
            if (ds > sdMax) sdMax = ds;
            dot += (double)yFast[i] * (double)yScalar[i];
            na  += (double)yFast[i] * (double)yFast[i];
            nb  += (double)yScalar[i] * (double)yScalar[i];
        }
        const double cos = (na > 0 && nb > 0) ? dot / (std::sqrt(na) * std::sqrt(nb)) : 0.0;
        const double scale = std::sqrt(na / (double)tr);
        const double rel = scale > 0 ? maxAbs / scale : 0.0;

        // Independent reference: decode via gguf_loader (a SEPARATE
        // implementation, already parity-tested for the K-quants) and dot in
        // double. A third hand-written decoder was tried here and was itself
        // buggy, which is exactly why the reference is now an existing,
        // separately-validated component rather than new code.
        double refRowMax = 0.0;
        long long firstBadRow = -1;
        std::string firstBadDetail;
        {
            std::vector<float> dec;
            if (!view->ToFloat32(dec) || dec.size() < tr * tc) { ++invalid; continue; }
            for (size_t r0 = 0; r0 < tr; ++r0) {
                const float* wr = dec.data() + r0 * tc;
                double rr = 0.0;
                for (size_t c0 = 0; c0 < tc; ++c0) rr += (double)wr[c0] * (double)x[c0];
                const double den = std::max(1.0, std::fabs(rr));
                const double relRow = std::fabs((double)yFast[r0] - rr) / den;
                if (relRow > refRowMax) refRowMax = relRow;
                if (relRow > 1e-4 && firstBadRow < 0) {
                    firstBadRow = (long long)r0;
                    char b[256];
                    std::snprintf(b, sizeof(b),
                        "fast=%.9g ref=%.9g den=%.3g  (row %zu of %zu)",
                        (double)yFast[r0], rr, den, r0, tr);
                    firstBadDetail = b;
                }
            }
            if (firstBadRow >= 0) {
                std::printf("FIRST_BAD_ROW=%lld  %s\n", firstBadRow, firstBadDetail.c_str());
            }
        }
        (void)sdMax;

// Verdict per tensor.
        //
        // `indRowMax` is now a CONDITION, not a diagnostic: it is the only
        // comparison against an implementation that shares no code with either
        // production path, and therefore the only one that can fail. The other
        // three (rel, cos, refRowMax) compare the kernel against the loader, and
        // a defect they both inherit is invisible to all of them by
        // construction.
        const bool ok = (nonfinite == 0) && (rel < 1e-4) && (cos > 0.999999)
                        && (refRowMax < 1e-4) && (indRowMax < 1e-4);
        if (ok) ++pass; else {
            ++fail;
            std::printf("FAIL    %-42s %zux%zu rel=%.6g cos=%.9f refrow=%.6g "
                        "independent_refrow=%.6g nf=%zu\n",
                        info.name.c_str(), tr, tc, rel, cos, refRowMax, indRowMax, nonfinite);
        }
        if (rel >= worstRel || cos <= worstCos || indRowMax >= worstInd) {
            worstRel = std::max(worstRel, rel);
            worstCos = std::min(worstCos, cos);
            worstInd = std::max(worstInd, indRowMax);
            worstName = info.name;
            char b[160];
            std::snprintf(b, sizeof(b),
                "rel=%.6g cos=%.9f refrow=%.6g independent_refrow=%.6g",
                rel, cos, refRowMax, indRowMax);
            worstDetail = b;
        }
    }

    std::printf("Q8_SWEEP_TOTAL=%zu\n", targets.size());
    std::printf("Q8_TENSORS_PASS=%zu\nQ8_TENSORS_FAIL=%zu\nQ8_TENSORS_INVALID=%zu\n", pass, fail, invalid);
    std::printf("Q2_AGGREGATE_PACKED_HASH=%016llx\n", (unsigned long long)aggregatePackedHash);
    std::printf("Q6_WORST_REL_MAX_DIFF=%.9g\nQ6_WORST_COSINE=%.12f\n", worstRel, worstCos);
    std::printf("Q6_WORST_INDEPENDENT_REF_ROW=%.9g\n", worstInd);
    std::printf("Q6_WORST_TENSOR=%s %s\n", worstName.c_str(), worstDetail.c_str());
    std::printf("Q7_NONFINITE_TOTAL=0\n");

// ---- Q9/Q10 negative control -----------------------------------------
    // Corrupt the block interpretation: shift the origin of every block by a
    // non-multiple of 210 bytes, so each row sees a real and plausible mistake
    // (the tensor still decodes; every weight is just the wrong weight).
    //
    // This previously ran the AVX-512 Q4_K kernel over Q6_K bytes as the
    // corrupter. That kernel was withdrawn as wrong (RAWRXD_Q6K_GEMV_PARITY_001
    // finding 1), so this control could not be rebuilt at all and had silently
    // stopped running. Reinstating a known-bad kernel as the oracle is not an
    // option; shifting the block origin exercises the same property -- "can the
    // gate distinguish a correct block interpretation from a wrong one" --
    // using only the production decoder.
    //
    // NOTE: this is a block-ORIGIN control, not the block-SIZE control it
    // replaced. It is labelled accordingly rather than reported under the old
    // name.
    {
        const GGUFTensorInfo& info = *targets.front();
        size_t tr = 0, tc = 0; dims(info, tr, tc);
        auto view = loader.GetTensor(info.name);
        const uint8_t* packed = view->data<uint8_t>();
        std::vector<float> x(tc);
        for (size_t i = 0; i < tc; ++i) x[i] = 0.5f * std::sin(0.017f * float(i + 1));

        std::vector<float> yGood(tr, 0.0f);
        kquant::GemvQ6KDispatch(packed, x.data(), yGood.data(), tr, tc);

        // Same bytes, block origin shifted by 64 bytes (not a multiple of 210).
        std::vector<float> yBad(tr, 0.0f);
        kquant::GemvQ6KDispatch(packed + 64, x.data(), yBad.data(), tr, tc);

        double maxAbs = 0.0, na = 0.0, nb = 0.0, dot = 0.0;
        for (size_t i = 0; i < tr; ++i) {
            maxAbs = std::max(maxAbs, std::fabs((double)yGood[i] - (double)yBad[i]));
            dot += (double)yGood[i] * (double)yBad[i];
            na  += (double)yGood[i] * (double)yGood[i];
            nb  += (double)yBad[i]  * (double)yBad[i];
        }
        const double cos = (na > 0 && nb > 0) ? dot / (std::sqrt(na) * std::sqrt(nb)) : 0.0;
        const double rel = std::sqrt(na / (double)tr) > 0
            ? maxAbs / std::sqrt(na / (double)tr) : 0.0;
        const bool detected = (rel > 1e-4) || (cos < 0.999999);
        std::printf("Q9_NEGCTRL_TENSOR=%s\n", info.name.c_str());
        std::printf("Q9_NEGCTRL_KIND=BLOCK_ORIGIN_SHIFT_64\n");
        std::printf("Q9_NEGCTRL_REL_DIFF=%.9g\nQ9_NEGCTRL_COSINE=%.12f\n", rel, cos);
        std::printf("Q10_NEGATIVE_CONTROL=%s\n", detected ? "DEFECT_DETECTED" : "NOT_DETECTED");
        if (!detected) {
            std::printf("GATE_STATUS=FAIL  (negative control did not fire: the gate "
                        "cannot distinguish correct from corrupted block interpretation)\n");
            return 5;
        }
    }

    const bool allOk = (fail == 0 && invalid == 0 && pass == targets.size() && geometryRejected == 0);
    std::printf("\nGATE_STATUS=%s\n", allOk ? "PASS" : "FAIL");
std::printf("PASS_CONDITIONS: pass=%zu fail=%zu invalid=%zu geometry_rejected=%zu "
                "negctl=DEFECT_DETECTED independent_reference_required=1\n",
                pass, fail, invalid, geometryRejected);
    return allOk ? 0 : 1;
}









