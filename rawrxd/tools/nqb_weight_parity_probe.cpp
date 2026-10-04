// nqb_weight_parity_probe.cpp
// RAWRXD_NQB_WEIGHT_PARITY_001
//
// The real-weight oracle now runs both paths end to end and reports a logit
// divergence (LOGIT_COSINE ~0.83, argmax mismatch). That is a SYMPTOM. This
// probe answers the question underneath it: are the WEIGHTS the same?
//
// For each named tensor it pulls the value two ways --
//   GGUF : production dequant kernel  -> float32
//   NQB  : streamer materialisation  -> bfloat16 -> float32
// -- and reports the difference. That splits the search space in half:
//
//   weights match to BF16 precision  -> the divergence is in COMPUTE
//                                        (attention / rope / norm / lm-head)
//   some tensor does NOT match      -> the divergence is in the DATA, and the
//                                        first such tensor names itself
//
// A tensor-level comparison is the cheapest possible first-bad-state probe:
// it needs no forward pass and it cannot be confused by downstream drift.
//
// Usage: nqb_weight_parity_probe <model.gguf> <model.nqb> <tensor> [tensor...]

#include "GGUFLoader.hpp"
#include "QuantKernelRegistry.hpp"
#include "Nanof32BraidStreamer.hpp"

#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr,
            "Usage: %s <model.gguf> <model.nqb>                 # compare ALL tensors\n"
            "       %s <model.gguf> <model.nqb> <tensor> [tensor...]\n",
            argv[0], argv[0]);
        return 64;
    }
    const char* ggufPath = argv[1];
    const char* nqbPath  = argv[2];

    std::fprintf(stderr, "=== RAWRXD_NQB_WEIGHT_PARITY_001 ===\n");
    std::fprintf(stderr, "GGUF=%s\nNQB=%s\n", ggufPath, nqbPath);

    Deep2::QuantKernelRegistry::Instance().Initialize();

    Deep2::GGUFLoader loader;
    if (!loader.load(ggufPath)) {
        std::fprintf(stderr, "FAIL=gguf_load %s\n", loader.error().c_str());
        return 1;
    }

    Deep2::Nanof32BraidStreamer streamer;
    if (!streamer.open(nqbPath)) {
        std::fprintf(stderr, "FAIL=nqb_open\n");
        return 1;
    }
    std::vector<std::pair<std::string, Deep2::NQBraidBlock>> blocks;
    if (!streamer.readAllTensors(blocks)) {
        std::fprintf(stderr, "FAIL=nqb_read_all\n");
        return 1;
    }
    std::unordered_map<std::string, const Deep2::NQBraidBlock*> byName;
    for (const auto& kv : blocks) byName[kv.first] = &kv.second;
    std::fprintf(stderr, "NQB_TENSORS=%zu GGUF_TENSORS=%zu\n", blocks.size(), loader.tensorCount());

    size_t compared = 0, mismatched = 0;
    double minCosine = 2.0;
    size_t degenerateTensors = 0;
    double maxMeanAbs = 0.0, maxAbsAll = 0.0;
    size_t argmaxMatched = 0;

    // With no tensor named, compare EVERY tensor the GGUF declares.
    //
    // RAWRXD_NQB_ALL_TENSOR_PARITY_001: a sample cannot support the claim that
    // the weight data path is healthy -- it can only support "the tensors I
    // looked at are healthy", and the tensors not looked at remain an open
    // hole exactly the size of the sample. The whole sweep reuses the machinery
    // already here: dequantise one GGUF tensor, compare, release, move on.
    const bool allTensors = (argc == 3);
    if (allTensors) {
        std::fprintf(stderr, "MODE=ALL_TENSORS declared=%zu\n", loader.tensorCount());
    }

    auto compareOne = [&](const std::string& name) {
        const Deep2::GGUFTensor* t = loader.getTensor(name);
        auto it = byName.find(name);
        if (!t) { std::fprintf(stderr, "TENSOR=%s SKIP=absent_in_gguf\n", name.c_str()); return; }
        if (it == byName.end()) {
            std::fprintf(stderr, "TENSOR=%s SKIP=absent_in_nqb\n", name.c_str());
            ++mismatched;
            return;
        }

        const size_t n = t->numElements();
        const Deep2::NQBraidBlock& blk = *it->second;
        if (blk.elements() != n) {
            std::fprintf(stderr,
                "TENSOR=%s ELEMENT_COUNT_MISMATCH gguf=%zu nqb=%zu  <-- FIRST BAD STATE\n",
                name.c_str(), n, blk.elements());
            ++mismatched;
            return;
        }

        std::vector<float> a(n);
        if (t->type == Deep2::GGMLType::GGML_TYPE_F32) {
            std::memcpy(a.data(), t->data, n * sizeof(float));
        } else {
            auto fn = Deep2::QuantKernelRegistry::Instance().GetDequant(static_cast<int>(t->type));
            if (!fn) { std::fprintf(stderr, "TENSOR=%s SKIP=no_dequant\n", name.c_str()); return; }
            fn(t->data, a.data(), n);
        }

        // Compare against whatever the INFERENCE path actually receives, not
        // against the container's own bytes. Before
        // RAWRXD_NQB_DENSE_F32_PRESERVE_F32_001 that was bfloat16; a dense F32
        // block now arrives as float32 and this becomes an exact comparison.
        const bool nqbIsF32 = !blk.f32Data.empty();
        double maxAbs = 0.0, sumAbs = 0.0, dot = 0.0, na = 0.0, nb = 0.0;
        size_t argA = 0, argB = 0;
        float amaxA = 0.0f, amaxB = 0.0f;
        size_t nonFiniteB = 0;
        for (size_t k = 0; k < n; ++k) {
            const float va = a[k];
            const float vb = nqbIsF32 ? blk.f32Data[k] : blk.bf16Data[k].toFloat();
            if (!std::isfinite(vb)) ++nonFiniteB;
            const double d = std::fabs(static_cast<double>(va) - static_cast<double>(vb));
            if (d > maxAbs) maxAbs = d;
            sumAbs += d;
            dot += static_cast<double>(va) * static_cast<double>(vb);
            na  += static_cast<double>(va) * static_cast<double>(va);
            nb  += static_cast<double>(vb) * static_cast<double>(vb);
            if (std::fabs(va) > std::fabs(amaxA)) { amaxA = va; argA = k; }
            if (std::fabs(vb) > std::fabs(amaxB)) { amaxB = vb; argB = k; }
        }
        const double cosine = (na > 0 && nb > 0) ? dot / (std::sqrt(na) * std::sqrt(nb)) : 0.0;
        // A tensor whose GGUF side is entirely zero has no direction, so cosine
        // is 0/0. Reporting that as "cosine 0" in a receipt reads like a total
        // disagreement. It is counted separately and excluded from MIN_COSINE.
        const bool degenerate = !(na > 0);
        if (degenerate) ++degenerateTensors;

        // Weight identity is claimed on the two statistics that actually
        // establish it: the tensors are parallel (cosine) and they peak in the
        // same place (argmax). A max-relative-error threshold was tried first
        // and was wrong: BF16 truncates each ELEMENT by at most 2^-8 of that
        // element, so normalising the largest error over ~4e8 samples by the
        // tensor maximum is not a bound the format guarantees. Gating on it
        // rejected tensors that were in fact identical. rel_max is still
        // printed -- it is the number that bounds the narrowing -- but it is an
        // observation here, not the verdict.
        ++compared;
        const bool ok = (nonFiniteB == 0) && (cosine > 0.99999) && (argA == argB);
        if (!ok) ++mismatched;
        if (argA == argB) ++argmaxMatched;
        if (!degenerate && cosine < minCosine) minCosine = cosine;
        if (sumAbs / static_cast<double>(n) > maxMeanAbs) maxMeanAbs = sumAbs / static_cast<double>(n);
        if (maxAbs > maxAbsAll) maxAbsAll = maxAbs;

        const double scale = std::max(1e-6, std::max(std::fabs((double)amaxA), std::fabs((double)amaxB)));
        const double relMax = maxAbs / scale;

        if (!allTensors) {
            std::fprintf(stderr,
                "TENSOR=%s elements=%zu gguf_type=%d nqb_format=%s\n"
                "  maxabs=%.6g meanabs=%.6g rel_max_vs_tensor_max=%.4g cosine=%.9f nonfinite_nqb=%zu\n"
                "  argmax|gguf|=%zu argmax|nqb|=%zu absargmax_match=%d\n"
                "  VERDICT=%s\n",
                name.c_str(), n, static_cast<int>(t->type),
                nqbIsF32 ? "F32" : "BF16",
                maxAbs, sumAbs / static_cast<double>(n), relMax, cosine, nonFiniteB,
                argA, argB, (argA == argB) ? 1 : 0,
                ok ? "MATCH" : "MISMATCH");
        } else if (!ok) {
            // In ALL mode only failures are printed, so the first bad tensor is
            // visible without 255 screens of noise ahead of it.
            std::fprintf(stderr, "MISMATCH name=%s elements=%zu cosine=%.9f argmax_match=%d\n",
                         name.c_str(), n, cosine, (argA == argB) ? 1 : 0);
        }
    };

    if (allTensors) {
        for (const std::string& name : loader.listTensors()) compareOne(name);
    } else {
        for (int i = 3; i < argc; ++i) compareOne(argv[i]);
    }

    std::fprintf(stderr, "\nTENSORS_EXPECTED=%zu\n", loader.tensorCount());
    std::fprintf(stderr, "TENSORS_COMPARED=%zu\n", compared);
    std::fprintf(stderr, "TENSORS_MATCH=%zu\n", compared - mismatched);
    std::fprintf(stderr, "TENSORS_FAIL=%zu\n", mismatched);
    std::fprintf(stderr, "ARGMAX_MATCH=%zu/%zu\n", argmaxMatched, compared);
    std::fprintf(stderr, "MIN_COSINE=%.9f\n", compared ? minCosine : 0.0);
    std::fprintf(stderr, "DEGENERATE_ALL_ZERO_TENSORS=%zu\n", degenerateTensors);
    std::fprintf(stderr, "MAX_MEAN_ABS=%.6g\n", maxMeanAbs);
    std::fprintf(stderr, "MAX_ABS=%.6g\n", maxAbsAll);
    std::fprintf(stderr, "WEIGHT_DATA_PATH=%s\n",
                 (mismatched == 0 && compared == loader.tensorCount())
                     ? "PASS_ALL_TENSORS" : "FAIL");
    std::fprintf(stderr, "VERDICT=%s\n", mismatched == 0 ? "PASS" : "FAIL");
    return mismatched == 0 ? 0 : 1;
}
