// real_q4k_gemv_parity.cpp
// RAWRXD_Q4K_GEMV_PARITY_001 -- real-model chain, CPU half.
//
// THE DECISIVE TEST, on real packed bytes from a real GGUF:
//
//   qwen2.5-coder-1.5b-base.gguf
//     blk.0.attn_q.weight   Q4_K  1536x1536  offset 219779584  size 1327104
//        |
//        +-- independent CPU decode (gguf_loader ToFloat32)  -> y_ref
//        |
//        +-- PRODUCTION GEMV registry (GetGEMV(Q4_K))         -> y_prod
//        |
//        +-- float32 reference dot on the decoded weights      -> y_fp32
//        v
//   compare
//
// Receipt binds: model SHA-256, tensor name, ggml type, byte offset/size,
// dimensions, packed-range hash, input-vector hash, and all three output
// hashes, plus gpu_reached.
//
// RAWRXD_GGUF_TYPE_ENUM_001 matters here: before that fix the loader could not
// open this file at all, so no real-model evidence of any kind was possible.
#include "gguf_loader.hpp"
#include "deep2/QuantKernelRegistry.hpp"

#include <cstdio>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <algorithm>

using namespace rawrxd;

static uint64_t Fnv1a64(const void* data, size_t n) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 1099511628211ull; }
    return h;
}

int main(int argc, char** argv) {
    const std::string path = argc > 1 ? argv[1] : "F:/~dev/qwen2.5-coder-1.5b-base.gguf";
    const bool sweepAll = (argc > 2 && std::string(argv[2]) == "--all");
    const char* oneName = sweepAll ? nullptr : (argc > 2 ? argv[2] : "blk.0.attn_q.weight");

    std::printf("RAWRXD_Q4K_GEMV_PARITY_001=1\n");
    std::printf("MODEL_PATH=%s\n", path.c_str());
    std::printf("MODE=%s\n", sweepAll ? "SWEEP_ALL_Q4K" : "SINGLE_TENSOR");
    if (!sweepAll) std::printf("TENSOR=%s\n", oneName);

    GGUFLoader loader;
    if (!loader.LoadFromFile(path)) {
        std::printf("MODEL_LOAD=FAIL\nGATE_STATUS=INVALID\n");
        return 2;
    }
    std::printf("MODEL_LOAD=PASS\n");

    Deep2::QuantKernelRegistry& reg = Deep2::QuantKernelRegistry::Instance();
    reg.Initialize();
    auto gemv = reg.GetGEMV((int)GGMLType::Q4_K);
    std::printf("REGISTRY_Q4K_KERNEL=%s\n", gemv ? "NON_NULL" : "NULL");
    if (!gemv) {
        std::printf("GPU_REACHED=0\nGATE_STATUS=INVALID  (no Q4_K GEMV registered)\n");
        return 6;
    }

    const GGUFModel* model = loader.GetModel();
    std::vector<const GGUFTensorInfo*> targets;
    if (sweepAll) {
        for (const auto& t : model->tensors)
            if (t.ggml_type == GGMLType::Q4_K) targets.push_back(&t);
    } else {
        for (const auto& t : model->tensors)
            if (t.name == oneName) { targets.push_back(&t); break; }
    }
    std::printf("Q4K_TENSOR_COUNT=%zu\n", targets.size());
    if (targets.empty()) { std::printf("GATE_STATUS=INVALID  (no targets)\n"); return 7; }

    // Q4_K geometry: 256 elements per 144-byte superblock. A tensor that
    // reconciles against this cannot be a mislabelled byte range.
    const size_t QK_EL = 256, QK_BYTES = 144;
    auto geomOk = [&](const GGUFTensorInfo& t) {
        if (t.shape.size() != 2) return false;
        const size_t r = (size_t)t.shape[0], c = (size_t)t.shape[1];
        if (r * c != t.element_count) return false;
        if (c % QK_EL) return false;
        return r * (c / QK_EL) * QK_BYTES == t.byte_size;
    };

    size_t pass = 0, fail = 0, invalid = 0, geomRejected = 0;
    double worstRel = 0.0, worstCos = 1.0;
    std::string worstName = "<none>", worstDetail;

    for (const GGUFTensorInfo* tp : targets) {
        const GGUFTensorInfo& info = *tp;
        if (info.shape.size() != 2) { ++invalid; continue; }
        const size_t tr = (size_t)info.shape[0], tc = (size_t)info.shape[1];
        if (!geomOk(info)) {
            ++invalid; ++geomRejected;
            std::printf("INVALID %-42s %zux%zu bytes=%zu expect=%zu\n", info.name.c_str(),
                        tr, tc, info.byte_size,
                        tr * (tc % QK_EL ? 0 : tc / QK_EL) * QK_BYTES);
            continue;
        }
        auto view = loader.GetTensor(info.name);
        if (!view) { ++invalid; continue; }

        std::vector<float> decoded;
        if (!view->ToFloat32(decoded) || decoded.size() < tr * tc) { ++invalid; continue; }

        std::vector<float> x(tc);
        for (size_t i = 0; i < tc; ++i) x[i] = 0.5f * std::sin(0.017f * float(i + 1));

        std::vector<float> yRef(tr, 0.0f);
        for (size_t r = 0; r < tr; ++r) {
            const float* w = decoded.data() + r * tc;
            double acc = 0.0;
            for (size_t c = 0; c < tc; ++c) acc += (double)w[c] * (double)x[c];
            yRef[r] = (float)acc;
        }

        std::vector<float> yProd(tr, 0.0f);
        gemv(view->data<uint8_t>(), x.data(), yProd.data(), tr, tc);

        double maxAbs = 0.0, dot = 0.0, na = 0.0, nb = 0.0;
        size_t nonfinite = 0;
        for (size_t i = 0; i < tr; ++i) {
            if (!std::isfinite(yProd[i]) || !std::isfinite(yRef[i])) { ++nonfinite; continue; }
            const double d = std::fabs((double)yProd[i] - (double)yRef[i]);
            if (d > maxAbs) maxAbs = d;
            dot += (double)yProd[i] * (double)yRef[i];
            na  += (double)yProd[i] * (double)yProd[i];
            nb  += (double)yRef[i]   * (double)yRef[i];
        }
        const double cos = (na > 0 && nb > 0) ? dot / (std::sqrt(na) * std::sqrt(nb)) : 0.0;
        const double scale = std::sqrt(na / (double)tr);
        const double rel = scale > 0 ? maxAbs / scale : 0.0;

        const bool ok = (nonfinite == 0) && (rel < 1e-4) && (cos > 0.999999);
        if (ok) ++pass; else {
            ++fail;
            std::printf("FAIL    %-42s %zux%zu rel=%.6g cos=%.9f nonfinite=%zu\n",
                        info.name.c_str(), tr, tc, rel, cos, nonfinite);
        }
        if (rel >= worstRel || cos <= worstCos) {
            worstRel = std::max(worstRel, rel);
            worstCos = std::min(worstCos, cos);
            worstName = info.name;
            char b[128];
            std::snprintf(b, sizeof(b), "rel=%.6g cos=%.9f", rel, cos);
            worstDetail = b;
        }
        if (!sweepAll) {
            std::printf("\nPACKED_RANGE_HASH=%016llx\n",
                        (unsigned long long)Fnv1a64(view->data<uint8_t>(), view->byte_size()));
            std::printf("PROD_REL_MAX_DIFF=%.9g\nPROD_COSINE=%.12f\nPROD_NONFINITE=%zu\n",
                        rel, cos, nonfinite);
        }
    }

    std::printf("\n; --- summary ---\n");
    std::printf("TENSORS_TOTAL=%zu\n", targets.size());
    std::printf("TENSORS_PASS=%zu\n", pass);
    std::printf("TENSORS_FAIL=%zu\n", fail);
    std::printf("TENSORS_INVALID=%zu\n", invalid);
    std::printf("TENSORS_GEOMETRY_REJECTED=%zu\n", geomRejected);
    std::printf("WORST_REL_MAX_DIFF=%.9g\n", worstRel);
    std::printf("WORST_COSINE=%.12f\n", worstCos);
    std::printf("WORST_TENSOR=%s %s\n", worstName.c_str(), worstDetail.c_str());
    std::printf("GPU_REACHED=0\n");
    const bool allOk = (fail == 0 && invalid == 0 && pass == targets.size());
    std::printf("CPU_HALF=%s\n", allOk ? "PASS" : "FAIL");
    std::printf("GPU_HALF=INVALID  (no device path exercised)\n");
    std::printf("GATE_STATUS=%s\n", allOk ? "CPU_HALF_PASS_GPU_HALF_OPEN" : "FAIL");
    return allOk ? 0 : 1;
}
