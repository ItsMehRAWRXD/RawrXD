// q2k_dequant_probe.cpp
// RAWRXD_Q2K_DEQUANT_001 — prove Q2_K dequantizer against real model weights.
//
// Loads a single Q2_K tensor from a real GGUF and verifies:
//   - GGUF opens and parses correctly
//   - The selected tensor exists and is Q2_K
//   - Dequantization produces finite values
//   - Output count matches expected element count
//   - Non-zero values are present (not all zeros)
//   - Byte coverage is exact (no under/over-read)
//
// Does NOT compare against another implementation; this gate certifies the
// dequantizer is internally consistent before it is trusted by the converter.

#include "gguf_loader.hpp"
#include "llm_adapter/gguf_k_quants.hpp"

#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <string>
#include <vector>

static bool checkFinite(const float* data, size_t n, size_t& nanCount, size_t& infCount) {
    nanCount = 0; infCount = 0;
    for (size_t i = 0; i < n; ++i) {
        if (std::isnan(data[i])) ++nanCount;
        else if (std::isinf(data[i])) ++infCount;
    }
    return nanCount == 0 && infCount == 0;
}

static size_t countNonZero(const float* data, size_t n) {
    size_t c = 0;
    for (size_t i = 0; i < n; ++i) {
        if (data[i] != 0.0f) ++c;
    }
    return c;
}

int main(int argc, char** argv) {
    const char* modelPath = (argc > 1) ? argv[1]
        : "G:\\~dev\\rawrxd\\models\\llama3.2-3b-Q2_K.gguf";
    const char* tensorName = (argc > 2) ? argv[2] : "blk.0.attn_q.weight";

    std::fprintf(stderr, "=== RAWRXD_Q2K_DEQUANT_001 ===\n");
    std::fprintf(stderr, "MODEL=%s\n", modelPath);
    std::fprintf(stderr, "TENSOR=%s\n", tensorName);

    // --- open GGUF ---------------------------------------------------------
    rawrxd::GGUFLoader loader;
    if (!loader.LoadFromFile(modelPath)) {
        std::fprintf(stderr, "GGUF_OPEN=FAIL\n");
        std::fprintf(stderr, "VERDICT=FAIL\n");
        return 1;
    }
    std::fprintf(stderr, "GGUF_OPEN=PASS\n");

    const auto* model = loader.GetModel();
    if (!model || !model->header.valid) {
        std::fprintf(stderr, "GGUF_MAGIC=FAIL\n");
        std::fprintf(stderr, "VERDICT=FAIL\n");
        return 1;
    }
    std::fprintf(stderr, "GGUF_MAGIC=PASS version=%u tensors=%llu metadata=%llu\n",
                 model->header.version,
                 static_cast<unsigned long long>(model->header.tensor_count),
                 static_cast<unsigned long long>(model->header.metadata_kv_count));

    // --- tensor census -------------------------------------------------------
    size_t typeCounts[32] = {};
    size_t unsupported = 0;
    size_t tensorCount = 0;
    for (const auto& t : model->tensors) {
        ++tensorCount;
        uint32_t typeRaw = static_cast<uint32_t>(t.ggml_type);
        if (typeRaw < 32) ++typeCounts[typeRaw];
        else ++unsupported;
    }
    std::fprintf(stderr, "GGUF_TENSOR_COUNT=%zu\n", tensorCount);
    std::fprintf(stderr, "TYPE_F32=%zu TYPE_F16=%zu TYPE_Q2_K=%zu TYPE_Q4_K=%zu TYPE_Q6_K=%zu\n",
                 typeCounts[0], typeCounts[1], typeCounts[10], typeCounts[12], typeCounts[14]);
    std::fprintf(stderr, "UNSUPPORTED_TYPE_COUNT=%zu\n", unsupported);

    // --- locate target tensor ------------------------------------------------
    auto tv = loader.GetTensor(tensorName);
    if (!tv) {
        std::fprintf(stderr, "REAL_TENSOR=FAIL (not found)\n");
        std::fprintf(stderr, "VERDICT=FAIL\n");
        return 1;
    }
    std::fprintf(stderr, "REAL_TENSOR=PASS name=%s\n", tensorName);

    rawrxd::GGMLType gt = tv->ggml_type();
    if (gt != rawrxd::GGMLType::Q2_K) {
        std::fprintf(stderr, "TYPE=Q2_K EXPECTED got=%u\n", static_cast<uint32_t>(gt));
        std::fprintf(stderr, "VERDICT=FAIL\n");
        return 1;
    }
    std::fprintf(stderr, "TYPE=Q2_K\n");

    size_t blockElems = 0, blockBytes = 0;
    if (!RawrXD::GgufTensorBytes::payloadBytes(static_cast<uint32_t>(gt), 256, blockBytes)) {
        std::fprintf(stderr, "TYPE_GEOMETRY_QUERY=FAIL\n");
        std::fprintf(stderr, "VERDICT=FAIL\n");
        return 1;
    }
    blockElems = 256; // Q2_K is 256 weights per block
    std::fprintf(stderr, "BLOCK_BYTES=%zu VALUES_PER_BLOCK=%zu\n", blockBytes, blockElems);

    size_t rows = tv->shape().empty() ? 0 : static_cast<size_t>(tv->shape()[0]);
    size_t cols = tv->shape().size() > 1 ? static_cast<size_t>(tv->shape()[1]) : 1;
    size_t totalElems = rows * cols;
    size_t blockCount = totalElems / blockElems;
    std::fprintf(stderr, "SHAPE=%zux%zu ELEMENTS=%zu BLOCK_COUNT=%zu\n",
                 rows, cols, totalElems, blockCount);

    if (blockCount == 0) {
        std::fprintf(stderr, "BLOCK_COUNT>0=FAIL\n");
        std::fprintf(stderr, "VERDICT=FAIL\n");
        return 1;
    }
    std::fprintf(stderr, "BLOCK_COUNT>0=PASS\n");

    // --- dequantize ----------------------------------------------------------
    std::vector<float> floats;
    if (!tv->ToFloat32(floats)) {
        std::fprintf(stderr, "DEQUANT=FAIL\n");
        std::fprintf(stderr, "VERDICT=FAIL\n");
        return 1;
    }
    std::fprintf(stderr, "DEQUANT=PASS output_count=%zu expected=%zu\n",
                 floats.size(), totalElems);

    if (floats.size() != totalElems) {
        std::fprintf(stderr, "OUTPUT_VALUE_COUNT_EXACT=FAIL got=%zu want=%zu\n",
                     floats.size(), totalElems);
        std::fprintf(stderr, "VERDICT=FAIL\n");
        return 1;
    }
    std::fprintf(stderr, "OUTPUT_VALUE_COUNT_EXACT=PASS\n");

    // --- validate output -----------------------------------------------------
    size_t nanCount = 0, infCount = 0;
    bool finite = checkFinite(floats.data(), floats.size(), nanCount, infCount);
    size_t nonzero = countNonZero(floats.data(), floats.size());

    std::fprintf(stderr, "ALL_OUTPUT_FINITE=%s NAN_COUNT=%zu INF_COUNT=%zu\n",
                 finite ? "PASS" : "FAIL", nanCount, infCount);
    std::fprintf(stderr, "NONZERO_COUNT=%zu\n", nonzero);
    std::fprintf(stderr, "NONZERO_COUNT>0=%s\n", nonzero > 0 ? "PASS" : "FAIL");

    // byte coverage check: tensor byte size should equal blockCount * blockBytes
    size_t expectedBytes = blockCount * blockBytes;
    size_t actualBytes = tv->byte_size();
    std::fprintf(stderr, "DEQUANT_BYTE_COVERAGE=%s expected=%zu actual=%zu\n",
                 (actualBytes == expectedBytes) ? "PASS" : "FAIL",
                 expectedBytes, actualBytes);

    // --- sample statistics ---------------------------------------------------
    double sum = 0.0, sumSq = 0.0;
    float minv = floats.empty() ? 0.0f : floats[0];
    float maxv = minv;
    for (float v : floats) {
        sum += v; sumSq += double(v) * double(v);
        if (v < minv) minv = v;
        if (v > maxv) maxv = v;
    }
    double mean = sum / static_cast<double>(floats.size());
    double var = sumSq / static_cast<double>(floats.size()) - mean * mean;
    std::fprintf(stderr, "SAMPLE_MEAN=%.6g SAMPLE_STD=%.6g MIN=%.6g MAX=%.6g\n",
                 mean, std::sqrt(var), minv, maxv);

    bool pass = finite && nonzero > 0 && floats.size() == totalElems && actualBytes == expectedBytes;
    std::fprintf(stderr, "VERDICT=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
