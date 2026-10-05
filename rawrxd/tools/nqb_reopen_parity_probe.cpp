// nqb_reopen_parity_probe.cpp
// RAWRXD_NQB_REAL_REOPEN_001
//
// Reopens a .nqb file written by gguf_to_nqb_converter and verifies:
//   - Header magic/version valid
//   - Tensor count matches expected
//   - Vocab section present and sized correctly
//   - Every tensor is finite (no NaN/Inf)
//   - Byte coverage exact (file size agrees with header)
//   - Per-tensor descriptive statistics for sampled tensors

#include "deep2/Nanof32BraidStreamer.hpp"
#include "rawr_build_identity_nqb_reopen_parity_probe.hpp"
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

static void tensorStats(const float* data, size_t n, float& outMin, float& outMax, double& outMean, double& outStd) {
    outMin = data[0]; outMax = data[0];
    double sum = 0.0, sumSq = 0.0;
    for (size_t i = 0; i < n; ++i) {
        float v = data[i];
        if (v < outMin) outMin = v;
        if (v > outMax) outMax = v;
        sum += v;
        sumSq += double(v) * double(v);
    }
    outMean = sum / static_cast<double>(n);
    outStd = std::sqrt(sumSq / static_cast<double>(n) - outMean * outMean);
}

int main(int argc, char** argv) {
    const char* nqbPath = (argc > 1) ? argv[1]
        : "f:\\~dev\\rawrxd\\build\\bin\\Release\\llama3.2-3b-Q2_K.nqb";
    const uint32_t expectedTensors = (argc > 2) ? static_cast<uint32_t>(std::atoi(argv[2])) : 255;

    std::fprintf(stderr, "=== RAWRXD_NQB_REAL_REOPEN_001 ===\n");
    RAWRXD_PRINT_BUILD_IDENTITY();
    std::fprintf(stderr, "NQB_PATH=%s\n", nqbPath);
    std::fprintf(stderr, "EXPECTED_TENSORS=%u\n", expectedTensors);

    Deep2::Nanof32BraidStreamer reader;
    if (!reader.open(nqbPath)) {
        std::fprintf(stderr, "FILE_OPEN=FAIL\n");
        std::fprintf(stderr, "VERDICT=FAIL\n");
        return 1;
    }
    std::fprintf(stderr, "FILE_OPEN=PASS\n");

    const Deep2::Nanof32BraidHeader* hdr = reader.header();
    if (!hdr || hdr->magic != Deep2::NANO_F32_BRAID_MAGIC || hdr->version != Deep2::NANO_F32_BRAID_VERSION) {
        std::fprintf(stderr, "HEADER_VALID=FAIL magic=0x%08X version=%u\n",
                     hdr ? hdr->magic : 0u, hdr ? hdr->version : 0u);
        std::fprintf(stderr, "VERDICT=FAIL\n");
        return 1;
    }
    std::fprintf(stderr, "HEADER_VALID=PASS magic=0x%08X version=%u\n", hdr->magic, hdr->version);
    std::fprintf(stderr, "TENSOR_COUNT=%u EXPECTED=%u\n", hdr->numTensors, expectedTensors);

    if (hdr->numTensors != expectedTensors) {
        std::fprintf(stderr, "TENSOR_COUNT_MISMATCH=FAIL\n");
        std::fprintf(stderr, "VERDICT=FAIL\n");
        return 1;
    }
    std::fprintf(stderr, "TENSOR_COUNT_MATCH=PASS\n");

    Deep2::Nanof32BraidArchMeta archMeta{};
    if (!reader.readArchMeta(archMeta)) {
        std::fprintf(stderr, "ARCH_META=FAIL\n");
        std::fprintf(stderr, "VERDICT=FAIL\n");
        return 1;
    }
    std::fprintf(stderr, "ARCH_META=PASS layers=%u hidden=%u vocab=%u\n",
                 archMeta.numLayers, archMeta.hiddenDim, archMeta.vocabSize);

    // vocab check
    if (hdr->vocabSectionOffset > 0 && hdr->vocabSectionBytes > 0) {
        std::fprintf(stderr, "VOCAB_PRESENT=PASS offset=%llu bytes=%llu\n",
                     static_cast<unsigned long long>(hdr->vocabSectionOffset),
                     static_cast<unsigned long long>(hdr->vocabSectionBytes));
    } else {
        std::fprintf(stderr, "VOCAB_PRESENT=WARN (no vocab section)\n");
    }

    std::vector<std::pair<std::string, Deep2::NQBraidBlock>> tensors;
    if (!reader.readAllTensors(tensors)) {
        std::fprintf(stderr, "TENSOR_READ=FAIL\n");
        std::fprintf(stderr, "VERDICT=FAIL\n");
        return 1;
    }
    std::fprintf(stderr, "TENSORS_READ=%zu\n", tensors.size());

    if (tensors.size() != expectedTensors) {
        std::fprintf(stderr, "TENSORS_REOPENED_MISMATCH=FAIL got=%zu want=%u\n",
                     tensors.size(), expectedTensors);
        std::fprintf(stderr, "VERDICT=FAIL\n");
        return 1;
    }
    std::fprintf(stderr, "TENSORS_REOPENED_MATCH=PASS\n");

    size_t totalNan = 0, totalInf = 0, nonFiniteTensors = 0;
    size_t sampled = 0;
    for (const auto& kv : tensors) {
        const auto& name = kv.first;
        const auto& block = kv.second;
        const size_t n = block.bf16Data.size();
        if (n == 0) continue;

        size_t nanC = 0, infC = 0;
        for (size_t i = 0; i < n; ++i) {
            float v = block.bf16Data[i].toFloat();
            if (std::isnan(v)) ++nanC;
            else if (std::isinf(v)) ++infC;
        }
        totalNan += nanC; totalInf += infC;
        if (nanC > 0 || infC > 0) ++nonFiniteTensors;

        // sample stats for first 8 and last tensor
        if (sampled < 8 || &kv == &tensors.back()) {
            float mn, mx; double mean, std;
            std::vector<float> f32;
            f32.reserve(n);
            for (const auto& bf : block.bf16Data) f32.push_back(bf.toFloat());
            tensorStats(f32.data(), f32.size(), mn, mx, mean, std);
            std::fprintf(stderr, "SAMPLE name=%s elements=%zu min=%.6g max=%.6g mean=%.6g std=%.6g\n",
                         name.c_str(), n, mn, mx, mean, std);
            ++sampled;
        }
    }

    std::fprintf(stderr, "NONFINITE_TENSORS=%zu NAN_TOTAL=%zu INF_TOTAL=%zu\n",
                 nonFiniteTensors, totalNan, totalInf);
    if (nonFiniteTensors > 0) {
        std::fprintf(stderr, "ALL_FINITE=FAIL\n");
        std::fprintf(stderr, "VERDICT=FAIL\n");
        return 1;
    }
    std::fprintf(stderr, "ALL_FINITE=PASS\n");

    // Byte coverage check via file size.
    //
    // RAWRXD_NQB_REOPEN_FTELL64_001 -- this used fseek/ftell, whose FILE offset
    // type is `long`, which is 32-bit under MSVC. On the real artifact it
    // returned -1:
    //     FILE_SIZE=-1 HEADER_FILESIZE=12857017048
    //     BYTE_COVERAGE=WARN
    // and the run still ended VERDICT=PASS, because a WARN is not a failure.
    // So the one check that could have proved the header's fileSize field was
    // true could never fire for any model over 2 GB -- which is every real
    // model. _fseeki64/_ftelli64 are the 64-bit forms.
    FILE* fp = std::fopen(nqbPath, "rb");
    if (fp) {
        if (_fseeki64(fp, 0, SEEK_END) != 0) {
            std::fprintf(stderr, "FILE_SIZE=UNAVAILABLE (_fseeki64 failed)\n");
            std::fclose(fp);
            std::fprintf(stderr, "BYTE_COVERAGE=FAIL\n");
            std::fprintf(stderr, "VERDICT=FAIL\n");
            return 1;
        }
        const long long fsize = static_cast<long long>(_ftelli64(fp));
        std::fclose(fp);
        std::fprintf(stderr, "FILE_SIZE=%lld HEADER_FILESIZE=%llu\n",
                     fsize, static_cast<unsigned long long>(hdr->fileSize));
        if (fsize > 0 && static_cast<uint64_t>(fsize) == hdr->fileSize) {
            std::fprintf(stderr, "BYTE_COVERAGE=PASS\n");
        } else {
            std::fprintf(stderr, "BYTE_COVERAGE=FAIL\n");
            std::fprintf(stderr, "VERDICT=FAIL\n");
            return 1;
        }
    } else {
        std::fprintf(stderr, "FILE_SIZE=UNREADABLE\n");
        std::fprintf(stderr, "BYTE_COVERAGE=FAIL\n");
        std::fprintf(stderr, "VERDICT=FAIL\n");
        return 1;
    }

    std::fprintf(stderr, "VERDICT=PASS\n");
    return 0;
}
