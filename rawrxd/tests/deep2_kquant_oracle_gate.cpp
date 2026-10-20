#include "../src/deep2/QuantKernelRegistry.cpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

namespace {

constexpr uint32_t kSeed = 0x514F524Cu;

uint16_t fp32_to_fp16(float value) {
    uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    const uint32_t sign = (bits >> 16) & 0x8000u;
    int exponent = static_cast<int>((bits >> 23) & 0xffu) - 127 + 15;
    uint32_t mantissa = bits & 0x7fffffu;
    if (exponent <= 0) {
        if (exponent < -10) return static_cast<uint16_t>(sign);
        mantissa |= 0x800000u;
        mantissa >>= static_cast<uint32_t>(14 - exponent);
        return static_cast<uint16_t>(sign | (mantissa >> 13));
    }
    if (exponent >= 31) return static_cast<uint16_t>(sign | 0x7c00u);
    return static_cast<uint16_t>(sign |
                                 (static_cast<uint32_t>(exponent) << 10) |
                                 (mantissa >> 13));
}

float fp16_to_fp32(uint16_t value) {
    const uint32_t sign = static_cast<uint32_t>(value & 0x8000u) << 16;
    const uint32_t exponent = (value >> 10) & 0x1fu;
    uint32_t fraction = value & 0x3ffu;
    uint32_t bits = 0;
    if (exponent == 0) {
        if (fraction == 0) bits = sign;
        else {
            int shift = 0;
            while ((fraction & 0x400u) == 0) {
                fraction <<= 1;
                ++shift;
            }
            fraction &= 0x3ffu;
            bits = sign | (static_cast<uint32_t>(113 - shift) << 23) |
                   (fraction << 13);
        }
    } else if (exponent == 31) {
        bits = sign | 0x7f800000u | (fraction << 13);
    } else {
        bits = sign | ((exponent + 112) << 23) | (fraction << 13);
    }
    float result = 0.0f;
    std::memcpy(&result, &bits, sizeof(result));
    return result;
}

void unpack_q4_scales(const uint8_t* packed, uint8_t* scales, uint8_t* mins) {
    for (int i = 0; i < 4; ++i) {
        scales[i] = packed[i] & 0x3fu;
        mins[i] = packed[i + 4] & 0x3fu;
    }
    for (int i = 0; i < 4; ++i) {
        scales[i + 4] = (packed[i + 8] & 0x0fu) | ((packed[i] >> 6) << 4);
        mins[i + 4] = (packed[i + 8] >> 4) | ((packed[i + 4] >> 6) << 4);
    }
}

void oracle_q2(const uint8_t* weights, const float* input, float* output,
               size_t rows, size_t cols) {
    const size_t blocksPerRow = (cols + 255) / 256;
    for (size_t row = 0; row < rows; ++row) {
        const auto* blocks = reinterpret_cast<const Deep2::block_q2_K*>(weights) +
                             row * blocksPerRow;
        double sum = 0.0;
        for (size_t blockIndex = 0; blockIndex < blocksPerRow; ++blockIndex) {
            const auto& block = blocks[blockIndex];
            const float d = fp16_to_fp32(block.d);
            const float dmin = fp16_to_fp32(block.dmin);
            const size_t base = blockIndex * 256;
            const size_t limit = std::min<size_t>(256, cols - base);
            for (size_t chunk = 0; chunk < 2; ++chunk) {
                for (size_t packedGroup = 0; packedGroup < 2; ++packedGroup) {
                    for (size_t position = 0; position < 16; ++position) {
                        const uint8_t packed = block.qs[chunk * 32 + packedGroup * 16 + position];
                        for (size_t lane = 0; lane < 4; ++lane) {
                            const size_t group = packedGroup;
                            const size_t index = chunk * 128 + lane * 32 + group * 16 + position;
                            const size_t subBlock = lane;
                        const size_t element = base + index;
                        if (index >= limit) continue;
                        const uint8_t scale = block.scales[chunk * 8 + subBlock * 2 + group];
                        const float decoded = d * static_cast<float>(scale & 0x0fu) *
                                                  static_cast<float>((packed >> (subBlock * 2)) & 0x03u) -
                                              dmin * static_cast<float>(scale >> 4);
                        sum += static_cast<double>(decoded) * input[element];
                        }
                    }
                }
            }
        }
        output[row] += static_cast<float>(sum);
    }
}

void oracle_q4(const uint8_t* weights, const float* input, float* output,
               size_t rows, size_t cols) {
    const size_t blocksPerRow = (cols + 255) / 256;
    for (size_t row = 0; row < rows; ++row) {
        const uint8_t* rowBase = weights + row * blocksPerRow * sizeof(Deep2::block_q4_K);
        double sum = 0.0;
        for (size_t blockIndex = 0; blockIndex < blocksPerRow; ++blockIndex) {
            const auto* block = reinterpret_cast<const Deep2::block_q4_K*>(
                rowBase + blockIndex * sizeof(Deep2::block_q4_K));
            uint8_t scales[8] = {}, mins[8] = {};
            unpack_q4_scales(block->scales, scales, mins);
            const float d = fp16_to_fp32(block->d);
            const float dmin = fp16_to_fp32(block->dmin);
            const size_t base = blockIndex * 256;
            const size_t limit = std::min<size_t>(256, cols - base);
            for (int pair = 0; pair < 8; pair += 2) {
                const uint8_t* packed = block->qs + (pair / 2) * 32;
                for (size_t position = 0; position < 32; ++position) {
                    const size_t low = static_cast<size_t>(pair) * 32 + position;
                    const size_t high = low + 32;
                    if (low < limit)
                        sum += (d * scales[pair] * (packed[position] & 0x0fu) -
                                dmin * mins[pair]) * input[base + low];
                    if (high < limit)
                        sum += (d * scales[pair + 1] * (packed[position] >> 4) -
                                dmin * mins[pair + 1]) * input[base + high];
                }
            }
        }
        output[row] += static_cast<float>(sum);
    }
}

void oracle_q6(const uint8_t* weights, const float* input, float* output,
               size_t rows, size_t cols) {
    const size_t blocksPerRow = (cols + 255) / 256;
    for (size_t row = 0; row < rows; ++row) {
        const auto* blocks = reinterpret_cast<const Deep2::block_q6_K*>(weights) +
                             row * blocksPerRow;
        double sum = 0.0;
        for (size_t blockIndex = 0; blockIndex < blocksPerRow; ++blockIndex) {
            const auto& block = blocks[blockIndex];
            const float d = fp16_to_fp32(block.d);
            const size_t base = blockIndex * 256;
            const size_t limit = std::min<size_t>(256, cols - base);
            for (size_t half = 0; half < 2; ++half) {
                for (size_t position = 0; position < 32; ++position) {
                    const size_t qlBase = half * 64;
                    const size_t qhBase = half * 32;
                    const int q1 = (block.ql[qlBase + position] & 0x0f) |
                                   ((block.qh[qhBase + position] & 0x03) << 4);
                    const int q2 = (block.ql[qlBase + 32 + position] & 0x0f) |
                                   (((block.qh[qhBase + position] >> 2) & 0x03) << 4);
                    const int q3 = (block.ql[qlBase + position] >> 4) |
                                   (((block.qh[qhBase + position] >> 4) & 0x03) << 4);
                    const int q4 = (block.ql[qlBase + 32 + position] >> 4) |
                                   (((block.qh[qhBase + position] >> 6) & 0x03) << 4);
                    const size_t indices[] = {
                        half * 128 + position,
                        half * 128 + 32 + position,
                        half * 128 + 64 + position,
                        half * 128 + 96 + position
                    };
                    const int values[] = {q1 - 32, q2 - 32, q3 - 32, q4 - 32};
                    const size_t scaleBase = half * 8 + position / 16;
                    const size_t scales[] = {
                        scaleBase, scaleBase + 2, scaleBase + 4, scaleBase + 6
                    };
                    for (int lane = 0; lane < 4; ++lane) {
                        if (indices[lane] < limit)
                            sum += static_cast<double>(d) * block.scales[scales[lane]] *
                                   values[lane] * input[base + indices[lane]];
                    }
                }
            }
        }
        output[row] += static_cast<float>(sum);
    }
}

struct Result {
    size_t cases = 0;
    size_t mismatches = 0;
    double maxAbs = 0.0;
    double maxRel = 0.0;
};

void record(const char* name, const Result& result) {
    std::printf("%s_CASES=%zu\n%s_MISMATCHES=%zu\n%s_MAX_ABS=%.9g\n%s_MAX_REL=%.9g\n%s=%s\n",
                name, result.cases, name, result.mismatches, name, result.maxAbs,
                name, result.maxRel, name, result.mismatches == 0 ? "PASS" : "FAIL");
}

template <typename Fill, typename Oracle>
Result run_family(int type, const char* name, double relativeTolerance,
                  Fill fill, Oracle oracle, Deep2::GEMVKernelFn kernel) {
    Result result;
    std::mt19937 rng(kSeed + static_cast<uint32_t>(type));
    for (size_t cols : {256u, 512u, 1024u}) {
        for (size_t rows : {1u, 3u}) {
            const size_t blocksPerRow = (cols + 255) / 256;
            std::vector<uint8_t> weights(rows * blocksPerRow * Deep2::GetBlockGeometryForType(type).blockBytes);
            fill(weights, rng);
            std::vector<float> input(cols);
            for (size_t i = 0; i < cols; ++i)
                input[i] = 0.35f * std::sin(0.013f * static_cast<float>(i)) + 0.05f;
            std::vector<float> got(rows, 0.25f), expected(rows, 0.25f);
            kernel(weights.data(), input.data(), got.data(), rows, cols);
            oracle(weights.data(), input.data(), expected.data(), rows, cols);
            for (size_t row = 0; row < rows; ++row) {
                const double absError = std::fabs(static_cast<double>(got[row]) - expected[row]);
                const double relError = absError / std::max(1.0, std::fabs(static_cast<double>(expected[row])));
                result.maxAbs = std::max(result.maxAbs, absError);
                result.maxRel = std::max(result.maxRel, relError);
                if (!std::isfinite(got[row]) || !std::isfinite(expected[row]) ||
                    relError > relativeTolerance)
                    ++result.mismatches;
            }
            ++result.cases;
            std::printf("%s_CASE cols=%zu rows=%zu\n", name, cols, rows);
        }
    }
    return result;
}

}

int main() {
    auto& registry = Deep2::QuantKernelRegistry::Instance();
    registry.Initialize();
    const int q2 = static_cast<int>(Deep2::GGMLType::GGML_TYPE_Q2_K);
    const int q4 = static_cast<int>(Deep2::GGMLType::GGML_TYPE_Q4_K);
    const int q6 = static_cast<int>(Deep2::GGMLType::GGML_TYPE_Q6_K);
    const auto q2Kernel = registry.GetGEMV(q2);
    const auto q4Kernel = registry.GetGEMV(q4);
    const auto q6Kernel = registry.GetGEMV(q6);
    if (!q2Kernel || !q4Kernel || !q6Kernel) {
        std::printf("GATE=DEEP2_KQUANT_ORACLE_001\nVERDICT=FAIL\nMISSING_KERNEL=1\n");
        return 1;
    }

    auto fillQ2 = [](std::vector<uint8_t>& bytes, std::mt19937& rng) {
        std::uniform_int_distribution<int> byte(0, 255);
        for (auto& value : bytes) value = static_cast<uint8_t>(byte(rng));
        for (size_t offset = 0; offset < bytes.size(); offset += sizeof(Deep2::block_q2_K)) {
            auto* block = reinterpret_cast<Deep2::block_q2_K*>(bytes.data() + offset);
            block->d = fp32_to_fp16(0.01f + 0.002f * static_cast<float>(offset % 11));
            block->dmin = fp32_to_fp16(0.005f + 0.001f * static_cast<float>(offset % 7));
        }
    };
    auto fillQ4 = [](std::vector<uint8_t>& bytes, std::mt19937& rng) {
        std::uniform_int_distribution<int> byte(0, 255);
        for (auto& value : bytes) value = static_cast<uint8_t>(byte(rng));
        for (size_t offset = 0; offset < bytes.size(); offset += sizeof(Deep2::block_q4_K)) {
            auto* block = reinterpret_cast<Deep2::block_q4_K*>(bytes.data() + offset);
            block->d = fp32_to_fp16(0.01f + 0.002f * static_cast<float>(offset % 11));
            block->dmin = fp32_to_fp16(0.005f + 0.001f * static_cast<float>(offset % 7));
        }
    };
    auto fillQ6 = [](std::vector<uint8_t>& bytes, std::mt19937& rng) {
        std::uniform_int_distribution<int> byte(0, 255);
        for (auto& value : bytes) value = static_cast<uint8_t>(byte(rng));
        for (size_t offset = 0; offset < bytes.size(); offset += sizeof(Deep2::block_q6_K)) {
            auto* block = reinterpret_cast<Deep2::block_q6_K*>(bytes.data() + offset);
            block->d = fp32_to_fp16(0.01f + 0.002f * static_cast<float>(offset % 11));
        }
    };

    const Result q2Result = run_family(q2, "Q2_K", 2e-5, fillQ2, oracle_q2, q2Kernel);
    const Result q4Result = run_family(q4, "Q4_K", 2e-5, fillQ4, oracle_q4, q4Kernel);
    const Result q6Result = run_family(q6, "Q6_K", 8e-3, fillQ6, oracle_q6, q6Kernel);
    record("Q2_K", q2Result);
    record("Q4_K", q4Result);
    record("Q6_K", q6Result);
    const bool pass = q2Result.mismatches == 0 && q4Result.mismatches == 0 &&
                      q6Result.mismatches == 0;
    std::printf("GATE=DEEP2_KQUANT_ORACLE_001\nORACLE=independent_canonical_dequant_dot\n"
                "Q2_K_IMPL=%s\nQ4_K_IMPL=%s\nQ6_K_IMPL=%s\nVERDICT=%s\n",
                Deep2::KernelImplName(q2, q2Kernel),
                Deep2::KernelImplName(q4, q4Kernel),
                Deep2::KernelImplName(q6, q6Kernel), pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
