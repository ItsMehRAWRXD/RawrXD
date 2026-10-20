#include "../src/deep2/QuantKernelRegistry.cpp"
#include "../src/gguf_loader.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

namespace {

struct Format {
    int type;
    const char* name;
};

uint16_t FloatToHalf(float value) {
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

float HalfToFloat(uint16_t value) {
    const uint32_t sign = static_cast<uint32_t>(value & 0x8000u) << 16;
    const uint32_t exponent = (value >> 10) & 0x1fu;
    uint32_t fraction = value & 0x03ffu;
    uint32_t bits = 0;
    if (exponent == 0) {
        if (fraction == 0) {
            bits = sign;
        } else {
            int shift = 0;
            while ((fraction & 0x0400u) == 0) {
                fraction <<= 1;
                ++shift;
            }
            fraction &= 0x03ffu;
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

uint16_t ReadU16(const uint8_t* source) {
    uint16_t value = 0;
    std::memcpy(&value, source, sizeof(value));
    return value;
}

bool CanonicalLegacyValue(const uint8_t* row, int type, size_t column,
                          float& value) {
    if (type == 0) {
        std::memcpy(&value, row + column * sizeof(float), sizeof(value));
        return true;
    }
    if (type == 1) {
        value = HalfToFloat(ReadU16(row + column * sizeof(uint16_t)));
        return true;
    }
    if (type == 30) {
        const uint32_t bits = static_cast<uint32_t>(ReadU16(
            row + column * sizeof(uint16_t))) << 16;
        std::memcpy(&value, &bits, sizeof(value));
        return true;
    }
    if (type != 2 && type != 3 && type != 6 && type != 7 &&
        type != 8 && type != 9) {
        return false;
    }

    const size_t blockIndex = column / 32;
    const size_t elementIndex = column % 32;
    const size_t blockBytes = type == 2 ? 18 : type == 3 ? 20 :
                              type == 6 ? 22 : type == 7 ? 24 :
                              type == 8 ? 34 : 36;
    const uint8_t* block = row + blockIndex * blockBytes;
    const float scale = HalfToFloat(ReadU16(block));
    const size_t pairIndex = elementIndex % 16;
    const bool upperHalf = elementIndex >= 16;
    const size_t quantOffset = type == 2 ? 2 : type == 3 ? 4 :
                               type == 6 ? 6 : type == 7 ? 8 :
                               type == 8 ? 2 : 4;
    const uint8_t* quantBytes = block + quantOffset;
    const uint8_t quantByte = quantBytes[pairIndex];

    if (type == 2) {
        const int quantized = static_cast<int>(upperHalf ? quantByte >> 4
                                                         : quantByte & 0x0f) - 8;
        value = scale * static_cast<float>(quantized);
        return true;
    }
    if (type == 3) {
        const float minimum = HalfToFloat(ReadU16(block + 2));
        const int quantized = upperHalf ? quantByte >> 4 : quantByte & 0x0f;
        value = scale * static_cast<float>(quantized) + minimum;
        return true;
    }

    uint32_t highBitsPacked = 0;
    std::memcpy(&highBitsPacked,
                block + (type == 6 ? 2 : type == 7 ? 4 : 0),
                sizeof(highBitsPacked));
    const size_t highBitShift = upperHalf ? pairIndex + 16 : pairIndex;
    const uint8_t highBit = static_cast<uint8_t>(
        (highBitsPacked >> highBitShift) & 1u);
    const int quantized = (upperHalf ? quantByte >> 4 : quantByte & 0x0f) |
                          (static_cast<int>(highBit) << 4);
    if (type == 6) {
        value = scale * static_cast<float>(quantized - 16);
    } else if (type == 7) {
        const float minimum = HalfToFloat(ReadU16(block + 2));
        value = scale * static_cast<float>(quantized) + minimum;
    } else {
        value = scale * static_cast<float>(
            reinterpret_cast<const int8_t*>(block + (type == 8 ? 2 : 4))[elementIndex]);
    }
    return true;
}

void FillBytes(std::vector<uint8_t>& bytes, int type, std::mt19937& rng) {
    std::uniform_int_distribution<int> byte(0, 255);
    for (auto& value : bytes) value = static_cast<uint8_t>(byte(rng));

    if (type == 0) {
        float* values = reinterpret_cast<float*>(bytes.data());
        for (size_t i = 0; i < bytes.size() / sizeof(float); ++i)
            values[i] = 0.01f * static_cast<float>((i % 17) + 1);
        return;
    }
    if (type == 1 || type == 30) {
        uint16_t* values = reinterpret_cast<uint16_t*>(bytes.data());
        for (size_t i = 0; i < bytes.size() / sizeof(uint16_t); ++i) {
            const float value = 0.01f * static_cast<float>((i % 17) + 1);
            values[i] = type == 1 ? FloatToHalf(value)
                                  : static_cast<uint16_t>(FloatToHalf(value) & 0xff80u);
        }
        return;
    }

    const size_t stride = Deep2::GetBlockGeometryForType(type).blockBytes;
    for (size_t offset = 0; offset < bytes.size(); offset += stride) {
        switch (type) {
        case 2: {
            auto* block = reinterpret_cast<Deep2::block_q4_0*>(bytes.data() + offset);
            block->d = FloatToHalf(0.05f);
            break;
        }
        case 3: {
            auto* block = reinterpret_cast<Deep2::block_q4_1*>(bytes.data() + offset);
            block->d = FloatToHalf(0.05f);
            block->m = FloatToHalf(0.01f);
            break;
        }
        case 6: {
            auto* block = reinterpret_cast<Deep2::block_q5_0*>(bytes.data() + offset);
            block->d = FloatToHalf(0.03f);
            break;
        }
        case 7: {
            auto* block = reinterpret_cast<Deep2::block_q5_1*>(bytes.data() + offset);
            block->d = FloatToHalf(0.03f);
            block->m = FloatToHalf(0.01f);
            break;
        }
        case 8: {
            auto* block = reinterpret_cast<Deep2::block_q8_0*>(bytes.data() + offset);
            block->d = FloatToHalf(0.02f);
            break;
        }
        case 9: {
            auto* block = reinterpret_cast<Deep2::block_q8_1*>(bytes.data() + offset);
            block->d = FloatToHalf(0.02f);
            block->s = FloatToHalf(0.1f);
            break;
        }
        case 10: {
            auto* block = reinterpret_cast<Deep2::block_q2_K*>(bytes.data() + offset);
            block->d = FloatToHalf(0.02f);
            block->dmin = FloatToHalf(0.01f);
            break;
        }
        case 11: {
            auto* block = reinterpret_cast<Deep2::block_q3_K*>(bytes.data() + offset);
            block->d = FloatToHalf(0.02f);
            break;
        }
        case 12: {
            auto* block = reinterpret_cast<Deep2::block_q4_K*>(bytes.data() + offset);
            block->d = FloatToHalf(0.02f);
            block->dmin = FloatToHalf(0.01f);
            break;
        }
        case 13: {
            auto* block = reinterpret_cast<Deep2::block_q5_K*>(bytes.data() + offset);
            block->d = FloatToHalf(0.02f);
            block->dmin = FloatToHalf(0.01f);
            break;
        }
        case 14: {
            auto* block = reinterpret_cast<Deep2::block_q6_K*>(bytes.data() + offset);
            block->d = FloatToHalf(0.02f);
            break;
        }
        case 15: {
            auto* block = reinterpret_cast<Deep2::block_q8_K*>(bytes.data() + offset);
            block->d = 0.02f;
            break;
        }
        case 16: {
            auto* block = reinterpret_cast<Deep2::block_iq2_xxs*>(bytes.data() + offset);
            block->d = FloatToHalf(0.02f);
            break;
        }
        case 17: {
            auto* block = reinterpret_cast<Deep2::block_iq2_xs*>(bytes.data() + offset);
            block->d = FloatToHalf(0.02f);
            break;
        }
        case 18: {
            auto* block = reinterpret_cast<Deep2::block_iq3_xxs*>(bytes.data() + offset);
            block->d = FloatToHalf(0.02f);
            break;
        }
        case 19: {
            auto* block = reinterpret_cast<Deep2::block_iq1_s*>(bytes.data() + offset);
            block->d = FloatToHalf(0.02f);
            break;
        }
        case 20: {
            auto* block = reinterpret_cast<Deep2::block_iq4_nl*>(bytes.data() + offset);
            block->d = FloatToHalf(0.02f);
            break;
        }
        case 21: {
            auto* block = reinterpret_cast<Deep2::block_iq3_s*>(bytes.data() + offset);
            block->d = FloatToHalf(0.02f);
            break;
        }
        case 22: {
            auto* block = reinterpret_cast<Deep2::block_iq2_s*>(bytes.data() + offset);
            block->d = FloatToHalf(0.02f);
            break;
        }
        case 23: {
            auto* block = reinterpret_cast<Deep2::block_iq4_xs*>(bytes.data() + offset);
            block->d = FloatToHalf(0.02f);
            break;
        }
        case 29: {
            auto* block = reinterpret_cast<Deep2::block_iq1_m*>(bytes.data() + offset);
            std::fill(std::begin(block->scales), std::end(block->scales), 0x55u);
            break;
        }
        default:
            break;
        }
    }
}

bool CheckFormat(const Format& format, std::mt19937& rng) {
    auto& registry = Deep2::QuantKernelRegistry::Instance();
    const Deep2::BlockGeometry geometry = registry.GetGeometry(format.type);
    const auto gemv = registry.GetGEMV(format.type);
    const auto dequant = registry.GetDequant(format.type);
    if (!gemv || !dequant || geometry.blockBytes == 0 || geometry.blockElements == 0) {
        std::printf("FORMAT=%s STATUS=FAIL REGISTRATION=missing\n", format.name);
        return false;
    }

    const size_t cols = geometry.blockElements == 1 ? 64 : geometry.blockElements;
    const size_t rows = 2;
    const size_t blocksPerRow = (cols + geometry.blockElements - 1) / geometry.blockElements;
    std::vector<uint8_t> weights(rows * blocksPerRow * geometry.blockBytes);
    FillBytes(weights, format.type, rng);
    std::vector<float> input(cols);
    for (size_t i = 0; i < cols; ++i)
        input[i] = 0.15f * std::sin(0.07f * static_cast<float>(i)) + 0.03f;

    std::vector<float> decoded(rows * cols, 0.0f);
    std::vector<float> reference(rows * cols, 0.0f);
    std::vector<float> got(rows, 0.125f);
    std::vector<float> expected(rows, 0.125f);
    dequant(weights.data(), decoded.data(), rows * cols);
    gemv(weights.data(), input.data(), got.data(), rows, cols);
    for (size_t row = 0; row < rows; ++row) {
        const size_t rowBytes = blocksPerRow * geometry.blockBytes;
        for (size_t col = 0; col < cols; ++col) {
            float canonicalValue = 0.0f;
            if (CanonicalLegacyValue(weights.data() + row * rowBytes,
                                     format.type, col, canonicalValue)) {
                reference[row * cols + col] = canonicalValue;
            } else {
                reference[row * cols + col] = decoded[row * cols + col];
            }
        }
        for (size_t col = 0; col < cols; ++col)
            expected[row] += reference[row * cols + col] * input[col];
        if (!std::isfinite(got[row]) || !std::isfinite(expected[row])) {
            std::printf("FORMAT=%s STATUS=FAIL RESULT=nonfinite\n", format.name);
            return false;
        }
        const float error = std::fabs(got[row] - expected[row]);
        if (error > 2.0e-3f * std::max(1.0f, std::fabs(expected[row]))) {
            std::printf("FORMAT=%s STATUS=FAIL MAX_ABS=%.9g GOT=%.9g EXPECTED=%.9g\n",
                        format.name, error, got[row], expected[row]);
            return false;
        }
    }
    std::printf("FORMAT=%s STATUS=PASS BLOCK_BYTES=%zu BLOCK_ELEMENTS=%zu\n",
                format.name, geometry.blockBytes, geometry.blockElements);
    return true;
}

bool CheckGenericLoader(const Format& format, std::mt19937& rng) {
    auto& registry = Deep2::QuantKernelRegistry::Instance();
    const Deep2::BlockGeometry geometry = registry.GetGeometry(format.type);
    const auto dequant = registry.GetDequant(format.type);
    const size_t elements = geometry.blockElements;
    std::vector<uint8_t> weights(geometry.blockBytes);
    FillBytes(weights, format.type, rng);
    std::vector<float> reference(elements, 0.0f);
    dequant(weights.data(), reference.data(), elements);

    rawrxd::GGUFTensorInfo info{};
    info.name = format.name;
    info.type = rawrxd::GGUFType::Float32;
    info.ggml_type = static_cast<rawrxd::GGMLType>(format.type);
    info.shape = {elements};
    info.element_size = geometry.blockBytes;
    info.block_size = elements;
    info.byte_size = weights.size();
    info.element_count = elements;
    rawrxd::GGUFTensorView view(weights.data(), info);
    std::vector<float> decoded;
    if (!view.ToFloat32(decoded) || decoded.size() != elements) {
        std::printf("GENERIC_FORMAT=%s STATUS=FAIL DECODE=false\n", format.name);
        return false;
    }
    float maxError = 0.0f;
    for (size_t index = 0; index < elements; ++index) {
        if (!std::isfinite(decoded[index])) {
            std::printf("GENERIC_FORMAT=%s STATUS=FAIL RESULT=nonfinite\n", format.name);
            return false;
        }
        maxError = std::max(maxError, std::fabs(decoded[index] - reference[index]));
    }
    const bool pass = maxError <= 1.0e-6f;
    std::printf("GENERIC_FORMAT=%s STATUS=%s MAX_ABS=%.9g\n",
                format.name, pass ? "PASS" : "FAIL", maxError);
    return pass;
}

}

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    auto& registry = Deep2::QuantKernelRegistry::Instance();
    registry.Initialize();
    const Format formats[] = {
        {0, "F32"}, {1, "F16"}, {30, "BF16"},
        {2, "Q4_0"}, {3, "Q4_1"}, {6, "Q5_0"}, {7, "Q5_1"},
        {8, "Q8_0"}, {9, "Q8_1"}, {10, "Q2_K"}, {11, "Q3_K"},
        {12, "Q4_K"}, {13, "Q5_K"}, {14, "Q6_K"}, {15, "Q8_K"},
        {16, "IQ2_XXS"}, {17, "IQ2_XS"}, {18, "IQ3_XXS"}, {19, "IQ1_S"},
        {20, "IQ4_NL"}, {21, "IQ3_S"}, {22, "IQ2_S"}, {23, "IQ4_XS"},
        {29, "IQ1_M"}
    };
    std::mt19937 rng(0x52415752u);
    size_t passed = 0;
    for (const auto& format : formats)
        if (CheckFormat(format, rng)) ++passed;
    const size_t total = sizeof(formats) / sizeof(formats[0]);
    std::printf("QUANT_REGISTRY_FORMATS=%zu\nQUANT_REGISTRY_PASSED=%zu\nVERDICT=%s\n",
                total, passed, passed == total ? "PASS" : "FAIL");
    size_t genericPassed = 0;
    for (const auto& format : formats) {
        if (format.type >= 16 && format.type <= 23) {
            if (CheckGenericLoader(format, rng)) ++genericPassed;
        } else if (format.type == 29) {
            if (CheckGenericLoader(format, rng)) ++genericPassed;
        }
    }
    const size_t genericTotal = 9;
    std::printf("GENERIC_IQ_FORMATS=%zu\nGENERIC_IQ_PASSED=%zu\nGENERIC_VERDICT=%s\n",
                genericTotal, genericPassed, genericPassed == genericTotal ? "PASS" : "FAIL");
    return passed == total && genericPassed == genericTotal ? 0 : 1;
}
