// (Removed duplicate simple smoke; keeping single thorough test below)
#include <vector>
#include <random>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <iostream>
#include <stdexcept>

static std::vector<uint8_t> quantize_generic_bits(const std::vector<float>& in, int bits, float& outScale) {
    int n = static_cast<int>(in.size());
    float amax = 0.f;
    for (float v : in) amax = std::max(amax, std::fabs(v));
    int qmax = (1 << (bits - 1)) - 1; // symmetric
    outScale = (amax > 0.f) ? (amax / float(qmax)) : 1.f;

    int totalBits = n * bits;
    int totalBytes = (totalBits + 7) / 8;

    std::vector<uint8_t> out(4 + totalBytes, 0);
    std::memcpy(out.data(), &outScale, 4);
    uint8_t* dst = out.data() + 4;

    int bitPos = 0;
    for (int i = 0; i < n; ++i) {
        int v = int(std::round(in[i] / outScale));
        v = std::min(std::max(v, -((1 << (bits - 1)) - 0)), (1 << (bits - 1)) - 1);
        uint32_t u = (uint32_t)(v & ((1u << bits) - 1));
        int byteIdx = bitPos / 8;
        int off = bitPos % 8;
        uint64_t carry = (uint64_t)u << off;
        int need = (bits + off + 7) / 8;
        for (int b = 0; b < need; ++b) {
            dst[byteIdx + b] |= uint8_t((carry >> (8 * b)) & 0xFF);
        }
        bitPos += bits;
    }
    return out;
}

static float unpack_at(const uint8_t* data, int n, int idx, int bits, float scale) {
    if (!data || n <= 0 || idx < 0 || idx >= n || bits < 1 || bits > 8)
        throw std::out_of_range("invalid packed scalar index or bit width");
    const size_t bitPos = static_cast<size_t>(idx) * bits;
    const size_t byteIdx = bitPos / 8;
    const unsigned off = static_cast<unsigned>(bitPos % 8);
    uint32_t mask = (1u << bits) - 1u;
    uint64_t block = 0;
    // Read only the bytes occupied by this value, not an eight-byte window
    // extending beyond the final packed element.
    const size_t need = (off + bits + 7) / 8;
    const size_t payload = (static_cast<size_t>(n) * bits + 7) / 8;
    if (byteIdx > payload || need > payload - byteIdx)
        throw std::out_of_range("packed scalar exceeds payload");
    for (size_t b = 0; b < need; ++b) {
        block |= uint64_t(data[byteIdx + b]) << (8 * b);
    }
    uint32_t u = (block >> off) & mask;
    // Interpret as signed of width `bits`
    int32_t signBit = 1u << (bits - 1);
    int32_t v = (u & signBit) ? (int32_t)(u | (~int32_t(mask))) : (int32_t)u;
    return float(v) * scale;
}

int main() {
    // Seeded random input
    std::mt19937 rng(123);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    const int n = 129; // odd size to stress packing
    std::vector<float> x(n);
    for (int i = 0; i < n; ++i) x[i] = dist(rng);

    // Q5 smoke
    float s5 = 0.f;
    auto q5 = quantize_generic_bits(x, 5, s5);
    int expect5 = 4 + (n * 5 + 7) / 8;
    if ((int)q5.size() != expect5) {
        std::cerr << "Q5 size mismatch: got " << q5.size() << " expect " << expect5 << "\n";
        return 1;
    }
    // Check every position, including the final partial byte.
    const uint8_t* d5 = q5.data() + 4;
    float maxErr5 = 0.f;
    for (int i = 0; i < n; ++i) {
        float rec = unpack_at(d5, n, i, 5, s5);
        maxErr5 = std::max(maxErr5, std::fabs(rec - x[i]));
    }
    if (!(maxErr5 <= (1.25f * s5 + 1e-6f))) {
        std::cerr << "Q5 maxErr too high: " << maxErr5 << " scale " << s5 << "\n";
        return 1;
    }

    // Q6 smoke
    float s6 = 0.f;
    auto q6 = quantize_generic_bits(x, 6, s6);
    int expect6 = 4 + (n * 6 + 7) / 8;
    if ((int)q6.size() != expect6) {
        std::cerr << "Q6 size mismatch: got " << q6.size() << " expect " << expect6 << "\n";
        return 1;
    }
    const uint8_t* d6 = q6.data() + 4;
    float maxErr6 = 0.f;
    for (int i = 0; i < n; ++i) {
        float rec = unpack_at(d6, n, i, 6, s6);
        maxErr6 = std::max(maxErr6, std::fabs(rec - x[i]));
    }
    if (!(maxErr6 <= (1.25f * s6 + 1e-6f))) {
        std::cerr << "Q6 maxErr too high: " << maxErr6 << " scale " << s6 << "\n";
        return 1;
    }

    // Exercise all short tail lengths at both bit widths, with mixed signed
    // values and zero input. No overallocated padding is required by contract.
    for (int bits : {5, 6}) {
        for (int len = 1; len <= 33; ++len) {
            for (bool zero : {false, true}) {
                std::vector<float> sample(static_cast<size_t>(len));
                if (!zero) for (int i = 0; i < len; ++i)
                    sample[i] = float((i % 7) - 3) / 3.0f;
                float scale = 0.f;
                const auto packed = quantize_generic_bits(sample, bits, scale);
                for (int i = 0; i < len; ++i) {
                    const float rec = unpack_at(packed.data()+4,len,i,bits,scale);
                    if (!std::isfinite(rec) || std::fabs(rec-sample[i]) > 0.501f*scale+1e-6f)
                        return 1;
                }
            }
        }
    }
    std::cout << "quant_scalar_smoke: PASS (Q5/Q6, 132 short-tail cases)\n";
    return 0;
}
