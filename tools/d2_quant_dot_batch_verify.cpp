#include "src/deep2/quant_dot_dispatch.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <vector>

namespace {

float CpuQ4(const uint8_t* row, const void* q8_ptr, size_t) {
    const float* q8 = static_cast<const float*>(q8_ptr);
    int32_t lanes[8] = {};
    int32_t min_sum = 0;
    for (int group = 0; group < 8; ++group) {
        int scale = 0;
        int minv = 0;
        if (group < 4) {
            scale = row[4 + group] & 63;
            minv = row[8 + group] & 63;
        } else {
            scale = (row[8 + group] & 15) | ((row[group] >> 6) << 4);
            minv = (row[8 + group] >> 4) | ((row[4 + group] >> 6) << 4);
        }
        const uint8_t* qs = row + 16 + (group / 2) * 32;
        const bool high = (group & 1) != 0;
        for (int i = 0; i < 32; ++i) {
            const int weight = high ? (qs[i] >> 4) : (qs[i] & 15);
            lanes[i & 7] += scale * weight * static_cast<int>(q8[1 + group * 32 + i]);
        }
        min_sum += minv * static_cast<int>(q8[257 + group * 2]) +
                   minv * static_cast<int>(q8[257 + group * 2 + 1]);
    }
    uint16_t d_bits = 0;
    uint16_t dmin_bits = 0;
    std::memcpy(&d_bits, row, sizeof(d_bits));
    std::memcpy(&dmin_bits, row + 2, sizeof(dmin_bits));
    const auto half = [](uint16_t bits) {
        const uint32_t sign = uint32_t(bits & 0x8000u) << 16;
        const uint32_t exp = (bits >> 10) & 31u;
        const uint32_t frac = bits & 1023u;
        uint32_t out = 0;
        if (exp == 0) {
            if (frac == 0) {
                out = sign;
            } else {
                uint32_t mantissa = frac;
                int exponent = -14;
                while ((mantissa & 1024u) == 0) {
                    mantissa <<= 1;
                    --exponent;
                }
                out = sign | (uint32_t(exponent + 127) << 23) |
                      ((mantissa & 1023u) << 13);
            }
        } else if (exp == 31) {
            out = sign | 0x7f800000u | (frac << 13);
        } else {
            out = sign | ((exp + 112u) << 23) | (frac << 13);
        }
        float value = 0.0f;
        std::memcpy(&value, &out, sizeof(value));
        return value;
    };
    const float d = half(d_bits) * q8[0];
    const float dmin = half(dmin_bits) * q8[0];
    float result = -dmin * static_cast<float>(min_sum);
    for (int lane : lanes) result += d * static_cast<float>(lane);
    return result;
}

void Fail(const char* message) {
    std::printf("D2_BATCH_FAIL: %s\n", message);
    std::exit(1);
}

} // namespace

int main() {
    using RawrXD::Deep2::QuantDot::BatchCapacity;
    using RawrXD::Deep2::QuantDot::BeginBatch;
    using RawrXD::Deep2::QuantDot::CpuDot;
    using RawrXD::Deep2::QuantDot::DotBlocked;
    using RawrXD::Deep2::QuantDot::EndBatch;

    constexpr size_t n_in = 256;
    constexpr size_t n_out = 8;
    std::vector<uint8_t> weights(n_out * 144, 0);
    for (size_t row = 0; row < n_out; ++row) {
        uint8_t* packed = weights.data() + row * 144;
        const uint16_t d = 0x2c00;
        std::memcpy(packed, &d, sizeof(d));
        for (size_t i = 0; i < 12; ++i) packed[4 + i] = static_cast<uint8_t>(1 + ((row + i) % 8));
        for (size_t i = 0; i < 128; ++i) packed[16 + i] = static_cast<uint8_t>((row * 17 + i * 5) & 0xff);
    }
    std::vector<float> x(n_in, 0.25f);
    std::vector<float> q8(273, 0.0f);
    q8[0] = 0.03125f;
    for (size_t i = 0; i < 256; ++i) q8[1 + i] = static_cast<float>((int(i * 13) % 127) - 63);
    for (size_t group = 0; group < 16; ++group) {
        float sum = 0.0f;
        for (size_t i = 0; i < 16; ++i) sum += q8[1 + group * 16 + i];
        q8[257 + group] = sum;
    }
    std::vector<float> q8_scaled = q8;
    for (size_t i = 1; i < q8_scaled.size(); ++i) q8_scaled[i] *= 0.5f;
    CpuDot cpu = CpuQ4;

    std::vector<float> single(n_out, 0.0f);
    if (!DotBlocked(0, weights.data(), weights.size(), x.data(), n_in, single.data(), n_out,
                    cpu, q8.data(), q8.size() * sizeof(float), false))
        return 2;

    std::vector<float> batched(n_out, 0.0f);
    if (!BeginBatch()) return 2;
    const bool queued = DotBlocked(0, weights.data(), weights.size(), x.data(), n_in,
                                   batched.data(), n_out, cpu, q8.data(),
                                   q8.size() * sizeof(float), false);
    if (!queued || !EndBatch()) Fail("single-entry batch did not submit");
    if (std::memcmp(single.data(), batched.data(), single.size() * sizeof(float)) != 0)
        Fail("single-entry batch was not bit-identical");

    std::vector<float> second(n_out, 0.0f);
    std::vector<float> two_a(n_out, 0.0f), two_b(n_out, 0.0f);
    if (!DotBlocked(0, weights.data(), weights.size(), x.data(), n_in, second.data(), n_out,
                    cpu, q8_scaled.data(), q8_scaled.size() * sizeof(float), false))
        return 2;
    if (!BeginBatch()) Fail("two-entry batch could not begin");
    const bool two_queued =
        DotBlocked(0, weights.data(), weights.size(), x.data(), n_in, two_a.data(), n_out,
                   cpu, q8.data(), q8.size() * sizeof(float), false) &&
        DotBlocked(0, weights.data(), weights.size(), x.data(), n_in, two_b.data(), n_out,
                   cpu, q8_scaled.data(), q8_scaled.size() * sizeof(float), false);
    if (!two_queued || !EndBatch()) Fail("two-entry batch did not submit");
    if (std::memcmp(single.data(), two_a.data(), single.size() * sizeof(float)) != 0 ||
        std::memcmp(second.data(), two_b.data(), second.size() * sizeof(float)) != 0)
        Fail("two-entry batch was not bit-identical");

    const size_t capacity = BatchCapacity();
    if (capacity < 2) Fail("invalid reported batch capacity");
    std::vector<std::vector<float>> overflow(capacity + 1, std::vector<float>(n_out, 0.0f));
    if (!BeginBatch()) Fail("overflow batch could not begin");
    for (size_t i = 0; i < overflow.size(); ++i) {
        if (!DotBlocked(0, weights.data(), weights.size(), x.data(), n_in, overflow[i].data(), n_out,
                        cpu, q8.data(), q8.size() * sizeof(float), false))
            Fail("valid dot was rejected before batch capacity");
    }
    if (EndBatch()) Fail("over-capacity batch did not fail closed");
    if (!BeginBatch() || !EndBatch()) Fail("backend batch state was not recovered");
    const float expected_cpu = CpuQ4(weights.data(), q8.data(), 0);
    for (const auto& output : overflow) {
        if (output[0] != expected_cpu) Fail("failed batch did not replay through CPU");
    }

    std::printf("D2_BATCH_RESULT: PASS capacity=%zu single_entries=1 two_entries=2 overflow_recovery=1\n",
                capacity);
    return 0;
}
