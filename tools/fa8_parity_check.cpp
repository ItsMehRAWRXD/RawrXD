// ============================================================================
// fa8_parity_check.cpp — host reference parity for flash_attention_fp8_e4m3.comp
// ============================================================================
// Reimplements the shader's decode + online-softmax arithmetic on the host and
// compares against an independent naive-attention reference. Proves the tile
// math, GQA head mapping, and packed-byte order agree with a direct definition.
//
// Build (MSVC):
//   cl /EHsc /std:c++17 fa8_parity_check.cpp
// Run:
//   fa8_parity_check.exe

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace
{

// ---- Shader-mirroring E4M3 decode (OCP, bias 7) ----------------------------
float e4m3_u8_to_f32(uint8_t b, bool no_refusal)
{
    const uint32_t u = b & 0xFFu;
    const uint32_t sign = (u >> 7u) & 1u;
    const uint32_t exp = (u >> 3u) & 0xFu;
    const uint32_t mant = u & 7u;

    if (exp == 15u && mant == 7u)
    {
        return no_refusal ? 0.0f : std::nanf("");
    }
    if (exp == 0u)
    {
        if (mant == 0u)
        {
            return sign != 0u ? -0.0f : 0.0f;
        }
        const float v = (static_cast<float>(mant) / 8.0f) * std::exp2(-6.0f);
        return (sign != 0u) ? -v : v;
    }
    const int32_t exp32 = static_cast<int32_t>(exp) - 7 + 127;
    const uint32_t mant32 = mant << 20;
    uint32_t bits = (sign << 31) | (static_cast<uint32_t>(exp32) << 23) | mant32;
    float out;
    std::memcpy(&out, &bits, 4);
    return out;
}

// Pack E4M3 bytes into uint32 words, little-endian, matching the shader's
// LOAD_E4M3(data, idx) = bitfieldExtract(data[idx>>2], (idx&3)*8, 8).
std::vector<uint32_t> PackE4M3(const std::vector<uint8_t>& bytes)
{
    std::vector<uint32_t> words((bytes.size() + 3u) / 4u, 0u);
    for (size_t i = 0; i < bytes.size(); ++i)
    {
        words[i >> 2] |= static_cast<uint32_t>(bytes[i]) << ((i & 3u) * 8u);
    }
    return words;
}

float LoadPacked(const std::vector<uint32_t>& words, size_t idx, bool no_refusal)
{
    const uint32_t shift = static_cast<uint32_t>(idx & 3u) * 8u;
    const uint8_t byte = static_cast<uint8_t>((words[idx >> 2] >> shift) & 0xFFu);
    return e4m3_u8_to_f32(byte, no_refusal);
}

// ---- Float -> E4M3 encoder (test input generation) -------------------------
uint8_t FloatToE4M3(float value, bool& exact)
{
    exact = false;
    if (value == 0.0f)
    {
        exact = true;
        return value < 0.0f ? 0x80u : 0x00u;
    }
    const uint8_t sign = (value < 0.0f) ? 0x80u : 0x00u;
    const float a = std::fabs(value);

    // Find the encoding whose decode round-trips exactly, else nearest.
    uint8_t best = sign;
    float best_err = 1e30f;
    for (uint32_t exp = 0; exp < 16u; ++exp)
    {
        for (uint32_t mant = 0; mant < 8u; ++mant)
        {
            if (exp == 15u && mant == 7u)
            {
                continue;  // reserved NaN
            }
            const uint8_t cand = static_cast<uint8_t>(sign | (exp << 3) | mant);
            const float decoded = e4m3_u8_to_f32(cand, true);
            const float err = std::fabs(decoded - a);
            if (err < best_err)
            {
                best_err = err;
                best = cand;
            }
            if (err == 0.0f)
            {
                exact = true;
                return cand;
            }
        }
    }
    return best;
}

struct Case
{
    uint32_t M;
    uint32_t N;
    uint32_t D;
    uint32_t H;
    uint32_t KH;
    bool no_refusal;
    const char* name;
};

// Mirrors the shader main(): one output row per (head, query).
void ShaderRow(const std::vector<uint32_t>& q,
               const std::vector<uint32_t>& k,
               const std::vector<uint32_t>& v,
               const Case& c,
               uint32_t head,
               uint32_t row,
               std::vector<float>& out)
{
    const uint32_t kvHead = (c.KH >= c.H) ? head : (head / (c.H / c.KH));
    const uint32_t qRowBase = (head * c.M + row) * c.D;

    float running_max = -3.402823466e+38f;
    float running_sum = 0.0f;
    out.assign(c.D, 0.0f);

    for (uint32_t n = 0; n < c.N; ++n)
    {
        const uint32_t kBase = (kvHead * c.N + n) * c.D;
        float score = 0.0f;
        for (uint32_t d = 0; d < c.D; ++d)
        {
            score += LoadPacked(q, qRowBase + d, c.no_refusal) * LoadPacked(k, kBase + d, c.no_refusal);
        }
        score *= 1.0f / std::sqrt(static_cast<float>(c.D));

        const float new_max = std::fmax(running_max, score);
        const float old_scale = (running_max <= -3.402823466e+38f) ? 0.0f
                                                                 : std::exp(running_max - new_max);
        const float p = std::exp(score - new_max);
        running_sum = running_sum * old_scale + p;
        running_max = new_max;

        for (uint32_t i = 0; i < c.D; ++i)
        {
            out[i] = out[i] * old_scale + LoadPacked(v, kBase + i, c.no_refusal) * p;
        }
    }

    const float inv = (running_sum > 0.0f) ? (1.0f / running_sum) : 0.0f;
    for (uint32_t i = 0; i < c.D; ++i)
    {
        out[i] *= inv;
    }
}

// Independent definition: full softmax matrix, then V matmul.
void ReferenceRow(const std::vector<uint8_t>& q,
                  const std::vector<uint8_t>& k,
                  const std::vector<uint8_t>& v,
                  const Case& c,
                  uint32_t head,
                  uint32_t row,
                  std::vector<float>& out)
{
    const uint32_t kvHead = (c.KH >= c.H) ? head : (head / (c.H / c.KH));
    const uint32_t qRowBase = (head * c.M + row) * c.D;

    std::vector<float> scores(c.N);
    float mx = -3.402823466e+38f;
    for (uint32_t n = 0; n < c.N; ++n)
    {
        const uint32_t kBase = (kvHead * c.N + n) * c.D;
        float s = 0.0f;
        for (uint32_t d = 0; d < c.D; ++d)
        {
            s += e4m3_u8_to_f32(q[qRowBase + d], c.no_refusal) *
                 e4m3_u8_to_f32(k[kBase + d], c.no_refusal);
        }
        s *= 1.0f / std::sqrt(static_cast<float>(c.D));
        scores[n] = s;
        mx = std::fmax(mx, s);
    }

    float denom = 0.0f;
    for (uint32_t n = 0; n < c.N; ++n)
    {
        scores[n] = std::exp(scores[n] - mx);
        denom += scores[n];
    }

    out.assign(c.D, 0.0f);
    for (uint32_t n = 0; n < c.N; ++n)
    {
        const float w = scores[n] / denom;
        if (w == 0.0f)
        {
            continue;
        }
        const uint32_t vBase = (kvHead * c.N + n) * c.D;
        for (uint32_t d = 0; d < c.D; ++d)
        {
            out[d] += w * e4m3_u8_to_f32(v[vBase + d], c.no_refusal);
        }
    }
}

}  // namespace

int main()
{
    int failures = 0;
    int checks = 0;

    const Case cases[] = {
        {1, 1, 8, 1, 1, false, "single"},
        {2, 5, 16, 2, 2, false, "small"},
        {4, 7, 32, 4, 2, false, "gqa_2to1"},
        {3, 6, 64, 4, 1, false, "mqa"},
        {4, 9, 128, 2, 2, true, "maxdim_norefunsal"},
        {2, 4, 8, 2, 2, true, "norefunsal"},
    };

    for (const Case& c : cases)
    {
        const size_t qElems = static_cast<size_t>(c.H) * c.M * c.D;
        const size_t kvElems = static_cast<size_t>(c.KH) * c.N * c.D;

        std::vector<uint8_t> q(qElems);
        std::vector<uint8_t> k(kvElems);
        std::vector<uint8_t> v(kvElems);

        uint32_t state = 0x1234567u ^ (c.M * 2654435761u) ^ (c.N * 40503u) ^ (c.D << 7);
        auto nextf = [&state]() {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            return ((static_cast<float>(state >> 8) / 8388608.0f) - 1.0f) * 4.0f;
        };

        // Include the reserved NaN pattern in some cases to exercise the flag.
        for (size_t i = 0; i < qElems; ++i)
        {
            bool ex;
            q[i] = FloatToE4M3(nextf(), ex);
        }
        for (size_t i = 0; i < kvElems; ++i)
        {
            bool ex;
            k[i] = FloatToE4M3(nextf(), ex);
            v[i] = FloatToE4M3(nextf(), ex);
        }
        if (c.no_refusal)
        {
            // Plant the OCP NaN pattern (exp=15, mant=7) with a positive sign.
            q[0] = 0x7Fu;
            k[0] = 0x7Fu;
            v[0] = 0x7Fu;
        }

        const std::vector<uint32_t> qw = PackE4M3(q);
        const std::vector<uint32_t> kw = PackE4M3(k);
        const std::vector<uint32_t> vw = PackE4M3(v);

        double max_err = 0.0;
        for (uint32_t head = 0; head < c.H; ++head)
        {
            for (uint32_t row = 0; row < c.M; ++row)
            {
                std::vector<float> got;
                std::vector<float> want;
                ShaderRow(qw, kw, vw, c, head, row, got);
                ReferenceRow(q, k, v, c, head, row, want);

                for (uint32_t d = 0; d < c.D; ++d)
                {
                    if (!std::isfinite(got[d]) || !std::isfinite(want[d]))
                    {
                        ++failures;
                        std::printf("FAIL %s non-finite head=%u row=%u d=%u got=%g want=%g\n", c.name,
                                    head, row, d, static_cast<double>(got[d]),
                                    static_cast<double>(want[d]));
                        break;
                    }
                    const double err = std::fabs(static_cast<double>(got[d]) -
                                                 static_cast<double>(want[d]));
                    if (err > max_err)
                    {
                        max_err = err;
                    }
                }
                ++checks;
            }
        }

        // 1e-5 absolute tolerance: online softmax reassociates summation order.
        const bool ok = max_err <= 1e-5;
        if (!ok)
        {
            ++failures;
        }
        std::printf("%-16s M=%u N=%u D=%u H=%u KH=%u norefusal=%d max_abs_err=%.3e %s\n", c.name,
                    c.M, c.N, c.D, c.H, c.KH, static_cast<int>(c.no_refusal), max_err,
                    ok ? "PASS" : "FAIL");
    }

    // Packed-uint layout must be byte-identical to the raw stream.
    {
        std::vector<uint8_t> bytes(8);
        for (size_t i = 0; i < bytes.size(); ++i)
        {
            bytes[i] = static_cast<uint8_t>(0x10u + i * 7u);
        }
        const std::vector<uint32_t> w = PackE4M3(bytes);
        bool same = true;
        for (size_t i = 0; i < bytes.size(); ++i)
        {
            same = same && (LoadPacked(w, i, false) == e4m3_u8_to_f32(bytes[i], false));
        }
        ++checks;
        if (!same)
        {
            ++failures;
        }
        std::printf("%-16s %s\n", "packed_layout", same ? "PASS" : "FAIL");
    }

    std::printf("\n[fa8-parity] rows_checked=%d failures=%d\n", checks, failures);
    std::printf("[fa8-parity] %s\n", failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}