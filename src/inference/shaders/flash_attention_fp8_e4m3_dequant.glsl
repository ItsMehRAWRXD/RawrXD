// ============================================================================
// flash_attention_fp8_e4m3_dequant.glsl — Reference E4M3 → float32 (GLSL 450)
// ============================================================================
// Compile to SPIR-V with glslangValidator. Intended to mirror host
// RawrXD::Quantization::SovereignFP8Quantizer E4M3 decode (OCP: exp=15,mant=7 => NaN).
// Accumulate in fp32 after dequant; WMMA / native FP8 is a separate fast path once
// validated against this reference in your RDNA3 pipeline.
// ============================================================================

#version 450

const uint FP8_E4M3_BIAS = 7u;

float e4m3_u8_to_f32(uint u8)
{
    const uint u = u8 & 0xFFu;
    const uint sign = (u >> 7u) & 1u;
    const uint exp = (u >> 3u) & 0xFu;
    const uint mant = u & 7u;

    if (exp == 15u && mant == 7u)
    {
        return uintBitsToFloat(0x7fc00000u);
    }

    if (exp == 0u)
    {
        if (mant == 0u)
        {
            return sign != 0u ? -0.0f : 0.0f;
        }
        const float v = float(mant) / 8.0f * exp2(-6.0f);
        return (sign != 0u) ? -v : v;
    }

    const int exp32 = int(exp) - int(FP8_E4M3_BIAS) + 127;
    const uint mant32 = mant << 20;
    const uint bits = (sign << 31) | (uint(exp32) << 23) | mant32;
    return uintBitsToFloat(bits);
}

// Example: unpack one byte from a packed SSBO u32 lane (thread supplies byte index 0..3).
float dequant_e4m3_byte(uint packed_u32, uint byte_idx, float inv_scale)
{
    const uint shift = byte_idx * 8u;
    const uint u8 = bitfieldExtract(packed_u32, int(shift), 8);
    return e4m3_u8_to_f32(u8) * inv_scale;
}
