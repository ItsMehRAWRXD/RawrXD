// ============================================================================
// Noise.hpp — the deterministic noise fields the terrain is built from.
//
// Written from scratch. The noise is value noise with a quintic fade, which
// is smooth enough that the terrain has no visible grid, and cheap enough
// that a chunk of 16x16 columns costs nothing to generate.
//
// The important property is determinism: the same seed and the same
// coordinates always give the same value, in this build and in any other.
// The world must be reproducible or the frame capture and the certification
// receipts would mean nothing.
// ============================================================================

#pragma once

#include <cstdint>

#include "Math.hpp"

namespace sunshine {

// A single octave of value noise.
//
// The lattice values are drawn from the integer hash rather than from a
// table, so there is no state and no table to keep in sync.
inline float valueNoise2D(float x, float y, uint32_t seed) {
    const int32_t xi = static_cast<int32_t>(std::floor(x));
    const int32_t yi = static_cast<int32_t>(std::floor(y));
    const float xf = x - static_cast<float>(xi);
    const float yf = y - static_cast<float>(yi);

    const float u = smoothstep(xf);
    const float v = smoothstep(yf);

    const float n00 = hashUnit(xi, 0, yi, seed);
    const float n10 = hashUnit(xi + 1, 0, yi, seed);
    const float n01 = hashUnit(xi, 0, yi + 1, seed);
    const float n11 = hashUnit(xi + 1, 0, yi + 1, seed);

    const float nx0 = n00 + (n10 - n00) * u;
    const float nx1 = n01 + (n11 - n01) * u;
    return nx0 + (nx1 - nx0) * v;
}

// The same noise summed over several octaves.
//
// The octaves double in frequency and halve in amplitude, which keeps the
// total in range while adding the fine detail that makes the surface look
// like a surface instead of a set of rolling hills.
inline float fbm2D(float x, float y, uint32_t seed, int octaves, float lacunarity = 2.0f,
                    float gain = 0.5f) {
    float sum = 0.0f;
    float amplitude = 1.0f;
    float frequency = 1.0f;
    float normalizer = 0.0f;

    for (int i = 0; i < octaves; ++i) {
        sum += valueNoise2D(x * frequency, y * frequency, seed + static_cast<uint32_t>(i) * 0x9E37U) * amplitude;
        normalizer += amplitude;
        amplitude *= gain;
        frequency *= lacunarity;
    }
    return normalizer > 1e-8f ? sum / normalizer : 0.0f;
}

// Three-dimensional value noise, used for the cave fields.
inline float valueNoise3D(float x, float y, float z, uint32_t seed) {
    const int32_t xi = static_cast<int32_t>(std::floor(x));
    const int32_t yi = static_cast<int32_t>(std::floor(y));
    const int32_t zi = static_cast<int32_t>(std::floor(z));
    const float xf = x - static_cast<float>(xi);
    const float yf = y - static_cast<float>(yi);
    const float zf = z - static_cast<float>(zi);

    const float u = smoothstep(xf);
    const float v = smoothstep(yf);
    const float w = smoothstep(zf);

    const auto n = [&](int32_t dx, int32_t dy, int32_t dz) {
        return hashUnit(xi + dx, yi + dy, zi + dz, seed);
    };

    const float c000 = n(0, 0, 0), c100 = n(1, 0, 0);
    const float c010 = n(0, 1, 0), c110 = n(1, 1, 0);
    const float c001 = n(0, 0, 1), c101 = n(1, 0, 1);
    const float c011 = n(0, 1, 1), c111 = n(1, 1, 1);

    const float x00 = c000 + (c100 - c000) * u;
    const float x10 = c010 + (c110 - c010) * u;
    const float x01 = c001 + (c101 - c001) * u;
    const float x11 = c011 + (c111 - c011) * u;

    const float y0 = x00 + (x10 - x00) * v;
    const float y1 = x01 + (x11 - x01) * v;
    return y0 + (y1 - y0) * w;
}

// Three-dimensional fractal noise, used for the caves.
inline float fbm3D(float x, float y, float z, uint32_t seed, int octaves) {
    float sum = 0.0f;
    float amplitude = 1.0f;
    float frequency = 1.0f;
    float normalizer = 0.0f;

    for (int i = 0; i < octaves; ++i) {
        sum += valueNoise3D(x * frequency, y * frequency, z * frequency,
                            seed + static_cast<uint32_t>(i) * 0x85EBCU) * amplitude;
        normalizer += amplitude;
        amplitude *= 0.5f;
        frequency *= 2.0f;
    }
    return normalizer > 1e-8f ? sum / normalizer : 0.0f;
}

// A ridge field, used for the mountain ranges. The absolute value of the
// noise is folded, which turns smooth hills into sharp crests.
inline float ridge2D(float x, float y, uint32_t seed, int octaves) {
    float sum = 0.0f;
    float amplitude = 1.0f;
    float frequency = 1.0f;
    float normalizer = 0.0f;

    for (int i = 0; i < octaves; ++i) {
        const float n = valueNoise2D(x * frequency, y * frequency, seed + static_cast<uint32_t>(i) * 0x27D4U);
        const float r = 1.0f - std::fabs(n * 2.0f - 1.0f);
        sum += r * r * amplitude;
        normalizer += amplitude;
        amplitude *= 0.5f;
        frequency *= 2.0f;
    }
    return normalizer > 1e-8f ? sum / normalizer : 0.0f;
}

} // namespace sunshine
