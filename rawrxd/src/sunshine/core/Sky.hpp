// Sky.hpp / Sky.cpp
// RAWRXD_SUNSHINE_SKY_002
//
// A real background instead of a flat clear colour.
//
// Drawn as a fullscreen pass BEFORE the scene with depth testing disabled. It
// reconstructs a view ray per pixel and shades it procedurally: zenith-to-
// horizon gradient, horizon glow, FBM cloud banding, and stars in the upper
// hemisphere. All of it is generated, so there are no texture assets to load and
// nothing to ship.
//
// RANDOMISATION, and why it is seeded rather than free-running
//   The variation is driven by an explicit seed uploaded per frame. Two modes:
//     * SUNSHINE_SKY_SEED set -> that seed is used verbatim, so a capture run is
//       byte-reproducible and a screenshot can be compared against another.
//     * unset -> the seed is derived from the clock, so successive live runs
//       differ.
//   The point is that the randomness is a real, controllable input rather than a
//   claim. A "random sky" that cannot be pinned cannot be regression-tested.
//
// SM4 constraints (already learned the hard way in this tree): `line` is a
// reserved HLSL word and `mix()` does not exist in ps_4_0 -- it is `lerp()`.

#pragma once

#include "RendererD3D11.hpp"
#include "Primitives.hpp"

namespace Sunshine {

struct SkyParams {
    float zenith[3]  = { 0.055f, 0.075f, 0.135f };
    float horizon[3] = { 0.150f, 0.170f, 0.215f };
    float cloud[3]   = { 0.230f, 0.245f, 0.285f };
    float glow       = 0.55f;   // strength of the horizon band
    float cloudScale = 3.10f;   // higher = finer cloud banding
    float cloudCover = 0.52f;   // 0 = clear, 1 = overcast
    float starDensity = 0.55f;
};

class Sky {
public:
    bool initialize(Renderer* renderer, const SkyParams& params);
    // timeSeconds drives cloud drift; seedOverride < 0 means "derive from clock".
    void draw(Renderer* renderer, double timeSeconds, long long seedOverride);
    void shutdown();

private:
    Renderer::Shader m_shader{};
    Mesh             m_quad{};
    ID3D11Buffer*    m_seedCB = nullptr;
    SkyParams        m_params{};
    Renderer*        m_renderer = nullptr;
    bool             m_ready  = false;
};

} // namespace Sunshine