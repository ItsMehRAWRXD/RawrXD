#include "Sky.hpp"

#include <cmath>
#include <cstdlib>
#include <cstring>

namespace Sunshine {
namespace {

// cbuffer layout, 5 x float4 = 20 floats = 80 bytes:
//   seedTime : x=seed  y=time  z=cloudCover  w=starDensity
//   zenith   : rgb
//   horizon  : rgb + a=glow strength
//   cloudCol : rgb + a=cloud scale
//   tuning   : x = reserved
static const char* kSkyVS = R"(
// Fullscreen pass: the quad is authored 2x2 so position.xy is already in clip
// space. No camera matrix is involved, which is the point -- the background is
// view-independent.
struct VS_IN { float3 pos : POSITION; float2 uv : TEXCOORD0; };
struct PS_IN { float4 pos : SV_POSITION; float2 uv : TEXCOORD0; };
PS_IN main(VS_IN input) {
    PS_IN o;
    o.pos = float4(input.pos.xy, 0.0, 1.0);
    o.uv  = input.uv;
    return o;
}
)";

static const char* kSkyPS = R"(
cbuffer Sky : register(b2) {
    float4 seedTime;   // x=seed y=time z=cloudCover w=starDensity
    float4 zenith;     // rgb
    float4 horizon;    // rgb, a = glow strength
    float4 cloudCol;   // rgb, a = cloud scale
    float4 tuning;     // reserved
};
struct PS_IN { float4 pos : SV_POSITION; float2 uv : TEXCOORD0; };

float hash21(float2 p) {
    return frac(sin(dot(p, float2(127.1, 311.7))) * 43758.5453123);
}
float vnoise(float2 p) {
    float2 i = floor(p);
    float2 f = frac(p);
    float2 u = f * f * (3.0 - 2.0 * f);
    float a = hash21(i);
    float b = hash21(i + float2(1.0, 0.0));
    float c = hash21(i + float2(0.0, 1.0));
    float d = hash21(i + float2(1.0, 1.0));
    return lerp(lerp(a, b, u.x), lerp(c, d, u.x), u.y);
}
float fbm(float2 p) {
    float v = 0.0;
    float amp = 0.5;
    for (int i = 0; i < 4; ++i) {
        v += vnoise(p) * amp;
        p *= 2.03;
        amp *= 0.5;
    }
    return v;
}

float4 main(PS_IN input) : SV_TARGET {
    // Reconstruct a view ray. The fixed 1.0 forward term is a narrow FOV, which
    // is adequate for a background and avoids a real inverse-projection.
    float2 ndc = input.uv * 2.0 - 1.0;
    float3 dir = normalize(float3(ndc.x, ndc.y, 1.0));

    float sd = seedTime.x;
    float t  = seedTime.y;
    float cover = seedTime.z;
    float starD = seedTime.w;

    // ---- vertical gradient -------------------------------------------------
    float up = saturate(dir.y);
    float3 col = lerp(horizon.rgb, zenith.rgb, pow(up, 0.62));

    // ---- horizon glow ------------------------------------------------------
    float band = 1.0 - saturate(abs(dir.y) * 5.5);
    col += horizon.rgb * horizon.a * band * band;

    // ---- stars, upper hemisphere only --------------------------------------
    if (dir.y > 0.02) {
        float2 sc = floor(dir.xy * 190.0 / max(dir.z, 0.35));
        float r = hash21(sc + sd * 13.0);
        float star = step(0.9965 - starD * 0.010, r);
        float tw = 0.65 + 0.35 * sin(t * 2.1 + r * 40.0);
        col += float3(0.85, 0.90, 1.00) * star * tw * up * 0.9;
    }

    // ---- FBM cloud banding -------------------------------------------------
    // Projected onto the dome so bands compress toward the horizon; that
    // compression is what gives the flat gradient a sense of depth.
    float2 cp = dir.xy / max(dir.z, 0.22);
    float2 drift = float2(t * 0.013, t * 0.007);
    float f = fbm(cp * cloudCol.a + drift + sd * 7.31);
    float dens = saturate((f - (1.0 - cover)) * 2.35);
    dens *= smoothstep(-0.02, 0.30, dir.y);   // no clouds below the horizon
    float3 lit = cloudCol.rgb * (0.72 + 0.55 * saturate(dir.y));
    col = lerp(col, lit, dens * 0.80);

    // ---- ground haze below the horizon -------------------------------------
    col = lerp(col, horizon.rgb * 0.55, saturate(-dir.y * 3.2));

    return float4(saturate(col), 1.0);
}
)";

} // namespace

bool Sky::initialize(Renderer* renderer, const SkyParams& params) {
    if (m_ready) return true;
    if (!renderer) return false;
    m_renderer = renderer;
    m_params = params;

    // 2x2 quad so position.xy lands exactly in clip space [-1,1].
    m_quad = makeQuadMesh(renderer, 2.0f, 2.0f);
    if (!m_quad.vertexBuffer || !m_quad.indexBuffer) return false;

    D3D11_INPUT_ELEMENT_DESC layout[] = {
        {"POSITION", 0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 0, D3D11_INPUT_PER_VERTEX_DATA, 0},
        {"TEXCOORD", 0, DXGI_FORMAT_R32G32_FLOAT,    0, 12, D3D11_INPUT_PER_VERTEX_DATA, 0},
    };
    if (!renderer->compileShader(kSkyVS, kSkyPS, layout, 2, &m_shader)) return false;

    // 5 x float4, matching the cbuffer exactly. Allocating 16 here would leave
    // the last float4 undefined and the shader would read garbage.
    m_seedCB = renderer->createConstantBuffer(sizeof(float) * 20);
    if (!m_seedCB) return false;

    m_ready = true;
    return true;
}

void Sky::draw(Renderer* renderer, double timeSeconds, long long seedOverride) {

    long long seed = seedOverride;
    if (seed < 0) {
        if (const char* e = std::getenv("SUNSHINE_SKY_SEED")) {
            seed = std::atoll(e);                                       // pinned
        } else {
            seed = (long long)(timeSeconds * 1000.0) ^ 0x5DEECE66Dull;   // live
        }
    }

    float data[20] = {0};
    data[0]  = (float)((seed % 9973) / 9973.0);  // seed, normalised to 0..1
    data[1]  = (float)timeSeconds;
    data[2]  = m_params.cloudCover;
    data[3]  = m_params.starDensity;

    data[4]  = m_params.zenith[0];  data[5]  = m_params.zenith[1];  data[6]  = m_params.zenith[2];

    data[8]  = m_params.horizon[0]; data[9]  = m_params.horizon[1]; data[10] = m_params.horizon[2];
    data[11] = m_params.glow;

    data[12] = m_params.cloud[0];   data[13] = m_params.cloud[1];   data[14] = m_params.cloud[2];
    data[15] = m_params.cloudScale;

    renderer->getContext()->UpdateSubresource(m_seedCB, 0, nullptr, data, 0, 0);
    renderer->setConstantBuffer(2, m_seedCB);

    renderer->setShader(&m_shader);
    renderer->setDepthDisabled();   // drawn first; must not be depth-rejected
    // The fullscreen quad is authored CCW in screen space, while the scene
    // rasterizer sets FrontCounterClockwise = FALSE (CW is the front face). The
    // sky quad is therefore back-face culled and renders nothing at all, which
    // looks exactly like "the sky pass silently does nothing". Culling is
    // disabled for this draw and restored immediately afterwards.
    renderer->setCullNone();
    drawMesh(renderer, &m_quad);
    renderer->setCullBack();
    renderer->setDepthEnabled();    // restore for the scene
}

void Sky::shutdown() {
    if (m_seedCB) { m_seedCB->Release(); m_seedCB = nullptr; }
    if (m_renderer) m_renderer->releaseShader(&m_shader);
    releaseMesh(&m_quad);
    m_renderer = nullptr;
    m_ready = false;
}

} // namespace Sunshine