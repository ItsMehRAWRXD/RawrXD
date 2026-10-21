// ============================================================================
// VoxelShaders.hpp - the renderer's HLSL, compiled at runtime.
//
// The shaders are carried as source and compiled with D3DCompile at start-up.
// Nothing is checked in as a binary blob, there is no shader build step, and
// there is no third-party shader compiler in the loop: d3dcompiler.dll ships
// with Windows and is part of the platform boundary.
//
// The vertex layout the shaders consume is exactly the 32-byte VoxelVertex:
//   POSITION  R32G32B32_FLOAT  offset  0
//   NORMAL    R32G32B32_FLOAT  offset 12
//   COLOR     R8G8B8A8_UNORM   offset 24
//   BLOCKAO   R8G8B8A8_UINT    offset 28
// ============================================================================

#pragma once

namespace RawrXD {
namespace Voxel {
namespace Shaders {

// ---------------------------------------------------------------------------
// Vertex + pixel shader.
//
// The matrix is uploaded column-major and multiplied with the row-vector
// convention (mul(float4, float4x4)), so the CPU-side matrix is consumed
// exactly as it was built, with no transposition on either side.
// ---------------------------------------------------------------------------
inline constexpr const char* kVoxelShader = R"(
cbuffer FrameConstants : register(b0)
{
    float4x4 ViewProjection;
    float4   CameraPosition;   // xyz camera, w = unused
    float4   LightDirection;   // xyz normalized toward the light, w = sun intensity
    float4   Params;           // x = ambient, y = fog start, z = fog range, w = sky tint
};

struct VSInput
{
    float3 Position : POSITION;
    float3 Normal   : NORMAL;
    float4 Color    : COLOR;
    uint4  BlockAo  : BLOCKAO;
};

struct VSOutput
{
    float4 Position : SV_POSITION;
    float3 Normal   : NORMAL;
    float4 Color    : COLOR;
    float3 World    : TEXCOORD0;
    float  Ao       : TEXCOORD1;
};

VSOutput VSMain(VSInput input)
{
    VSOutput o;
    o.Position = mul(float4(input.Position, 1.0f), ViewProjection);
    o.Normal   = input.Normal;
    o.Color    = input.Color;
    o.World    = input.Position;
    // blockAo packs the block type in the low byte and this corner's ambient
    // occlusion in bits 8..9. 0 is fully occluded, 3 is fully open.
    o.Ao       = (float)(input.BlockAo.y & 3u) * (1.0f / 3.0f);
    return o;
}

static const float3 kSkyColor     = float3(0.36f, 0.55f, 0.82f);
static const float3 kHorizonColor = float3(0.70f, 0.79f, 0.90f);
static const float3 kSunColor     = float3(1.00f, 0.95f, 0.84f);

float4 PSMain(VSOutput input) : SV_TARGET
{
    float3 n = normalize(input.Normal);

    // Hemispheric ambient: upward faces catch the sky, downward faces catch
    // the ground bounce. This is what makes a voxel scene read as solid.
    float up = n.y * 0.5f + 0.5f;
    float3 ambient = mix(float3(0.20f, 0.18f, 0.16f), float3(0.34f, 0.42f, 0.55f), up);

    float3 l = normalize(LightDirection.xyz);
    float ndotl = max(dot(n, l), 0.0f);
    float3 diffuse = kSunColor * (ndotl * LightDirection.w);

    float ao = 0.35f + 0.65f * input.Ao;
    float3 lit = input.Color.rgb * (ambient * Params.x + diffuse) * ao;

    // Distance fog toward the sky, so the far edge of the world does not end
    // in a hard line.
    float dist = length(input.World - CameraPosition.xyz);
    float fog = saturate((dist - Params.y) / max(Params.z, 0.001f));
    float3 sky = mix(kHorizonColor, kSkyColor, saturate(input.World.y * 0.01f));
    float3 color = lerp(lit, sky, fog * Params.w);

    return float4(saturate(color), 1.0f);
}
)";

} // namespace Shaders
} // namespace Voxel
} // namespace RawrXD
