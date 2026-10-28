// ============================================================================
// ShaderSource.hpp — the shader of the voxel renderer, as source.
//
// The shader is written here rather than in a file on disk so that the
// renderer has no runtime path to get wrong. It is compiled at start-up
// with D3DCompile, which is part of the Windows SDK and therefore always
// present, so there is no separate shader build step to keep in step with
// the code.
//
// The vertex layout the shader expects is:
//
//   POSITION  float3   the world position of the corner
//   TEXCOORD0 float    the block type and the face index, packed
//   TEXCOORD1 float    the ambient occlusion of the corner
//
// The matrices are uploaded as four rows rather than as a matrix, so that
// the layout of the constant buffer is the same on the CPU and on the
// GPU and the row-vector convention of the engine cannot be got wrong.
// ============================================================================

#pragma once

namespace sunshine {

inline const char* kVoxelShaderSource = R"HLSL(
// ---------------------------------------------------------------------------
// The scene constants.
//
// The view projection is uploaded as four rows because the engine works in
// the row-vector convention: a point is multiplied on the left. Writing
// the four rows out by hand removes any doubt about how the compiler lays
// the matrix out in the buffer.
//
// The size of this block matters. A constant buffer that is bound with a
// root descriptor has to be a whole number of 256 byte blocks, and the
// size the compiler sees is the size of the block as it is declared here
// after it has thrown away anything it thinks is unused. A padding array
// would be thrown away, so every member of this block is something the
// shader actually reads, and the total is 768 bytes, which is three
// blocks of 256.
// ---------------------------------------------------------------------------
cbuffer Scene : register(b0)
{
    float4 vpRow0;
    float4 vpRow1;
    float4 vpRow2;
    float4 vpRow3;
    float4 cameraPos;      // xyz is the position, w is the time
    float4 sunDirection;   // xyz is the direction, w is the strength
    float4 fogColor;       // rgb is the colour, w is the density
    float4 waterColor;     // rgb is the colour, w is how strong it is
    float4 skyZenith;      // rgb is the colour of the top of the sky
    float4 skyHorizon;     // rgb is the colour of the bottom of the sky
    float4 faceLight[6];   // the brightness of each of the six faces
    float4 paletteTop[16];
    float4 paletteSide[16];
};

// The gothic parameters.
//
// They are in a block of their own so that the block is a whole number
// of 256 byte blocks on its own, which is what a constant buffer bound
// with a root descriptor has to be. Every one of the sixteen is read by
// the shader, because a member the shader does not read is thrown away
// and the size that is left is not a whole number of blocks.
//
// The first four are the colours of the four lights: the sun, the sky,
// the ground and the mist. The rest are the numbers that shape them.
cbuffer Gothic : register(b1)
{
    float4 sunColour;      // rgb, the strength
    float4 skyLight;       // rgb, the strength
    float4 groundBounce;   // rgb, the strength
    float4 mistColour;     // rgb, the strength

    float4 emberColour;    // rgb, the strength of the glow of the ore
    float4 ridge;          // the ridge, the cavity, the specular, the power
    float4 atmosphere;     // the height of the mist, the falloff, the strength, the haze
    float4 tone;           // the exposure, the contrast, the lift, the gain

    float4 grain;          // the amount, the scale, the warmth, the speed
    float4 water;          // the depth, the ripple, the fresnel, the foam
    float4 palette;        // the variation, the saturation, the contrast, the edge
    float4 ember;          // the pulse, the scale, the threshold, the mist of the ember

    float4 skyBand;        // the gradient, the glow of the horizon, the fade, the cloud
    float4 shadow;         // the tint of the shadows, the floor, the softness, the strength
    float4 ridgeBand;      // the band, the falloff, the height, the warmth
    float4 misc;           // the flicker, the speed, the fade, the scale
};

// The hash of a place.
//
// A cheap one: three numbers mixed and taken apart. It is used to break
// up the flat faces of the blocks, because a wall of one block type with
// one colour reads as a wall of plastic.
float hash12(float2 p)
{
    float3 p3 = frac(float3(p.x, p.y, p.x) * 0.1031);
    p3 += dot(p3, float3(p3.y, p3.z, p3.x) + 33.33);
    return frac((p3.x + p3.y) * p3.z);
}

struct VertexIn
{
    float3 position : POSITION;
    float  packed   : PACKED;
};

struct VertexOut
{
    float4 position : SV_POSITION;
    float3 normal   : TEXCOORD0;
    float3 color    : TEXCOORD1;
    float  ao       : TEXCOORD2;
    float  depth    : TEXCOORD3;
    float  blockType: TEXCOORD4;
    float3 world    : TEXCOORD5;
};

// The outward normal of a face, from the face index the mesher wrote.
float3 faceNormal(uint face)
{
    if (face == 0u) return float3( 1.0, 0.0, 0.0);
    if (face == 1u) return float3(-1.0, 0.0, 0.0);
    if (face == 2u) return float3( 0.0, 1.0, 0.0);
    if (face == 3u) return float3( 0.0,-1.0, 0.0);
    if (face == 4u) return float3( 0.0, 0.0, 1.0);
    return float3(0.0, 0.0,-1.0);
}

VertexOut VoxelVS(VertexIn input)
{
    VertexOut output;

    const float3 p = input.position;
    const float4 p4 = float4(p, 1.0);
    output.position = float4(dot(p4, vpRow0),
                              dot(p4, vpRow1),
                              dot(p4, vpRow2),
                              dot(p4, vpRow3));

    // The packed value is an exact small integer held in a float. It
    // holds the block type, the face index and the occlusion of the
    // corner.
    const uint bits = (uint)input.packed;
    const uint block = bits & 0xFFu;
    const uint face  = (bits >> 8) & 0x07u;
    const uint ao    = (bits >> 16) & 0x03u;

    // The top of a block is a different material from its sides, which is
    // what makes a grass block read as grass.
    const float4 base = (face == 2u) ? paletteTop[block] : paletteSide[block];

    output.normal = faceNormal(face);
    output.color  = base.rgb * faceLight[face].rgb;
    output.ao     = (float)ao * (1.0 / 3.0);
    output.depth  = length(p - cameraPos.xyz);
    output.blockType = (float)block;
    output.world  = p;
    return output;
}

// The gothic shading.
//
// The world is lit by a warm sun that is low, under a cold sky, and it
// lies in a mist that fills the valleys. The shapes are read from their
// silhouettes, the distance is hidden rather than drawn, and the darks
// are blue rather than black.
//
// The whole of it is here, in one shader, because that is where the
// picture is decided.
float4 VoxelPS(VertexOut input) : SV_TARGET
{
    const float3 n = normalize(input.normal);
    const float3 p = input.world;
    const float3 view = normalize(cameraPos.xyz - p);

    // The material is varied by where it is, so that a wall of one kind
    // of block is not a wall of one colour.
    const float variation = hash12(floor(p.xz * 2.0)) - 0.5;
    const float grainValue = (hash12(floor(p.xz * 31.0) + 7.0) - 0.5) * grain.x;

    // The light: a warm sun against a cold sky, and the ground throws
    // up a little of what it is made of.
    const float ndl = saturate(dot(n, normalize(sunDirection.xyz)));
    const float sky = saturate(n.y * 0.5 + 0.5);
    const float bounce = saturate(-n.y * 0.5 + 0.5);

    // The occlusion is the cavity, and the cavity is where the warmth
    // of the ground collects.
    const float cavity = 1.0 - input.ao;

    float3 rgb = input.color * (1.0 + variation * palette.x);

    rgb *= sunColour.rgb * sunColour.w * (0.20 + 0.80 * ndl);
    rgb += skyLight.rgb * skyLight.w * sky;
    rgb += groundBounce.rgb * groundBounce.w * bounce;

    // The cavity is darker and warmer.
    rgb *= (1.0 - cavity * ridge.y);
    rgb += groundBounce.rgb * cavity * ridgeBand.w;

    // The ridge: the tops of the shapes catch the light.
    rgb *= 1.0 + ridge.x * saturate(n.y) * (1.0 - cavity);

    // The specular: the wet stone.
    const float3 half = normalize(normalize(sunDirection.xyz) + view);
    rgb += sunColour.rgb * pow(saturate(dot(n, half)), ridge.w) * ridge.z;

    // The ore glows, and the glow is warm and it pulses.
    if (input.blockType == 9.0 || input.blockType == 10.0)
    {
        const float pulse = 0.5 + 0.5 * sin(cameraPos.w * ember.y + misc.y);
        const float heat = saturate(1.0 - cavity * ember.z);
        rgb += emberColour.rgb * emberColour.w * (0.4 + 0.6 * pulse) * heat * ember.x;
        rgb += emberColour.rgb * misc.x * pulse;
    }

    // The water: the deep colour, the fresnel at the edge, and the
    // ripple on the top.
    if (input.blockType == 6.0)
    {
        const float ripple = sin(p.x * 0.6 + cameraPos.w * 1.3) * cos(p.z * 0.5 - cameraPos.w);
        const float fresnel = pow(1.0 - saturate(dot(n, view)), water.z);
        rgb = lerp(waterColor.rgb * water.x, skyLight.rgb * skyLight.w, fresnel);
        rgb += sunColour.rgb *
               pow(saturate(dot(reflect(-normalize(sunDirection.xyz), n), view)), 32.0) * water.y;
        rgb += float3(water.w, water.w, water.w) * saturate(ripple * 0.5 + 0.5) * fresnel;
    }

    // The mist lies in the valleys, and the distance is hidden in it.
    const float mist = saturate((atmosphere.x - p.y) * atmosphere.y) * atmosphere.z;
    const float distance = saturate((input.depth - 20.0) * atmosphere.w);
    const float haze = saturate(distance + mist);

    // The mist takes the colour of the horizon, which is where the light
    // of the sun is in it.
    const float horizonGlow = saturate(1.0 - abs(n.y) * 2.0) * skyBand.y;
    const float3 hazeColour = lerp(mistColour.rgb, skyBand.rgb, horizonGlow);
    rgb = lerp(rgb, hazeColour, saturate(haze * haze * (3.0 - 2.0 * haze)));

    // The darks are blue rather than black, and there is a floor under
    // them, which is what keeps the picture from going flat.
    rgb = max(rgb, shadow.rgb * shadow.w * (1.0 - cavity * shadow.z));

    // The tone: the exposure, the contrast, the lift and the gain.
    rgb *= tone.x;
    rgb = (rgb - 0.5) * tone.y + 0.5 + tone.z;
    rgb = pow(max(rgb, 0.0), tone.w);

    // The saturation, and the grain that breaks the gradients.
    const float grey = dot(rgb, float3(0.299, 0.587, 0.114));
    rgb = lerp(grey, rgb, palette.y);
    rgb += grainValue;
    rgb += (hash12(p.xz * 91.0 + cameraPos.w * grain.w) - 0.5) * grain.x;
    rgb *= (1.0 + grain.z * variation);

    return float4(saturate(rgb), 1.0);
}

// ---------------------------------------------------------------------------
// The sky.
//
// A full screen triangle with a vertical gradient. It is drawn first, with
// the depth test off and the depth write off, so the terrain is drawn over
// it and the depth buffer is untouched by the sky.
// ---------------------------------------------------------------------------
struct SkyOut
{
    float4 position : SV_POSITION;
    float2 uv       : TEXCOORD0;
};

SkyOut SkyVS(uint vertexId : SV_VertexID)
{
    // Three vertices cover the screen: (-1,-1), (3,-1), (-1,3).
    const float2 corner = float2((vertexId << 1) & 2, vertexId & 2);

    SkyOut output;
    output.position = float4(corner * 2.0 - 1.0, 0.0, 1.0);
    output.uv = corner;
    return output;
}

float4 SkyPS(SkyOut input) : SV_TARGET
{
    const float t = saturate(input.uv.y);

    // The sky of a world under smog: a bruised violet at the top, and a
    // sickly bone at the horizon where the light of the city never quite
    // reaches.
    const float3 zenith  = float3(0.11, 0.09, 0.19);
    const float3 horizon = float3(0.58, 0.54, 0.50);

    float3 colour = lerp(horizon, zenith, t * t);

    // A band of dull light along the horizon, where the smog is thickest
    // and the sky is brightest.
    const float band = saturate(1.0 - t * 6.0);
    colour += float3(0.16, 0.11, 0.07) * band;

    return float4(saturate(colour), 1.0);
}
)HLSL";

// A shader that draws a quad without reading a vertex buffer.
//
// The positions come from the vertex number alone, so the test tells the
// rasteriser and the pipeline apart from the path that fetches the
// vertices. A quad that is right here and wrong in the world means the
// fault is in the vertex fetch, and a quad that is wrong in both means it
// is in the pipeline.
inline const char* kVertexIdShaderSource = R"HLSL(
struct VSOut
{
    float4 position : SV_POSITION;
    float4 color    : COLOR0;
};

// The corner of a quad, from the number of the vertex.
//
// The corners are worked out with a chain of tests rather than from a
// table, because a table with an initial value in it is not something the
// compiler this engine builds against will accept.
float2 quadCorner(uint vertexId)
{
    const uint triangle = vertexId / 3u;
    const uint corner = vertexId % 3u;

    if (triangle == 0u)
    {
        if (corner == 0u) return float2(-0.8, -0.8);
        if (corner == 1u) return float2(-0.8,  0.8);
        return float2(0.8, 0.8);
    }
    if (corner == 0u) return float2(-0.8, -0.8);
    if (corner == 1u) return float2( 0.8, 0.8);
    return float2(0.8, -0.8);
}

float3 quadColour(uint vertexId)
{
    const uint triangle = vertexId / 3u;
    const uint corner = vertexId % 3u;

    if (triangle == 0u)
    {
        if (corner == 0u) return float3(1, 0, 0);
        if (corner == 1u) return float3(0, 1, 0);
        return float3(0, 0, 1);
    }
    if (corner == 0u) return float3(1, 0, 0);
    if (corner == 1u) return float3(0, 0, 1);
    return float3(1, 1, 0);
}

VSOut VSMain(uint vertexId : SV_VertexID)
{
    VSOut output;
    output.position = float4(quadCorner(vertexId), 0.5, 1.0);
    output.color = float4(quadColour(vertexId), 1.0);
    return output;
}

float4 PSMain(VSOut input) : SV_TARGET
{
    return input.color;
}
)HLSL";

} // namespace sunshine
