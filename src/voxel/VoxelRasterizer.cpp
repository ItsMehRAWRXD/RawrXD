// ============================================================================
// VoxelRasterizer.cpp - the software reference rasterizer.
//
// The pipeline mirrors the DX12 path exactly:
//   world position -> View -> Projection -> NDC -> viewport
//   backface cull by the outward normal against the view direction
//   depth test with LESS against a per-pixel z buffer
//   perspective-correct interpolation of colour, normal, AO and world space
//   the same lighting model as VoxelShaders.hpp
//
// The only difference from the GPU path is the rasterization rule, so the two
// frames agree on what is drawn and roughly where, and differ only at the
// sub-pixel edges.
// ============================================================================

#include "VoxelRasterizer.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <string>

namespace RawrXD {
namespace Voxel {
namespace {

struct Shading {
    Vec3 lightDir{0.45f, 0.82f, 0.35f};
    float sunIntensity = 0.95f;
    float ambientScale = 1.0f;
    float fogStart = 60.0f;
    float fogRange = 140.0f;
    float fogStrength = 0.85f;
};

// The same constants as the HLSL, so the two paths agree.
const Vec3 kSkyColor{0.36f, 0.55f, 0.82f};
const Vec3 kHorizonColor{0.70f, 0.79f, 0.90f};
const Vec3 kSunColor{1.00f, 0.95f, 0.84f};

// The clear colour the DX12 path uses.
const Vec3 kClearColor{0.44f, 0.55f, 0.72f};

struct ScreenVertex {
    float x = 0.0f;   // screen space, y down
    float y = 0.0f;
    float z = 0.0f;   // NDC depth in [0,1]
    float invW = 0.0f;
    Vec3 world{};
    Vec3 normal{};
    float ao = 1.0f;
    Vec3 albedo{1.0f, 1.0f, 1.0f};
};

inline float Saturate(float v) { return v < 0.0f ? 0.0f : (v > 1.0f ? 1.0f : v); }

inline Vec3 Mix(const Vec3& a, const Vec3& b, float t) {
    return {a.x + (b.x - a.x) * t, a.y + (b.y - a.y) * t, a.z + (b.z - a.z) * t};
}

inline Vec3 Scale(const Vec3& v, float s) { return {v.x * s, v.y * s, v.z * s}; }

inline Vec3 Mul(const Vec3& a, const Vec3& b) { return {a.x * b.x, a.y * b.y, a.z * b.z}; }

// The pixel shader, transcribed from the HLSL so both paths produce the same
// image for the same geometry.
inline Vec3 Shade(const Vec3& normal, const Vec3& world, const Vec3& cameraPos,
                  float ao, const Vec3& albedo, const Shading& s) {
    const Vec3 n = Normalize(normal);
    const float up = n.y * 0.5f + 0.5f;
    const Vec3 ambient = Mix(Vec3{0.20f, 0.18f, 0.16f}, Vec3{0.34f, 0.42f, 0.55f}, up);

    const Vec3 l = Normalize(s.lightDir);
    const float ndotl = std::max(Dot(n, l), 0.0f);
    const Vec3 diffuse = Scale(kSunColor, ndotl * s.sunIntensity);

    const float aoFactor = 0.35f + 0.65f * ao;
    const Vec3 lightSum = Scale(ambient, s.ambientScale) + diffuse;
    const Vec3 lit = Scale(Mul(albedo, lightSum), aoFactor);

    const float dist = Length(world - cameraPos);
    const float fog = Saturate((dist - s.fogStart) / std::max(s.fogRange, 0.001f));
    const Vec3 sky = Mix(kHorizonColor, kSkyColor, Saturate(world.y * 0.01f));
    const Vec3 color = Mix(lit, sky, fog * s.fogStrength);

    return {Saturate(color.x), Saturate(color.y), Saturate(color.z)};
}

inline float Edge(const ScreenVertex& a, const ScreenVertex& b, float px, float py) {
    return (b.x - a.x) * (py - a.y) - (b.y - a.y) * (px - a.x);
}

} // namespace

bool RasterizeFrame(const std::vector<const ChunkMesh*>& meshes,
                    const VoxelCamera& camera,
                    uint32_t width,
                    uint32_t height,
                    std::vector<uint8_t>& rgba,
                    std::string* error) {
    if (width == 0 || height == 0) {
        if (error) *error = "invalid frame size";
        return false;
    }

    const float aspect = static_cast<float>(width) / static_cast<float>(height);
    const float fov = camera.fovYDegrees * 3.14159265358979323846f / 180.0f;
    const Mat4 view = LookAt(camera.position, camera.target, camera.up);
    const Mat4 proj = Perspective(fov, aspect, camera.zNear, camera.zFar);
    const Mat4 viewProjection = proj * view;

    const Shading shading;

    // Clear to the sky colour and reset the depth buffer.
    rgba.assign(static_cast<size_t>(width) * height * 4u, 0);
    for (size_t i = 0; i < static_cast<size_t>(width) * height; ++i) {
        rgba[i * 4 + 0] = static_cast<uint8_t>(Saturate(kClearColor.x) * 255.0f);
        rgba[i * 4 + 1] = static_cast<uint8_t>(Saturate(kClearColor.y) * 255.0f);
        rgba[i * 4 + 2] = static_cast<uint8_t>(Saturate(kClearColor.z) * 255.0f);
        rgba[i * 4 + 3] = 255u;
    }
    std::vector<float> depth(static_cast<size_t>(width) * height, 1.0f);

    std::vector<ScreenVertex> screen;
    std::vector<bool> valid;

    for (const ChunkMesh* mesh : meshes) {
        if (mesh == nullptr || mesh->vertices.empty() || mesh->indices.empty()) continue;

        screen.clear();
        screen.reserve(mesh->vertices.size());
        valid.clear();
        valid.reserve(mesh->vertices.size());

        for (const VoxelVertex& v : mesh->vertices) {
            ScreenVertex sv;
            const Vec4 clip = viewProjection.Transform(Vec4{v.px, v.py, v.pz, 1.0f});
            const bool inFront = clip.w > 1e-6f;
            sv.invW = inFront ? (1.0f / clip.w) : 0.0f;
            const float ndcX = clip.x * sv.invW;
            const float ndcY = clip.y * sv.invW;
            const float ndcZ = clip.z * sv.invW;
            // The D3D viewport maps NDC y=+1 to the top of the target.
            sv.x = (ndcX * 0.5f + 0.5f) * static_cast<float>(width);
            sv.y = (1.0f - (ndcY * 0.5f + 0.5f)) * static_cast<float>(height);
            sv.z = ndcZ;
            sv.world = Vec3{v.px, v.py, v.pz};
            sv.normal = Vec3{v.nx, v.ny, v.nz};
            sv.ao = static_cast<float>((v.blockAo >> 8) & 0x3u) * (1.0f / 3.0f);
            sv.albedo = Vec3{static_cast<float>((v.color >> 16) & 0xFFu) / 255.0f,
                             static_cast<float>((v.color >> 8) & 0xFFu) / 255.0f,
                             static_cast<float>(v.color & 0xFFu) / 255.0f};
            screen.push_back(sv);
            valid.push_back(inFront);
        }

        for (size_t i = 0; i + 2 < mesh->indices.size(); i += 3) {
            const uint32_t i0 = mesh->indices[i];
            const uint32_t i1 = mesh->indices[i + 1];
            const uint32_t i2 = mesh->indices[i + 2];
            if (i0 >= screen.size() || i1 >= screen.size() || i2 >= screen.size()) continue;
            if (!valid[i0] || !valid[i1] || !valid[i2]) continue;  // behind the near plane

            const ScreenVertex& v0 = screen[i0];
            const ScreenVertex& v1 = screen[i1];
            const ScreenVertex& v2 = screen[i2];

            // Backface cull. The VERTEX normal is used, not the geometric one:
            // the mesher reverses the triangle winding for the negative face
            // direction, so a cross product would point inward for half the
            // faces. The vertex normal is always outward, and a face is
            // visible when it points back toward the camera.
            const Vec3 faceNormal = Normalize(Vec3{v0.normal.x + v1.normal.x + v2.normal.x,
                                                   v0.normal.y + v1.normal.y + v2.normal.y,
                                                   v0.normal.z + v1.normal.z + v2.normal.z});
            const Vec3 viewDir = camera.position - v0.world;
            if (Dot(faceNormal, viewDir) <= 0.0f) continue;  // facing away

            const float area = Edge(v0, v1, v2.x, v2.y);
            if (std::fabs(area) < 1e-9f) continue;

            const int32_t minX = std::max(0, static_cast<int32_t>(std::floor(std::min({v0.x, v1.x, v2.x}))));
            const int32_t maxX = std::min(static_cast<int32_t>(width) - 1,
                                          static_cast<int32_t>(std::ceil(std::max({v0.x, v1.x, v2.x}))));
            const int32_t minY = std::max(0, static_cast<int32_t>(std::floor(std::min({v0.y, v1.y, v2.y}))));
            const int32_t maxY = std::min(static_cast<int32_t>(height) - 1,
                                          static_cast<int32_t>(std::ceil(std::max({v0.y, v1.y, v2.y}))));
            if (minX > maxX || minY > maxY) continue;

            for (int32_t py = minY; py <= maxY; ++py) {
                for (int32_t px = minX; px <= maxX; ++px) {
                    const float fx = static_cast<float>(px) + 0.5f;
                    const float fy = static_cast<float>(py) + 0.5f;

                    const float w0 = Edge(v1, v2, fx, fy);
                    const float w1 = Edge(v2, v0, fx, fy);
                    const float w2 = Edge(v0, v1, fx, fy);
                    if (w0 * area < 0.0f || w1 * area < 0.0f || w2 * area < 0.0f) continue;

                    const float l0 = w0 / area;
                    const float l1 = w1 / area;
                    const float l2 = w2 / area;

                    const float z = l0 * v0.z + l1 * v1.z + l2 * v2.z;
                    const size_t pixel = static_cast<size_t>(py) * width + static_cast<size_t>(px);
                    if (z >= depth[pixel]) continue;  // depth test: LESS

                    const float invW = l0 * v0.invW + l1 * v1.invW + l2 * v2.invW;
                    if (invW <= 0.0f) continue;

                    const float p0 = l0 * v0.invW / invW;
                    const float p1 = l1 * v1.invW / invW;
                    const float p2 = l2 * v2.invW / invW;

                    const Vec3 world{p0 * v0.world.x + p1 * v1.world.x + p2 * v2.world.x,
                                     p0 * v0.world.y + p1 * v1.world.y + p2 * v2.world.y,
                                     p0 * v0.world.z + p1 * v1.world.z + p2 * v2.world.z};
                    const Vec3 normal{p0 * v0.normal.x + p1 * v1.normal.x + p2 * v2.normal.x,
                                      p0 * v0.normal.y + p1 * v1.normal.y + p2 * v2.normal.y,
                                      p0 * v0.normal.z + p1 * v1.normal.z + p2 * v2.normal.z};
                    const Vec3 albedo{p0 * v0.albedo.x + p1 * v1.albedo.x + p2 * v2.albedo.x,
                                      p0 * v0.albedo.y + p1 * v1.albedo.y + p2 * v2.albedo.y,
                                      p0 * v0.albedo.z + p1 * v1.albedo.z + p2 * v2.albedo.z};
                    const float ao = p0 * v0.ao + p1 * v1.ao + p2 * v2.ao;

                    const Vec3 color = Shade(normal, world, camera.position, ao, albedo, shading);

                    depth[pixel] = z;
                    rgba[pixel * 4 + 0] = static_cast<uint8_t>(color.x * 255.0f);
                    rgba[pixel * 4 + 1] = static_cast<uint8_t>(color.y * 255.0f);
                    rgba[pixel * 4 + 2] = static_cast<uint8_t>(color.z * 255.0f);
                    rgba[pixel * 4 + 3] = 255u;
                }
            }
        }
    }

    return true;
}

} // namespace Voxel
} // namespace RawrXD
