// ============================================================================
// Math3D.hpp - the minimal 4x4 math the voxel renderer needs.
//
// First-party: column-major matrices, row-vector convention (v * M), which is
// the same convention HLSL consumes for cbuffer packing, so the matrix that
// leaves the CPU is the matrix the vertex shader sees with no transposition.
//
//   clip = world * View * Projection
//
// Nothing here depends on a third-party math library.
// ============================================================================

#pragma once

#include <cmath>
#include <cstdint>

namespace RawrXD {
namespace Voxel {

struct Vec3 {
    float x = 0.0f;
    float y = 0.0f;
    float z = 0.0f;
};

struct Vec4 {
    float x = 0.0f;
    float y = 0.0f;
    float z = 0.0f;
    float w = 0.0f;
};

inline Vec3 operator+(const Vec3& a, const Vec3& b) { return {a.x + b.x, a.y + b.y, a.z + b.z}; }
inline Vec3 operator-(const Vec3& a, const Vec3& b) { return {a.x - b.x, a.y - b.y, a.z - b.z}; }
inline Vec3 operator*(const Vec3& a, float s) { return {a.x * s, a.y * s, a.z * s}; }
inline float Dot(const Vec3& a, const Vec3& b) { return a.x * b.x + a.y * b.y + a.z * b.z; }
inline Vec3 Cross(const Vec3& a, const Vec3& b) {
    return {a.y * b.z - a.z * b.y, a.z * b.x - a.x * b.z, a.x * b.y - a.y * b.x};
}
inline float Length(const Vec3& v) { return std::sqrt(Dot(v, v)); }
inline Vec3 Normalize(const Vec3& v) {
    const float len = Length(v);
    if (len <= 1e-8f) return {0.0f, 0.0f, 0.0f};
    return {v.x / len, v.y / len, v.z / len};
}

// Column-major 4x4: m[column][row], matching the HLSL cbuffer layout where
// each register is a column of four floats.
struct Mat4 {
    float m[4][4] = {};

    static Mat4 Identity() {
        Mat4 r;
        for (int i = 0; i < 4; ++i) r.m[i][i] = 1.0f;
        return r;
    }

    Vec4 Transform(const Vec4& v) const {
        return {v.x * m[0][0] + v.y * m[1][0] + v.z * m[2][0] + v.w * m[3][0],
                v.x * m[0][1] + v.y * m[1][1] + v.z * m[2][1] + v.w * m[3][1],
                v.x * m[0][2] + v.y * m[1][2] + v.z * m[2][2] + v.w * m[3][2],
                v.x * m[0][3] + v.y * m[1][3] + v.z * m[2][3] + v.w * m[3][3]};
    }
};

inline Mat4 operator*(const Mat4& a, const Mat4& b) {
    Mat4 r;
    for (int c = 0; c < 4; ++c) {
        for (int row = 0; row < 4; ++row) {
            float sum = 0.0f;
            for (int k = 0; k < 4; ++k) sum += a.m[k][row] * b.m[c][k];
            r.m[c][row] = sum;
        }
    }
    return r;
}

// Right-handed look-at. The camera looks down its local -Z, matching the
// DXGI/D3D12 convention and the perspective matrix below.
inline Mat4 LookAt(const Vec3& eye, const Vec3& target, const Vec3& up) {
    const Vec3 f = Normalize(target - eye);
    const Vec3 s = Normalize(Cross(f, up));
    const Vec3 u = Cross(s, f);

    Mat4 r = Mat4::Identity();
    r.m[0][0] = s.x;  r.m[1][0] = s.y;  r.m[2][0] = s.z;  r.m[3][0] = -Dot(s, eye);
    r.m[0][1] = u.x;  r.m[1][1] = u.y;  r.m[2][1] = u.z;  r.m[3][1] = -Dot(u, eye);
    r.m[0][2] = -f.x; r.m[1][2] = -f.y; r.m[2][2] = -f.z; r.m[3][2] = Dot(f, eye);
    r.m[0][3] = 0.0f; r.m[1][3] = 0.0f; r.m[2][3] = 0.0f; r.m[3][3] = 1.0f;
    return r;
}

// Right-handed perspective with a [0,1] depth range, which is what
// D3D12 expects (unlike OpenGL's [-1,1]).
inline Mat4 Perspective(float fovYRadians, float aspect, float zNear, float zFar) {
    Mat4 r;
    const float f = 1.0f / std::tan(fovYRadians * 0.5f);
    r.m[0][0] = f / aspect;
    r.m[1][1] = f;
    r.m[2][2] = zFar / (zFar - zNear);
    r.m[2][3] = -1.0f;
    r.m[3][2] = -(zFar * zNear) / (zFar - zNear);
    r.m[3][3] = 0.0f;
    return r;
}

// The camera the voxel renderer and the reference rasterizer both use. It
// lives here, not in the renderer, so the two paths cannot drift apart.
struct VoxelCamera {
    Vec3 position{0.0f, 34.0f, 48.0f};
    Vec3 target{0.0f, 18.0f, 0.0f};
    Vec3 up{0.0f, 1.0f, 0.0f};
    float fovYDegrees = 70.0f;
    float zNear = 0.1f;
    float zFar = 900.0f;
};

} // namespace Voxel
} // namespace RawrXD