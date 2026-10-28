// ============================================================================
// Math.hpp — the small amount of linear algebra the voxel engine needs.
//
// Written from scratch for this engine. No third-party matrix library is
// used, and no engine header is pulled in. The engine needs exactly four
// things: a vector, a 4x4 matrix, a perspective projection and a
// look-at view, plus a couple of hashes for the terrain generator.
//
// The conventions are the Direct3D ones, because the renderer is D3D12:
//
//   * the matrix is row-major in memory, and a vector is a row vector that
//     is multiplied on the left: v' = v * M
//   * the clip space is left-handed, with z in [0, 1]
//   * the projection therefore uses the Direct3D-style depth range and not
//     the OpenGL-style [-1, 1]
//
// Every function here is header-only and side-effect free.
// ============================================================================

#pragma once

#include <cmath>
#include <cstdint>

namespace sunshine {

// ---------------------------------------------------------------------------
// Vec3
// ---------------------------------------------------------------------------

struct Vec3 {
    float x = 0.0f;
    float y = 0.0f;
    float z = 0.0f;

    constexpr Vec3() = default;
    constexpr Vec3(float ix, float iy, float iz) : x(ix), y(iy), z(iz) {}

    constexpr Vec3 operator+(const Vec3& o) const { return {x + o.x, y + o.y, z + o.z}; }
    constexpr Vec3 operator-(const Vec3& o) const { return {x - o.x, y - o.y, z - o.z}; }
    constexpr Vec3 operator*(float s) const { return {x * s, y * s, z * s}; }
    constexpr Vec3 operator/(float s) const { return {x / s, y / s, z / s}; }
    Vec3& operator+=(const Vec3& o) { x += o.x; y += o.y; z += o.z; return *this; }
    Vec3& operator-=(const Vec3& o) { x -= o.x; y -= o.y; z -= o.z; return *this; }
    Vec3& operator*=(float s) { x *= s; y *= s; z *= s; return *this; }
    constexpr bool operator==(const Vec3& o) const { return x == o.x && y == o.y && z == o.z; }
    constexpr bool operator!=(const Vec3& o) const { return !(*this == o); }

    constexpr float dot(const Vec3& o) const { return x * o.x + y * o.y + z * o.z; }

    Vec3 cross(const Vec3& o) const {
        return {y * o.z - z * o.y, z * o.x - x * o.z, x * o.y - y * o.x};
    }

    float lengthSquared() const { return x * x + y * y + z * z; }
    float length() const { return std::sqrt(lengthSquared()); }

    Vec3 normalized() const {
        const float len = length();
        if (len <= 1e-8f) return {0.0f, 0.0f, 0.0f};
        return {x / len, y / len, z / len};
    }
};

// ---------------------------------------------------------------------------
// Mat4 — row-major, row-vector convention (v' = v * M).
// ---------------------------------------------------------------------------

struct Mat4 {
    float m[4][4] = {};

    static Mat4 identity() {
        Mat4 r{};
        r.m[0][0] = r.m[1][1] = r.m[2][2] = r.m[3][3] = 1.0f;
        return r;
    }

    // The projection, for the row-vector convention.
    //
    // A point is multiplied on the right: clip = v * P. The w component
    // of the result is the z of the point, so the row that holds it is
    // the third row, and the z of the result is the z of the point moved
    // into the range zero to one.
    static Mat4 perspective(float fovYRadians, float aspect, float nearZ, float farZ) {
        Mat4 r{};
        const float tanHalf = std::tan(fovYRadians * 0.5f);
        const float invTan = 1.0f / tanHalf;

        r.m[0][0] = invTan / (aspect > 1e-8f ? aspect : 1.0f);
        r.m[1][1] = invTan;
        r.m[2][2] = farZ / (farZ - nearZ);
        r.m[3][2] = -(farZ * nearZ) / (farZ - nearZ);
        r.m[2][3] = 1.0f;
        return r;
    }

    // The view, for the column-vector convention.
    //
    // The axes are the rows of the upper part and the translation is the
    // last row, so that a point is multiplied on the right: view = V * v.
    static Mat4 lookAtLH(const Vec3& eye, const Vec3& target, const Vec3& up) {
        const Vec3 f = (target - eye).normalized();

        // The world is left handed, so the right of the camera is the up
        // crossed with the forward, and the up of the camera is the
        // forward crossed with the right.
        Vec3 s = up.cross(f).normalized();
        if (s.lengthSquared() < 1e-12f) {
            // The view direction is parallel to `up`. Pick any
            // perpendicular axis rather than producing a NaN matrix.
            s = (Vec3{0.0f, 0.0f, 1.0f}.cross(f)).normalized();
            if (s.lengthSquared() < 1e-12f) s = Vec3{1.0f, 0.0f, 0.0f};
        }
        const Vec3 u = f.cross(s);

        Mat4 r = identity();
        r.m[0][0] = s.x;  r.m[0][1] = s.y;  r.m[0][2] = s.z;  r.m[0][3] = 0.0f;
        r.m[1][0] = u.x;  r.m[1][1] = u.y;  r.m[1][2] = u.z;  r.m[1][3] = 0.0f;
        r.m[2][0] = f.x;  r.m[2][1] = f.y;  r.m[2][2] = f.z;  r.m[2][3] = 0.0f;
        r.m[3][0] = -s.dot(eye);
        r.m[3][1] = -u.dot(eye);
        r.m[3][2] = -f.dot(eye);
        r.m[3][3] = 1.0f;
        return r;
    }

    // r = a * b
    Mat4 operator*(const Mat4& b) const {
        Mat4 r{};
        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 4; ++j) {
                float sum = 0.0f;
                for (int k = 0; k < 4; ++k) sum += m[i][k] * b.m[k][j];
                r.m[i][j] = sum;
            }
        }
        return r;
    }

    // The point is multiplied on the right, so each component of the
    // result is the dot of the point with a column of the matrix.
    Vec3 transformPoint(const Vec3& p) const {
        const float x = p.x * m[0][0] + p.y * m[1][0] + p.z * m[2][0] + m[3][0];
        const float y = p.x * m[0][1] + p.y * m[1][1] + p.z * m[2][1] + m[3][1];
        const float z = p.x * m[0][2] + p.y * m[1][2] + p.z * m[2][2] + m[3][2];
        const float w = p.x * m[0][3] + p.y * m[1][3] + p.z * m[2][3] + m[3][3];
        if (std::fabs(w) < 1e-8f) return {x, y, z};
        return {x / w, y / w, z / w};
    }
};

// ---------------------------------------------------------------------------
// Hashes — the deterministic source of the terrain.
//
// These are integer hashes with no floating point in them, so the same
// coordinates always give the same answer on every machine and in every
// build. The terrain generator relies on that: a world must be reproducible.
// ---------------------------------------------------------------------------

inline uint32_t hash32(uint32_t x) {
    x ^= x >> 16;
    x *= 0x7feb352dU;
    x ^= x >> 15;
    x *= 0x846ca68bU;
    x ^= x >> 16;
    return x;
}

inline uint32_t hash3(int32_t x, int32_t y, int32_t z, uint32_t seed) {
    uint32_t h = seed;
    h = hash32(h ^ static_cast<uint32_t>(x) * 0x9E3779B1U);
    h = hash32(h ^ static_cast<uint32_t>(y) * 0x85EBCA77U);
    h = hash32(h ^ static_cast<uint32_t>(z) * 0xC2B2AE3DU);
    return h;
}

// A float in [0, 1) derived from a coordinate hash.
inline float hashUnit(int32_t x, int32_t y, int32_t z, uint32_t seed) {
    return static_cast<float>(hash3(x, y, z, seed) >> 8) / static_cast<float>(1 << 24);
}

inline float clampf(float v, float lo, float hi) {
    return v < lo ? lo : (v > hi ? hi : v);
}

inline float lerpf(float a, float b, float t) { return a + (b - a) * t; }

// Smoothstep, used everywhere a value has to ease rather than snap.
inline float smoothstep(float t) {
    t = clampf(t, 0.0f, 1.0f);
    return t * t * (3.0f - 2.0f * t);
}

} // namespace sunshine
