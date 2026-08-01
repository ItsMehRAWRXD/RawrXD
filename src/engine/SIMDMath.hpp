#pragma once
#include <cstdint>
#include <xmmintrin.h>
#include <emmintrin.h>
#include <pmmintrin.h>
#include <immintrin.h>

// ============================================================================
// SIMD Math Layer — AVX2/AVX512 vector primitives for engine transforms
// All operations are cache-line aligned and branchless where possible.
// ============================================================================

// ---------------------------------------------------------------------------
// Vec4 — 4-component float vector (maps to __m128)
// ---------------------------------------------------------------------------
struct alignas(16) Vec4 {
    union { float f[4]; __m128 m; };

    Vec4() : m(_mm_setzero_ps()) {}
    Vec4(float x, float y, float z, float w) : m(_mm_set_ps(w, z, y, x)) {}
    Vec4(__m128 v) : m(v) {}

    float& operator[](int i) { return f[i]; }
    const float& operator[](int i) const { return f[i]; }

    // Arithmetic
    Vec4 operator+(const Vec4& v) const { return _mm_add_ps(m, v.m); }
    Vec4 operator-(const Vec4& v) const { return _mm_sub_ps(m, v.m); }
    Vec4 operator*(const Vec4& v) const { return _mm_mul_ps(m, v.m); }
    Vec4 operator/(const Vec4& v) const { return _mm_div_ps(m, v.m); }
    Vec4 operator*(float s) const { return _mm_mul_ps(m, _mm_set1_ps(s)); }

    // Dot product
    float Dot(const Vec4& v) const {
        __m128 d = _mm_mul_ps(m, v.m);
        d = _mm_hadd_ps(d, d);
        d = _mm_hadd_ps(d, d);
        return _mm_cvtss_f32(d);
    }

    // Cross product (3D)
    Vec4 Cross(const Vec4& v) const {
        __m128 a = m, b = v.m;
        __m128 a_yzx = _mm_shuffle_ps(a, a, _MM_SHUFFLE(3, 0, 2, 1));
        __m128 b_yzx = _mm_shuffle_ps(b, b, _MM_SHUFFLE(3, 0, 2, 1));
        __m128 c = _mm_sub_ps(_mm_mul_ps(a, b_yzx), _mm_mul_ps(a_yzx, b));
        return _mm_shuffle_ps(c, c, _MM_SHUFFLE(3, 0, 2, 1));
    }

    // Normalize
    Vec4 Normalized() const {
        float len = sqrtf(Dot(*this));
        if (len > 1e-8f) return *this * (1.0f / len);
        return Vec4(0, 0, 0, 1);
    }

    // Length
    float Length() const { return sqrtf(Dot(*this)); }
};

// ---------------------------------------------------------------------------
// Mat4 — 4x4 column-major matrix (maps to 4 __m128)
// ---------------------------------------------------------------------------
struct alignas(16) Mat4 {
    __m128 col[4];

    Mat4() {
        col[0] = _mm_set_ps(0, 0, 0, 1);
        col[1] = _mm_set_ps(0, 0, 1, 0);
        col[2] = _mm_set_ps(0, 1, 0, 0);
        col[3] = _mm_set_ps(1, 0, 0, 0);
    }

    static Mat4 Identity() { return Mat4(); }

    static Mat4 Perspective(float fovY, float aspect, float nearZ, float farZ) {
        float yScale = 1.0f / tanf(fovY * 0.5f);
        float xScale = yScale / aspect;
        Mat4 m;
        m.col[0] = _mm_set_ps(0, 0, 0, xScale);
        m.col[1] = _mm_set_ps(0, 0, yScale, 0);
        m.col[2] = _mm_set_ps(-1, 0, 0, 0);
        m.col[3] = _mm_set_ps(0, farZ * nearZ / (nearZ - farZ), 0, 0);
        return m;
    }

    static Mat4 Translation(float x, float y, float z) {
        Mat4 m;
        m.col[3] = _mm_set_ps(1, z, y, x);
        return m;
    }

    Vec4 operator*(const Vec4& v) const {
        __m128 r = _mm_mul_ps(col[0], _mm_shuffle_ps(v.m, v.m, 0x00));
        r = _mm_add_ps(r, _mm_mul_ps(col[1], _mm_shuffle_ps(v.m, v.m, 0x55)));
        r = _mm_add_ps(r, _mm_mul_ps(col[2], _mm_shuffle_ps(v.m, v.m, 0xAA)));
        r = _mm_add_ps(r, _mm_mul_ps(col[3], _mm_shuffle_ps(v.m, v.m, 0xFF)));
        return r;
    }

    Mat4 operator*(const Mat4& b) const {
        Mat4 r;
        for (int i = 0; i < 4; ++i) {
            __m128 a0 = _mm_shuffle_ps(col[i], col[i], 0x00);
            __m128 a1 = _mm_shuffle_ps(col[i], col[i], 0x55);
            __m128 a2 = _mm_shuffle_ps(col[i], col[i], 0xAA);
            __m128 a3 = _mm_shuffle_ps(col[i], col[i], 0xFF);
            r.col[i] = _mm_add_ps(
                _mm_add_ps(_mm_mul_ps(a0, b.col[0]), _mm_mul_ps(a1, b.col[1])),
                _mm_add_ps(_mm_mul_ps(a2, b.col[2]), _mm_mul_ps(a3, b.col[3]))
            );
        }
        return r;
    }
};

// ---------------------------------------------------------------------------
// Quaternion — for rotation interpolation
// ---------------------------------------------------------------------------
struct alignas(16) Quat {
    __m128 m;

    Quat() : m(_mm_set_ps(1, 0, 0, 0)) {}
    Quat(float w, float x, float y, float z) : m(_mm_set_ps(z, y, x, w)) {}

    static Quat FromAxisAngle(const Vec4& axis, float angle) {
        float s = sinf(angle * 0.5f);
        return Quat(cosf(angle * 0.5f), axis.f[0] * s, axis.f[1] * s, axis.f[2] * s);
    }

    Mat4 ToMatrix() const {
        float f[4];
        _mm_store_ps(f, m);
        float w = f[0], x = f[1], y = f[2], z = f[3];
        float x2 = x + x, y2 = y + y, z2 = z + z;
        float xx = x * x2, xy = x * y2, xz = x * z2;
        float yy = y * y2, yz = y * z2, zz = z * z2;
        float wx = w * x2, wy = w * y2, wz = w * z2;

        Mat4 r;
        r.col[0] = _mm_set_ps(0, 0, yz + wz, 1 - yy - zz);
        r.col[1] = _mm_set_ps(0, 0, 1 - xx - zz, xy - wz);
        r.col[2] = _mm_set_ps(0, 0, 1 - xx - yy, xz + wy);
        r.col[3] = _mm_set_ps(1, 0, 0, 0);
        return r;
    }
};
