#pragma once

#include <cmath>
#include <cstdint>

namespace Sunshine {

struct Vec2 {
    float x, y;
    Vec2() : x(0.0f), y(0.0f) {}
    Vec2(float _x, float _y) : x(_x), y(_y) {}
    Vec2 operator+(const Vec2& o) const { return Vec2(x + o.x, y + o.y); }
    Vec2 operator-(const Vec2& o) const { return Vec2(x - o.x, y - o.y); }
    Vec2 operator*(float s) const { return Vec2(x * s, y * s); }
    float length() const { return std::sqrt(x * x + y * y); }
};

struct Vec3 {
    float x, y, z;
    Vec3() : x(0.0f), y(0.0f), z(0.0f) {}
    Vec3(float _x, float _y, float _z) : x(_x), y(_y), z(_z) {}
    Vec3 operator+(const Vec3& o) const { return Vec3(x + o.x, y + o.y, z + o.z); }
    Vec3 operator-(const Vec3& o) const { return Vec3(x - o.x, y - o.y, z - o.z); }
    Vec3 operator*(float s) const { return Vec3(x * s, y * s, z * s); }
    Vec3 operator*(const Vec3& o) const { return Vec3(x * o.x, y * o.y, z * o.z); }
    Vec3 operator-() const { return Vec3(-x, -y, -z); }
    float dot(const Vec3& o) const { return x * o.x + y * o.y + z * o.z; }
    Vec3 cross(const Vec3& o) const { return Vec3(y * o.z - z * o.y, z * o.x - x * o.z, x * o.y - y * o.x); }
    float length() const { return std::sqrt(x * x + y * y + z * z); }
    Vec3 normalize() const { float len = length(); if (len > 0) return (*this) * (1.0f / len); return *this; }
};

struct Vec4 {
    float x, y, z, w;
    Vec4() : x(0.0f), y(0.0f), z(0.0f), w(0.0f) {}
    Vec4(float _x, float _y, float _z, float _w) : x(_x), y(_y), z(_z), w(_w) {}
};

struct Mat4 {
    float m[4][4];
    Mat4() {
        for (int i = 0; i < 4; ++i)
            for (int j = 0; j < 4; ++j)
                m[i][j] = (i == j) ? 1.0f : 0.0f;
    }
    static Mat4 identity() {
        return Mat4();
    }
    static Mat4 perspective(float fovDeg, float aspect, float nearPlane, float farPlane) {
        Mat4 r = identity();
        float f = 1.0f / std::tan(fovDeg * 3.14159265f / 360.0f);
        r.m[0][0] = f / aspect;
        r.m[1][1] = f;
        r.m[2][2] = farPlane / (farPlane - nearPlane);
        r.m[2][3] = 1.0f;
        r.m[3][2] = -(farPlane * nearPlane) / (farPlane - nearPlane);
        r.m[3][3] = 0.0f;
        return r;
    }
    static Mat4 lookAt(const Vec3& eye, const Vec3& target, const Vec3& up) {
        Vec3 z = (eye - target).normalize();
        Vec3 x = up.cross(z).normalize();
        Vec3 y = z.cross(x);
        Mat4 r;
        r.m[0][0] = x.x; r.m[1][0] = x.y; r.m[2][0] = x.z; r.m[3][0] = -x.dot(eye);
        r.m[0][1] = y.x; r.m[1][1] = y.y; r.m[2][1] = y.z; r.m[3][1] = -y.dot(eye);
        r.m[0][2] = z.x; r.m[1][2] = z.y; r.m[2][2] = z.z; r.m[3][2] = -z.dot(eye);
        r.m[0][3] = 0.0f; r.m[1][3] = 0.0f; r.m[2][3] = 0.0f; r.m[3][3] = 1.0f;
        return r;
    }
    static Mat4 translate(const Vec3& t) {
        Mat4 r = identity();
        r.m[3][0] = t.x; r.m[3][1] = t.y; r.m[3][2] = t.z;
        return r;
    }
    static Mat4 scale(float s) {
        Mat4 r = identity();
        r.m[0][0] = s; r.m[1][1] = s; r.m[2][2] = s;
        return r;
    }
    static Mat4 scale(const Vec3& s) {
        Mat4 r = identity();
        r.m[0][0] = s.x; r.m[1][1] = s.y; r.m[2][2] = s.z;
        return r;
    }
    static Mat4 rotateX(float angleDeg) {
        float c = std::cos(angleDeg * 3.14159265f / 180.0f);
        float s = std::sin(angleDeg * 3.14159265f / 180.0f);
        Mat4 r = identity();
        r.m[1][1] = c;  r.m[2][1] = -s;
        r.m[1][2] = s;  r.m[2][2] = c;
        return r;
    }
    static Mat4 rotateY(float angleDeg) {
        float c = std::cos(angleDeg * 3.14159265f / 180.0f);
        float s = std::sin(angleDeg * 3.14159265f / 180.0f);
        Mat4 r = identity();
        r.m[0][0] = c;  r.m[2][0] = s;
        r.m[0][2] = -s; r.m[2][2] = c;
        return r;
    }
    Mat4 operator*(const Mat4& o) const {
        Mat4 r;
        for (int i = 0; i < 4; ++i)
            for (int j = 0; j < 4; ++j)
                r.m[i][j] = m[i][0] * o.m[0][j] + m[i][1] * o.m[1][j] + m[i][2] * o.m[2][j] + m[i][3] * o.m[3][j];
        return r;
    }
    Vec3 transformPoint(const Vec3& p) const {
        Vec4 v(p.x, p.y, p.z, 1.0f);
        float x = m[0][0]*v.x + m[1][0]*v.y + m[2][0]*v.z + m[3][0]*v.w;
        float y = m[0][1]*v.x + m[1][1]*v.y + m[2][1]*v.z + m[3][1]*v.w;
        float z = m[0][2]*v.x + m[1][2]*v.y + m[2][2]*v.z + m[3][2]*v.w;
        float w = m[0][3]*v.x + m[1][3]*v.y + m[2][3]*v.z + m[3][3]*v.w;
        return Vec3(x / w, y / w, z / w);
    }
};

struct Quat {
    float x, y, z, w;
    Quat() : x(0.0f), y(0.0f), z(0.0f), w(1.0f) {}
    Quat(float _x, float _y, float _z, float _w) : x(_x), y(_y), z(_z), w(_w) {}
    static Quat fromAxisAngle(const Vec3& axis, float angleDeg) {
        float half = angleDeg * 3.14159265f / 360.0f;
        float s = std::sin(half);
        float c = std::cos(half);
        Vec3 n = axis.normalize();
        return Quat(n.x * s, n.y * s, n.z * s, c);
    }
    Mat4 toMat4() const {
        Mat4 r;
        float xx = x * x, yy = y * y, zz = z * z;
        float xy = x * y, xz = x * z, yz = y * z;
        float wx = w * x, wy = w * y, wz = w * z;
        r.m[0][0] = 1.0f - 2.0f * (yy + zz); r.m[1][0] = 2.0f * (xy - wz);     r.m[2][0] = 2.0f * (xz + wy);     r.m[3][0] = 0.0f;
        r.m[0][1] = 2.0f * (xy + wz);       r.m[1][1] = 1.0f - 2.0f * (xx + zz); r.m[2][1] = 2.0f * (yz - wx);     r.m[3][1] = 0.0f;
        r.m[0][2] = 2.0f * (xz - wy);       r.m[1][2] = 2.0f * (yz + wx);     r.m[2][2] = 1.0f - 2.0f * (xx + yy); r.m[3][2] = 0.0f;
        r.m[0][3] = 0.0f;                   r.m[1][3] = 0.0f;                   r.m[2][3] = 0.0f;                   r.m[3][3] = 1.0f;
        return r;
    }
};

} // namespace Sunshine
