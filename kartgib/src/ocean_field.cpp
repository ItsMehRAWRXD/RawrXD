#include "ocean_field.hpp"
#include <cmath>
#include <vector>

static Cx mul(Cx a, Cx b) { return {a.r * b.r - a.i * b.i, a.r * b.i + a.i * b.r}; }

void buildOcean(const OceanParams& params, float time, OceanField& out) {
    int n = params.n;
    out = {};
    out.n = n;
    out.tile = params.tile;
    out.level = params.level;
    out.height.assign(static_cast<size_t>(n * n), 0.0f);
    out.dispX.assign(static_cast<size_t>(n * n), 0.0f);
    out.dispY.assign(static_cast<size_t>(n * n), 0.0f);
    out.foam.assign(static_cast<size_t>(n * n), 0.0f);
    const float tiles[3] = {params.tile, params.tile * 0.35f, params.tile * 0.12f};
    const float gains[3] = {1.0f, 0.45f, 0.2f};
    for (int cascade = 0; cascade < params.cascades; ++cascade) {
        OceanParams local = params;
        local.tile = tiles[cascade];
        local.seed ^= uint64_t(cascade + 1) * 0x9e3779b97f4a7c15ull;
        std::vector<Cx> h0, height(static_cast<size_t>(n * n)), dx(height.size()), dy(height.size());
        fillSpectrum(local, h0);
        for (int j = 0; j < n; ++j) for (int i = 0; i < n; ++i) {
            float kx, kz;
            waveVector(i, j, local, kx, kz);
            float k = std::sqrt(kx * kx + kz * kz);
            size_t id = static_cast<size_t>(j * n + i);
            if (k < 1.0e-4f) { height[id] = dx[id] = dy[id] = {}; continue; }
            float w = oceanOmega(kx, kz, local) * time;
            Cx pos{std::cos(w), std::sin(w)};
            Cx neg{std::cos(w), -std::sin(w)};
            int ni = (n - i) % n, nj = (n - j) % n;
            Cx mirror = h0[static_cast<size_t>(nj * n + ni)];
            mirror.i = -mirror.i;
            Cx h = mul(h0[id], pos);
            Cx back = mul(mirror, neg);
            h.r += back.r; h.i += back.i;
            height[id] = h;
            dx[id] = {kx / k * h.i, -kx / k * h.r};
            dy[id] = {kz / k * h.i, -kz / k * h.r};
        }
        ifft2d(height, n); ifft2d(dx, n); ifft2d(dy, n);
        for (size_t id = 0; id < height.size(); ++id) {
            out.height[id] += height[id].r * gains[cascade];
            out.dispX[id] += dx[id].r * gains[cascade];
            out.dispY[id] += dy[id].r * gains[cascade];
            out.imagMax = std::max(out.imagMax, std::fabs(height[id].i));
        }
    }
    double mean = 0;
    for (float h : out.height) mean += h;
    mean /= static_cast<double>(out.height.size());
    double var = 0;
    for (float h : out.height) var += (h - mean) * (h - mean);
    var /= static_cast<double>(out.height.size());
    out.gain = 0.65f / static_cast<float>(std::sqrt(var + 1.0e-8));
    out.minH = 1.0e9f; out.maxH = -1.0e9f;
    for (size_t id = 0; id < out.height.size(); ++id) {
        out.height[id] = (out.height[id] - static_cast<float>(mean)) * out.gain;
        out.dispX[id] *= out.gain * 0.6f;
        out.dispY[id] *= out.gain * 0.6f;
        out.minH = std::min(out.minH, out.height[id]);
        out.maxH = std::max(out.maxH, out.height[id]);
    }
    for (int j = 0; j < n; ++j) for (int i = 0; i < n; ++i) {
        float dxx = out.dispX[static_cast<size_t>(j * n + (i + 1) % n)] - out.dispX[static_cast<size_t>(j * n + i)];
        float dyy = out.dispY[static_cast<size_t>(((j + 1) % n) * n + i)] - out.dispY[static_cast<size_t>(j * n + i)];
        float jacobian = (1.0f + dxx) * (1.0f + dyy);
        if (jacobian < 0.72f) { out.foam[static_cast<size_t>(j * n + i)] = std::min(1.0f, (0.72f - jacobian) * 2.0f); ++out.foamCells; }
    }
    int wake = n / 2;
    out.height[static_cast<size_t>(wake * n + wake)] -= 0.35f;
}

float sampleOcean(const OceanField& field, float x, float z) {
    float u = x / field.tile + 0.5f;
    float v = z / field.tile + 0.5f;
    u -= std::floor(u); v -= std::floor(v);
    float fx = u * static_cast<float>(field.n);
    float fz = v * static_cast<float>(field.n);
    int i0 = static_cast<int>(fx) % field.n, j0 = static_cast<int>(fz) % field.n;
    int i1 = (i0 + 1) % field.n, j1 = (j0 + 1) % field.n;
    float tx = fx - std::floor(fx), tz = fz - std::floor(fz);
    auto h = [&](int i, int j) { return field.height[static_cast<size_t>(j * field.n + i)]; };
    float a = h(i0, j0) * (1 - tx) + h(i1, j0) * tx;
    float b = h(i0, j1) * (1 - tx) + h(i1, j1) * tx;
    return field.level + a * (1 - tz) + b * tz;
}
