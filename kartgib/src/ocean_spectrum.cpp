#include "ocean_field.hpp"
#include <cmath>

static float hash01(uint64_t x) {
    x ^= x >> 30; x *= 0xbf58476d1ce4e5b9ull; x ^= x >> 27; x *= 0x94d049bb133111ebull; x ^= x >> 31;
    return static_cast<float>((x >> 11) * (1.0 / 9007199254740992.0));
}
static Cx gaussian(uint64_t seed) {
    float u = hash01(seed);
    float v = hash01(seed ^ 0x9e3779b97f4a7c15ull);
    if (u < 1.0e-6f) u = 1.0e-6f;
    float radius = std::sqrt(-2.0f * std::log(u));
    float ang = 6.28318530718f * v;
    return {radius * std::cos(ang), radius * std::sin(ang)};
}
void waveVector(int i, int j, const OceanParams& params, float& kx, float& kz) {
    auto axis = [&](int c) { return (c <= params.n / 2 ? c : c - params.n) * 6.28318530718f / params.tile; };
    kx = axis(i);
    kz = axis(j);
}
float oceanOmega(float kx, float kz, const OceanParams& params) {
    float k = std::sqrt(kx * kx + kz * kz);
    if (k < 1.0e-5f) return 0.0f;
    return std::sqrt(params.gravity * k * std::tanh(k * params.depth));
}
static float spread(float kx, float kz, const OceanParams& params, float k) {
    float wind = std::sqrt(params.windX * params.windX + params.windZ * params.windZ);
    float align = (kx * params.windX + kz * params.windZ) / (k * wind + 1.0e-6f);
    return align > 0.0f ? align * align : 0.0f;
}
float phillipsP(float kx, float kz, const OceanParams& params) {
    float k = std::sqrt(kx * kx + kz * kz);
    if (k < 1.0e-4f) return 0.0f;
    float wind = std::sqrt(params.windX * params.windX + params.windZ * params.windZ);
    float length = wind * wind / params.gravity;
    float k2 = k * k;
    float small = length * 0.001f;
    return params.amplitude * std::exp(-1.0f / (k2 * length * length)) / (k2 * k2) * spread(kx, kz, params, k) * std::exp(-k2 * small * small);
}
float piersonP(float kx, float kz, const OceanParams& params) {
    float k = std::sqrt(kx * kx + kz * kz);
    if (k < 1.0e-4f) return 0.0f;
    float wind = std::sqrt(params.windX * params.windX + params.windZ * params.windZ);
    float expo = std::exp(-0.74f * std::pow(params.gravity / (k * wind * wind), 2.0f));
    return 0.0081f * expo / (k * k * k) * spread(kx, kz, params, k);
}
float jonswapP(float kx, float kz, const OceanParams& params) {
    float base = piersonP(kx, kz, params);
    float k = std::sqrt(kx * kx + kz * kz);
    if (k < 1.0e-4f) return 0.0f;
    float wind = std::sqrt(params.windX * params.windX + params.windZ * params.windZ);
    float fetch = params.gravity * params.fetch / (wind * wind + 1.0f);
    float omegaP = 22.0f * params.gravity / (wind * std::pow(fetch, 0.33f) + 1.0f);
    float omega = oceanOmega(kx, kz, params);
    float sigma = omega <= omegaP ? 0.07f : 0.09f;
    float peak = std::exp(-((omega - omegaP) * (omega - omegaP)) / (2.0f * sigma * sigma * omegaP * omegaP + 1.0e-6f));
    return base * std::pow(3.3f, peak);
}
void fillSpectrum(const OceanParams& params, std::vector<Cx>& h0) {
    int n = params.n;
    h0.assign(static_cast<size_t>(n * n), {});
    for (int j = 0; j < n; ++j) for (int i = 0; i < n; ++i) {
        float kx, kz;
        waveVector(i, j, params, kx, kz);
        float power = jonswapP(kx, kz, params);
        Cx g = gaussian(params.seed ^ (uint64_t(i) * 1315423911ull) ^ (uint64_t(j) * 2654435761ull));
        float amp = std::sqrt(std::max(power, 0.0f) * 0.5f);
        h0[static_cast<size_t>(j * n + i)] = {g.r * amp, g.i * amp};
    }
}
