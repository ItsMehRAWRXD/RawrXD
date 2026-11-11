#include "ocean_field.hpp"
#include <cmath>
#include <iostream>
#include <vector>

static OceanCert gCert;

static bool sineMatches() {
    const int n = 8;
    std::vector<Cx> data(static_cast<size_t>(n), {});
    data[1] = {0.0f, -0.5f * n};
    data[n - 1] = {0.0f, 0.5f * n};
    ifft1d(data.data(), n);
    float err = 0;
    for (int i = 0; i < n; ++i) {
        float expect = std::sin(6.28318530718f * static_cast<float>(i) / n);
        err = std::max(err, std::fabs(data[static_cast<size_t>(i)].r - expect));
        err = std::max(err, std::fabs(data[static_cast<size_t>(i)].i));
    }
    return err < 1.0e-3f;
}

static bool spectraPeak() {
    OceanParams params;
    float best = -1.0f; int bestI = -1;
    bool nonNeg = true;
    for (int i = 1; i <= 24; ++i) {
        float k = static_cast<float>(i) * 0.03f;
        float p = phillipsP(k, 0.01f, params);
        float m = piersonP(k, 0.01f, params);
        float j = jonswapP(k, 0.01f, params);
        if (p < 0 || m < 0 || j < 0 || !std::isfinite(p + m + j)) nonNeg = false;
        if (j > best) { best = j; bestI = i; }
    }
    return nonNeg && phillipsP(0, 0, params) == 0 && bestI > 2 && bestI < 24 && best > 0;
}

const OceanCert& oceanCpuCert() { return gCert; }
void setOceanGpu(bool ok, float error) { gCert.gpu = ok ? "PASS" : "FAIL"; gCert.gpuError = error; }

OceanCert runOceanCpuCert() {
    OceanCert cert;
    cert.fft = sineMatches();
    cert.spectra = spectraPeak();
    OceanField a, later, single;
    OceanParams params;
    buildOcean(params, 0.0f, a);
    buildOcean(params, 2.5f, later);
    OceanParams one = params; one.cascades = 1;
    buildOcean(one, 0.0f, single);
    cert.finite = std::isfinite(a.minH) && std::isfinite(a.maxH) && a.height.size() == 32u * 32u;
    cert.hermitian = a.imagMax < 1.0e-2f;
    cert.animated = a.maxH - a.minH > 0.2f && a.height[20] != later.height[20];
    cert.foam = a.foamCells > 0;
    float x = (4.0f / 32.0f - 0.5f) * a.tile;
    float z = (5.0f / 32.0f - 0.5f) * a.tile;
    float surface = sampleOcean(a, x, z);
    float expect = a.level + a.height[5 * 32 + 4];
    auto accel = [&](float probe) { float depth = surface - probe; return depth > 0.0f ? depth * params.gravity : 0.0f; };
    cert.buoyant = std::fabs(surface - expect) < 1.0e-3f && accel(surface - 0.4f) > 3.0f && accel(surface + 0.4f) == 0.0f;
    cert.cascade = std::fabs(single.height[20] - a.height[20]) > 1.0e-4f;
    cert.imagMax = a.imagMax; cert.minH = a.minH; cert.maxH = a.maxH;
    cert.gpu = "NOT_RUN";
    gCert = cert;
    std::cout << "[OCEAN] fft=" << cert.fft << " spectra=" << cert.spectra << " imag=" << cert.imagMax
              << " range=" << cert.minH << "," << cert.maxH << " foam=" << a.foamCells
              << " gain=" << a.gain << " animated=" << cert.animated << std::endl;
    return cert;
}
