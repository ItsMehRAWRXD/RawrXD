#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct Cx { float r = 0, i = 0; };
struct OceanParams {
    uint64_t seed = 20261025;
    float windX = 9.0f;
    float windZ = 4.0f;
    float gravity = 9.81f;
    float fetch = 80000.0f;
    float depth = 40.0f;
    float amplitude = 0.0008f;
    int n = 32;
    int cascades = 3;
    float tile = 180.0f;
    float level = 8.0f;
};
struct OceanField {
    int n = 0;
    float tile = 0, level = 0, gain = 1, imagMax = 0, minH = 0, maxH = 0;
    int foamCells = 0;
    std::vector<float> height, dispX, dispY, foam;
};
struct OceanCert {
    bool fft = false, finite = false, animated = false, spectra = false;
    bool foam = false, buoyant = false, hermitian = false, cascade = false;
    float imagMax = 0, minH = 0, maxH = 0, gpuError = -1;
    const char* gpu = "NOT_RUN";
};

void ifft1d(Cx* data, int n);
void ifft2d(std::vector<Cx>& data, int n);
float phillipsP(float kx, float kz, const OceanParams& params);
float piersonP(float kx, float kz, const OceanParams& params);
float jonswapP(float kx, float kz, const OceanParams& params);
void waveVector(int i, int j, const OceanParams& params, float& kx, float& kz);
float oceanOmega(float kx, float kz, const OceanParams& params);
void fillSpectrum(const OceanParams& params, std::vector<Cx>& h0);
void buildOcean(const OceanParams& params, float time, OceanField& out);
float sampleOcean(const OceanField& field, float x, float z);
void appendOceanMesh(std::vector<struct Vertex>& verts, std::vector<uint32_t>& indices, const OceanField& field);
OceanCert runOceanCpuCert();
void setOceanGpu(bool ok, float error);
int runTerrainCert(const std::string& dir);
bool runOceanGpuParity(class VulkanRenderer& renderer, float& maxError);
const OceanCert& oceanCpuCert();
