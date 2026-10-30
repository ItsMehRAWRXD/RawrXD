#include "terrain_studio.hpp"

static const int kN = 33;
float* studioHeights();

float studioHeight(float x, float z) {
    const float world = 128.0f;
    float u = (x + world * 0.5f) / world;
    float v = (z + world * 0.5f) / world;
    if (u < 0.0f || v < 0.0f || u > 1.0f || v > 1.0f) return 0.0f;
    int i = static_cast<int>(u * (kN - 1) + 0.5f);
    int j = static_cast<int>(v * (kN - 1) + 0.5f);
    return studioHeights()[j * kN + i];
}
int studioResolution() { return kN; }
float studioHash() {
    float s = 0.0f;
    float* h = studioHeights();
    for (int i = 0; i < kN * kN; ++i) s += h[i];
    return s;
}
