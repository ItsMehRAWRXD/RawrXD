#include "worldforge.hpp"
#include <cmath>
#include <fstream>
#include <iostream>
#include <string>

static float evalGraph(uint64_t seed, double x, double z) {
    kg::Settings broad; broad.seed = seed; broad.biome = kg::Biome::Tropical;
    double warp = kg::sampleHeight(x * 0.15, z * 0.15, broad);
    double px = x + warp * 18.0, pz = z + warp * 11.0;
    kg::Settings relief = broad; relief.seed ^= 0x51A7ull;
    return static_cast<float>(kg::sampleHeight(px * 0.04, pz * 0.04, broad) * 0.35 + kg::sampleHeight(px, pz, relief));
}
static int plateId(uint64_t seed, double x, double z) {
    int best = 0; double bestD = 1.0e30;
    for (int i = 0; i < 4; ++i) {
        kg::Settings s; s.seed = seed + uint64_t(i * 97); s.biome = kg::Biome::Tropical;
        double sx = kg::sampleHeight(i * 40.0, 10.0, s);
        double sz = kg::sampleHeight(10.0, i * 40.0, s);
        double d = (x - sx) * (x - sx) + (z - sz) * (z - sz);
        if (d < bestD) { bestD = d; best = i; }
    }
    return best;
}

int runTerrainCert(const std::string& dir) {
    const char* name[25] = {"G07 graph","G08 tectonics","G09 warp","G10 hydraulic","G11 thermal","G12 geology","G13 rivers","G14 lakes","G15 dunes","G16 glaciers","G17 volcanoes","G18 coast","G19 seafloor","G20 sdf","G21 caves","G22 climate","G23 forests","G24 seasons","G25 planets","G26 floating","G27 fractals","G28 non-euclidean","G29 settlements","G30 editor","G31 release"};
    const char* status[25];
    for (int i = 0; i < 25; ++i) status[i] = "NOT_RUN";
    float a = evalGraph(20261025, 12.0, 40.0);
    float b = evalGraph(20261025, 12.0, 40.0);
    float edgeA = evalGraph(20261025, 64.0, 0.0);
    float edgeB = evalGraph(20261025, 64.0, 0.0);
    status[0] = (a == b && edgeA == edgeB && std::isfinite(a)) ? "PARTIAL" : "FAIL";
    int boundaries = 0;
    for (int i = 0; i < 12; ++i) if (plateId(20261025, i * 30.0, 0.0) != plateId(20261025, (i + 1) * 30.0, 0.0)) ++boundaries;
    status[1] = boundaries > 0 ? "PARTIAL" : "FAIL";
    status[2] = evalGraph(7, 3.0, 9.0) == evalGraph(7, 3.0, 9.0) ? "PARTIAL" : "FAIL";
    constexpr int n = 12;
    float h[n * n]; int nx[n * n], ny[n * n];
    for (int j = 0; j < n; ++j) for (int i = 0; i < n; ++i) {
        h[j * n + i] = evalGraph(20261025, i * 28.0, j * 28.0); nx[j * n + i] = ny[j * n + i] = -1;
    }
    for (int j = 0; j < n; ++j) for (int i = 0; i < n; ++i) {
        float best = h[j * n + i];
        for (int dj = -1; dj <= 1; ++dj) for (int di = -1; di <= 1; ++di) {
            int x = i + di, z = j + dj;
            if ((di || dj) && x >= 0 && z >= 0 && x < n && z < n && h[z * n + x] < best) { best = h[z * n + x]; nx[j * n + i] = x; ny[j * n + i] = z; }
        }
    }
    int steps = 0;
    for (int s = 0; s < n * n; ++s) {
        int i = s % n, j = s / n, walked = 0;
        for (int g = 0; g < 16 && nx[j * n + i] >= 0; ++g) { int i2 = nx[j * n + i], j2 = ny[j * n + i]; i = i2; j = j2; ++walked; }
        if (walked > steps) steps = walked;
    }
    status[6] = steps >= 3 ? "PARTIAL" : "FAIL";
    std::ofstream json(dir + "/G07_G31_TERRAIN_CERTIFICATION_001.json");
    json << "{\"gate\":\"G07_G31_UNIVERSAL_TERRAIN_GENERATION_001\",\"promote\":0,\"batches\":[\n";
    int pass = 0, partial = 0, notrun = 0, fail = 0;
    for (int i = 0; i < 25; ++i) {
        json << "{\"id\":" << (7 + i) << ",\"name\":\"" << name[i] << "\",\"status\":\"" << status[i] << "\"}" << (i == 24 ? "\n" : ",\n");
        if (std::string(status[i]) == "PASS") ++pass; else if (std::string(status[i]) == "PARTIAL") ++partial; else if (std::string(status[i]) == "FAIL") ++fail; else ++notrun;
        std::cout << "[" << name[i] << "] " << status[i] << std::endl;
    }
    json << "],\"pass\":" << pass << ",\"fail\":" << fail << ",\"partial\":" << partial << ",\"not_run\":" << notrun << "}\n";
    return fail == 0 ? 0 : 1;
}
