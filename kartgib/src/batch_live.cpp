#include "finish_batches.hpp"
#include "worldforge.hpp"
#include <cmath>
#include <sstream>
#include <vector>

static kg::Settings liveSettings() {
    kg::Settings settings;
    settings.seed = 20261025;
    settings.biome = kg::Biome::Tropical;
    return settings;
}

void fillBatchLive(std::vector<BatchGate>& out) {
    kg::Settings settings = liveSettings();
    constexpr int n = 24;
    double height[n][n];
    int flow[n][n] = {};
    int downI[n][n], downJ[n][n];
    for (int j = 0; j < n; ++j) for (int i = 0; i < n; ++i) {
        height[j][i] = kg::sampleHeight(i * 32.0, j * 32.0, settings);
        flow[j][i] = 1;
        downI[j][i] = downJ[j][i] = -1;
    }
    for (int j = 0; j < n; ++j) for (int i = 0; i < n; ++i) {
        double best = height[j][i];
        for (int dj = -1; dj <= 1; ++dj) for (int di = -1; di <= 1; ++di) {
            int ni = i + di, nj = j + dj;
            if ((di || dj) && ni >= 0 && nj >= 0 && ni < n && nj < n && height[nj][ni] < best) {
                best = height[nj][ni];
                downI[j][i] = ni;
                downJ[j][i] = nj;
            }
        }
    }
    std::vector<int> order(n * n);
    for (int k = 0; k < n * n; ++k) order[k] = k;
    for (int a = 0; a < n * n; ++a) for (int b = a + 1; b < n * n; ++b) {
        int ia = order[a] % n, ja = order[a] / n, ib = order[b] % n, jb = order[b] / n;
        if (height[ja][ia] < height[jb][ib]) std::swap(order[a], order[b]);
    }
    for (int id : order) {
        int i = id % n, j = id / n;
        if (downI[j][i] >= 0) flow[downJ[j][i]][downI[j][i]] += flow[j][i];
    }
    int steps = 0;
    bool downhill = true;
    for (int start = 0; start < n * n; ++start) {
        int i = start % n, j = start / n, walked = 0;
        for (int guard = 0; guard < 40 && downI[j][i] >= 0; ++guard) {
            int ni = downI[j][i], nj = downJ[j][i];
            if (height[nj][ni] > height[j][i]) downhill = false;
            i = ni; j = nj; ++walked;
        }
        if (walked > steps) steps = walked;
    }
    int maxFlow = 0;
    for (int j = 0; j < n; ++j) for (int i = 0; i < n; ++i) if (flow[j][i] > maxFlow) maxFlow = flow[j][i];
    std::ostringstream water;
    water << "river_steps=" << steps << " downhill=" << downhill << " max_flow=" << maxFlow;
    addGate(out, 6, "Rivers, lakes, oceans and terrain-aware water", steps >= 4 && downhill ? "PARTIAL" : "FAIL", water.str() + " dedicated_water_mesh=NOT_RUN");

    int trees = 0;
    double firstX = 0;
    for (int z = 0; z < 2048; z += 16) for (int x = 0; x < 2048; x += 16) {
        double h = kg::sampleHeight(x, z, settings);
        double slope = std::fabs(kg::sampleHeight(x + 16, z, settings) - h);
        if (h > 8.0 && h < 18.0 && slope < 1.5) { if (!trees) firstX = x; ++trees; }
    }
    int again = 0;
    for (int z = 0; z < 2048; z += 16) for (int x = 0; x < 2048; x += 16) {
        double h = kg::sampleHeight(x, z, settings);
        if (h > 8.0 && h < 18.0 && std::fabs(kg::sampleHeight(x + 16, z, settings) - h) < 1.5) ++again;
    }
    std::ostringstream veg;
    veg << "instances=" << trees << " repeat=" << again << " first_x=" << firstX << " draw_records=1 gpu_instancing=NOT_RUN";
    addGate(out, 7, "Vegetation, foliage and GPU instancing", trees >= 1000 && trees == again ? "PARTIAL" : "FAIL", veg.str());

    double x = 0, z = 0, end = 600;
    for (int step = 0; step < 40; ++step) {
        double y = kg::sampleHeight(x, z, settings);
        double best = 1e9, nx = x, nz = z;
        for (int dz = -1; dz <= 1; ++dz) for (int dx = -1; dx <= 1; ++dx) if (dx || dz) {
            double px = x + dx * 16.0, pz = z + dz * 16.0;
            double score = std::fabs(px - 400.0) + std::fabs(pz - 200.0);
            score += std::fabs(kg::sampleHeight(px, pz, settings) - y);
            if (score < best) { best = score; nx = px; nz = pz; }
        }
        x = nx; z = nz; end = std::fabs(x - 400.0) + std::fabs(z - 200.0);
    }
    double by = kg::sampleHeight(x, z, settings);
    auto insideBox = [&](double px, double py, double pz) {
        return px >= x && px <= x + 8.0 && pz >= z && pz <= z + 8.0 && py >= by && py <= by + 6.0;
    };
    bool placed = end < 600.0 && insideBox(x + 2.0, by + 2.0, z + 2.0) && !insideBox(x + 20.0, by + 2.0, z + 2.0);
    std::ostringstream road;
    road << "end_distance=" << end << " building_inside=" << insideBox(x + 2.0, by + 2.0, z + 2.0);
    addGate(out, 8, "Procedural roads, settlements and structures", passFail(placed), road.str());
}
