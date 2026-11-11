#include "worldforge_bridge.hpp"
#include <cmath>
#include <cstdint>
#include <vector>

static void climateUv(double x, double z, const kg::Settings& settings, float& u, float& v) {
    kg::Settings temp = settings;
    temp.seed ^= 0x51A7ull;
    temp.biome = kg::Biome::Tropical;
    kg::Settings moist = settings;
    moist.seed ^= 0xC0FFEEull;
    moist.biome = kg::Biome::Tropical;
    double t = ((kg::sampleHeight(x, z, temp) - 6.0) / 22.0) * 0.5 + 0.5;
    double m = ((kg::sampleHeight(x, z, moist) - 6.0) / 22.0) * 0.5 + 0.5;
    u = static_cast<float>(std::clamp(t, 0.0, 1.0));
    v = static_cast<float>(std::clamp(m, 0.0, 1.0));
}

void appendChunkMesh(std::vector<Vertex>& verts, std::vector<uint32_t>& indices,
    int cx, int cz, const std::vector<double>& h, const kg::Settings& settings, int step, int edgeMask) {
    constexpr int cells = 64;
    constexpr int full = 65;
    constexpr double kCell = 8.0;
    int n = cells / step + 1;
    uint32_t base = static_cast<uint32_t>(verts.size());
    for (int j = 0; j < n; ++j) {
        for (int i = 0; i < n; ++i) {
            int si = i * step, sj = j * step;
            double x = (cx * cells + si) * kCell;
            double z = (cz * cells + sj) * kCell;
            double y = h[static_cast<size_t>(sj * full + si)];
            double dx = kg::sampleHeight(x + kCell, z, settings) - kg::sampleHeight(x - kCell, z, settings);
            double dz = kg::sampleHeight(x, z + kCell, settings) - kg::sampleHeight(x, z - kCell, settings);
            double nx = -dx, ny = 2 * kCell, nz = -dz;
            double len = std::sqrt(nx * nx + ny * ny + nz * nz);
            Vertex v{};
            v.pos[0] = static_cast<float>(x);
            v.pos[1] = static_cast<float>(y);
            v.pos[2] = static_cast<float>(z);
            v.normal[0] = static_cast<float>(nx / len);
            v.normal[1] = static_cast<float>(ny / len);
            v.normal[2] = static_cast<float>(nz / len);
            climateUv(x, z, settings, v.uv[0], v.uv[1]);
            verts.push_back(v);
        }
    }
    auto at = [&](int i, int j) { return base + static_cast<uint32_t>(j * n + i); };
    if (edgeMask & 1) for (int j = 1; j < n - 1; j += 2)
        verts[at(n - 1, j)].pos[1] = 0.5f * (verts[at(n - 1, j - 1)].pos[1] + verts[at(n - 1, j + 1)].pos[1]);
    if (edgeMask & 2) for (int j = 1; j < n - 1; j += 2)
        verts[at(0, j)].pos[1] = 0.5f * (verts[at(0, j - 1)].pos[1] + verts[at(0, j + 1)].pos[1]);
    if (edgeMask & 4) for (int i = 1; i < n - 1; i += 2)
        verts[at(i, n - 1)].pos[1] = 0.5f * (verts[at(i - 1, n - 1)].pos[1] + verts[at(i + 1, n - 1)].pos[1]);
    if (edgeMask & 8) for (int i = 1; i < n - 1; i += 2)
        verts[at(i, 0)].pos[1] = 0.5f * (verts[at(i - 1, 0)].pos[1] + verts[at(i + 1, 0)].pos[1]);
    for (int j = 0; j < n - 1; ++j) {
        for (int i = 0; i < n - 1; ++i) {
            uint32_t a = at(i, j), b = at(i + 1, j), c = at(i, j + 1), d = at(i + 1, j + 1);
            indices.insert(indices.end(), {a, c, b, b, c, d});
        }
    }
}
