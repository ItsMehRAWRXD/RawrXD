#include "ocean_field.hpp"
#include "vulkan_renderer.hpp"
#include <cmath>
#include <vector>

static float fieldAt(const std::vector<float>& src, int n, int i, int j) {
    i = (i % n + n) % n; j = (j % n + n) % n;
    return src[static_cast<size_t>(j * n + i)];
}

void appendOceanMesh(std::vector<Vertex>& verts, std::vector<uint32_t>& indices, const OceanField& field) {
    const int cells = 48;
    uint32_t base = static_cast<uint32_t>(verts.size());
    for (int j = 0; j <= cells; ++j) {
        for (int i = 0; i <= cells; ++i) {
            float x = -field.tile * 0.5f + field.tile * static_cast<float>(i) / cells;
            float z = -field.tile * 0.5f + field.tile * static_cast<float>(j) / cells;
            float u = (x / field.tile + 0.5f) * field.n;
            float v = (z / field.tile + 0.5f) * field.n;
            int i0 = static_cast<int>(std::floor(u)), j0 = static_cast<int>(std::floor(v));
            float y = field.level + fieldAt(field.height, field.n, i0, j0);
            x += fieldAt(field.dispX, field.n, i0, j0);
            z += fieldAt(field.dispY, field.n, i0, j0);
            float hl = fieldAt(field.height, field.n, i0 - 1, j0);
            float hr = fieldAt(field.height, field.n, i0 + 1, j0);
            float hd = fieldAt(field.height, field.n, i0, j0 - 1);
            float hu = fieldAt(field.height, field.n, i0, j0 + 1);
            float nx = hl - hr, ny = 4.0f, nz = hd - hu;
            float len = std::sqrt(nx * nx + ny * ny + nz * nz);
            Vertex vert{};
            vert.pos[0] = x; vert.pos[1] = y; vert.pos[2] = z;
            vert.normal[0] = nx / len; vert.normal[1] = ny / len; vert.normal[2] = nz / len;
            vert.uv[0] = fieldAt(field.foam, field.n, i0, j0);
            vert.uv[1] = 2.0f;
            verts.push_back(vert);
        }
    }
    int row = cells + 1;
    for (int j = 0; j < cells; ++j) for (int i = 0; i < cells; ++i) {
        uint32_t a = base + static_cast<uint32_t>(j * row + i);
        uint32_t b = a + 1, c = a + static_cast<uint32_t>(row), d = c + 1;
        indices.insert(indices.end(), {a, c, b, b, c, d});
    }
}
