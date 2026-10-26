#include "terrain_studio.hpp"
#include <cmath>

void studioCamera(float view[16], float proj[16], int width, int height) {
    float ex = -40, ey = 24, ez = -55, tx = 20, ty = 12, tz = 35;
    float fx = tx - ex, fy = ty - ey, fz = tz - ez;
    float fl = std::sqrt(fx * fx + fy * fy + fz * fz);
    fx /= fl; fy /= fl; fz /= fl;
    float rx = fy, ry = -fz, rz = -fx * 0 + fx; 
    rx = fy * 0 - fz * 1; ry = fz * 0 - fx * 0; rz = fx * 1 - fy * 0;
    float rl = std::sqrt(rx * rx + ry * ry + rz * rz);
    rx /= rl; ry /= rl; rz /= rl;
    float ux = ry * fz - rz * fy, uy = rz * fx - rx * fz, uz = rx * fy - ry * fx;
    view[0] = rx; view[1] = ux; view[2] = -fx; view[3] = 0;
    view[4] = ry; view[5] = uy; view[6] = -fy; view[7] = 0;
    view[8] = rz; view[9] = uz; view[10] = -fz; view[11] = 0;
    view[12] = -(rx * ex + ry * ey + rz * ez);
    view[13] = -(ux * ex + uy * ey + uz * ez);
    view[14] = (fx * ex + fy * ey + fz * ez); view[15] = 1;
    for (int i = 0; i < 16; ++i) proj[i] = 0;
    float aspect = static_cast<float>(width) / static_cast<float>(height > 0 ? height : 1);
    float f = 1.0f / std::tan(1.04719755f * 0.5f);
    proj[0] = f / aspect; proj[5] = -f;
    proj[10] = 4000.0f / (0.5f - 4000.0f); proj[11] = -1.0f;
    proj[14] = (4000.0f * 0.5f) / (0.5f - 4000.0f);
}
bool studioProject(const float view[16], const float proj[16], float x, float y, float z,
    int width, int height, int& px, int& py) {
    float e0 = view[0] * x + view[4] * y + view[8] * z + view[12];
    float e1 = view[1] * x + view[5] * y + view[9] * z + view[13];
    float e2 = view[2] * x + view[6] * y + view[10] * z + view[14];
    float e3 = view[3] * x + view[7] * y + view[11] * z + view[15];
    float c0 = proj[0] * e0 + proj[4] * e1 + proj[8] * e2 + proj[12] * e3;
    float c1 = proj[1] * e0 + proj[5] * e1 + proj[9] * e2 + proj[13] * e3;
    float c3 = proj[3] * e0 + proj[7] * e1 + proj[11] * e2 + proj[15] * e3;
    if (c3 < 0.05f) return false;
    px = static_cast<int>((c0 / c3 * 0.5f + 0.5f) * width);
    py = static_cast<int>((c1 / c3 * 0.5f + 0.5f) * height);
    return true;
}
int studioStampScreen(const float view[16], const float proj[16], int width, int height, int mx, int my) {
    float rx = view[0], ry = view[4], rz = view[8];
    float ux = view[1], uy = view[5], uz = view[9];
    float fx = -view[2], fy = -view[6], fz = -view[10];
    float ex = rx * -view[12] + ux * -view[13] + fx * view[14];
    float ey = ry * -view[12] + uy * -view[13] + fy * view[14];
    float ez = rz * -view[12] + uz * -view[13] + fz * view[14];
    float ndcX = (static_cast<float>(mx) + 0.5f) / static_cast<float>(width) * 2.0f - 1.0f;
    float ndcY = (static_cast<float>(my) + 0.5f) / static_cast<float>(height) * 2.0f - 1.0f;
    float dx = rx * ndcX / proj[0] + ux * ndcY / proj[5] + fx;
    float dy = ry * ndcX / proj[0] + uy * ndcY / proj[5] + fy;
    float dz = rz * ndcX / proj[0] + uz * ndcY / proj[5] + fz;
    float len = std::sqrt(dx * dx + dy * dy + dz * dz);
    if (len < 1.0e-4f || proj[0] == 0.0f || proj[5] == 0.0f) return 0;
    dx /= len; dy /= len; dz /= len;
    for (float t = 1.0f; t < 300.0f; t += 0.75f) {
        float x = ex + dx * t, y = ey + dy * t, z = ez + dz * t;
        if (x < -64.0f || x > 64.0f || z < -64.0f || z > 64.0f) continue;
        if (y <= studioHeight(x, z) + 0.25f) return studioStamp(x, z);
    }
    return 0;
}
int studioStrokeScreen(const float view[16], const float proj[16], int width, int height, int mx, int my) {
    studioBegin();
    int n = studioStampScreen(view, proj, width, height, mx, my);
    studioEnd();
    return n;
}
