#include "editor_api.hpp"
#include <cmath>
#include <algorithm>

static float gEx = -30, gEy = 72, gEz = -95, gTx = 16, gTy = 8, gTz = 24, gShift = 0;
void editorPose(float& ex, float& ey, float& ez, float& tx, float& ty, float& tz) {
    float shift = studioCameraShift(), delta = shift - gShift;
    gEx += delta; gTx += delta; gShift = shift;
    ex = gEx; ey = gEy; ez = gEz; tx = gTx; ty = gTy; tz = gTz;
}
void editorCamera(float view[16], float proj[16], int width, int height) {
    float ex, ey, ez, tx, ty, tz, ux = 0, uy = 1, uz = 0;
    editorPose(ex, ey, ez, tx, ty, tz);
    float fx = tx - ex, fy = ty - ey, fz = tz - ez;
    float fl = std::sqrt(fx * fx + fy * fy + fz * fz);
    fx /= fl; fy /= fl; fz /= fl;
    float rx = fy * uz - fz * uy, ry = fz * ux - fx * uz, rz = fx * uy - fy * ux;
    float rl = std::sqrt(rx * rx + ry * ry + rz * rz);
    rx /= rl; ry /= rl; rz /= rl;
    float uxx = ry * fz - rz * fy, uyy = rz * fx - rx * fz, uzz = rx * fy - ry * fx;
    view[0] = rx; view[1] = uxx; view[2] = -fx; view[3] = 0;
    view[4] = ry; view[5] = uyy; view[6] = -fy; view[7] = 0;
    view[8] = rz; view[9] = uzz; view[10] = -fz; view[11] = 0;
    view[12] = -(rx * ex + ry * ey + rz * ez);
    view[13] = -(uxx * ex + uyy * ey + uzz * ez);
    view[14] = (fx * ex + fy * ey + fz * ez); view[15] = 1;
    for (int i = 0; i < 16; ++i) proj[i] = 0;
    float aspect = static_cast<float>(width) / static_cast<float>(std::max(1, height));
    float f = 1.0f / std::tan(1.04719755f * 0.5f);
    proj[0] = f / aspect; proj[5] = -f;
    proj[10] = 4000.0f / (0.5f - 4000.0f); proj[11] = -1.0f;
    proj[14] = (4000.0f * 0.5f) / (0.5f - 4000.0f);
}
static void mul(const float m[16], float x, float y, float z, float w, float o[4]) {
    o[0] = m[0] * x + m[4] * y + m[8] * z + m[12] * w;
    o[1] = m[1] * x + m[5] * y + m[9] * z + m[13] * w;
    o[2] = m[2] * x + m[6] * y + m[10] * z + m[14] * w;
    o[3] = m[3] * x + m[7] * y + m[11] * z + m[15] * w;
}
bool editorProject(const float view[16], const float proj[16], float x, float y, float z,
    int width, int height, int& px, int& py, float& depth) {
    float e[4], c[4];
    mul(view, x, y, z, 1, e);
    mul(proj, e[0], e[1], e[2], e[3], c);
    if (c[3] < 0.05f) return false;
    float nx = c[0] / c[3], ny = c[1] / c[3];
    px = static_cast<int>((nx * 0.5f + 0.5f) * width);
    py = static_cast<int>((ny * 0.5f + 0.5f) * height);
    depth = c[3];
    return true;
}
void editorAxis(int axis, float& dx, float& dy, float& dz) {
    dx = axis == 0 ? 1.0f : 0.0f; dy = axis == 1 ? 1.0f : 0.0f; dz = axis == 2 ? 1.0f : 0.0f;
    const EditorEnt* e = nullptr;
    for (int i = 0; i < editorCount(); ++i) if (editorAt(i)->id == editorSelected()) e = editorAt(i);
    if (!e || !editorLocal()) return;
    float c = std::cos(e->yaw), s = std::sin(e->yaw);
    if (axis == 0) { dx = c; dy = 0; dz = s; }
    if (axis == 2) { dx = -s; dy = 0; dz = c; }
}
