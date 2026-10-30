#include "vulkan_renderer.hpp"
#include <algorithm>
#include <cmath>

static void cross3(const float a[3], const float b[3], float o[3]) {
    o[0] = a[1] * b[2] - a[2] * b[1];
    o[1] = a[2] * b[0] - a[0] * b[2];
    o[2] = a[0] * b[1] - a[1] * b[0];
}
static void norm3(float v[3]) {
    float l = std::sqrt(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]);
    if (l > 1e-6f) { v[0] /= l; v[1] /= l; v[2] /= l; }
}

void VulkanRenderer::fillCascadeMatrices(UniformBufferObject& ubo) {
    float dir[3] = {ubo.lightDir[0], ubo.lightDir[1], ubo.lightDir[2]};
    norm3(dir);
    float upRef[3] = {std::fabs(dir[1]) > 0.9f ? 1.0f : 0.0f, std::fabs(dir[1]) > 0.9f ? 0.0f : 1.0f, 0.0f};
    float rightL[3], upL[3];
    cross3(upRef, dir, rightL);
    norm3(rightL);
    cross3(dir, rightL, upL);
    float right[3] = {ubo.view[0], ubo.view[4], ubo.view[8]};
    float up[3] = {ubo.view[1], ubo.view[5], ubo.view[9]};
    float fwd[3] = {-ubo.view[2], -ubo.view[6], -ubo.view[10]};
    float eye[3] = {ubo.cameraPos[0], ubo.cameraPos[1], ubo.cameraPos[2]};
    float ends[5] = {0.5f, 0, 0, 0, 300.0f};
    for (int i = 1; i <= 4; ++i) {
        float p = static_cast<float>(i) / 4.0f;
        float logd = 0.5f * std::pow(300.0f / 0.5f, p);
        float uni = 0.5f + (300.0f - 0.5f) * p;
        ends[i] = uni * 0.4f + logd * 0.6f;
    }
    for (int c = 0; c < 4; ++c) {
        float lx[8], ly[8], lz[8];
        int n = 0;
        for (int slice = 0; slice < 2; ++slice) {
            float dist = ends[c + slice];
            float hx = dist / ubo.proj[0];
            float hy = dist / ubo.proj[5];
            for (int sx = -1; sx <= 1; sx += 2) {
                for (int sy = -1; sy <= 1; sy += 2) {
                    float w[3] = {
                        eye[0] + right[0] * sx * hx + up[0] * sy * hy + fwd[0] * dist,
                        eye[1] + right[1] * sx * hx + up[1] * sy * hy + fwd[1] * dist,
                        eye[2] + right[2] * sx * hx + up[2] * sy * hy + fwd[2] * dist};
                    lx[n] = rightL[0] * w[0] + rightL[1] * w[1] + rightL[2] * w[2];
                    ly[n] = upL[0] * w[0] + upL[1] * w[1] + upL[2] * w[2];
                    lz[n] = dir[0] * w[0] + dir[1] * w[1] + dir[2] * w[2];
                    n++;
                }
            }
        }
        float cx = 0, cy = 0, z0 = lz[0], z1 = lz[0], radius = 40.0f;
        for (int i = 0; i < 8; ++i) { cx += lx[i]; cy += ly[i]; z0 = std::min(z0, lz[i]); z1 = std::max(z1, lz[i]); }
        cx /= 8.0f; cy /= 8.0f;
        for (int i = 0; i < 8; ++i) {
            float d = std::sqrt((lx[i] - cx) * (lx[i] - cx) + (ly[i] - cy) * (ly[i] - cy));
            radius = std::max(radius, d);
        }
        radius += 180.0f;
        float texel = (2.0f * radius) / 1024.0f;
        cx = std::floor(cx / texel) * texel;
        cy = std::floor(cy / texel) * texel;
        float minX = cx - radius, maxX = cx + radius, minY = cy - radius, maxY = cy + radius;
        z0 -= 400.0f; z1 += 80.0f;
        float sx = 2.0f / (maxX - minX), sy = 2.0f / (maxY - minY), sz = 1.0f / (z1 - z0);
        float* m = ubo.cascadeVp[c];
        m[0] = sx * rightL[0]; m[1] = sy * upL[0]; m[2] = sz * dir[0]; m[3] = 0;
        m[4] = sx * rightL[1]; m[5] = sy * upL[1]; m[6] = sz * dir[1]; m[7] = 0;
        m[8] = sx * rightL[2]; m[9] = sy * upL[2]; m[10] = sz * dir[2]; m[11] = 0;
        m[12] = -(maxX + minX) / (maxX - minX);
        m[13] = -(maxY + minY) / (maxY - minY);
        m[14] = -z0 * sz;
        m[15] = 1;
        ubo.cascadeSplits[c] = ends[c + 1];
    }
}
