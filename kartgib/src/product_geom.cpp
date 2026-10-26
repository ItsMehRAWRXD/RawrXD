#include "product_scene.hpp"
#include "worldforge_bridge.hpp"
#include "ocean_field.hpp"
#include <cmath>
#include <fstream>

static ProductStats gStats;
ProductStats& productStats() { return gStats; }

static void box(std::vector<Vertex>& v, std::vector<uint32_t>& idx,
    float x, float y, float z, float yaw, float s, float uv) {
    float c = std::cos(yaw), sn = std::sin(yaw), h = 1.6f * s;
    uint32_t b = static_cast<uint32_t>(v.size());
    const float p[8][3] = {{-h,-h,-h},{h,-h,-h},{h,h,-h},{-h,h,-h},{-h,-h,h},{h,-h,h},{h,h,h},{-h,h,h}};
    for (int i = 0; i < 8; ++i) {
        Vertex t{};
        t.pos[0] = x + p[i][0] * c - p[i][2] * sn;
        t.pos[1] = y + p[i][1];
        t.pos[2] = z + p[i][0] * sn + p[i][2] * c;
        t.normal[1] = 1.0f; t.uv[1] = uv;
        v.push_back(t);
    }
    const int f[] = {0,2,1,0,3,2,4,5,6,4,6,7,0,1,5,0,5,4,1,2,6,1,6,5,3,7,6,3,6,2,0,4,7,0,7,3,
        0,1,2,0,2,3,4,6,5,4,7,6,0,5,1,0,4,5,1,6,2,1,5,6,3,6,7,3,2,6,0,7,4,0,3,7};
    for (int i : f) idx.push_back(b + i);
}

static void ribbon(std::vector<Vertex>& v, std::vector<uint32_t>& idx,
    float x0, float y0, float z0, float x1, float y1, float z1) {
    float dx = x1 - x0, dz = z1 - z0, len = std::sqrt(dx * dx + dz * dz);
    if (len < 0.01f) return;
    float px = -dz / len * 8.0f, pz = dx / len * 8.0f;
    uint32_t b = static_cast<uint32_t>(v.size());
    float q[4][3] = {{x0-px,y0,z0-pz},{x0+px,y0,z0+pz},{x1+px,y1,z1+pz},{x1-px,y1,z1-pz}};
    for (int i = 0; i < 4; ++i) {
        Vertex t{}; t.pos[0]=q[i][0]; t.pos[1]=q[i][1]; t.pos[2]=q[i][2]; t.normal[1]=1; t.uv[1]=2;
        v.push_back(t);
    }
    const int f[] = {0,2,1,0,3,2,0,1,2,0,2,3};
    for (int i : f) idx.push_back(b + i);
}

void appendProductScene(std::vector<Vertex>& v, std::vector<uint32_t>& idx, WorldForgeBridge& w) {
    float x = 200.0f, z = 200.0f, best = 1.0e9f;
    for (float s = -480.0f; s <= 480.0f; s += 48.0f)
        for (float t = -480.0f; t <= 480.0f; t += 48.0f) {
            float h = static_cast<float>(w.sampleHeightAt(s, t));
            float d = s * s + t * t;
            if (h > 12.0f && h < 24.0f && d < best && d > 14400.0f) { best = d; x = s; z = t; }
        }
    int steps = 0;
    for (; steps < 14; ++steps) {
        float len = std::sqrt(x * x + z * z);
        if (len < 40.0f) break;
        float dirx = -x / len, dirz = -z / len;
        float h = static_cast<float>(w.sampleHeightAt(x, z));
        float nx = x + dirx * 48.0f, nz = z + dirz * 48.0f;
        float nh = static_cast<float>(w.sampleHeightAt(nx, nz));
        float lx = nx - dirz * 28.0f, lz = nz + dirx * 28.0f;
        float rx = nx + dirz * 28.0f, rz = nz - dirx * 28.0f;
        float lh = static_cast<float>(w.sampleHeightAt(lx, lz));
        float rh = static_cast<float>(w.sampleHeightAt(rx, rz));
        if (lh < nh) { nh = lh; nx = lx; nz = lz; }
        if (rh < nh) { nh = rh; nx = rx; nz = rz; }
        float y0 = h > 8.0f ? h + 1.2f : 9.2f;
        float y1 = nh > 8.0f ? nh + 1.2f : 9.2f;
        ribbon(v, idx, x, y0, z, nx, y1, nz);
        x = nx; z = nz;
    }
    gStats.riverSteps = steps;
    OceanField field; OceanParams params; buildOcean(params, 0.0f, field);
    appendOceanMesh(v, idx, field);
    bool moved = w.productStep() == 1 || w.productStep() == 3;
    float yaw = moved ? 0.7f : 0.0f, scale = moved ? 2.2f : 1.0f;
    float ax = moved ? 28.0f : 16.0f;
    box(v, idx, ax, 18.0f, 24.0f, yaw, scale, 3.0f);
    box(v, idx, 34.0f, 14.0f, 36.0f, 0.0f, 1.3f, 3.0f);
    box(v, idx, gStats.remoteX, gStats.remoteY + 6.0f, gStats.remoteZ, 0.0f, 1.1f, 3.0f);
    std::ifstream rig("F:/rawrxd/kartgib/assets/debug_rig.txt");
    int bones = 0; rig >> bones;
    float baseX = 8.0f, baseZ = 42.0f;
    for (int i = 0; i < bones; ++i) {
        float px, py, pz, len; rig >> px >> py >> pz >> len;
        float ang = (i == 1 && moved) ? 0.9f : 0.0f;
        box(v, idx, baseX + px + std::sin(ang) * py, 8.0f + py, baseZ + pz, ang, len * 0.35f, 3.0f);
    }
    gStats.bones = bones;
    gStats.combatHp = 2;
    if (moved) {
        std::ofstream out("F:/rawrxd/kartgib/evidence/kartgib_editor_pose.txt");
        out << ax << " " << yaw << " " << scale << "\n";
        out.close();
        std::ifstream in("F:/rawrxd/kartgib/evidence/kartgib_editor_pose.txt");
        float rx, ryaw, rs; in >> rx >> ryaw >> rs;
        gStats.poseSaved = std::fabs(rx - ax) < 1.0e-4f && std::fabs(ryaw - yaw) < 1.0e-4f;
    }
}
