#include "editor_api.hpp"
#include "terrain_studio.hpp"
#include "worldforge.hpp"
#include <cmath>

static uint64_t gSeed = 20261025;
void studioSetSeed(uint64_t seed) { gSeed = seed; }
static bool gShow = false, gEditor2 = false;
void studioSetShow(bool show) { gShow = show; }
bool studioShowOnly() { return gShow; }
void studioSetEditor2(bool on) { gEditor2 = on; }
bool studioEditor2() { return gEditor2; }
static float gShift = 0;
void studioShiftCamera(float meters) { gShift = meters; }
float studioCameraShift() { return gShift; }

bool studioBrush(Win32Window& window, int px, int py) {
    float view[16], proj[16];
    editorCamera(view, proj, window.getWidth(), window.getHeight());
    float ndcX = (static_cast<float>(px) + 0.5f) / window.getWidth() * 2.0f - 1.0f;
    float ndcY = (static_cast<float>(py) + 0.5f) / window.getHeight() * 2.0f - 1.0f;
    float vx = ndcX / proj[0], vy = ndcY / proj[5];
    float rx = view[0], ry = view[4], rz = view[8];
    float ux = view[1], uy = view[5], uz = view[9];
    float fx = -view[2], fy = -view[6], fz = -view[10];
    float dx = rx * vx + ux * vy + fx, dy = ry * vx + uy * vy + fy, dz = rz * vx + uz * vy + fz;
    float len = std::sqrt(dx * dx + dy * dy + dz * dz);
    dx /= len; dy /= len; dz /= len;
    kg::Settings settings; settings.seed = gSeed; settings.biome = kg::Biome::Tropical;
    for (int i = 1; i < 80; ++i) {
        float t = static_cast<float>(i) * 8.0f;
        float x = -40.0f + gShift + dx * t, y = 24.0f + dy * t, z = -55.0f + dz * t;
        if (y < static_cast<float>(kg::sampleHeight(x, z, settings))) {
            const StudioBrush& b = studioBrush();
            float radius = b.radius > 1.0f ? b.radius : 36.0f;
            float lift = b.strength > 0.0f ? b.strength : 22.0f;
            if (b.mode == 1) lift = -lift;
            if (b.mode == 3) lift = y;
            return studioSculpt(x, z, radius, lift);
        }
    }
    return false;
}
