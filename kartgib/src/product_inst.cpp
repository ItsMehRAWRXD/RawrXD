#include "product_scene.hpp"
#include "worldforge_bridge.hpp"
#include <cmath>

void fillInstances(WorldForgeBridge& world, std::vector<float>& xyz) {
    ProductStats& stats = productStats();
    stats.instancesSeen = 0;
    stats.instancesKept = 0;
    for (float x = -480.0f; x <= 480.0f && stats.instancesKept < 3000; x += 8.0f) {
        for (float z = -480.0f; z <= 480.0f && stats.instancesKept < 3000; z += 8.0f) {
            ++stats.instancesSeen;
            float h = static_cast<float>(world.sampleHeightAt(x, z));
            if (h < 9.0f || h > 22.0f) continue;
            xyz.push_back(x); xyz.push_back(h); xyz.push_back(z);
            ++stats.instancesKept;
        }
    }
}
