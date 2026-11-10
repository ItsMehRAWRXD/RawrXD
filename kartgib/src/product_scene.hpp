#pragma once
#include "vulkan_renderer.hpp"
#include <vector>

class WorldForgeBridge;
struct ProductStats {
    int riverSteps = 0;
    int instancesSeen = 0;
    int instancesKept = 0;
    int bones = 0;
    bool poseSaved = false;
    bool audio = false;
    int gamepad = 0;
    bool sync = false;
    float remoteX = 0, remoteY = 0, remoteZ = 0;
    int mouseDx = 0, mouseDy = 0;
    int combatHp = 3;
};
ProductStats& productStats();
void appendProductScene(std::vector<Vertex>& v, std::vector<uint32_t>& idx, WorldForgeBridge& world);
void fillInstances(WorldForgeBridge& world, std::vector<float>& xyz);
bool runProductPeer(int port, uint64_t seed);
bool runProductHost(WorldForgeBridge& world);
bool submitProductAudio();
int queryGamepad();
inline void applyLook(float& yaw, float& pitch, int dx, int dy) {
    yaw += static_cast<float>(dx) * 0.002f;
    pitch += static_cast<float>(dy) * 0.002f;
    if (pitch > 1.2f) pitch = 1.2f;
    if (pitch < -1.2f) pitch = -1.2f;
}
