#pragma once
#include "game_loop.hpp"
#include <cmath>

template <class F>
void stepKartBody(KartState& k, float dt, F groundFn) {
    float forwardSpeed = k.throttle * 12.0f * dt;
    if (k.throttle != 0.0f) {
        k.x += std::sin(k.yaw) * forwardSpeed;
        k.z += std::cos(k.yaw) * forwardSpeed;
    }
    if (k.steer != 0.0f && std::abs(k.throttle) > 0.01f)
        k.yaw += k.steer * 2.5f * dt * std::abs(k.throttle);
    if (k.jump && !k.airborne) { k.vertical = 8.0f; k.airborne = true; k.jump = false; }
    float terrainY = groundFn(k.x, k.z);
    if (k.airborne) {
        k.vertical -= 9.8f * dt;
        k.y += k.vertical * dt;
        if (k.y <= terrainY + 0.5f) { k.y = terrainY + 0.5f; k.vertical = 0.0f; k.airborne = false; }
    } else {
        k.y = terrainY + 0.5f;
    }
    k.throttle *= 0.95f;
    k.steer *= 0.90f;
}
