// ============================================================================
// Camera.hpp — the camera and the matrices it produces.
//
// The camera is a position, a yaw and a pitch. It walks with the keyboard
// and turns with the mouse. The engine has no physics and no collision:
// a camera in a voxel world is for looking at the world, not for living in
// it, and adding collision would be a different program.
//
// The view matrix is left-handed and the projection is the Direct3D one,
// so the clip space has z in [0, 1]. That pair is what the shader and the
// depth buffer expect.
// ============================================================================

#pragma once

#include "Math.hpp"

namespace sunshine {

class Camera {
public:
    Camera() = default;

    // The position of the eye.
    Vec3 position{0.0f, 80.0f, 0.0f};

    // The turn, in radians. The yaw is about the world up axis and the
    // pitch is about the right axis.
    float yaw = 0.0f;
    float pitch = 0.0f;

    float fovYRadians = 1.0472f;   // 60 degrees
    float nearZ = 0.1f;
    float farZ = 512.0f;

    // How fast the camera walks, in blocks per second.
    float moveSpeed = 18.0f;
    float turnSpeed = 0.0022f;     // radians per pixel of mouse movement

    // The direction the camera is looking along.
    Vec3 forward() const {
        const float cp = std::cos(pitch);
        return {std::sin(yaw) * cp, -std::sin(pitch), std::cos(yaw) * cp};
    }

    // The direction to the right of the camera, on the ground plane.
    Vec3 right() const {
        return {std::cos(yaw), 0.0f, -std::sin(yaw)};
    }

    // Move the camera by a distance along its own axes.
    void move(float forwardAmount, float rightAmount, float upAmount) {
        position += forward() * forwardAmount;
        position += right() * rightAmount;
        position.y += upAmount;
    }

    // Turn the camera by a mouse movement, in pixels.
    void turn(float dx, float dy) {
        yaw += dx * turnSpeed;
        pitch += dy * turnSpeed;

        // The pitch is clamped so the camera cannot roll over the pole.
        const float limit = 1.5533f;   // 89 degrees
        if (pitch > limit) pitch = limit;
        if (pitch < -limit) pitch = -limit;

        // The yaw is wrapped so it cannot grow without bound.
        const float twoPi = 6.28318530718f;
        while (yaw > 3.14159265359f) yaw -= twoPi;
        while (yaw < -3.14159265359f) yaw += twoPi;
    }

    // The view matrix.
    Mat4 view() const {
        return Mat4::lookAtLH(position, position + forward(), Vec3{0.0f, 1.0f, 0.0f});
    }

    // The projection matrix.
    Mat4 projection(float aspect) const {
        return Mat4::perspective(fovYRadians, aspect, nearZ, farZ);
    }

    // The two matrices together.
    Mat4 viewProjection(float aspect) const {
        return view() * projection(aspect);
    }
};

} // namespace sunshine
