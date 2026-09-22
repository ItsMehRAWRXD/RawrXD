#pragma once

#include "math.hpp"

namespace Sunshine {

class Camera {
public:
    void setPerspective(float fovDeg, float aspect, float nearPlane, float farPlane);
    void setPosition(const Vec3& pos);
    void setLookAt(const Vec3& target);
    void setUp(const Vec3& up);
    void rotateYawPitch(float yawDeltaDeg, float pitchDeltaDeg);
    void moveForward(float dist);
    void moveRight(float dist);
    void moveUp(float dist);

    Mat4 getViewMatrix() const;
    Mat4 getProjectionMatrix() const;
    Vec3 getPosition() const { return m_position; }
    Vec3 getForward() const { return m_forward; }

private:
    Vec3 m_position;
    Vec3 m_target;
    Vec3 m_up;
    Vec3 m_forward;
    Vec3 m_right;
    float m_fov = 60.0f;
    float m_aspect = 16.0f / 9.0f;
    float m_near = 0.1f;
    float m_far = 1000.0f;
    float m_yaw = 0.0f;
    float m_pitch = 0.0f;
    void updateVectors();
};

} // namespace Sunshine
