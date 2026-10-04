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
    // RAWRXD_SUNSHINE_CAMERA_DEFAULT_001
    // These previously had NO initialisers, so a default-constructed Camera had
    // m_position = m_target = m_up = m_forward = m_right = (0,0,0). getViewMatrix()
    // then evaluated lookAt(eye==target, up==0), whose basis vectors are all zero
    // (z = normalize(0) = 0; x = up.cross(z) = 0; y = z.cross(x) = 0), so it
    // returned the ZERO MATRIX. Every mesh vertex collapsed to clip (0,0,0,0) with
    // w = 0 and nothing rasterised. Measured: GROUND_WVP row0 = row3 = all zeros,
    // while the HUD still drew -- which is why the scene read as "black" with the
    // HUD floating on it.
    //
    // A camera must be usable the moment it exists. These defaults are an
    // ordinary first-person pose: eye at standing height, looking down -Z.
    Vec3 m_position{0.0f, 1.7f, 0.0f};
    Vec3 m_target{0.0f, 1.7f, -1.0f};
    Vec3 m_up{0.0f, 1.0f, 0.0f};
    Vec3 m_forward{0.0f, 0.0f, -1.0f};
    Vec3 m_right{1.0f, 0.0f, 0.0f};
    float m_fov = 60.0f;
    float m_aspect = 16.0f / 9.0f;
    float m_near = 0.1f;
    float m_far = 1000.0f;
    float m_yaw = 0.0f;
    float m_pitch = 0.0f;
    void updateVectors();
};

} // namespace Sunshine
