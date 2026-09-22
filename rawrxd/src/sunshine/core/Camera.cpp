#include "Camera.hpp"
#include <cmath>

namespace Sunshine {

void Camera::setPerspective(float fovDeg, float aspect, float nearPlane, float farPlane) {
    m_fov = fovDeg;
    m_aspect = aspect;
    m_near = nearPlane;
    m_far = farPlane;
}

void Camera::setPosition(const Vec3& pos) {
    m_position = pos;
    updateVectors();
}

void Camera::setLookAt(const Vec3& target) {
    m_target = target;
    updateVectors();
}

void Camera::setUp(const Vec3& up) {
    m_up = up.normalize();
    updateVectors();
}

void Camera::updateVectors() {
    m_forward = (m_target - m_position).normalize();
    m_right = m_forward.cross(m_up).normalize();
}

void Camera::rotateYawPitch(float yawDeltaDeg, float pitchDeltaDeg) {
    m_yaw += yawDeltaDeg;
    m_pitch += pitchDeltaDeg;
    if (m_pitch > 89.0f) m_pitch = 89.0f;
    if (m_pitch < -89.0f) m_pitch = -89.0f;

    float yawRad = m_yaw * 3.14159265f / 180.0f;
    float pitchRad = m_pitch * 3.14159265f / 180.0f;
    Vec3 fwd;
    fwd.x = std::cos(pitchRad) * std::cos(yawRad);
    fwd.y = std::sin(pitchRad);
    fwd.z = std::cos(pitchRad) * std::sin(yawRad);
    m_forward = fwd.normalize();
    m_right = m_forward.cross(m_up).normalize();
    m_target = m_position + m_forward;
}

void Camera::moveForward(float dist) {
    m_position = m_position + m_forward * dist;
    m_target = m_position + m_forward;
}

void Camera::moveRight(float dist) {
    m_position = m_position + m_right * dist;
    m_target = m_position + m_forward;
}

void Camera::moveUp(float dist) {
    m_position = m_position + m_up * dist;
    m_target = m_position + m_forward;
}

Mat4 Camera::getViewMatrix() const {
    return Mat4::lookAt(m_position, m_target, m_up);
}

Mat4 Camera::getProjectionMatrix() const {
    return Mat4::perspective(m_fov, m_aspect, m_near, m_far);
}

} // namespace Sunshine
