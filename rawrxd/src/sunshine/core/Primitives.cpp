#include "Primitives.hpp"
#include <string>

namespace Sunshine {

struct Vertex {
    float x, y, z;
    float nx, ny, nz;
    float u, v;
};

Mesh makeCubeMesh(Renderer* renderer, float size) {
    Mesh m = {};
    float h = size * 0.5f;
    Vertex verts[24] = {
        // front
        {-h, -h,  h, 0,0,1, 0,1},
        { h, -h,  h, 0,0,1, 1,1},
        { h,  h,  h, 0,0,1, 1,0},
        {-h,  h,  h, 0,0,1, 0,0},
        // back
        { h, -h, -h, 0,0,-1, 0,1},
        {-h, -h, -h, 0,0,-1, 1,1},
        {-h,  h, -h, 0,0,-1, 1,0},
        { h,  h, -h, 0,0,-1, 0,0},
        // right
        { h, -h,  h, 1,0,0, 0,1},
        { h, -h, -h, 1,0,0, 1,1},
        { h,  h, -h, 1,0,0, 1,0},
        { h,  h,  h, 1,0,0, 0,0},
        // left
        {-h, -h, -h, -1,0,0, 0,1},
        {-h, -h,  h, -1,0,0, 1,1},
        {-h,  h,  h, -1,0,0, 1,0},
        {-h,  h, -h, -1,0,0, 0,0},
        // top
        {-h,  h,  h, 0,1,0, 0,1},
        { h,  h,  h, 0,1,0, 1,1},
        { h,  h, -h, 0,1,0, 1,0},
        {-h,  h, -h, 0,1,0, 0,0},
        // bottom
        {-h, -h, -h, 0,-1,0, 0,1},
        { h, -h, -h, 0,-1,0, 1,1},
        { h, -h,  h, 0,-1,0, 1,0},
        {-h, -h,  h, 0,-1,0, 0,0},
    };
    uint16_t indices[36] = {
        0,1,2,0,2,3,
        4,5,6,4,6,7,
        8,9,10,8,10,11,
        12,13,14,12,14,15,
        16,17,18,16,18,19,
        20,21,22,20,22,23,
    };
    m.stride = sizeof(Vertex);
    m.vertexCount = 24;
    m.indexCount = 36;
    m.indexFormat = DXGI_FORMAT_R16_UINT;
    renderer->createVertexBuffer(verts, sizeof(verts), m.stride, &m.vertexBuffer);
    renderer->createIndexBuffer(indices, sizeof(indices), m.indexFormat, &m.indexBuffer);
    return m;
}

Mesh makeQuadMesh(Renderer* renderer, float width, float height) {
    Mesh m = {};
    float w = width * 0.5f;
    float h = height * 0.5f;
    Vertex verts[4] = {
        {-w, -h, 0, 0,0,1, 0,1},
        { w, -h, 0, 0,0,1, 1,1},
        { w,  h, 0, 0,0,1, 1,0},
        {-w,  h, 0, 0,0,1, 0,0},
    };
    uint16_t indices[6] = {0,1,2,0,2,3};
    m.stride = sizeof(Vertex);
    m.vertexCount = 4;
    m.indexCount = 6;
    m.indexFormat = DXGI_FORMAT_R16_UINT;
    renderer->createVertexBuffer(verts, sizeof(verts), m.stride, &m.vertexBuffer);
    renderer->createIndexBuffer(indices, sizeof(indices), m.indexFormat, &m.indexBuffer);
    return m;
}

void drawMesh(Renderer* renderer, const Mesh* mesh) {
    if (!mesh || !mesh->vertexBuffer) return;
    renderer->setPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    renderer->setVertexBuffer(mesh->vertexBuffer, mesh->stride);
    if (mesh->indexBuffer) {
        renderer->setIndexBuffer(mesh->indexBuffer, mesh->indexFormat);
        renderer->drawIndexed(mesh->indexCount);
    } else {
        renderer->draw(mesh->vertexCount);
    }
}

void releaseMesh(Mesh* mesh) {
    if (mesh->vertexBuffer) { mesh->vertexBuffer->Release(); mesh->vertexBuffer = nullptr; }
    if (mesh->indexBuffer) { mesh->indexBuffer->Release(); mesh->indexBuffer = nullptr; }
    mesh->vertexCount = 0;
    mesh->indexCount = 0;
}

bool Sphere::intersects(const Sphere& other) const {
    Vec3 d = center - other.center;
    float distSq = d.x * d.x + d.y * d.y + d.z * d.z;
    float radSum = radius + other.radius;
    return distSq <= radSum * radSum;
}

bool Sphere::contains(const Vec3& point) const {
    Vec3 d = center - point;
    float distSq = d.x * d.x + d.y * d.y + d.z * d.z;
    return distSq <= radius * radius;
}

bool AABB::intersects(const AABB& other) const {
    return (min.x <= other.max.x && max.x >= other.min.x) &&
           (min.y <= other.max.y && max.y >= other.min.y) &&
           (min.z <= other.max.z && max.z >= other.min.z);
}

bool AABB::contains(const Vec3& point) const {
    return (point.x >= min.x && point.x <= max.x) &&
           (point.y >= min.y && point.y <= max.y) &&
           (point.z >= min.z && point.z <= max.z);
}

void AABB::expand(const Vec3& point) {
    if (point.x < min.x) min.x = point.x;
    if (point.y < min.y) min.y = point.y;
    if (point.z < min.z) min.z = point.z;
    if (point.x > max.x) max.x = point.x;
    if (point.y > max.y) max.y = point.y;
    if (point.z > max.z) max.z = point.z;
}

bool Ray::intersectsSphere(const Sphere& s, float* outT) const {
    Vec3 oc = origin - s.center;
    float a = dir.dot(dir);
    float b = 2.0f * oc.dot(dir);
    float c = oc.dot(oc) - s.radius * s.radius;
    float disc = b * b - 4.0f * a * c;
    if (disc < 0) return false;
    float t = (-b - std::sqrt(disc)) / (2.0f * a);
    if (t < 0) t = (-b + std::sqrt(disc)) / (2.0f * a);
    if (t < 0) return false;
    if (outT) *outT = t;
    return true;
}

bool Ray::intersectsAABB(const AABB& box, float* outT) const {
    float tmin = -1e30f, tmax = 1e30f;
    for (int i = 0; i < 3; ++i) {
        float invD = ((&dir.x)[i] != 0.0f) ? 1.0f / (&dir.x)[i] : 1e30f;
        float t1 = ((&box.min.x)[i] - (&origin.x)[i]) * invD;
        float t2 = ((&box.max.x)[i] - (&origin.x)[i]) * invD;
        if (t1 > t2) { float tmp = t1; t1 = t2; t2 = tmp; }
        if (t1 > tmin) tmin = t1;
        if (t2 < tmax) tmax = t2;
        if (tmin > tmax) return false;
    }
    float t = tmin > 0.0f ? tmin : tmax;
    if (t < 0.0f) return false;
    if (outT) *outT = t;
    return true;
}

} // namespace Sunshine
