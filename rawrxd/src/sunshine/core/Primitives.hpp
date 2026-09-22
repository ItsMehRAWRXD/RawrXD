#pragma once

#include <d3d11.h>
#include "RendererD3D11.hpp"
#include "math.hpp"

namespace Sunshine {

struct Mesh {
    ID3D11Buffer* vertexBuffer = nullptr;
    ID3D11Buffer* indexBuffer = nullptr;
    uint32_t vertexCount = 0;
    uint32_t indexCount = 0;
    uint32_t stride = 0;
    DXGI_FORMAT indexFormat = DXGI_FORMAT_R16_UINT;
};

Mesh makeCubeMesh(Renderer* renderer, float size);
Mesh makeQuadMesh(Renderer* renderer, float width, float height);
void drawMesh(Renderer* renderer, const Mesh* mesh);
void releaseMesh(Mesh* mesh);

struct Sphere {
    Vec3 center;
    float radius;
    bool intersects(const Sphere& other) const;
    bool contains(const Vec3& point) const;
};

struct AABB {
    Vec3 min;
    Vec3 max;
    bool intersects(const AABB& other) const;
    bool contains(const Vec3& point) const;
    void expand(const Vec3& point);
};

struct Ray {
    Vec3 origin;
    Vec3 dir;
    bool intersectsSphere(const Sphere& s, float* outT) const;
    bool intersectsAABB(const AABB& box, float* outT) const;
};

} // namespace Sunshine
