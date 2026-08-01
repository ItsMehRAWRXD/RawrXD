# Physics System — MASM x64 Native

## Overview

The physics system is a **from-scratch MASM x64 rigid body simulator** with no external physics libraries (no PhysX, no Bullet, no Jolt).

## Core Components

### Rigid Body
```
struct RigidBody {
    float   mass;
    float   invMass;
    float   position[3];
    float   rotation[4];      // Quaternion
    float   velocity[3];
    float   angularVelocity[3];
    float   force[3];
    float   torque[3];
    float   restitution;       // Bounciness 0.0-1.0
    float   friction;
    uint32_t shapeType;        // 0=sphere, 1=box, 2=mesh
    float   shapeData[8];      // radius, halfExtents, etc.
};
// Total: 112 bytes
```

### Collision Detection
| Shape Pair | Algorithm | MASM Kernel |
|------------|-----------|-------------|
| Sphere-Sphere | Distance check | `collide_sphere_sphere.asm` |
| Sphere-Box | SAT | `collide_sphere_box.asm` |
| Box-Box | SAT | `collide_box_box.asm` |
| Mesh-Mesh | GJK + EPA | `collide_gjk.asm` |

### Constraint Solver
- Sequential impulse solver
- Contact constraints (normal + friction)
- Joint constraints (ball, hinge, slider)
- 8 iterations per frame

## Performance Targets

| Bodies | Broadphase | Narrowphase | Solve | Total |
|--------|-----------|-------------|-------|-------|
| 100 | 0.01ms | 0.05ms | 0.1ms | **0.16ms** |
| 1,000 | 0.1ms | 0.5ms | 1.0ms | **1.6ms** |
| 10,000 | 1.0ms | 5.0ms | 10ms | **16ms** |

## Competitive Comparison

| Feature | Sunshine Physics | PhysX | Bullet | Jolt |
|---------|-----------------|-------|--------|------|
| Runtime deps | **None** | ~10MB | ~5MB | ~3MB |
| MASM kernels | **Yes** | No | No | No |
| SIMD | **AVX2/AVX512** | SSE4 | SSE4 | SSE4 |
| GPU compute | Vulkan | CUDA | CUDA | No |
| License | **Owned** | NVIDIA | zlib | MIT |
