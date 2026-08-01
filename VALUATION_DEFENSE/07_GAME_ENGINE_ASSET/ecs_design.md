# Entity Component System (ECS) Design

## Architecture

```
┌─────────────────────────────────────────────┐
│              Entity Manager                   │
│  Entity IDs (uint32_t), Sparse Set           │
├─────────────────────────────────────────────┤
│              Component Pools                  │
│  Transform, Mesh, Material, RigidBody,      │
│  AudioSource, Light, Script, Camera         │
├─────────────────────────────────────────────┤
│              System Pipeline                  │
│  PhysicsSystem → AnimationSystem →          │
│  RenderSystem → AudioSystem → ScriptSystem  │
└─────────────────────────────────────────────┘
```

## Data Layout

```
Entity: { id: uint32, version: uint32, archetype: uint32 }

Component Pool (SoA):
  Transform:   { position[3], rotation[4], scale[3] }  // 40 bytes
  Mesh:        { vertexBuffer, indexBuffer, lod }       // 16 bytes
  RigidBody:   { mass, velocity[3], force[3] }          // 32 bytes
  Script:      { codePtr, statePtr, interval }          // 12 bytes
```

## System Pipeline Order

1. **InputSystem** — Poll Win32 input, update input state
2. **PhysicsSystem** — Apply forces, integrate velocities, detect collisions
3. **AnimationSystem** — Update skeletal poses, blend trees
4. **ScriptSystem** — Execute agent-generated MASM scripts
5. **RenderSystem** — Build draw lists, submit to Vulkan
6. **AudioSystem** — Update audio sources, submit to WASAPI

## MASM Implementation

All ECS hot paths are implemented in MASM x64:

| Operation | Kernel | Cycles |
|-----------|--------|--------|
| Entity create | `ecs_create.asm` | ~50 |
| Entity destroy | `ecs_destroy.asm` | ~30 |
| Component add | `ecs_add_component.asm` | ~40 |
| Component get | `ecs_get_component.asm` | ~15 |
| System iterate | `ecs_iterate.asm` | ~8/entity |
| Physics integrate | `physics_integrate.asm` | ~120/body |

## Performance Targets

| Entity Count | Update Time | Memory |
|-------------|-------------|--------|
| 1,000 | ~0.1ms | ~2MB |
| 10,000 | ~0.8ms | ~20MB |
| 100,000 | ~8ms | ~200MB |
| 1,000,000 | ~80ms | ~2GB |
