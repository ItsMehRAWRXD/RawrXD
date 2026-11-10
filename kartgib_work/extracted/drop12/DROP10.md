# Drop 10 / 15 — Combat, Projectiles, Particles, Destruction Foundation

Adds 15 public combat/math utilities: clamp, add, scale, dot, length, normalize, config validation, deterministic hashing, projectile spawn, swept segment/sphere intersection, fixed-step projectile advancement, radial explosions, impact particles, particle updates, and simulation fingerprint.

**Scope:** CPU deterministic prototype with projectile-vs-sphere targets, damage, simple particle trajectories. Destroyed targets are marked dead, not fractured into debris. No Vulkan particles, networking, physics integration, gameplay UI, audio, or live KartGib hookup.

**Run:** `worldforge-combat-cli --ticks 120`; `ctest --test-dir build --output-on-failure`.

**Integration:** add `worldforge-combat` to the KartGib GameWorld build, map kart IDs and positions to combat target IDs and spheres, step at fixed dt, turn Hit records into gameplay events, and upload particles through a dedicated Vulkan effect renderer. Never change existing source before baseline backups.

**Known constraints:** collision assumes stationary targets per step; projectile vs moving target and world geometry requires a separate continuous collision phase. Cross-platform bitwise determinism is not certified. `emitImpact` has a hard cap of 16384 particles independent of Config.maxParticles.
