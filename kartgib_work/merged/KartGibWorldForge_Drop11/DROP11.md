# Drop 11 / 15 — Native Scene Editor Document Core

15 capabilities: create entity, recursive delete, cycle-safe reparent, rename, set transform, translate, visibility, lock, selection, hierarchy children, hierarchical world transforms (translation/scale and additive Euler only), CPU ray picking, versioned scene save, validated transactional load, bounded undo/redo. Additional orbit camera math and CLI.

**Scope:** This is the scene graph/document/model for a future Win32 visual editor, **not a visual UI**. No viewport rendering, gizmo widget, mouse input routing, live KartGib integration or Vulkan scene drawing yet. Parent rotation is not applied to child translation; fix before production transform usage. Undo records scene mutations, not selection changes. Serialization is a custom quoted-text .wfs format, not JSON.

Build: `cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure`.
CLI: `worldforge-scene-cli sample.wfs`.
