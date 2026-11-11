# Drop 12 / 15 — Editor Tools and Asset Browser

Adds 15 standalone native C++20 editor utilities: asset scanning, filtering, safe relative paths, identity/matrix multiplication, TRS matrices, point transforms, affine inverse, viewport ray construction, ray-plane intersection, grid snapping, translate/scale/rotate commands, and read-only inspector snapshots.

`worldforge-editor-tools-tests` verifies asset enumeration, math, picking, snapping, edit commands, locked-object rejection, and undo integration.

No GUI is implemented in this drop. The existing scene graph's world-transform calculation remains approximate; use matrix utilities for proper composed rotations in future integration. No Vulkan viewport or Win32 panels are wired.
