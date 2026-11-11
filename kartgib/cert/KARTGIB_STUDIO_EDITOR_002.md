# KARTGIB_STUDIO_EDITOR_002

Hierarchy, gizmos, selection highlight, docking, and multi-object reload. `PROMOTE=0`. `evidence/KARTGIB_STUDIO_INSPECTOR_001.json` and executable `70D48401CBC4F9B603447FB9EFD52D2774BB7756A7678F125D997AF7F1555BD0` remain the Inspector witness.

## Replay

From `kartgib/build/msvc/Release` after a Release build:

```
KartGib.exe --seed 20261025 --biome tropical --studio-editor2
```

The process writes `evidence/studio_project/scene.txt` and asks a child `--studio-editor2-load` to restore it. Logs are prefixed `[E2]`.

## Observed result

- Executable SHA-256 for this replay: `4E706EB6DA44922146C40325AFA6D20C1668DD2488936D266C5D9709150696D3`
- Unselected frame gold pixels `0`, selected box gold pixels `2911`.
- Translate X `16 -> 4.5 -> -5.5`, one undo returned X to `4.5`. Yaw `1.309`. Scale `1.4`.
- Parent button set BoxB's parent to `1` and the hierarchy row read `2 1 BoxB`. World pose stayed put (`keep=11`).
- Unparent returned parent `0`. Reparent set BoxA's parent to `2`. Undo restored `0`. Redo restored `2`.
- Docked width `320`. Detach placed the panel at `90,70` size `360x560`. The next move was `130,94` size `410x600`. Docking again reported width `320`.
- Saved scene: `BoxA 4.5 18 24 1.309 1.4` parent `2`, `BoxB 34 14 36 0 1.3` parent `0`. Child reload matched. `save=1 reload=1`.

Object 2 did not take selection in the second shot (`selected=1`, same frame hash). Other object types, a manual title-bar drag, crash recovery, partial mesh updates, colliders, material paint, voxels, and the separate terrain viewport were not run.
