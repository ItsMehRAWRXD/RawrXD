# KARTGIB_STUDIO_INSPECTOR_001

Sanitized witness for the native Inspector. `PROMOTE=0`. The local receipt `evidence/KARTGIB_STUDIO_INSPECTOR_001.json` stays the regression copy and is not rewritten by later gates.

- Source reference at publication: `b4b4baa45e0f213f5e25694901d7f4827db7e5d7`
- Executable SHA-256: `70D48401CBC4F9B603447FB9EFD52D2774BB7756A7678F125D997AF7F1555BD0`
- GPU: AMD Radeon AI PRO R9700

## Replay

From `kartgib/build/msvc/Release`:

```
KartGib.exe --seed 20261025 --biome tropical --studio
```

The process creates `evidence/studio_project/`, edits through the Inspector HWND, and exits. A child `--studio-load` checks the saved project.

## Observed result

- Selected object 1, X field `16.00`
- Apply wrote X `22`, yaw `0.50`, scale `1.40`
- Brush modes `0,1,2,3`, radius `48`, strength `10`, falloff `2`
- Sculpt height `-2.31971` to `4.76473`
- Frame hashes `14711186484092473613` then `18214139137340325718`
- Sunshine set the X field to `9.00`
- Undo restored `22.00` and yaw `0.50`; redo restored X `9`
- Child peak `4.76473 9 48 340 0 1`
- Saved scene `BoxA 9 18 24 0 1`

Hierarchy parenting, gizmo drags, selection outlines, and dock dragging were not part of this witness.
