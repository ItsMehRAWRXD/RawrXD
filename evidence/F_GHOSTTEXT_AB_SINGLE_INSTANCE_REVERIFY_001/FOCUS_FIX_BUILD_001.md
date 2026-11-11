# Editor focus fix build

The candidate source now restores focus to `m_hwndEditor` after the final startup layout pass in `src/win32app/Win32IDE_lifecycle.cpp`.

```ini
BUILD_TARGET=RawrXD-Win32IDE-Native
BUILD_EXIT=0
CANDIDATE_SHA256=16EAC58DA23D89CC6747A66CE05BE9AF21E7BD0B8486F49574CD382CE0ECB44C
PHYSICAL_FOCUS_REVERIFY=HELD
REASON=Codex desktop window was foreground during observation
PRODUCTION_BINARY_MODIFIED=0
PROMOTE=0
```
