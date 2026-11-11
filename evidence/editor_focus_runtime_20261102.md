# Editor focus runtime verification

Date: 2026-11-02

## Observation

The canonical IDE window was physically inspected after the successful rebuild. The Win32 child-window inventory showed a visible `RichEdit20A` editor at screen rectangle `516,351,1118,726`, with visible/enabled child styles. The screenshot showed the expected central editor surface.

The initial physical click observation was contaminated by the Codex desktop overlay. A Windows hit-test at the tested editor coordinates returned `Chrome_RenderWidgetHostHWND` with rectangle `351,231,1300,878`, not a RawrXD child window. The accessibility focus result therefore cannot be used to classify RawrXD editor focus. A clean no-overlay physical run is still required.

## Disposition

```ini
EDITOR_WINDOW_PRESENT=PASS
EDITOR_RECT_VISIBLE=PASS
EDITOR_PHYSICAL_FOCUS=NOT_VERIFIED_OVERLAY_INTERCEPTED
POWERSHELL_FOCUS_RETAINED=NOT_VERIFIED_OVERLAY_INTERCEPTED
GHOSTTEXT_EDITOR_INPUT=NOT_CERTIFIED
CANDIDATE_SHA256=4F45D326D83ECFF6E874331F682B442F591CA8FD1896D4FB1EC0DC19EDC28D8B
PROMOTE=0
```

No source or binary was changed by this diagnostic. The existing focus-restoration source patch is built in the current candidates, but it does not yet close the physical focus gate.
