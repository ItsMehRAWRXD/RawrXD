# HWND and Focus Analysis

Source inspection establishes the intended native hierarchy and routing:

- `Win32IDE::initializeEditorSurface()` creates `m_hwndEditor` with class `RICHEDIT_CLASSA`, as a visible child of `m_hwndMain`.
- Layout places that HWND in the central editor rectangle below the breadcrumb.
- `initializeNativeGhostText()` attaches the main editor controller to `m_hwndEditor` and attaches additional controllers to chat/PowerShell/find/replace input surfaces.
- Attachment stores the `RawrXD.GhostText` window property and subclasses the target HWND with `SetWindowLongPtrA`.
- `Ctrl+Space`, Tab, Escape, and the debounce timer are handled by the subclass procedure on the editor/input HWND itself.
- Provider completion is posted back to the main window as `WM_APP + 73`; `WindowProc` routes it to `handleNativeGhostTextMessage()`.
- User edits reach GhostText through `EN_CHANGE` on the exact editor HWND; bulk loads are intentionally suppressed.

Observed harness focus was on exposed combo/chat/PowerShell controls, not the `RICHEDIT` editor. The center-pane coordinate was therefore not a reliable HWND-targeted interaction. The evidence supports an automation target/geometry and focus defect; it does not show that the editor HWND was absent or that its message path failed.
