# Harness Root Confirmation

The failed path was `evidence/F_RAWRXD_EDITOR_002/open-main-cpp.ps1`. It uses `GetMenuItemRect`, cursor coordinates, `mouse_event`, and a text-length heuristic (`EditorSample`). It does not enumerate or focus the native editor control. The new harness is `native_editor_harness.ps1` and uses process attribution, child-HWND enumeration, class filtering (`RichEdit50W`), visibility/enabled checks, `SetFocus`, `GetFocus`, and client-rectangle validation.

Production source and GhostText source were not changed.
