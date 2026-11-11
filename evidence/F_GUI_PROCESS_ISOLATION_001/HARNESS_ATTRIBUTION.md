# Harness Attribution

The repaired harness starts the candidate itself, records the returned process object, restricts descendant HWND enumeration to that process's main HWND, and refuses to start if an existing process with the same executable name is present. It verifies the editor class, visibility, enabled state, client geometry, and focus before proceeding.

Static parsing and default static-only execution passed in `F_GUI_GHOSTTEXT_HARNESS_REPAIR_001`.
