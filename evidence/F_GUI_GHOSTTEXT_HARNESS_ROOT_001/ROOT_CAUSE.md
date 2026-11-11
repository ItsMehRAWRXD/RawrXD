# Root Cause

Primary classification: `HARNESS_DEFECT`.

The demonstrated failure boundary is the automation layer: it could enumerate shell controls but could not obtain reliable geometry or target/focus the native `RICHEDIT` editor. A center-pane click reached the PowerShell surface, and menu/close clicks reported unavailable coordinate geometry. Consequently the test stopped before the product interaction contract began.

Secondary classification: `UNRESOLVED_INSUFFICIENT_EVIDENCE` for clean shutdown, because forced termination replaced a normal close observation in this run.

There is no evidence here for `IDE_INTERACTION_DEFECT` or `GHOSTTEXT_RUNTIME_DEFECT`: no editor HWND interaction or GhostText request was demonstrated as failing. The prior GhostText receipt is preserved separately and is hash-distinct from this binary.
