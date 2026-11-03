# Cancellation root cause

The first violated observable invariant is request invalidation before UI commit. The exact upstream cause remains unresolved because the current instrumentation does not trace Escape entry, focus HWND, or generation before/after `dismiss()`. The evidence does not justify a speculative handler change.
