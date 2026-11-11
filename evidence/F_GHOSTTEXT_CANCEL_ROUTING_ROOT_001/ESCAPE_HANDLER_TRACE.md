# Escape handler trace

Source inspection found `VK_ESCAPE` handling only in `NativeGhostTextController::editorProc` under `WM_KEYDOWN`. It calls `dismiss()` only when the editor subclass receives Escape and a timer, active completion, or pending request exists.

There is no dedicated trace before or inside that branch. Consequently the existing evidence cannot distinguish:

1. Escape not reaching the editor subclass;
2. Escape arriving before `m_requestPending` becomes true;
3. focus being elsewhere when Escape was sent.

The first unverified invariant is therefore **editor Escape delivery and synchronous invalidation**. The later response path must remain fail-closed regardless of transport cancellation.
