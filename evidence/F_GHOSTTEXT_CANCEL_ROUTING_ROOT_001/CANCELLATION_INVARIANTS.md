# Cancellation invariants

- `dismiss()` increments `m_generation` and clears `m_requestPending`.
- A result carries the request generation and identity.
- `handleMessage()` checks request identity and `showCompletion()` checks generation plus editor snapshot.
- The observed request 3 rendered after the Escape action, so the required invariant was not demonstrated:

`cancelled_or_invalidated_request => never_render_and_never_modify_editor`

Transport cancellation is not sufficient; the UI message commit must reject an invalid request.
