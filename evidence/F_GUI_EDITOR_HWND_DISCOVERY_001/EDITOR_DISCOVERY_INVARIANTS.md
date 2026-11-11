# Editor Discovery Invariants

The repaired harness now requires all of:

- candidate process ownership through the launched main HWND;
- runtime class `RichEdit20A`;
- source-backed dialog/control ID `1001`;
- visible and enabled state;
- positive client geometry;
- focus verification before interaction.

It does not select the first keyboard-capable RichEdit or infer identity from geometry alone.
