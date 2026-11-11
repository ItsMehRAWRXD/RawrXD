# Class-level stateful production dispatch receipt

Executable SHA-256: `5D7F1D3DB01639C52D0CF85D6B455F8C1A2CECDC97A50705FC86DEF3AB4EDA9B`
Device: `AMD Radeon AI PRO R9700`
Geometry: key heads 2, value heads 4, head dimension 8

The probe exercised `VulkanCompute::DispatchGdn`, the persistent state map,
device-local state initialization, descriptor allocation, real Vulkan submit,
download, `ResetGdnState`, and three dispatch-count increments.

```text
GDN_CLASS_PIPELINE=READY
GDN_CLASS_FIRST_PARITY=PASS max_abs=8.9407e-08
GDN_CLASS_STATE_CONTINUITY=PASS max_abs=1.49012e-07
GDN_CLASS_RESET_CONTINUITY=PASS max_abs=8.9407e-08
GDN_CLASS_RESET_INDEPENDENT=PASS
GDN_CLASS_DISPATCHES=3
GDN_CLASS_RESULT=PASS
EXIT=0
```

The first run before the scale-contract repair reached the same real pipeline
but failed parity. That failure was reproduced, localized to the scale
mismatch, corrected in the shared reference/runtime contract, and re-run to
the passing receipt above.

