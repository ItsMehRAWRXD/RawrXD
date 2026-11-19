# REAP-ZERO component parity

- Executable: `build/bin-msvc/Release/reap_zero_parity_test.exe`
- SHA-256: `86C34E57A76D454B6A6E56E8C75E807179C7FE6C0362D6C4A086D1ED1F3D4D4B`
- Exit: `0`
- Tests passed: `5/5`
- Expert-slice addressing: PASS
- Weighted MoE boundary parity: PASS
- Streamed finite logits/tokens: PASS
- Vulkan Q4_0 numerical parity: PASS
- REAP16 retained-weight byte identity: PASS

This is component-level REAP-ZERO evidence. It does not establish production
MoE physical-expert routing parity on a compressed model.

`S048=REAP_ZERO_COMPONENT_PASS`
`PRODUCTION_MOE_PARITY=OPEN`
`PROMOTE=0 CERTIFIED=0 RELEASE=HELD`
