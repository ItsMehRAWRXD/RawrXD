# Verdict

`DEEP2_GDN_COMPONENT=PASS`

The real `VulkanCompute::DispatchGdn` path is now wired into its build target,
executes the checked-in GDN SPIR-V on the AMD Vulkan device, preserves recurrent
state across calls, resets state independently, and matches the shared CPU
reference at the tested geometries. The Deep2 engine library compiles and
links with the runtime executor call site present.

This receipt does **not** certify:

- full Qwen3.6/Qwen4Exp model logits or token-generation parity;
- zero CPU fallback calls during a full production model run;
- runtime IR routed MoE or SSM paths;
- Kimi MLA multi-window certification;
- Phi-3 independent logits;
- global IDE certification or promotion.

`PROMOTE=0`
`CERTIFIED=0`

