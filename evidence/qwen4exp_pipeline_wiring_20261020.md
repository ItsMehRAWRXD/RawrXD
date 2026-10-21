# Qwen4Exp shader-to-Vulkan wiring audit

The pipeline probe created real Vulkan objects on the AMD Radeon AI PRO R9700:

```text
PLE_PIPELINE=PASS
HC_PIPELINE=PASS
QUEUE_FAMILY=0
DISPATCHES=0
EXECUTION=NOT_RUN
```

Verified wiring:

- PLE SPIR-V loaded into a real `VkShaderModule`.
- PLE descriptor layout created with 5 storage-buffer bindings.
- PLE push-constant range created at 16 bytes.
- Hyperconnection SPIR-V loaded into a real `VkShaderModule`.
- Hyperconnection descriptor layout created with 6 storage-buffer bindings.
- Hyperconnection push-constant range created at 20 bytes.
- Both compute pipelines were created successfully on the selected AMD device.

This proves source -> SPIR-V -> descriptor layout -> pipeline layout -> compute pipeline wiring. It does not prove command submission, tensor residency, numerical parity, or full-model execution. The executor therefore remains fail-closed and Qwen4Exp remains `NOT_CERTIFIED`.
