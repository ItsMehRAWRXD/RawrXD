# Ollama ROCm kernel-image failure recovery

Date: 2026-10-27

## Observed failure

Ollama `0.40.11` returned HTTP 500 while running `nemotron-3.5-lightning:30b`.
The server log identifies the selected devices and the first deterministic
failure:

```text
ROCm0 AMD Radeon AI PRO R9700 gfx1201
ROCm1 AMD Radeon RX 7800 XT gfx1101
rocblaslt error: Could not load TensileLibrary_lazy_gfx1201.dat
ROCm error: no kernel image is available for execution on the device
```

The runtime was launched with both devices visible (`HIP_VISIBLE_DEVICES=0,1`).
The failure is a provider/device compatibility error, not a transient request
failure or a Deep2 inference result.

## Recovery behavior

The adaptive LLM retry policy now classifies the following signatures as
non-retryable: `TensileLibrary`, `rocblaslt`, `no kernel image`, ROCm/HIP
kernel-image errors, and unsupported GPU architecture errors. The centralized
error classifier maps the same signatures to `ConfigurationError`, allowing
the IDE to preserve the checkpoint and offer a compatible model or backend
instead of repeating identical HTTP 500 requests.

## Verification

The isolated native resilience suite was rebuilt with MSVC 19.44 and passed:

```text
1/1 test passed: agentic-resilience
```

The regression test executes the exact kernel-image failure signature and
asserts one attempt, one captured error, and zero retries.

## Remaining runtime action

This change does not claim that Ollama's bundled ROCm library supports
`gfx1201`. A compatible Ollama/ROCm build, a supported-device-only launch, or
a CPU/Deep2 fallback is still required for `nemotron-3.5-lightning:30b`.
