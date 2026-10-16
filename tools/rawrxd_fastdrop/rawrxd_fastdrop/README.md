# RawrXD immediate integration drop

Source-only diagnostics and fail-closed geometry guard. No new third-party dependencies. This is NOT a complete MoE execution implementation or an enterprise certification.

## Run

In Developer PowerShell:

```powershell
cd F:\rawrxd\tools\rawrxd_fastdrop
.\RawrXD-Link-Triage.ps1 -Root F:\rawrxd
cl /std:c++20 /EHsc /W4 moe_contract_test.cpp /Fe:moe_contract_test.exe
.\moe_contract_test.exe
.\RawrXD-Forward-Gate.ps1 -Root F:\rawrxd -Model nemotron-bolt.gguf -Build
```

## Integration

Call `rawrxd::moe::expert_slice` only AFTER deriving the true per-expert matrix dimensions and quant block layout from GGUF metadata. It validates row-oriented `[input, output, experts]` tensor slices and rejects any dimension mismatch. It does not invent a 1024-to-4096 projection. If actual GGUF stores dimensions in another order, convert to this descriptor explicitly after verifying the model format. Do not use it to bypass the Layer 1 failure.

The gate requires `GENERATED_TOKENS` telemetry and exit 0. This is a smoke gate, not parity, safety, or autonomous task certification. All writes are confined to a timestamped evidence directory; model files are not modified.
