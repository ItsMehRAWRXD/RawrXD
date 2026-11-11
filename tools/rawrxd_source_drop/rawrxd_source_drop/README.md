# RawrXD no-dependency source drop

These files do not edit model weights, source, Git history, or existing executables.

## 1. Link symbol audit
From a **Developer PowerShell for VS 2022**:

```powershell
.\RawrXD-Link-Audit.ps1 -Root F:\rawrxd
```

Inspect `F:\rawrxd\evidence\link-symbol-audit.txt` and compare decorated names. Do not introduce fake definitions. The audit can take time on large builds.

## 2. MoE geometry guard

```powershell
cl /std:c++20 /EHsc /W4 rawrxd_moe_geometry_test.cpp /Fe:moe_geometry_test.exe
.\moe_geometry_test.exe
```

Use `rawrxd_moe_geometry.hpp` at the expert slice/dispatch boundary. Supply the **actual** tensor dimensions and quant geometry; the test uses a synthetic tensor. A LatentMoE projection chain may need intermediate GEMVs rather than direct 4096-output GEMV.

## 3. End-to-end generation receipt

```powershell
.\RawrXD-Production-Gate.ps1 -Root F:\rawrxd -Model nemotron-bolt.gguf -Build
```

The gate requires a real `GENERATED_TOKENS=N` receipt, exit code zero, and no failure receipt. It does not claim to verify model correctness, numeric parity, or SNAP autonomy.

Run on a test workspace; the model command may perform actions depending on the current CLI behavior. `-Task` defaults to a reply-only prompt. Model path resolution remains the CLI's responsibility.
