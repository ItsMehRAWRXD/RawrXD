# Batch 007: 15 + 15 + 15 — Dual AMD authorization and IDE end-to-end gates

This is a **45-gate audit and implementation plan**, not 45 completed features.

## Batch A: 15 build and source gates
01 branch preservation [checked]; 02 native Win32 source [found]; 03 Qt client source [found]; 04 CMake optional Qt [found]; 05 Linux C++ smoke CI [configured]; 06 MSVC smoke CI [configured]; 07 native headless CMake CI [configured]; 08 native LSP framing [source]; 09 signed LSP length rejection [fixed]; 10 LSP framing execution [unverified]; 11 executable IDE build [unverified]; 12 executable launch [unverified]; 13 gateway health [unverified in CI]; 14 no-Qt linked dependencies [unverified]; 15 reproducible build receipt [unverified].

## Batch B: 15 dual GPU and model gates
16 self-hosted dual GPU workflow [committed]; 17 manual dispatch gate [configured]; 18 runner label isolation [configured]; 19 AMD device inventory [configured]; 20 Vulkan device enumeration [configured]; 21 MSVC smoke suite [configured]; 22 Vulkan kernel compile [pending]; 23 physical R9700 compute [pending]; 24 physical RX7800XT compute [pending]; 25 dual GPU dispatch [pending]; 26 GPU synchronization and fences [pending]; 27 packed GGUF quant parity [pending]; 28 MoE expert routing [pending]; 29 multi-token generation [pending]; 30 150 TPS measurement [pending].

## Batch C: 15 IDE completion gates
31 native editor [source]; 32 native GhostText [source]; 33 GhostText physical accept [pending]; 34 LSP process transport [pending]; 35 LSP initialize [pending]; 36 LSP diagnostics [pending]; 37 PowerShell panel [source]; 38 PowerShell cancellation [pending]; 39 debugger expressions [pending]; 40 browser navigation/rendering [pending]; 41 autonomous multi-file edit [pending]; 42 build/test verification [pending]; 43 snapshot rollback [pending]; 44 top 25 product parity [pending]; 45 100% completeness certification [pending].

## Security and hardware constraints
- Workflow `.github/workflows/rawrxd-dual-amd-admission.yml` is manual only and targets runner labels `self-hosted,Windows,X64,rawrxd-dual-amd`.
- The workflow runs read-only GPU/Vulkan inventory and source smoke tests. It **does not** read model files, start autonomous agents, alter drivers, flash firmware, or run heavy GPU inference.
- Installing/registering a GitHub Actions self-hosted runner on the Windows GPU machine requires the machine owner's explicit local setup; repository source commits cannot install one remotely.
- For a private repo, do not allow untrusted pull requests to execute on a self-hosted runner.
- A successful inventory is not dual-GPU compute parity.
- Existing standard GitHub-hosted Windows jobs cannot prove local dual-AMD performance.
- Qt conversion remains a separate per-component implementation and runtime test, not a blanket find/replace.
