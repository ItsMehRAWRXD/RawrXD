# Offline provenance only (NOT part of Deep2 runtime or normal certification)

Deep2 certification uses **frozen golden** artifacts under `evidence/PARITY_CERT_001/`.

This directory may hold optional offline reference tooling. It must **never** be linked into Deep2, started during `run_parity_cert_001.ps1` default path, or treated as an Ollama/llama.cpp product dependency.

`live_external_runtime_required=false`
