# benchmarks/runs/README.md
# Benchmark Run Capture

This directory contains signed benchmark run manifests captured by `BackendManager::CaptureBenchmarkRun()`.

## File Format

Each file is a JSON manifest with:
- `benchmarkRun` — label, timestamp, active backend, capabilities, security state
- `hardware` — processor architecture, core count, memory
- `signature` — run identifier

## Naming Convention

```
YYYY-MM-DD_HHMMSS_<label>.json
```

## Verification

To verify a run's integrity, check the SHA256 manifest:

```powershell
Get-FileHash .\runs\*.json | Format-Table
```
