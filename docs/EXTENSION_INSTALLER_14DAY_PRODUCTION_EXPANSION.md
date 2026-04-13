# Extension Installer 14-Day Production Expansion

## Goal
Close the remaining production gaps for the extension installer subsystem with executable checks and release gates:
- Real install execution path
- Concurrent install stress and race detection
- Failure injection and consistency checks
- Live marketplace verification

## New Harness Capabilities
The smoke test executable now supports:
- `--live-install`: real install verification for `ms-vscode.cpptools` and `rust-lang.rust-analyzer`
- `--stress N`: concurrent install stress harness (offline/mixed)
- `--stress-live N`: concurrent install stress harness (live/network)
- `--failure-inject`: invalid ID, invalid payload, and corrupt VSIX rollback checks

## 14-Day Execution Plan

### Day 1
- Baseline security + coherence
- Command: `ExtensionInstallerSmoke.exe --failure-inject --stress 3`
- Exit criteria: zero failures in offline mode

### Day 2
- Marketplace live metadata validation
- Command: `ExtensionInstallerSmoke.exe --live`
- Exit criteria: Copilot and Amazon Q live resolution pass

### Day 3
- Idempotency and pending-state stability
- Command: `ExtensionInstallerSmoke.exe --stress 10`
- Exit criteria: no crashes, pending list clears, installed list unique

### Day 4
- Failure recovery regression
- Command: `ExtensionInstallerSmoke.exe --failure-inject --stress 5`
- Exit criteria: state consistency retained after failures

### Day 5
- Real install path validation
- Command: `ExtensionInstallerSmoke.exe --live-install --live`
- Exit criteria:
  - install succeeds or extension already installed
  - install artifacts exist
  - activation events found in manifest

### Day 6
- Medium concurrency stress
- Command: `ExtensionInstallerSmoke.exe --stress-live 10`
- Exit criteria: stable completion, no pending residue

### Day 7
- High concurrency stress
- Command: `ExtensionInstallerSmoke.exe --stress-live 20`
- Exit criteria: no deadlocks, no duplicate state entries

### Day 8
- Combined live + failure mode
- Command: `ExtensionInstallerSmoke.exe --live --failure-inject`
- Exit criteria: network + failure routes both stable

### Day 9
- Activation artifact verification rerun
- Command: `ExtensionInstallerSmoke.exe --live --live-install`
- Exit criteria: manifests continue exposing activation events

### Day 10
- Stress + failure mixed gate
- Command: `ExtensionInstallerSmoke.exe --failure-inject --stress-live 15`
- Exit criteria: consistency under mixed adverse workload

### Day 11
- Offline regression baseline
- Command: `ExtensionInstallerSmoke.exe --failure-inject --stress 3`
- Exit criteria: no drift from day 1 baseline

### Day 12
- Marketplace consistency recheck
- Command: `ExtensionInstallerSmoke.exe --live`
- Exit criteria: same critical IDs resolve with valid version/publisher

### Day 13
- Release gate pass
- Command: `ExtensionInstallerSmoke.exe --live --failure-inject --stress-live 10`
- Exit criteria: all P0 routes green

### Day 14
- Final production certification
- Command: `ExtensionInstallerSmoke.exe --live --live-install --failure-inject --stress-live 10`
- Exit criteria: production-ready installer subsystem sign-off

## Automation Runner
Use the runner script:
- File: `scripts/extension_installer_14day_expansion.ps1`
- Example:
  - `pwsh scripts/extension_installer_14day_expansion.ps1 -Day 1 -Strict`
  - `pwsh scripts/extension_installer_14day_expansion.ps1 -Day 14 -Live -LiveInstall -Strict`

Reports are emitted to:
- `contract_reports/extension-installer/`

## Production Gates
P0 gates:
- Live marketplace resolution for Copilot/Amazon Q
- Real install path verification for cpptools and rust-analyzer
- Concurrent stress with no pending-state residue
- Failure injection with state consistency

P1 gates:
- Repeatability across day 1, day 11, and day 14
- Live stress repeatability with no duplicate installed state

## Notes
- Offline stress mode validates concurrency safety and idempotency behavior without requiring all VSIX payloads to pass strict package checks.
- Live install/stress modes are the certification routes for full runtime confidence.
