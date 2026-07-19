# Sovereign Validation IDE Integration

## Overview
This integration connects the RawrXD Win32 IDE to the Sovereign Runtime validation pipeline, enabling one-click execution of comprehensive model validation directly from the IDE.

## Features Implemented

### 1. Menu Integration
**Location:** `Tools → Run Sovereign Validation` (Ctrl+Shift+V)

**Flow:**
```
IDE Menu
    ↓
Save Current File (if modified)
    ↓
Launch rawrxd.exe --validate --autonomous
    ↓
Capture Output → Output Panel
    ↓
Display Results
```

### 2. Evidence Bundle Viewer
**Location:** `Tools → View Evidence Bundle`

Displays the latest validation results:
- Bundle path
- PASS/FAIL status
- Gates passed/failed
- Links to certificate.json, manifest.json, telemetry.json

### 3. Command Execution
The integration:
- Builds command line with current file context
- Creates process with piped stdout/stderr
- Reads output with 5-minute timeout
- Converts UTF-8 output to wide char for display
- Shows exit code and completion status

## Code Changes

### Header File: `RawrXD_IDE_Win32.h`
```c
/* Added menu IDs */
#define IDM_TOOLS_SOVEREIGN_RUN     2305
#define IDM_TOOLS_VIEW_EVIDENCE     2306

/* Added function declarations */
void RawrXD_IDE_RunSovereignValidation(RawrXD_IDE* ide);
void RawrXD_IDE_ViewEvidenceBundle(RawrXD_IDE* ide);
```

### Implementation: `RawrXD_IDE_Win32.cpp`

**Menu Creation (line ~551):**
```c
AppendMenuW(hTools, MF_STRING, IDM_TOOLS_SOVEREIGN_RUN,
    L"Run &Sovereign Validation\tCtrl+Shift+V");
AppendMenuW(hTools, MF_STRING, IDM_TOOLS_VIEW_EVIDENCE,
    L"View &Evidence Bundle");
```

**Accelerator (line ~598):**
```c
{ FCONTROL | FSHIFT | FVIRTKEY,  'V',      IDM_TOOLS_SOVEREIGN_RUN },
```

**Command Handler (line ~1148):**
```c
case IDM_TOOLS_SOVEREIGN_RUN: RawrXD_IDE_RunSovereignValidation(ide); break;
case IDM_TOOLS_VIEW_EVIDENCE: RawrXD_IDE_ViewEvidenceBundle(ide); break;
```

**Implementation Functions (lines ~2140-2300):**
- `RawrXD_IDE_RunSovereignValidation()` - Full validation execution
- `RawrXD_IDE_ViewEvidenceBundle()` - Evidence display

## Usage

### Running Validation
1. Open a source file in the IDE
2. Select `Tools → Run Sovereign Validation` (or Ctrl+Shift+V)
3. If unsaved changes exist, you'll be prompted to save
4. The runtime executes with the current file as context
5. Output appears in the Output panel
6. Evidence bundle is created in `validation/runs/<RUN-ID>/`

### Viewing Results
1. Select `Tools → View Evidence Bundle`
2. The latest validation results display in the Output panel
3. Check `validation/runs/latest/` for full artifacts

## Runtime Requirements

The integration searches for `rawrxd.exe` in:
1. Current directory
2. `..\..\rawrxd.exe`
3. `..\..\..\rawrxd.exe`
4. `d:\rawrxd-ci-bootstrap\build\rawrxd.exe`
5. `d:\rawrxd-ci-bootstrap\rawrxd.exe`

## Evidence Bundle Structure

```
validation/runs/
└── <RUN-ID>/
    ├── manifest.json      # Run metadata
    ├── certificate.json   # Validation results
    ├── telemetry.json     # Performance data
    ├── hardware.json      # System info
    └── tensors/           # Intermediate hashes
```

## Future Enhancements

1. **Model Selection Dialog** - Choose from available GGUF files
2. **Validation Configuration** - Adjust max_tokens, backend, seed
3. **Evidence Comparison** - Diff between validation runs
4. **Certificate Signing** - Cryptographic validation proofs
5. **Real-time Streaming** - Live output during validation

## Build Notes

Compile with standard IDE flags:
```bash
cl /W4 /O2 /DUNICODE /D_UNICODE RawrXD_IDE_Win32.cpp \
   /link user32.lib gdi32.lib comctl32.lib comdlg32.lib \
         shell32.lib shlwapi.lib advapi32.lib ole32.lib
```

No additional dependencies required.
