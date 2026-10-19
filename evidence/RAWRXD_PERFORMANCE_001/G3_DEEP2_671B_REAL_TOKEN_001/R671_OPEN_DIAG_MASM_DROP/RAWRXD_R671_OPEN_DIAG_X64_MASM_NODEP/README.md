# RAWRXD_R671_OPEN_DIAG_X64_MASM_NODEP

No-dependency Win64 diagnostic replacement for `r671_open`.

Purpose:
identify exactly which API fails and preserve the exact Win32 error code.

The context records:
- `open_stage`
- `open_rc`
- `win32_last_error`

Stages:
1. CreateFileA
2. GetFileSizeEx
3. CreateFileMappingA
4. GetSystemInfo
5. Ready

Important correction:
the old `[rsp+38h]` file-size scratch is not an overlap with CreateFileA's
stack arguments. This drop names it explicitly as `R671_LOCAL_FILESIZE`.

Build:
    build_masm.bat

If the smoke exits nonzero:
    high byte = open stage
    low byte  = low 8 bits of GetLastError
The full error remains in `ctx.win32_last_error` for debugger inspection.
