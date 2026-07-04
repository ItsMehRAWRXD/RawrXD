# DEPRECATED Build Scripts

**Date:** 2026-07-02  
**Phase:** Stabilization Phase 2

The following build scripts are **DEPRECATED** and should not be used:

## Deprecated Scripts

| Script | Status | Replacement |
|--------|--------|-------------|
| `build.ps1` | ❌ Deprecated | `ninja-build.ps1` |
| `build-ninja/` directory | ❌ Deprecated | `build/` directory |
| Manual `link.exe` workarounds | ❌ Deprecated | `ninja-build.ps1` (handles environment) |

## Why These Are Deprecated

1. **`build.ps1`** - Sets LIB manually but doesn't call `vcvarsall.bat`, causing `vs_link_exe` to fail silently when it can't find `rc.exe` and `mt.exe`

2. **`build-ninja/`** - Old build directory with stale artifacts that can cause confusion

3. **Manual workarounds** - Bypass the proper build pipeline and create inconsistent binaries

## Correct Build Process

```powershell
# Always use ninja-build.ps1 - it properly initializes MSVC environment
.\ninja-build.ps1 rawrxd

# Verify binary freshness before testing
.\test_precheck.ps1

# Run regression tests
.\test_regression.ps1
```

## What ninja-build.ps1 Does

1. Calls `vcvarsall.bat x64` to set up complete MSVC environment (LIB, INCLUDE, PATH)
2. Runs `ninja -C d:\rawrxd\build <target>`
3. Verifies EXE was actually created (catches silent link failures)

## Migration Checklist

- [ ] Stop using `build.ps1`
- [ ] Stop using `build-ninja/` directory
- [ ] Update any CI/CD to use `ninja-build.ps1`
- [ ] Update documentation to reference `ninja-build.ps1`
- [ ] Delete deprecated scripts after 30-day grace period

## Emergency Fallback

If `ninja-build.ps1` fails, check:
1. VS2022 Enterprise is installed at expected path
2. Run `test_precheck.ps1` to verify binary state
3. Check `build/` directory exists and has CMake cache
