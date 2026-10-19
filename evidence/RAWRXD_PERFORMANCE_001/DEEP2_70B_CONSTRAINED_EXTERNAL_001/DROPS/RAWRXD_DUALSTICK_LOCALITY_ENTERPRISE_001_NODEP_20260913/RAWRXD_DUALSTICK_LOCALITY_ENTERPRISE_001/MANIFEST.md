# Source-drop manifest

`RAWRXD_DUALSTICK_LOCALITY_ENTERPRISE_001`

## Included source

- `include/deep2/EnterpriseDualStickLocality.hpp`
- `src/EnterpriseDualStickLocality.cpp`
- `tests/selftest.cpp`
- `adapter/RAWRXD_K2_BIND.md`
- `CMakeLists.txt`
- `build_msvc.bat`
- `build_linux.sh`
- `README.md`
- `AUTHORITY_LAW.txt`
- `SECURITY.md`
- `LICENSE_NOTICE.txt`
- `evidence/SELFTEST_RECEIPT.txt`
- `evidence/VERIFICATION.txt`
- `SHA256SUMS.txt`

## Dependency declaration

```text
THIRD_PARTY_SOURCE_FILES=0
THIRD_PARTY_RUNTIME_LIBS_REQUIRED_BY_CORE=0
LANGUAGE_STANDARD=C++17
CORE_DEPENDENCY=C++17_STANDARD_LIBRARY_ONLY
```

CMake is optional tooling, not a runtime dependency. `build_msvc.bat` can compile the drop directly with MSVC without CMake.

## Authority declaration

The selftest is synthetic and does not represent RawrXD live GPU performance. Product authority remains fail-closed until the adapter is bound to real DualStick device handles and a matched live comparison passes the law in `AUTHORITY_LAW.txt`.
