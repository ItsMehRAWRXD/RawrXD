# Verification status

The portable core (`LifecycleBus` + `CommandCenter`) is intended to compile on any C++20 toolchain. The browser verifier is Windows-only and uses WinHTTP/Edge CDP.

The pack contains no `TODO`, `STUB`, `return true` compatibility shims, fake-success symbols, or alternate model runtime.

A successful Windows certification must include both the core test and a live Edge browser test. Do not mark `RAWRXD_BROWSER_AUTHORITY_001` PASS without actually launching/attaching Edge and producing the PNG receipt.
