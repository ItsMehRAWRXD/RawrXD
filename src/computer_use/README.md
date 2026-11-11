# RawrXD Native Computer Use — clean-room source drop

Original C++20/Win32 implementation, **not** OpenAI/ChatGPT proprietary source or a reproduction of its internals.

## Build (Windows, MSVC Developer PowerShell)

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

No third-party libraries or cloud services. Requires Windows SDK, C++20 compiler, CMake and Ninja (build tools only). Integrate `rawrxd_computer_use` into the IDE target and include `AgentAdapter.h`.

## Supported operations

Window title lookup, Win32 child control enumeration, BMP capture of a client area, mouse click/move/scroll, Unicode typing, virtual-key press, direct executable launch, cancellation and minimal privacy-aware receipts. Mouse coordinates are **client-relative**. All actions are subject to explicit policy; default is deny. Window lookup is restricted to allowlisted process IDs. Launches do not automatically add their PID to the allowlist.

Example configuration:

```cpp
SafetyPolicy p;
p.allowedProcessIds = {GetCurrentProcessId()};
p.allowInspection = true;
p.allowScreenshots = true;
p.allowMouse = false;  // enable only with explicit authorization
p.allowTyping = false;
p.allowKeyboard = false;
p.allowLaunch = false;
ComputerUseEngine engine(p);
```

## Security and limitations

- Do not directly execute arbitrary model-provided commands. Parse into typed actions, validate the target and require application-level approval through `AgentAdapter`.
- `CreateProcessW` launches a specific absolute executable, not a shell; arguments still require caller validation. Prefer an explicit executable allowlist in production.
- Windows UIPI prevents input to higher-integrity apps; do not bypass it.
- Win32 `EnumChildWindows` is **not** full UI Automation. Custom-rendered controls and browser DOM nodes are not enumerated. Add an optional `IUIAutomation` COM adapter if required.
- GDI `BitBlt` may fail to capture occluded, hardware-accelerated, or protected content. Screenshot BMP files contain potentially sensitive screen data; delete after use.
- `SendInput` only confirms event injection, not application-level effect. Verify intended changes by inspection or user review.
- `TypeText` sends UTF-16 code units; complex surrogate sequences and IME input require additional validation.
- Keyboard shortcuts with modifiers, high-DPI/multi-monitor coordinate policies, durable audit storage, application-specific confirmation dialogs, and independent full-system acceptance are not implemented.
- Tests are smoke tests, not certification. This package has not been compiled or executed on Windows in this environment.

## RawrXD acceptance gates

1. Build and run smoke tests on Windows.
2. Verify allowlisted target window, foreground protection and denial cases.
3. Exercise mouse, typing, screenshots, cancellation and UI result readback against a disposable test application.
4. Test agent adapter approval/denial and ensure tool calls never bypass policy.
5. Run integration tests in a new candidate build and seal its own SHA. Do not modify the existing certified `4DE0…` binary.
