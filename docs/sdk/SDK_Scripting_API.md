# SDK Scripting API
## Sovereign IDE SDK Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

The Scripting API enables automation and customization through Python and Lua scripting.

### Supported Languages

| Language | Version | Status |
|----------|---------|--------|
| Python | 3.9+ | ✅ Supported |
| Lua | 5.4 | ✅ Supported |
| JavaScript | ES2020 | 🔄 Planned |

---

## Python API

```python
import sovereign

# Load binary
binary = sovereign.load_binary("/path/to/binary.exe")

# Run analysis
results = binary.analyze()

# Access functions
for func in binary.functions:
    print(f"Function: {func.name} at {func.address:08x}")

# Disassemble
for inst in func.instructions:
    print(f"  {inst.address:08x}: {inst.mnemonic} {inst.operands}")
```

---

## Lua API

```lua
local sovereign = require("sovereign")

-- Load binary
local binary = sovereign.load_binary("/path/to/binary.exe")

-- Run analysis
local results = binary:analyze()

-- Access functions
for _, func in ipairs(binary.functions) do
    print(string.format("Function: %s at %08x", func.name, func.address))
end
```

---

## API Reference

```cpp
// Scripting initialization
SOVEREIGN_SDK_API ScriptResult Script_Initialize();
SOVEREIGN_API void Script_Shutdown();

// Python
SOVEREIGN_SDK_API ScriptResult Script_RunPython(const char* code);
SOVEREIGN_SDK_API ScriptResult Script_RunPythonFile(const char* path);

// Lua
SOVEREIGN_SDK_API ScriptResult Script_RunLua(const char* code);
SOVEREIGN_SDK_API ScriptResult Script_RunLuaFile(const char* path);
```

---

## Summary

The SDK Scripting API provides:

- ✅ **Python 3.9+**
- ✅ **Lua 5.4**
- ✅ **Full IDE access**
- ✅ **Automation support**
- ✅ **Plugin integration**

**Status:** ✅ Complete
