# Sovereign Subsystem Wiring Guide
## Phase 8: Unified Runtime Integration

### Overview
This guide shows how to wire any subsystem into the Sovereign Unified Runtime through the Subsystem Registry.

### The 5-Step Wiring Pattern

Every subsystem follows the same pattern:

```
┌─────────────────────────────────────────────────────────────┐
│  Step 1: Create Handler                                       │
│  Step 2: Define Subsystem Structure                           │
│  Step 3: Register in Unified CLI                              │
│  Step 4: Implement Commands                                   │
│  Step 5: Add GUI Binding                                      │
└─────────────────────────────────────────────────────────────┘
```

### Step 1: Create Handler File

Create: `src/subsystems/<name>/<Name>Subsystem.cpp`

```cpp
#include "../../core/SovereignSubsystemRegistry.h"

int <Name>Subsystem_Handler(int argc, char** argv, char* output, size_t output_size) {
    if (argc < 1) {
        snprintf(output, output_size, "{\"error\":\"no command\"}");
        return -1;
    }
    
    const char* cmd = argv[0];
    
    if (strcmp(cmd, "status") == 0) {
        snprintf(output, output_size, 
            "{\"subsystem\":\"<name>\",\"status\":\"ready\",\"version\":\"0.1.0\"}");
        return 0;
    }
    
    // Add more commands...
    
    snprintf(output, output_size, "{\"error\":\"unknown command '%s'\"}", cmd);
    return -1;
}
```

### Step 2: Define Subsystem Entry

In `SovereignCLI_Unified.cpp`, add:

```cpp
static SovereignSubsystem g_<name>_subsystem = {
    SUBSYSTEM_NAME_<NAME>,     // Name constant
    "0.1.0",                   // Version
    SUBSYSTEM_<NAME>,          // Type enum
    CAP_<CAPABILITIES>,        // Capabilities
    STATE_UNINITIALIZED,
    <Name>Subsystem_Handler,   // Handler function
    nullptr, nullptr, nullptr, // Lifecycle functions
    "Product-Line",            // Product line
    "Build-System",            // Build system
    0, 0                       // File counts
};
```

### Step 3: Register in main()

```cpp
Sovereign_RegisterSubsystem(&g_<name>_subsystem);
```

### Step 4: Add to Command Router

In `Sovereign_AutoRoute()`, add:

```cpp
else if (strcmp(cmd, "<command>") == 0) {
    subsystem_name = SUBSYSTEM_NAME_<NAME>;
}
```

### Step 5: GUI Binding

```javascript
// GUI code
async function run<Name>Command(command, args) {
    const result = await backend.run(`<name> ${command} ${args}`);
    return JSON.parse(result);
}
```

---

## Subsystem Wiring Order

### Priority 1: Core Runtime (DONE ✓)
- [x] kernel - 9/9 MASM kernels operational
- [x] audit - Codebase introspection
- [x] cli - Command interface
- [x] gui - GUI status

### Priority 2: Language Runtimes
- [ ] roslyn - MASM C# compiler
- [ ] java - MASM Java backend

### Priority 3: Specialized Engines
- [ ] codexpro - Reverse engineering
- [ ] sunshine - Game engine

### Priority 4: Hardware Abstraction
- [ ] titan - DMA/memory
- [ ] vulkan - GPU compute

---

## JSON Response Format

All subsystems must return valid JSON:

```json
{
  "subsystem": "name",
  "status": "ready|busy|error",
  "version": "x.y.z",
  "data": { }
}
```

Error format:
```json
{
  "subsystem": "name",
  "error": "description",
  "code": 123
}
```

---

## Verification Checklist

For each subsystem:
- [ ] Handler compiles
- [ ] Registers successfully
- [ ] Responds to "status" command
- [ ] Returns valid JSON
- [ ] Shows in registry list
- [ ] Auto-routes correctly
- [ ] GUI can call it
- [ ] Error handling works

---

## Next Steps

1. Pick a subsystem from Priority 2
2. Create its handler file
3. Follow the 5-step pattern
4. Test with: `SovereignCLI_Unified.exe <name> status`
5. Wire into GUI
6. Repeat for next subsystem
