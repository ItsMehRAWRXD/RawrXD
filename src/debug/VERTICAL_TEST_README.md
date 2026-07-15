# RawrXD DAP Vertical Slice Test

## Overview

This test harness validates the entire debugging stack from DAP protocol down to Windows API:

```
DAP Protocol (JSON-RPC) → DAPAdapter → DebugBackend → Windows API (DbgHelp, Debug API)
```

## Files Created

### 1. VerticalTest.cpp
**Purpose:** C++ unit test harness that tests each layer independently

**Tests:**
- JSON Serialization (JSONWriter)
- JSON Parsing (JSONParser)
- DebugBridge Event System
- DebugBackend Direct API (Launch, Breakpoints, StackWalk, Memory Read)
- DAPAdapter Initialize

**Build:**
```batch
build_vertical_test.bat
```

**Run:**
```batch
..\..\build\debug\VerticalTest.exe
```

### 2. dap_test_harness.py
**Purpose:** Python integration test that drives the actual DAPServer.exe

**Tests:**
- Initialize request/response
- Launch request
- Threads request
- Disconnect request

**Usage:**
```bash
python dap_test_harness.py --server ..\..\build\debug\DAPServer.exe --verbose
```

### 3. test_messages.txt
**Purpose:** Raw DAP messages for manual testing

**Usage:**
```batch
DAPServer.exe < test_messages.txt
```

## Test Strategy

### Phase 1: Component Tests (VerticalTest.cpp)
Run these first to verify each layer works in isolation:

1. **JSON Tests** - Verify serialization/parsing
2. **DebugBridge** - Verify event posting/processing
3. **DebugBackend** - Verify actual Windows debugging API calls

### Phase 2: Protocol Tests (dap_test_harness.py)
Run these to verify the full DAP protocol:

1. **Initialize** - Server responds with capabilities
2. **Launch** - Server starts target process
3. **Threads** - Server returns thread list
4. **Disconnect** - Server cleans up and exits

### Phase 3: Manual Testing (test_messages.txt)
Use for debugging specific protocol scenarios

## Expected Results

### VerticalTest.cpp Output (Success)
```
[PASS] JSON serialization test passed
[PASS] JSON parsing test passed
[PASS] DebugBridge test passed
[PASS] DebugBackend direct test passed
[PASS] DAP Initialize test passed

Test Results: 5 passed, 0 failed
[SUCCESS] All vertical slice tests passed!
```

### dap_test_harness.py Output (Success)
```
[INFO] Testing initialize...
[INFO] Initialize test PASSED
[INFO] Testing launch...
[INFO] Launch test PASSED
...
Test Results:
  Initialize: PASS
  Launch: PASS
  Threads: PASS
  Disconnect: PASS
Total: 4 passed, 0 failed
[SUCCESS] All DAP protocol tests passed!
```

## Debugging Failures

### If VerticalTest.cpp fails:

1. **JSON Serialization fails**
   - Check JSONWriter implementation in DAPTransport.hpp
   - Verify buffer sizes are sufficient

2. **DebugBackend fails**
   - Check if running with proper permissions (admin may be needed for some operations)
   - Verify DbgHelp.dll is available
   - Check if target process (notepad.exe) exists at specified path

3. **DAPAdapter fails**
   - Verify all dependencies compile
   - Check for linker errors

### If dap_test_harness.py fails:

1. **Server won't start**
   - Verify DAPServer.exe exists and is compiled
   - Check Windows Defender/antivirus isn't blocking it

2. **No response from server**
   - Verify stdin/stdout are working (binary mode)
   - Check Content-Length headers are correct

3. **Initialize fails**
   - Check JSON format in request
   - Verify server is reading from stdin correctly

## Next Steps After Success

Once vertical slice tests pass:

1. **Build VS Code Extension** - Create the TypeScript glue code
2. **Integration Test** - Test with actual VS Code debugger UI
3. **LSP Phase** - Now safe to add Language Server Protocol

## Architecture Validation

This test proves:

✅ **DAP Protocol Layer** - JSON-RPC message handling works
✅ **Adapter Layer** - Request dispatch and response generation works
✅ **Backend Layer** - Windows Debug API integration works
✅ **Vertical Integration** - All layers communicate correctly

The stack is ready for VS Code integration.
