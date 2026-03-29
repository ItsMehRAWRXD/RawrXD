# RawrXD IDE - Debugger Critical Gaps Analysis

**Date**: March 28, 2026  
**Scope**: `Win32IDE_Debugger.cpp`, `Win32IDE_Core.cpp`, `Win32IDE.h`  
**Purpose**: Identify gaps in DAP integration, frame tracking, error handling, and thread safety

---

## Executive Summary

The debugger implementation is **partially complete** with dual-path architecture:
- **Path 1 (Preferred)**: DAP (Debug Adapter Protocol) via external adapters (cppdbg)
- **Path 2 (Fallback)**: Native DbgEng COM wrapper via `NativeDebuggerEngine`

**Critical gaps exist** in frame tracking consistency, DAP error recovery, and thread safety for debugger callbacks.

---

## 1. DAP (Debug Adapter Protocol) Integration Status

### ✅ What's Implemented

1. **DAP Session Management** (Win32IDE_Debugger.cpp:55-75)
   - `DapUiSession` struct holds connection state, thread ID, and frame ID
   - Global `g_dapSessionMutex` protects `g_dapSessions` map
   - `getDapSession()` / `storeDapSession()` thread-safe accessors
   - Per-adapter event callback routing via `setEventCallback()`

2. **DAP Adapter Discovery & Launch** (Win32IDE_Debugger.cpp:260-305)
   - Auto-detects cpptools adapter from `.vscode/extensions/`
   - Parses `launch.json` or `.rawrxd/launch.json`
   - Supports both `launch` and `attach` requests
   - Extracts variable substitutions (`${workspaceFolder}`, `${file}`, etc.)

3. **DAP Initialization Flow** (Win32IDE_Debugger.cpp:615-680)
   - `initialize()` request with IDE branding + workspace root
   - `setBreakpoints()` per file before launch
   - `configurationDone()` handshake
   - `launch()` / `attach()` process control
   - Event callback wired to `handlePostedDapEvent()`

4. **DAP Event Handling** (Win32IDE_Debugger.cpp:2230-2310)
   - `stopped` → pause UI, update frame context
   - `continued` → resume UI, clear frame
   - `output` → append to Output tab
   - `terminated` → cleanup session
   - `exception` → error logging
   - Posts via `WM_DAP_EVENT_SAFE` for thread safety

### ❌ Critical Gaps

1. **Frame ID Staleness After Commands**
   ```cpp
   // Gap: Frame ID (-1) not updated until stopped event
   dapSession->currentFrameId = -1;  // Line 1116, 1133, 1149
   ```
   - After `stepInto()`, `stepOver()`, `stepOut()`: frame ID set to -1 (invalid)
   - Variables/watch evaluation fails if attempted before next `stopped` event
   - **Risk**: UI shows "(No DAP scopes for this frame)" or crashes on `evaluate()`

2. **Missing DAP Error Recovery**
   ```cpp
   // Line 680: "breaking on" adapter startup failure, no alternative path
   if (!adapterStarted) {
       appendToOutput("❌ DAP adapter failed to start: " + adapterExecutable, ...);
       // ** Falls back to NativeDebuggerEngine, but no user feedback on why
   }
   ```
   - No retry logic (e.g., wait for port, check executable)
   - No graceful degradation messaging
   - User sees cryptic "DAP initialize request failed or timed out (20s)" with no context

3. **DAP Timeout Handling**
   - `initialize()` timeout: hardcoded 20 seconds (no config)
   - No exponential backoff for `setBreakpoints()` retries
   - Adapter crash mid-session: no reconnect attempt

4. **Incomplete DAP Scopes Support**
   ```cpp
   // Line ~1650: DAP scopes enumeration
   for (const auto& scope : scopes) {
       const int ref = scope.value("variablesReference", 0);
       if (ref <= 0) continue;
       const bool expensive = scope.value("expensive", false);
       if (expensive) continue;  // ** Silently skips expensive scopes (heap dump)
   ```
   - Expensive scopes (memory, registers) skipped
   - No UI affordance to expand on-demand (e.g., checkbox)
   - Nested variable resolution depth NOT limited (potential infinite recursion)

5. **Missing DAP Capabilities Negotiation**
   ```cpp
   // No use of DAP capabilities response to enable/disable features:
   // - supportsReadMemoryRequest
   // - supportsSetVariable
   // - supportsRestartFrame
   // - supportsDelayedStackTraceReferences
   ```

---

## 2. Frame Tracking Implementation Status

### ✅ What's Implemented

1. **DAP Frame Context Tracking** (Win32IDE_Debugger.cpp:1800-1830)
   ```cpp
   struct StackFrame {
       std::string function;
       std::string file;
       int line;
       int dapFrameId;  // Preserved per-frame DAP ID
   };
   
   void selectStackFrame(int index) {
       if (frame.dapFrameId >= 0) {
           dapSession->currentFrameId = frame.dapFrameId;
       }
   }
   ```
   - Frame ID persisted in `StackFrame` struct
   - `selectStackFrame()` updates active frame for subsequent evaluations
   - Variables/watch evaluated in correct frame context

2. **Native Engine Frame Locals** (Win32IDE_Debugger.cpp:1670-1700)
   ```cpp
   int frameIndex = m_selectedStackFrameIndex;
   DebugResult r = engine.getFrameLocals(frameIndex, frameLocals);
   ```
   - Index-based frame selection
   - Per-frame locals retrieved from engine

3. **Stack Trace Refresh** (Win32IDE_Debugger.cpp:1800-1850)
   ```cpp
   const auto dapFrames = dapSession->service->stackTrace(
       dapSession->currentThreadId, 0, 128);
   m_selectedStackFrameIndex = 0;
   dapSession->currentFrameId = dapFrames.front().id;
   ```
   - Initializes to frame 0 on each pause
   - Updates `m_debuggerCurrentFile` + `m_debuggerCurrentLine` from top frame

### ❌ Critical Gaps

1. **Frame ID Invalidation After Step Commands**
   ```cpp
   // Lines 1116, 1133, 1149: All step operations invalidate frame
   stepIntoExecution() {
       dapSession->currentFrameId = -1;  // ❌ Stale context
       m_debuggerPaused = false;
       SetWindowTextA(..., "↓ DAP stepping in...");
   }
   ```
   - **Problem**: During stepping pause → new frame arrives → but UI hasn't called `selectStackFrame()`
   - **Race condition**: Watch expressions evaluated with `-1` frame ID before pause event processed
   - **Fix needed**: Delay evaluation requests until `stopped` event arrives

2. **No Frame ID Validation**
   ```cpp
   // evaluateWatch() at line 1580 — no validation before evaluate()
   if (dapSession->currentFrameId >= 0 && m_debuggerPaused) {
       // ❌ No check: is this frame still valid after timeout?
       const std::string result = dapSession->service->evaluate(
           dapSession->currentFrameId, expression, "watch");
   }
   ```
   - Frame IDs can stale if:
     - Adapter crashes mid-session
     - Target process exits
     - DAP protocol desynchronization
   - **Result**: Evaluate requests hang or return error 104 (frame not found)

3. **No Frame Depth Tracking**
   ```cpp
   // m_callStack just stores StackFrame objects
   // BUT: No tracking of max depth, no loop detection
   // If adapter returns circular frame chain, app could crash
   std::vector<StackFrame> m_callStack;  // No size limit
   ```

4. **Multi-Thread Frame Confusion**
   ```cpp
   // Line 1800-1830: updateCallStack() only uses currentThreadId
   const auto dapFrames = dapSession->service->stackTrace(
       dapSession->currentThreadId, 0, 128);
   ```
   - Only shows frames for one thread
   - No UI to switch threads
   - If target has 10 threads, only active thread inspectable

5. **DAP Frame ID Mismatch with UI Index**
   ```cpp
   // ❌ DAP uses 0-based frame IDs, UI uses m_selectedStackFrameIndex
   // selectStackFrame(2) → m_selectedStackFrameIndex = 2
   //                     → m_callStack[2].dapFrameId = ???
   // If DAP adapter skipped frame 1, IDs don't align
   ```

---

## 3. Error Handling in Debugger

### ✅ What's Implemented

1. **DAP Adapter Startup Error Logging** (Win32IDE_Debugger.cpp:628-635)
   ```cpp
   if (!adapterStarted) {
       appendToOutput("❌ DAP adapter failed to start: " + adapterExecutable, 
                      "Output", OutputSeverity::Error);
   }
   if (!initialized) {
       appendToOutput("❌ DAP initialize request failed or timed out (20s)", ...);
   }
   ```

2. **Breakpoint Set/Remove Error Handling** (Win32IDE_Debugger.cpp:1220-1245)
   ```cpp
   DebugResult r = engine.addBreakpointBySourceLine(file, line);
   if (!r.success) {
       std::string warn = "⚠️ Engine breakpoint at " + file + ": " + r.detail;
       appendToOutput(warn, "Output", OutputSeverity::Warning);
   }
   ```

3. **DAP Watch Expression Error Catching** (Win32IDE_Debugger.cpp:1580-1600)
   ```cpp
   try {
       const std::string result = dapSession->service->evaluate(...);
       item.value = result;
       item.type = "dap";
   } catch (const std::exception& ex) {
       std::string err = "⚠️ DAP watch eval failed for '" + item.expression + "': ";
       err += ex.what();
       appendToOutput(err, "Output", OutputSeverity::Warning);
       item.value = "<DAP error>";
   }
   ```

4. **Native Engine Error Propagation** (Win32IDE_Debugger.cpp:1210-1230)
   ```cpp
   DebugResult r = engine.stepOver();
   if (!r.success) {
       std::string err = "❌ Step Over failed: " + r.detail;
       appendToOutput(err, "Output", OutputSeverity::Error);
       return;
   }
   ```

### ❌ Critical Gaps

1. **Missing Timeout Protection on DAP Evaluate**
   ```cpp
   // Line ~1580: evaluate() call has NO timeout
   const std::string result = dapSession->service->evaluate(
       dapSession->currentFrameId, item.expression, "watch");
   ```
   - If adapter hangs, UI blocks forever
   - No async/await pattern; synchronous blocking call
   - **Symptom**: IDE freezes for 30+ seconds when watch expression evaluation stalls

2. **DAP Error Never Falls Back to Native**
   ```cpp
   // Line 680-700: If DAP initialization fails, code does fallback
   // BUT: If DAP attached successfully, then crashes mid-session?
   // -> No fallback to NativeDebuggerEngine
   // -> User loses all debugging capability
   ```

3. **Incomplete DAP Event Error Parsing**
   ```cpp
   // Line 2290-2305: exception event handling
   if (reason == "exception") {
       const std::string excText = body.value("text", "");
       statusText = "⏸ Exception" + (excText.empty() ? "" : ": " + excText);
       appendToOutput("⚠️ DAP exception: " + (excText.empty() ? "(unknown)" : excText), ...);
   }
   // ❌ No access to exception details: type, code, inner exception, stack trace
   ```

4. **No Retry Logic for Transient DAP Failures**
   ```cpp
   // Line 640: setBreakpoints failure = log warning, continue silently
   if (!dapSession->service->setBreakpoints(entry.first, entry.second)) {
       breakpointSyncOk = false;
       appendToOutput("⚠️ DAP breakpoint sync failed for: " + entry.first, ...);
   }
   // ❌ No automatic retry; user must manually re-attach
   ```

5. **Watch Expression Errors Not Differentiated**
   ```cpp
   // evaluateWatch(): catches std::exception but treats all as "error"
   // Actual adapter returned 400 (syntax error) vs 500 (internal error)?
   // -> Cannot determine if user's expression is wrong or adapter is broken
   item.value = "<error: " + r.detail + ">";  // Too generic
   ```

6. **No DAP Adapter Crash Detection**
   ```cpp
   // Adapter crashes while paused with valid frame?
   // -> Next evaluate() will fail
   // -> But code doesn't check adapter health before attempting evaluate()
   ```

---

## 4. Thread Safety Issues in Debugger Callbacks

### ✅ What's Implemented

1. **DAP Session Mutex** (Win32IDE_Debugger.cpp:61, 65, 71)
   ```cpp
   std::mutex g_dapSessionMutex;
   
   std::shared_ptr<DapUiSession> getDapSession(Win32IDE* ide) {
       std::lock_guard<std::mutex> lock(g_dapSessionMutex);
       auto it = g_dapSessions.find(ide);
       return it == g_dapSessions.end() ? nullptr : it->second;
   }
   ```
   - Protects DAP session map from concurrent access
   - Lock acquired/released per call

2. **Event Callback Safe Posting** (Win32IDE_Debugger.cpp:613-620)
   ```cpp
   dapSession->service->setEventCallback([this](const std::string& event, const nlohmann::json& body) {
       if (isShuttingDown() || !m_hwndMain) {
           return;  // Guard against detached window
       }
       char* payload = makePostedDapEventPayload(event, body);
       if (payload) {
           PostMessageA(m_hwndMain, WM_DAP_EVENT_SAFE, 0, reinterpret_cast<LPARAM>(payload));
       }
   });
   ```
   - Callbacks post to message queue (async)
   - No direct access to IDE state from callback thread
   - Allocated payload freed by message handler

3. **State Spinlock for Shutdown** (Win32IDE_Core.cpp:~Win32IDE)
   ```cpp
   m_shuttingDown.store(true, std::memory_order_release);
   if (m_activeDetachedThreads.load(std::memory_order_acquire) > 0) {
       for (int i = 0; i < 60 && m_activeDetachedThreads.load(...) > 0; ++i) {
           Sleep(50);
       }
   }
   ```

### ❌ Critical Gaps

1. **DAP Event Callback → UI State Race Condition**
   ```cpp
   // Line 613-620: Callback acquires no locks
   // Timeline:
   // T1 (DAP adapter thread): Event arrives -> callback fired
   // T2 (main thread):         pauseExecution() releases DAP session -> null
   // T3 (DAP adapter thread): callback tries getDapSession(this) -> nullptr
   // T4 (callback thread):    attempts to access released m_hwndMain
   ```
   - **Race**: Callback's `this` pointer may dangle if IDE destroyed
   - **Mitigation**: `isShuttingDown()` check, but not atomic with callback

2. **Posted DAP Event Payload Memory Leak**
   ```cpp
   // Line 619: char* payload allocated via _strdup()
   // Handler at line 2265: handlePostedDapEvent(const char* payloadJson)
   // ❌ Responsibility to free payload NOT DOCUMENTED
   // Handler doesn't call free(payload)
   ```

3. **NativeDebuggerEngine Callbacks Without Locks**
   ```cpp
   // Line 760-800: Engine callbacks set directly
   engine.setBreakpointHitCallback([](const NativeBreakpoint* bp, ..., void* userData) {
       auto* ide = static_cast<Win32IDE*>(userData);
       if (ide && bp) {
           ide->onDebuggerBreakpoint(bp->sourceFile, bp->sourceLine);
       }
   }, this);
   ```
   - `userData` (this pointer) could dangle
   - If debugger detaches mid-callback, `ide->onDebuggerBreakpoint()` accesses freed object
   - **No refcount or token validation**

4. **Concurrent Access to m_breakpoints Vector**
   ```cpp
   // Line 1200+: setBreakpoint() modifies m_breakpoints
   m_breakpoints.push_back(bp);
   updateBreakpointList();
   
   // ❌ If DAP callback thread calls handlePostedDapEvent() while setBreakpoint() iterates?
   // updateBreakpointList() iterates m_breakpoints without lock
   ```

5. **Unprotected m_callStack Access During Frame Selection**
   ```cpp
   // Line 1800: updateCallStack() clears + repopulates m_callStack
   m_callStack.clear();
   for (const auto& frame : dapFrames) { m_callStack.push_back(...); }
   
   // Line 1850: selectStackFrame() reads m_callStack[index]
   if (index < 0 || (size_t)index >= m_callStack.size()) return;
   const StackFrame& frame = m_callStack[index];
   
   // ❌ No mutex: Race if updateCallStack() executes while selectStackFrame() reads
   ```

6. **DAP Session Map Not Locked During Entire Operation**
   ```cpp
   // Line 640: setBreakpoints() called INSIDE getDapSession() scope
   const bool breakpointSyncOk = true;
   for (const auto& entry : byFile) {
       if (!dapSession->service->setBreakpoints(entry.first, entry.second)) {
           // ❌ Lock released BEFORE this check
           // Another thread could have invalidated dapSession
       }
   }
   ```

7. **No Thread ID Tracking for Debuggee Threads**
   ```cpp
   // currentThreadId set once on stopped event
   session->currentThreadId = body.value("threadId", session->currentThreadId);
   
   // ❌ If target has 5 threads and adapter sends frame IDs from thread T1,
   // but we're querying thread T2's locals?
   // -> Mismatch in frames vs. locals
   ```

8. **Callback Capture of `this` Without Pinning**
   ```cpp
   // Line 760, 769: Lambdas capture [this]
   engine.setBreakpointHitCallback([](... void* userData) {
       auto* ide = static_cast<Win32IDE*>(userData);
       // ❌ userData could be invalid if Win32IDE destroyed
       // Lambda has no way to validate
   }, this);
   ```

---

## 5. Recommendations & Implementation Priority

### High Priority (P0) - Must Fix

| Gap | Category | Impact | Effort | Fix |
|-----|----------|--------|--------|-----|
| Frame ID invalidation after steps | Frame Tracking | UI hangs/crashes | Medium | Defer eval until `stopped` event; queue pending requests |
| DAP evaluate() timeout | Error Handling | IDE freezes | Medium | Add async evaluate with 5s timeout + cancellation token |
| Callback memory leaks (payload) | Thread Safety | Memory leak | Low | Document payload ownership; free in handler |
| Dangling `this` in callbacks | Thread Safety | Crash on detach | High | Weak-ptr validation or refcounting for Win32IDE |
| Unprotected m_breakpoints/m_callStack | Thread Safety | Race condition/crash | Medium | Add m_debuggerMutex; protect all collections |

### Medium Priority (P1) - Should Fix

| Gap | Category | Fix |
|-----|----------|-----|
| No DAP error recovery/retry | Error Handling | Add exponential backoff, fallback to native |
| Missing thread context in frame tracking | Frame Tracking | Show all threads in UI; let user select |
| DAP capabilities negotiation | DAP Integration | Query adapter capabilities on init; suppress unsupported features |
| No frame depth limit | Frame Tracking | Add max recursion depth (e.g., 500 frames) |
| Incomplete exception details | Error Handling | Extract full exception info from DAP body |

### Low Priority (P2) - Nice to Have

| Gap | Category | Fix |
|-----|----------|-----|
| Hardcoded 20s timeout | DAP Integration | Make config-driven |
| Silent skip of expensive scopes | DAP Integration | Add "Load Expensive Scope" button |
| No adapter health check | Error Handling | Periodic probe: send empty evaluate |

---

## 6. Code Locations & Quick Reference

| Feature | File | Lines | Status |
|---------|------|-------|--------|
| DAP Session Management | Win32IDE_Debugger.cpp | 55-75 | ✅ |
| DAP Event Handler | Win32IDE_Debugger.cpp | 2265-2310 | ✅ Partial |
| Frame Tracking (DAP) | Win32IDE_Debugger.cpp | 1850-1900 | ⚠️ Stale frames |
| Frame Tracking (Native) | Win32IDE_Debugger.cpp | 1700-1750 | ✅ |
| Breakpoint Management | Win32IDE_Debugger.cpp | 1200-1400 | ✅ |
| Watch Evaluation | Win32IDE_Debugger.cpp | 1580-1620 | ⚠️ No timeout |
| Variable Inspector | Win32IDE_Debugger.cpp | 1630-1750 | ✅ Partial |
| Call Stack Display | Win32IDE_Debugger.cpp | 1800-1850 | ✅ Partial |
| Memory View | Win32IDE_Debugger.cpp | 1880-2050 | ✅ |
| Debugger UI Creation | Win32IDE_Debugger.cpp | 340-590 | ✅ |
| Debugger State | Win32IDE.h | 2005-2025 | ✅ |
| Thread Safety | Win32IDE.h | 1750-1760 | ⚠️ Incomplete |

---

## 7. Test Matrix for Frame Tracking + Error Handling

### Test Cases to Add

```
DAP Frame Tracking:
  [ ] Pause on breakpoint → frame ID 0 + locals populated
  [ ] Step Over → frame ID invalidated, next stopped event restores
  [ ] Evaluate watch before stopped event → queue + replay on stopped
  [ ] Select frame[2] → dapSession->currentFrameId = frame[2].dapFrameId
  [ ] Adapter crash during evaluate → graceful error, no freeze

DAP Error Recovery:
  [ ] Adapter executable not found → fallback to native
  [ ] setBreakpoints fails → retry up to 3 times with backoff
  [ ] evaluate times out after 5s → return "<timeout>" + cancel request
  [ ] initialize hangs 25s → timeout + fallback
  [ ] Exception event without details → show reason code

Thread Safety:
  [ ] Detach during DAP callback → no crash
  [ ] updateCallStack() during selectStackFrame() → no race
  [ ] Breakpoint added while handler running → consistent state
  [ ] Shutdown with active callbacks → all threads joined
```

---

## Appendix: Data Structures

### Debugger State
```cpp
// Win32IDE.h lines 2005-2025
bool m_debuggerEnabled = false;
bool m_debuggerAttached = false;
bool m_debuggerPaused = false;
std::string m_debuggerCurrentFile;
int m_debuggerCurrentLine = -1;

std::vector<Breakpoint> m_breakpoints;        // ⚠️ Unprotected
std::vector<StackFrame> m_callStack;          // ⚠️ Unprotected
std::vector<Variable> m_localVariables;       // ⚠️ Unprotected
std::vector<WatchItem> m_watchList;           // ⚠️ Unprotected
int m_selectedStackFrameIndex = 0;            // ⚠️ Unprotected
```

### DAP Session
```cpp
// Win32IDE_Debugger.cpp line 47
struct DapUiSession {
    std::unique_ptr<DapClientService> service;
    std::string configName;
    std::string configType;
    int currentThreadId = 1;
    int currentFrameId = -1;  // ⚠️ -1 = invalid (stale after step)
    bool initializedSeen = false;
};
```

### Event Callback Flow
```
Adapter                DAP Callback        Main Thread         UI
   |                        |                    |              |
   +-- stopped event ------->|                    |              |
   |                        | PostMessage(DAP_EVENT_SAFE)       |
   |                        +-------------------->|              |
   |                        |                    |--updateCallStack()
   |                        |                    |--updateVariables()
   |                        |                    +--Repaint
```

---

**Report Generated**: March 28, 2026  
**Next Steps**: Prioritize P0 fixes; add mutex protection layer; implement async evaluate with timeout
