# IDE CLI/GUI Audit & Phased Improvement Plan

## Executive Summary

**Current State:** The RawrXD IDE has extensive CLI/GUI integration capabilities but lacks unified cohesion between modes. This audit identifies gaps and proposes a 6-phase improvement plan.

**Scope:**
- SovereignCLIIDE (standalone + integrated tab)
- Win32IDE (main GUI application)
- HeadlessIDE (server mode)
- Agentic integration bridges

---

## Current Architecture Audit

### 1. Existing Components

| Component | Location | Purpose | Current Status |
|-----------|----------|---------|----------------|
| **SovereignCLIIDE** | `src/win32app/SovereignCLIIDE.h/cpp` | CLI that runs standalone or as GUI tab | ✅ Functional but isolated |
| **Win32IDE** | `src/win32app/Win32IDE.h/cpp` | Main GUI application | ✅ 300+ files, feature-rich |
| **HeadlessIDE** | `src/win32app/HeadlessIDE.h/cpp` | Server mode without GUI | ✅ Basic implementation |
| **AgenticBridge** | `src/win32app/Win32IDE_AgenticBridge.cpp` | Connects IDE to agentic system | ✅ Active but complex |
| **ExtensionHost** | `src/win32app/ExtensionHost*.cpp` | VSCode-compatible extensions | ⚠️ Partial |

### 2. Identified Gaps

#### Gap 1: Mode Switching Friction
- **Issue:** No seamless transition between CLI ↔ GUI ↔ Headless modes
- **Impact:** User context loss when switching modes
- **Evidence:** Separate initialization paths, no shared session state

#### Gap 2: Command Parity
- **Issue:** CLI commands don't map 1:1 to GUI actions
- **Impact:** Feature fragmentation, documentation complexity
- **Evidence:** `SovereignCLIIDE::executeCommand()` vs `Win32IDE_CommandHandlers.cpp`

#### Gap 3: State Synchronization
- **Issue:** No real-time sync between CLI and GUI views
- **Impact:** Stale data, conflicting operations
- **Evidence:** Separate file watchers, no unified event bus

#### Gap 4: Configuration Drift
- **Issue:** Different config formats for CLI vs GUI
- **Impact:** Maintenance burden, user confusion
- **Evidence:** `settings.json` vs registry vs command-line args

#### Gap 5: Extension Compatibility
- **Issue:** Extensions work in GUI but not CLI/Headless
- **Impact:** Limited automation capabilities
- **Evidence:** ExtensionHost tied to HWND

---

## Phased Improvement Plan

### Phase 1: Unified Session State (Foundation)
**Goal:** Single source of truth for IDE state across all modes

**Architecture Decision:** Use Win32 Shared Memory Section instead of file-backed JSON for real-time sync.

**Deliverables:**
- [ ] Create `UnifiedSessionState` class using `CreateFileMappingW` + `MapViewOfFile`
- [ ] Allocate ~1-2 MB fixed-size shared memory arena across all rawrxd.exe instances
- [ ] Implement atomic index swaps (Epoch-RCU style) for lock-free MPMC ring buffer
- [ ] Migrate Win32IDE state to unified model
- [ ] Update SovereignCLIIDE to use unified state
- [ ] Add state change notifications via shared memory pub/sub

**Files to Modify:**
- `src/win32app/SessionController.h/cpp` - Extend for unified state
- `src/win32app/SovereignCLIIDE.cpp` - Integrate unified state
- New: `src/core/UnifiedSessionState.hpp/cpp` (Win32 shared memory based)

**Success Criteria:**
- Open file in GUI → visible in CLI `status` command (< 1ms latency)
- CLI `cd` command → GUI updates working directory
- Zero data loss on mode switch
- **Performance:** Shared memory access < 100ns (vs ~10ms for file I/O)

**Estimated Effort:** 4-5 days (includes shared memory implementation)

---

### Phase 2: Command Router Unification
**Goal:** Single command system for CLI, GUI, and API

**Architecture Decision:** Use compile-time string hashing (FNV-1a) for O(1) zero-allocation command routing.

**Deliverables:**
- [ ] Create `IDECommandRouter` with `constexpr` FNV-1a hash function
- [ ] Implement `HashCommand(std::string_view)` → `uint64_t` for O(1) lookup
- [ ] Map all GUI actions to CLI commands using `switch (hash)` pattern
- [ ] Implement command discovery (`help`, `list-commands`)
- [ ] Add command history sync via shared memory (Phase 1)

**Files to Modify:**
- `src/win32app/Win32IDE_Commands.cpp` - Refactor to use router
- `src/win32app/SovereignCLIIDE.cpp` - Use unified router
- New: `src/core/IDECommandRouter.hpp/cpp` (zero-allocation, hash-based)

**Success Criteria:**
- Every GUI menu item has CLI equivalent
- Commands work identically in all modes
- Command history persists across sessions
- **Performance:** Command routing O(1) with zero heap allocations
- **Memory:** No string copies, use `std::string_view` throughout

**Example:**
```cpp
switch (HashCommand(cmdView)) {
    case "file/open"_hash:       HandleFileOpen(); break;
    case "model/hotpatch"_hash:  HandleHotpatch(); break;
    case "v1/decode"_hash:       HandleDecode(); break;
}
```

**Estimated Effort:** 4-5 days

---

### Phase 3: Event Bus Architecture
**Goal:** Real-time synchronization between CLI and GUI

**Architecture Decision:** Build Event Bus on top of Phase 1 shared memory ring buffer (no separate system).

**Deliverables:**
- [ ] Create `IDEEventBus` using existing shared memory arena from Phase 1
- [ ] Implement lock-free MPMC ring buffer with atomic index swaps (Epoch-RCU style)
- [ ] Define event types: FileChange, ConfigChange, ModelUpdate, etc.
- [ ] Add CLI `watch` command for live updates
- [ ] GUI panels subscribe to relevant events via shared memory

**Files to Modify:**
- `src/win32app/Win32IDE_Core.cpp` - Integrate event bus
- `src/win32app/SovereignCLIIDE.cpp` - Add event subscription
- New: `src/core/IDEEventBus.hpp/cpp` (built on UnifiedSessionState shared memory)

**Success Criteria:**
- File save in GUI → CLI shows updated content immediately
- Model hotpatch → both CLI and GUI update simultaneously
- **Performance:** Event latency < 1ms (shared memory vs 50ms file I/O)
- **Memory:** Zero-copy events via shared memory views

**Estimated Effort:** 4-5 days (leverages Phase 1 infrastructure)

---

### Phase 4: Configuration Consolidation
**Goal:** Single configuration system for all modes

**Architecture Decision:** Single-pass non-allocating JSON5 scanner using pointer views.

**Deliverables:**
- [ ] Create `UnifiedConfig` with single-pass JSON5 scanner
- [ ] Use pointer views into memory-mapped file (no heap allocations)
- [ ] Migration tool from old formats
- [ ] Environment variable overlay
- [ ] CLI `--config` override support

**Files to Modify:**
- `src/win32app/Win32IDE_Settings.cpp` - Use unified config
- `src/win32app/SovereignCLIIDE.cpp` - Config integration
- New: `src/core/UnifiedConfig.hpp/cpp` (zero-allocation, pointer-view based)

**Success Criteria:**
- One config file rules all modes
- Changes apply immediately (no restart)
- Schema validation with helpful errors
- **Performance:** Config load O(n) with zero heap allocations
- **Memory:** Pointer views into mapped file, no string copies

**Example:**
```cpp
// Single-pass scan, pointer views only
ConfigView cfg = ConfigParser::Parse(mappedFile);
auto modelPath = cfg.Get("model/path");  // Returns string_view, not copy
```

**Estimated Effort:** 3-4 days

---

### Phase 5: Extension Host Decoupling
**Goal:** Extensions work in CLI and Headless modes

**Architecture Decision:** Define `IIDEInterface` struct with pure virtual function pointers for abstraction.

**Deliverables:**
- [ ] Define `IIDEInterface` struct: `OpenFile`, `GetBuffer`, `DispatchCommand`, etc.
- [ ] Refactor ExtensionHost to use `IIDEInterface*` instead of HWND
- [ ] Create `Win32IDEInterface` implementation (GUI mode)
- [ ] Create `HeadlessIDEInterface` implementation (pipes to stdout/TCP)
- [ ] Implement headless extension runner
- [ ] Add extension CLI commands (`ext install`, `ext list`)

**Files to Modify:**
- `src/win32app/ExtensionHost.cpp` - Decouple from GUI
- `src/win32app/ExtensionAPI_VSCode.cpp` - Add headless support
- New: `src/core/IIDEInterface.hpp` (pure virtual interface)
- New: `src/core/Win32IDEInterface.cpp` (GUI implementation)
- New: `src/core/HeadlessIDEInterface.cpp` (headless implementation)

**Success Criteria:**
- Extensions load in `rawrxd --headless` mode
- CLI can install/manage extensions
- Extension output visible in CLI
- **Architecture:** Extension host blissfully unaware of GUI vs headless

**Estimated Effort:** 5-6 days

---

### Phase 6: Mode-Aware UI Components
**Goal:** Components adapt to current mode (CLI/GUI/Headless)

**Architecture Decision:** Compile-time mode selection via template parameters for zero-overhead abstraction.

**Deliverables:**
- [ ] Create `UIModeAdapter` template with compile-time mode selection
- [ ] Refactor ChatPanel for CLI output using `if constexpr (Mode == CLI)`
- [ ] Refactor ModelManager for CLI interaction
- [ ] Add `rawrxd --mode=cli|gui|headless` flag

**Files to Modify:**
- `src/win32app/Win32IDE_ChatPanel.cpp` - Add CLI renderer
- `src/win32app/Win32IDE_ModelManager.cpp` - Add CLI interface
- New: `src/core/UIModeAdapter.hpp` (compile-time mode selection)

**Success Criteria:**
- Same component code works in all modes
- Graceful degradation (GUI features → CLI equivalents)
- Mode switch without restart
- **Performance:** Zero runtime overhead for mode checks (compile-time)
- **Memory:** No virtual dispatch, monomorphized templates

**Example:**
```cpp
template<UIMode Mode>
void ChatPanel::Render() {
    if constexpr (Mode == UIMode::GUI) {
        RenderRichText();
    } else if constexpr (Mode == UIMode::CLI) {
        RenderPlainText();
    }
}
```

**Estimated Effort:** 5-6 days

---

## Implementation Timeline

```
Week 1: Phase 1 (Unified Session State)
Week 2: Phase 2 (Command Router) + Phase 3 start
Week 3: Phase 3 (Event Bus) complete
Week 4: Phase 4 (Configuration)
Week 5: Phase 5 (Extensions)
Week 6: Phase 6 (Mode-Aware UI) + Integration testing
```

**Total Estimated Duration:** 6 weeks

---

## Testing Strategy

### Per-Phase Tests
1. **Unit Tests:** Each new class (UnifiedSessionState, IDECommandRouter, etc.)
2. **Integration Tests:** Mode switching, state sync
3. **Regression Tests:** Existing 6/6 tests must still pass

### Final Validation
- [ ] CLI-only workflow (no GUI)
- [ ] GUI with integrated CLI tab
- [ ] Headless server mode
- [ ] Mode switching mid-session
- [ ] Extension compatibility across modes

---

## Success Metrics

| Metric | Current | Target |
|--------|---------|--------|
| Mode switch time | N/A (not possible) | < 2 seconds |
| Command parity | ~40% | 100% |
| State sync latency | N/A | < 50ms |
| Config files | 3+ | 1 |
| Extension modes supported | 1 (GUI) | 3 (CLI/GUI/Headless) |
| User satisfaction | Baseline | +50% improvement |

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Breaking existing GUI | Extensive regression testing per phase |
| Performance degradation | Benchmark before/after each phase |
| User confusion | Clear migration guide, backward compatibility layer |
| Extension breakage | Extension compatibility testing harness |

---

## Conclusion

This 6-phase plan transforms the RawrXD IDE from a collection of separate modes into a unified, mode-agnostic development environment. The phased approach minimizes risk while delivering incremental value.

**Recommendation:** Proceed with Phase 1 immediately after current hotpatch system stabilization.

---

## Peer Review Summary

**Review Date:** 2026-07-03  
**Key Recommendations Incorporated:**

1. **Phase 1 (Unified Session State):** Changed from file-backed JSON to Win32 Shared Memory with Epoch-RCU atomic index swaps for <100ns access latency
2. **Phase 2 (Command Router):** Added compile-time FNV-1a hashing for O(1) zero-allocation command routing
3. **Phase 3 (Event Bus):** Built on Phase 1 shared memory infrastructure instead of separate system
4. **Phase 4 (Configuration):** Specified single-pass non-allocating JSON5 scanner with pointer views
5. **Phase 5 (Extensions):** Defined `IIDEInterface` pure virtual abstraction for GUI/Headless decoupling
6. **Phase 6 (Mode-Aware UI):** Added compile-time mode selection via templates for zero runtime overhead

**Architecture Principles Applied:**
- Zero-allocation patterns throughout (`std::string_view`, pointer views)
- Compile-time computation where possible (FNV-1a hashing, mode selection)
- Shared memory for real-time sync (not file I/O)
- Lock-free MPMC ring buffers (Epoch-RCU style)
- Pure virtual interfaces for abstraction (not templates for this case)

---

**Document Version:** 1.1  
**Date:** 2026-07-03  
**Author:** Copilot Code Review  
**Status:** Peer Review Incorporated, Ready for Implementation
