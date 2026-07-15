// ============================================================================
// Win32IDE_GhostCode_Removal.md - Ghost Feature Cleanup Guide
// ============================================================================
// This document identifies "Ghost Code" - features declared but never
// implemented - and provides safe removal instructions.
//
// Ghost Code Definition:
// - Declared in headers (classes, methods, members)
// - Compiled into binary (object files exist)
// - NEVER called in initialization or runtime
// - Creates technical debt and confusion
// ============================================================================

## 🔴 CRITICAL GHOST FEATURES (Remove Immediately)

### 1. Omega Orchestrator
**Status:** Header-only ghost feature
**Impact:** 12+ methods declared, ZERO implementation

**Declarations to Remove from Win32IDE.h:**
```cpp
// DELETE THESE LINES (around line 528):
rawrxd::OmegaOrchestrator* m_omegaOrchestrator = nullptr;
bool m_omegaActive = false;

void initializeOmegaOrchestrator();  // NO IMPLEMENTATION
void onOmegaStart();                  // NO IMPLEMENTATION
void onOmegaStop();                   // NO IMPLEMENTATION
void onOmegaPause();                  // NO IMPLEMENTATION
void onOmegaResume();                 // NO IMPLEMENTATION
void onOmegaSetGoal();                // NO IMPLEMENTATION
void onOmegaObserve();                // NO IMPLEMENTATION
void onOmegaCancel();                 // NO IMPLEMENTATION
void onOmegaSpawnAgent();             // NO IMPLEMENTATION
void onOmegaGetStats();               // NO IMPLEMENTATION
void onOmegaExport();                 // NO IMPLEMENTATION
void onOmegaImport();                 // NO IMPLEMENTATION
```

**Menu IDs to Remove (if not used elsewhere):**
```cpp
// DELETE from resource.h or wherever defined:
#define IDM_OMEGA_START_AUTONOMOUS 12400
#define IDM_OMEGA_SET_GOAL 12401
#define IDM_OMEGA_OBSERVE_PIPELINE 12402
#define IDM_OMEGA_CANCEL_TASK 12403
#define IDM_OMEGA_SPAWN_AGENT 12404
#define IDM_OMEGA_GET_STATS 12405
```

**Rationale:**
- No implementation file exists (Win32IDE_Omega.cpp is missing)
- No design document exists
- No roadmap for completion
- Creates false expectation of capability

**Alternative:** If you want to keep the idea, create a GitHub issue and delete the code.
You can always restore from Git history later.

---

## 🟡 PARTIAL GHOST FEATURES (Conditional Removal)

### 2. Extension Host IPC Bridge
**Status:** Stub implementation
**Decision:** Keep or Remove?

**Current State:**
- Class exists: ExtensionHostIpcBridge.hpp/cpp
- Methods: Connect(), Disconnect(), SendMessage(), ReceiveMessage()
- Implementation: Returns false/empty (stub)
- Integration: NONE - never instantiated by Win32IDE

**Options:**

**Option A - Remove (Recommended for v1.0):**
```cpp
// DELETE from Win32IDE.h:
std::unique_ptr<ExtensionHostIpcBridge> m_extensionHostIpc;

// DELETE files:
// - ExtensionHostIpcBridge.hpp
// - ExtensionHostIpcBridge.cpp
```

**Option B - Keep for v1.1:**
- Mark with TODO comment
- Add FeatureRegistry flag (disabled by default)
- Implement actual IPC mechanism

**Rationale:**
- VS Code extension compatibility is a v1.1+ feature
- Current stub adds no value
- Can be reimplemented properly later

---

### 3. Voice Assistant
**Status:** Complete implementation, never started
**Decision:** Keep (config-disabled)

**Current State:**
- Implementation: VoiceAssistantWorker.cpp (complete)
- Global instance: g_voiceAssistantWorker (declared, never constructed)
- Config: voiceAutomation.enabled = false

**Action:**
```cpp
// KEEP the implementation
// ADD to FeatureRegistry (already done):
//   FeatureRegistry::IsVoiceAssistantEnabled() returns false by default

// ADD initialization in InitializeOptionalSubsystemsSafe():
if (FeatureRegistry::IsVoiceAssistantEnabled()) {
    // Initialize g_voiceAssistantWorker here
}
```

**Rationale:**
- Implementation is complete
- Just needs wiring
- Can be enabled via config when ready

---

## 🟢 VALID FEATURES (Keep, Properly Wired)

### 4. AgentBridge
**Status:** Implemented but not initialized
**Action:** Wire up initialization (see Win32IDE_Core_Patched.cpp)

### 5. Autonomous Systems (4 components)
**Status:** Implemented but not initialized
**Action:** Wire up initialization (see Win32IDE_Core_Patched.cpp)

### 6. DAP Server
**Status:** On-demand initialization (correct)
**Action:** No change needed

### 7. LSP Client
**Status:** Manual initialization (correct for v1.0)
**Action:** No change needed

---

## 🛠️ Removal Scripts

### Script 1: Remove Omega Orchestrator
```bash
#!/bin/bash
# remove_omega_ghost.sh

echo "Removing Omega Orchestrator ghost code..."

# Backup first
cp Win32IDE.h Win32IDE.h.backup.$(date +%Y%m%d_%H%M%S)

# Remove member declarations
sed -i '/rawrxd::OmegaOrchestrator\* m_omegaOrchestrator/d' Win32IDE.h
sed -i '/bool m_omegaActive/d' Win32IDE.h

# Remove method declarations (12 methods)
sed -i '/void initializeOmegaOrchestrator/d' Win32IDE.h
sed -i '/void onOmegaStart/d' Win32IDE.h
sed -i '/void onOmegaStop/d' Win32IDE.h
sed -i '/void onOmegaPause/d' Win32IDE.h
sed -i '/void onOmegaResume/d' Win32IDE.h
sed -i '/void onOmegaSetGoal/d' Win32IDE.h
sed -i '/void onOmegaObserve/d' Win32IDE.h
sed -i '/void onOmegaCancel/d' Win32IDE.h
sed -i '/void onOmegaSpawnAgent/d' Win32IDE.h
sed -i '/void onOmegaGetStats/d' Win32IDE.h
sed -i '/void onOmegaExport/d' Win32IDE.h
sed -i '/void onOmegaImport/d' Win32IDE.h

echo "Omega Orchestrator ghost code removed."
echo "Verify build compiles successfully."
```

### Script 2: Remove Extension Host IPC
```bash
#!/bin/bash
# remove_extension_host_ghost.sh

echo "Removing Extension Host IPC ghost code..."

# Remove from Win32IDE.h
sed -i '/std::unique_ptr<ExtensionHostIpcBridge> m_extensionHostIpc/d' Win32IDE.h

# Remove files (if not used elsewhere)
# git rm ExtensionHostIpcBridge.hpp
# git rm ExtensionHostIpcBridge.cpp

echo "Extension Host IPC ghost code removed."
```

---

## 📊 Ghost Code Impact Summary

| Feature | Lines to Remove | Binary Size Reduction | Risk |
|---------|-----------------|----------------------|------|
| Omega Orchestrator | ~25 lines | ~500 bytes | None |
| Extension Host IPC | ~5 lines | ~2 KB | Low |
| **Total** | **~30 lines** | **~2.5 KB** | **Minimal** |

---

## ✅ Post-Removal Checklist

- [ ] Win32IDE.h compiles without errors
- [ ] Win32IDE.cpp compiles without errors
- [ ] All existing tests pass
- [ ] IDE launches successfully
- [ ] No runtime errors in Output panel
- [ ] Git commit with message: "Remove ghost features: Omega, ExtensionHost"

---

## 📝 Git Commit Message Template

```
Remove ghost features: Omega Orchestrator and Extension Host IPC

Ghost features are declared in headers but have no implementation:
- Omega Orchestrator: 12 methods declared, 0 implemented
- Extension Host IPC: Class exists, never instantiated

These features created technical debt and confusion:
- Compiled into binary but never executed
- Suggested capabilities that don't exist
- Required maintenance for dead code

Removal reduces:
- Code complexity
- Compile time
- Binary size (~2.5 KB)
- Cognitive load

Can be restored from Git history if needed later.

Fixes: DEPENDENCY_CHAINS_AUDIT.md #2, #5
```

---

## 🎯 Philosophy

**"If it's not tested, it's broken. If it's not initialized, it's dead."**

Ghost code is worse than no code because:
1. It suggests features exist that don't
2. It compiles, so it seems valid
3. It never runs, so bugs are hidden
4. It confuses new developers
5. It adds maintenance burden

**Better to delete and restore later than maintain dead code.**

---

*Ghost Code Removal Guide v1.0*
*Part of RawrXD IDE Dependency Chain Fix*
