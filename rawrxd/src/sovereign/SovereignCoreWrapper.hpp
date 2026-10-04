// ============================================================================
// src/sovereign/SovereignCoreWrapper.hpp -- SovereignCore / SovereignIDEBridge
// ============================================================================
// Declares the RawrXD::Sovereign autonomous-cycle core and its IDE-side bridge.
// The definitions live in src/core/gold_link_closure.cpp.
//
// ----------------------------------------------------------------------------
// WHY THIS FILE EXISTS NOW (RAWRXD_MISSING_SOURCE_001)
// ----------------------------------------------------------------------------
// src/core/gold_link_closure.cpp:419 opens with this header, and gold_link_closure.cpp
// is in the RawrXD_Gold source list:
//
//     src\core\gold_link_closure.cpp(419,10): error C1083: Cannot open include
//         file: 'sovereign/SovereignCoreWrapper.hpp': No such file or directory
//
// The .cpp is explicit that this header is meant to be the real interface, not a
// local fallback: the comment above the include reads "Include the real header to
// get correct class definitions". The header it names was never written, so the
// 170 lines of SovereignCore/SovereignIDEBridge definitions below it have never
// compiled. Stale SovereignCoreWrapper.obj files survive in three older build
// directories (build_clean_n1, build_prod_gate, build_prod_gate2), which is what
// makes the absence look like a deletion rather than a never-written file.
//
// ----------------------------------------------------------------------------
// SCOPE LIMIT THAT MATTERS MORE THAN THE DECLARATIONS
// ----------------------------------------------------------------------------
// These are link-closure definitions for RawrXD_Gold, not an implementation.
// Read the bodies before believing any capability here:
//   - initialize(uint32_t) discards numAgents and only sets a flag.
//   - runCycle() calls Sovereign_Pipeline_Cycle(), which gold_link_closure.cpp:423
//     defines as an empty MASM stub, so no pipeline work happens.
//   - getStats() returns a zeroed CycleStats with status IDLE, unconditionally.
//   - getAgentStates() returns an empty vector, unconditionally.
//   - getCurrentStatus() returns Status::IDLE, unconditionally.
//   - triggerFullChatPipeline(), triggerSelfHeal() and validateAlignment() have
//     empty bodies.
//   - startAutonomousLoop() sets a bool and starts no thread, even though the
//     class holds m_loopThread and defines autonomousLoopProc().
// Nothing in this header should be read as an autonomous system that works.
// ============================================================================

#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace RawrXD {
namespace Sovereign {

// ============================================================================
// SovereignCore
// ============================================================================
class SovereignCore {
public:
    // Process-wide singleton, resolved lazily and cached in s_instance.
    static SovereignCore& getInstance();
    static SovereignCore* s_instance;

    SovereignCore();
    ~SovereignCore();

    SovereignCore(const SovereignCore&)            = delete;
    SovereignCore& operator=(const SovereignCore&) = delete;

    // --- Lifecycle ---
    // numAgents is accepted and discarded; see the scope limit above.
    void initialize(uint32_t numAgents);
    void shutdown();
    bool isInitialized() const;

    // --- Cycle control ---
    void runCycle();
    // Sets m_running only. Does not start m_loopThread and does not call
    // autonomousLoopProc(); nothing in this class ever creates a thread.
    void startAutonomousLoop();
    void stopAutonomousLoop();
    bool isRunning() const;

    // --- Statistics ---
    // Status is declared before CycleStats because CycleStats holds one by
    // value. IDLE is the only enumerator referenced anywhere in the tree
    // (gold_link_closure.cpp:510, 516); no other value was recoverable, so
    // none is invented here. The underlying type is int32_t so that
    // `stats.status = Status::IDLE;` and any future enumerator agree with the
    // zero-initialisation in `CycleStats stats{}`.
    enum class Status : int32_t {
        IDLE = 0
    };

    // Fully reconstructed from getStats(), which zero-initialises and assigns
    // each member by name -- so the member set and types below are pinned by
    // that function rather than guessed.
    struct CycleStats {
        uint64_t                   cycleCount = 0;
        uint64_t                   healCount  = 0;
        Status                     status     = Status::IDLE;
        std::chrono::milliseconds elapsed{0};
    };

    CycleStats getStats() const;
    Status     getCurrentStatus() const;

    struct AgentState {
        uint64_t agentId = 0;
        uint64_t address = 0;
        uint32_t state   = 0;
        uint64_t workUnits = 0;
    };

    // Always empty in this implementation.
    std::vector<AgentState> getAgentStates() const;

    // --- Triggers ---
    // All three are empty bodies in the current implementation.
    void triggerFullChatPipeline();
    void triggerSelfHeal(const std::string& symbol);
    void validateAlignment();

    // --- Callbacks ---
    // Raw function pointer, matching the convention used by the other singleton
    // interfaces in this tree (SupportTierManager, MultiGPUManager).
    using CycleCallback = void (*)(const CycleStats&);
    void setOnCycleComplete(CycleCallback cb);

    // --- Interval ---
    uint32_t getCycleIntervalMs() const;
    void     setCycleIntervalMs(uint32_t ms);

private:
    // Busy-waits on m_running and calls runCycle() plus the callback. Reachable
    // only from a future threaded startAutonomousLoop(); nothing calls it today.
    void autonomousLoopProc();

    bool          m_initialized;
    bool          m_running;
    // Opaque handle. Null in every path in the current implementation; there is
    // no code in this class that assigns it a non-null value.
    void*         m_loopThread;
    uint32_t      m_cycleIntervalMs;
    CycleCallback m_onCycleComplete;
};

// ============================================================================
// SovereignIDEBridge
// ============================================================================
// IDE-facing adapter over SovereignCore. Holds a reference to the singleton and
// a UI update callback; every method body in the current implementation either
// ignores its input or returns a fixed value.
class SovereignIDEBridge {
public:
    static SovereignIDEBridge& getInstance();

    SovereignIDEBridge();
    ~SovereignIDEBridge();

    SovereignIDEBridge(const SovereignIDEBridge&)            = delete;
    SovereignIDEBridge& operator=(const SovereignIDEBridge&) = delete;

    void onEngineCycle(const std::string& chatInput);

    // Returns the fixed string "Cycle: 0 | Status: IDLE | Heals: 0".
    std::string getStatusDisplayLine() const;

    // Always empty.
    std::vector<uint64_t> getLatestTokens(uint32_t count) const;

    using UIUpdateCallback = void (*)(const std::string&);
    void setUIUpdateCallback(UIUpdateCallback cb);

private:
    // A reference, not a pointer: the constructor takes the address of the
    // SovereignCore singleton and the bridge never owns a core.
    SovereignCore&   m_core;
    UIUpdateCallback m_uiCallback;
};

} // namespace Sovereign
} // namespace RawrXD