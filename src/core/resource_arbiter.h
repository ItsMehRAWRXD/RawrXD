#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <functional>

namespace RawrXD {
namespace Core {

// ============================================================================
// Resource Arbiter — Coordinates memory between Vision, Crucible, Inference
// Prevents OOM when multiple heavy subsystems are active simultaneously
// ============================================================================

enum class Subsystem {
    Inference,      // LLM inference (largest memory consumer)
    Vision,         // Vision encoder (image processing)
    Crucible,       // Game engine / stress harness
    Collaboration,  // CRDT / WebSocket hub
    Debugger,       // Debug symbols / memory scanner
    Compiler        // Build system / linker
};

enum class MemoryTier {
    Critical,       // Cannot be evicted (active inference KV cache)
    High,           // Important but can be compressed
    Normal,         // Standard priority
    Low             // Can be unloaded immediately
};

struct ResourceBudget {
    size_t max_ram_bytes = 0;           // 0 = auto-detect from system
    size_t max_vram_bytes = 0;          // 0 = auto-detect from GPU
    size_t max_disk_cache_bytes = 0;    // Disk swap budget
    float inference_fraction = 0.50f;   // 50% to inference
    float vision_fraction = 0.15f;      // 15% to vision
    float crucible_fraction = 0.20f;   // 20% to game engine
    float system_fraction = 0.15f;      // 15% to OS + other
};

struct SubsystemState {
    Subsystem id;
    std::string name;
    size_t current_bytes = 0;
    size_t peak_bytes = 0;
    size_t budget_bytes = 0;
    MemoryTier priority = MemoryTier::Normal;
    bool active = false;
    bool can_compress = false;
    bool can_offload = false;
    std::function<void()> on_pressure_callback;      // Called when under pressure
    std::function<void()> on_evict_callback;          // Called to free memory
    std::function<bool()> on_compress_callback;      // Called to compress in-place
};

class ResourceArbiter {
public:
    static ResourceArbiter& Instance();

    // Initialize with system detection or explicit budget
    bool Initialize(const ResourceBudget& budget = ResourceBudget{});
    void Shutdown();

    // Subsystem registration
    bool RegisterSubsystem(const SubsystemState& state);
    void UnregisterSubsystem(Subsystem id);
    bool IsSubsystemActive(Subsystem id) const;

    // Memory allocation coordination
    bool RequestAllocation(Subsystem id, size_t bytes, size_t& granted);
    void ReleaseAllocation(Subsystem id, size_t bytes);
    void ReportUsage(Subsystem id, size_t bytes);

    // Focus mode — one subsystem gets priority, others are compressed/offloaded
    void EnterFocusMode(Subsystem id);
    void ExitFocusMode();
    bool IsFocusMode() const { return m_focus_subsystem != Subsystem::Compiler; }
    Subsystem GetFocusSubsystem() const { return m_focus_subsystem; }

    // Pressure management
    enum class PressureLevel { None, Low, Medium, High, Critical };
    PressureLevel GetPressureLevel() const;
    void SetPressureCallback(std::function<void(PressureLevel)> callback);

    // Global memory query
    size_t GetTotalPhysicalRAM() const { return m_total_ram; }
    size_t GetAvailableRAM() const;
    size_t GetTotalVRAM() const { return m_total_vram; }
    size_t GetUsedVRAM() const;

    // Statistics
    struct Stats {
        size_t total_allocated = 0;
        size_t total_budget = 0;
        size_t peak_usage = 0;
        size_t eviction_count = 0;
        size_t compression_count = 0;
        size_t focus_mode_switches = 0;
        double avg_pressure = 0.0;
    };
    Stats GetStats() const;

    // Emergency — free everything non-critical
    bool EmergencyPurge();

private:
    ResourceArbiter() = default;
    ~ResourceArbiter() = default;
    ResourceArbiter(const ResourceArbiter&) = delete;
    ResourceArbiter& operator=(const ResourceArbiter&) = delete;

    bool DetectSystemResources();
    void ApplyPressureMitigation(PressureLevel level);
    bool TryEvict(Subsystem id, size_t target_bytes);
    bool TryCompress(Subsystem id, size_t target_bytes);
    bool TryOffload(Subsystem id, size_t target_bytes);
    void RebalanceBudgets();

    std::map<Subsystem, SubsystemState> m_subsystems;
    mutable std::recursive_mutex m_mutex;
    std::atomic<bool> m_initialized{false};

    ResourceBudget m_budget;
    size_t m_total_ram = 0;
    size_t m_total_vram = 0;
    size_t m_used_ram = 0;
    size_t m_used_vram = 0;
    size_t m_peak_usage = 0;

    std::atomic<Subsystem> m_focus_subsystem{Subsystem::Compiler};
    std::atomic<bool> m_focus_mode_active{false};
    std::function<void(PressureLevel)> m_pressure_callback;

    Stats m_stats;
    mutable std::recursive_mutex m_stats_mutex;
};

} // namespace Core
} // namespace RawrXD
