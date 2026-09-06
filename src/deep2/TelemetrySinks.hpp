// ============================================================================
// TelemetrySinks.hpp — attribution-safe I/O + run RAM peaks
// Physical bytes ONLY from ReadFile/completion. Logical ≠ physical.
// ============================================================================
#pragma once

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <mutex>

namespace Deep2 {

using IoTransferId = uint64_t;

struct IoTelemetry {
    std::atomic<uint64_t> nvmeLogicalRequestedBytes{0};
    std::atomic<uint64_t> nvmePhysicalReadBytes{0};
    std::atomic<uint64_t> nvmeUsefulPayloadBytes{0};
    std::atomic<uint64_t> nvmePrefetchBytes{0};
    std::atomic<uint64_t> nvmeDiscardedPrefetchBytes{0};
    std::atomic<uint64_t> hostToGpuBytes{0};
    std::atomic<uint32_t> nvmeRequestOps{0};
    std::atomic<uint32_t> nvmeCompletionOps{0};
    std::atomic<uint32_t> duplicateCompletionAttempts{0};
    std::atomic<uint32_t> failedIoNotCounted{0};
    std::atomic<IoTransferId> nextId{1};

    // Legacy aggregate — prefer nvmePhysicalReadBytes for penalties.
    uint64_t nvmeToRamBytes() const { return nvmePhysicalReadBytes.load(); }

    void resetRun() {
        nvmeLogicalRequestedBytes.store(0);
        nvmePhysicalReadBytes.store(0);
        nvmeUsefulPayloadBytes.store(0);
        nvmePrefetchBytes.store(0);
        nvmeDiscardedPrefetchBytes.store(0);
        hostToGpuBytes.store(0);
        nvmeRequestOps.store(0);
        nvmeCompletionOps.store(0);
        duplicateCompletionAttempts.store(0);
        failedIoNotCounted.store(0);
    }
};

struct IoTransferRecord {
    IoTransferId id = 0;
    uint64_t requested = 0;
    uint64_t completed = 0;
    uint64_t consumed = 0;
    uint64_t discarded = 0;
    bool prefetch = false;
    bool open = false;
    bool completedOnce = false;
};

inline constexpr size_t kIoTransferSlots = 256;

struct TelemetrySinks {
    IoTelemetry io;
    IoTransferRecord slots[kIoTransferSlots]{};
    std::mutex slotMu;

    // Run-local RAM peaks (NOT OS PeakWorkingSetSize lifetime).
    uint64_t runWorkingSetPeak = 0;
    uint64_t runPrivateCommitPeak = 0;
    uint64_t processLifetimeWorkingSetPeak = 0; // informational only
    uint64_t processWorkingSetCurrent = 0;
    uint64_t privateCommitCurrent = 0;

    void resetRun() {
        io.resetRun();
        std::lock_guard<std::mutex> lock(slotMu);
        for (auto& s : slots) s = IoTransferRecord{};
    }
};

inline TelemetrySinks& GlobalTelemetry() {
    static TelemetrySinks s;
    return s;
}

inline IoTransferRecord* SlotFor(IoTransferId id) {
    if (id == 0) return nullptr;
    return &GlobalTelemetry().slots[id % kIoTransferSlots];
}

// ExecuteNvmeToRam / streamer intent — logical request (not physical I/O).
inline IoTransferId NoteNvmeRequest(uint64_t requested, bool prefetch = false) {
    auto& g = GlobalTelemetry();
    const IoTransferId id = g.io.nextId.fetch_add(1);
    g.io.nvmeLogicalRequestedBytes.fetch_add(requested);
    g.io.nvmeRequestOps.fetch_add(1);
    if (prefetch)
        g.io.nvmePrefetchBytes.fetch_add(requested);
    {
        std::lock_guard<std::mutex> lock(g.slotMu);
        auto* slot = SlotFor(id);
        if (slot) {
            *slot = IoTransferRecord{};
            slot->id = id;
            slot->requested = requested;
            slot->prefetch = prefetch;
            slot->open = true;
        }
    }
    return id;
}

// successful ReadFile / IOCP completion — physical bytes ACTUALLY transferred.
inline void NoteNvmeCompletion(IoTransferId id, uint64_t actualBytes) {
    auto& g = GlobalTelemetry();
    std::lock_guard<std::mutex> lock(g.slotMu);
    auto* slot = SlotFor(id);
    if (slot && slot->id == id && slot->open) {
        if (slot->completedOnce) {
            g.io.duplicateCompletionAttempts.fetch_add(1);
            return; // ONE_PHYSICAL_READ_COUNTED_ONCE
        }
        slot->completed = actualBytes;
        slot->completedOnce = true;
        g.io.nvmePhysicalReadBytes.fetch_add(actualBytes);
        g.io.nvmeCompletionOps.fetch_add(1);
        return;
    }
    // Orphan completion (no request): still count physical once under id=0 path.
    if (id == 0 && actualBytes > 0) {
        g.io.nvmePhysicalReadBytes.fetch_add(actualBytes);
        g.io.nvmeCompletionOps.fetch_add(1);
    }
}

// Payload actually used by residency / inference.
inline void NoteNvmeConsumed(IoTransferId id, uint64_t usefulBytes) {
    auto& g = GlobalTelemetry();
    g.io.nvmeUsefulPayloadBytes.fetch_add(usefulBytes);
    std::lock_guard<std::mutex> lock(g.slotMu);
    auto* slot = SlotFor(id);
    if (slot && slot->id == id)
        slot->consumed += usefulBytes;
}

inline void NoteNvmeDiscardedPrefetch(IoTransferId id, uint64_t bytes) {
    if (bytes == 0) return;
    auto& g = GlobalTelemetry();
    g.io.nvmeDiscardedPrefetchBytes.fetch_add(bytes);
    std::lock_guard<std::mutex> lock(g.slotMu);
    auto* slot = SlotFor(id);
    if (slot && slot->id == id) {
        slot->discarded += bytes;
        slot->open = false;
    }
}

inline void NoteNvmeFailed(IoTransferId id) {
    auto& g = GlobalTelemetry();
    g.io.failedIoNotCounted.fetch_add(1);
    std::lock_guard<std::mutex> lock(g.slotMu);
    auto* slot = SlotFor(id);
    if (slot && slot->id == id)
        slot->open = false;
    // Do NOT add to nvmePhysicalReadBytes.
}

inline void NoteHostToGpu(uint64_t bytes) {
    if (bytes == 0) return;
    GlobalTelemetry().io.hostToGpuBytes.fetch_add(bytes);
}

// Deprecated: do not use for physical accounting. Prefer NoteNvmeCompletion.
// Kept as alias to Request+Consumed for accidental callers (never physical).
inline void NoteNvmeToRam(uint64_t bytes) {
    const IoTransferId id = NoteNvmeRequest(bytes, false);
    NoteNvmeConsumed(id, bytes);
}

inline uint64_t StreamChurnBytes() {
    const auto& io = GlobalTelemetry().io;
    const uint64_t phys = io.nvmePhysicalReadBytes.load();
    const uint64_t useful = io.nvmeUsefulPayloadBytes.load();
    return (phys > useful) ? (phys - useful) : 0;
}

} // namespace Deep2
