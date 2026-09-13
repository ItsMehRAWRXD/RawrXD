// GpuTransferCounters.hpp — GPU copy / reuse / overlap (GPU_TRANSFER_*)
#pragma once
#include "StreamTransferCounters.hpp"
#include "Deep2Locality64.hpp"
#include <atomic>
#include <cstdint>
#include <cstdio>

namespace Deep2 {

enum class GpuCopyKind : uint8_t { Weight = 0, Activation = 1, Other = 2 };

inline std::atomic<uint64_t>& GTC_bytes() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& GTC_ops() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& GTC_weight() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& GTC_act() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& GTC_waitUs() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& GTC_submitUs() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& GTC_overlapUs() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& GTC_overlapEv() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& GTC_overlapB() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& GTC_tokens() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& GTC_layers() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& GTC_fwdLayers() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& GTC_wHits() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& GTC_wMiss() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& GTC_wHitB() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& GTC_firstB() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& GTC_reloadB() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& GTC_reloadMoe() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& GTC_reloadMla() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& GTC_reloadGen() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& GTC_slotReuse() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& GTC_redundant() { static std::atomic<uint64_t> v{0}; return v; }

void GpuTransfer_ResetSeenKeys();

inline void GpuTransfer_Reset() {
    GTC_bytes().store(0); GTC_ops().store(0); GTC_weight().store(0); GTC_act().store(0);
    GTC_waitUs().store(0); GTC_submitUs().store(0); GTC_overlapUs().store(0);
    GTC_overlapEv().store(0); GTC_overlapB().store(0);
    GTC_tokens().store(0); GTC_layers().store(0); GTC_fwdLayers().store(0);
    GTC_wHits().store(0); GTC_wMiss().store(0); GTC_wHitB().store(0);
    GTC_firstB().store(0); GTC_reloadB().store(0);
    GTC_reloadMoe().store(0); GTC_reloadMla().store(0); GTC_reloadGen().store(0);
    GTC_slotReuse().store(0); GTC_redundant().store(0);
    GpuTransfer_ResetSeenKeys();
}

inline void GpuTransfer_NoteCopy(uint64_t bytes, GpuCopyKind kind) {
    if (!bytes) return;
    GTC_bytes().fetch_add(bytes, std::memory_order_relaxed);
    GTC_ops().fetch_add(1, std::memory_order_relaxed);
    if (kind == GpuCopyKind::Weight)
        GTC_weight().fetch_add(bytes, std::memory_order_relaxed);
    else if (kind == GpuCopyKind::Activation)
        GTC_act().fetch_add(bytes, std::memory_order_relaxed);
    StreamTransfer_RecordGpuUpload(bytes);
    Locality64_NoteHostToDevice(bytes, Locality64_Global().armed());
}

inline void GpuTransfer_AddWaitUs(uint64_t us) {
    GTC_waitUs().fetch_add(us, std::memory_order_relaxed);
}
inline void GpuTransfer_AddSubmitUs(uint64_t us) {
    GTC_submitUs().fetch_add(us, std::memory_order_relaxed);
}
inline void GpuTransfer_AddOverlapUs(uint64_t us) {
    GTC_overlapUs().fetch_add(us, std::memory_order_relaxed);
}
inline void GpuTransfer_NoteOverlapEvent(uint64_t bytes) {
    GTC_overlapEv().fetch_add(1, std::memory_order_relaxed);
    GTC_overlapB().fetch_add(bytes, std::memory_order_relaxed);
}
inline void GpuTransfer_RecordToken() { GTC_tokens().fetch_add(1, std::memory_order_relaxed); }
inline void GpuTransfer_RecordLayer() { GTC_layers().fetch_add(1, std::memory_order_relaxed); }
inline void GpuTransfer_RecordFwdLayerExec(uint64_t n = 1) {
    GTC_fwdLayers().fetch_add(n, std::memory_order_relaxed);
}
inline void GpuTransfer_NoteWeightHit(uint64_t bytes) {
    GTC_wHits().fetch_add(1, std::memory_order_relaxed);
    if (bytes) GTC_wHitB().fetch_add(bytes, std::memory_order_relaxed);
    Locality64_NoteDemand(LocalityKind::Weight, bytes, true);
}
inline void GpuTransfer_NoteWeightMiss(uint64_t bytes, bool firstEver) {
    GTC_wMiss().fetch_add(1, std::memory_order_relaxed);
    if (firstEver) GTC_firstB().fetch_add(bytes, std::memory_order_relaxed);
    else GTC_reloadB().fetch_add(bytes, std::memory_order_relaxed);
    Locality64_NoteDemand(LocalityKind::Weight, bytes, false);
}
/* Class-split reload (MOE/MLA/GENERAL). firstEver still updates totals. */
enum class GpuWeightClass : uint8_t { MoE = 0, Mla = 1, General = 2 };
inline void GpuTransfer_NoteWeightMissClass(uint64_t bytes, bool firstEver,
                                           GpuWeightClass c) {
    GpuTransfer_NoteWeightMiss(bytes, firstEver);
    if (firstEver || !bytes) return;
    if (c == GpuWeightClass::MoE)
        GTC_reloadMoe().fetch_add(bytes, std::memory_order_relaxed);
    else if (c == GpuWeightClass::Mla)
        GTC_reloadMla().fetch_add(bytes, std::memory_order_relaxed);
    else
        GTC_reloadGen().fetch_add(bytes, std::memory_order_relaxed);
}
inline void GpuTransfer_NoteSlotReuse() {
    GTC_slotReuse().fetch_add(1, std::memory_order_relaxed);
}
inline void GpuTransfer_NoteRedundantUpload() {
    GTC_redundant().fetch_add(1, std::memory_order_relaxed);
}

struct GpuTransferSnapshot {
    uint64_t copyBytes = 0, copyOps = 0, weightBytes = 0, actBytes = 0;
    uint64_t waitUs = 0, submitUs = 0, overlapUs = 0, overlapEvents = 0, overlapBytes = 0;
    uint64_t tokens = 0, layers = 0, fwdLayers = 0;
    uint64_t weightHits = 0, weightMisses = 0, weightHitBytes = 0;
    uint64_t firstLoadBytes = 0, reloadBytes = 0;
    uint64_t reloadBytesMoe = 0, reloadBytesMla = 0, reloadBytesGeneral = 0;
    uint64_t slotReuses = 0, redundantUploads = 0;
};
GpuTransferSnapshot GpuTransfer_Snapshot();
void GpuTransfer_Emit(FILE* f);
// Returns true on first observation of key (first-load), false on reload.
bool GpuTransfer_MarkSeenKey(uintptr_t key);

} // namespace Deep2
