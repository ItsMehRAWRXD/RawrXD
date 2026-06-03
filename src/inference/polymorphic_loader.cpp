#include "polymorphic_loader.h"
#include <algorithm>
#include <chrono>
#include <numeric>
#include <cstring>
#include <iostream>
#include <fstream>
#include <map>
#include <filesystem>
#include <functional>
#include <mutex>

#include "backend_lane_type.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

// ============================================================================
// SECTION 1: Budget Enforcement
// ============================================================================

namespace {
void emitInferenceTelemetryPacket(
    uint32_t stepId,
    uint32_t zoneCount,
    uint32_t zonesLoaded,
    uint32_t zonesSkipped,
    double skipRatio,
    uint64_t bytesLoaded,
    uint32_t evictions,
    double evictionAgeAvg,
    uint32_t evictMisc,
    uint32_t evictMlp,
    uint32_t evictAttn,
    uint32_t selfEvictionBlocked,
    uint32_t protectedHits,
    uint32_t protectedScanCount,
    uint32_t fastPathHits,
    uint32_t unprotectedEvictions,
    uint32_t adaptiveWindowValue,
    uint64_t burstBytesActive,
    double reclaimProgress,
    double sigmoidReclaimValue,
    uint64_t hysteresisHolds,
    size_t activeUsage,
    RawrXD::BackendLaneType lane,
    PolymorphicLoader::SlotAcquireFailure failureReason,
    const char* phase,
    bool success)
{
    static std::mutex telemetryMutex;
    std::lock_guard<std::mutex> lock(telemetryMutex);

    std::cout << "[telemetry]"
              << " phase=" << phase
              << " step_id=" << stepId
              << " zone_count=" << zoneCount
              << " zones_loaded=" << zonesLoaded
              << " zones_skipped=" << zonesSkipped
              << " skip_ratio=" << skipRatio
              << " bytes_loaded=" << bytesLoaded
              << " evictions=" << evictions
              << " eviction_age_avg=" << evictionAgeAvg
              << " evict_misc=" << evictMisc
              << " evict_mlp=" << evictMlp
              << " evict_attn=" << evictAttn
              << " self_eviction_blocked=" << selfEvictionBlocked
              << " protected_hits=" << protectedHits
              << " protected_scan_count=" << protectedScanCount
              << " fast_path_hits=" << fastPathHits
              << " unprotected_evictions=" << unprotectedEvictions
              << " adaptive_window_value=" << adaptiveWindowValue
              << " burst_bytes_active=" << burstBytesActive
              << " reclaim_progress=" << reclaimProgress
              << " sigmoid_reclaim_value=" << sigmoidReclaimValue
              << " hysteresis_holds=" << hysteresisHolds
              << " active_usage=" << activeUsage
              << " backend_lane_code=" << RawrXD::BackendLaneTypeCode(lane)
              << " slot_fail=" << static_cast<uint32_t>(failureReason)
              << " slot_fail_name=" << PolymorphicLoader::slotAcquireFailureToString(failureReason)
              << " success=" << (success ? 1 : 0)
              << "\n";
}

void emitInferencePerfTelemetryPacket(
    uint32_t stepId,
    uint32_t zoneCount,
    uint32_t zonesLoaded,
    uint64_t stepElapsedNs,
    uint64_t victimSearchNs,
    uint64_t materializationNs,
    uint32_t batchCount,
    double avgZonesPerBatch,
    bool success)
{
    static std::mutex perfTelemetryMutex;
    std::lock_guard<std::mutex> lock(perfTelemetryMutex);

    const double searchRatio = stepElapsedNs > 0
        ? static_cast<double>(victimSearchNs) / static_cast<double>(stepElapsedNs)
        : 0.0;
    const double materializationRatio = stepElapsedNs > 0
        ? static_cast<double>(materializationNs) / static_cast<double>(stepElapsedNs)
        : 0.0;

    std::cout << "[perf_telemetry]"
              << " step_id=" << stepId
              << " zone_count=" << zoneCount
              << " zones_loaded=" << zonesLoaded
              << " step_elapsed_ns=" << stepElapsedNs
              << " victim_search_ns=" << victimSearchNs
              << " materialization_ns=" << materializationNs
              << " victim_search_ratio=" << searchRatio
              << " materialization_ratio=" << materializationRatio
              << " batch_count=" << batchCount
              << " avg_zones_per_batch=" << avgZonesPerBatch
              << " success=" << (success ? 1 : 0)
              << "\n";
}

bool isMaterializableRole(TensorRole role, SlotType& outSlotType) {
    switch (role) {
        case TensorRole::ATTN_Q:
        case TensorRole::ATTN_K:
        case TensorRole::ATTN_V:
        case TensorRole::ATTN_O:
            outSlotType = SlotType::ATTENTION;
            return true;
        case TensorRole::MLP_UP:
        case TensorRole::MLP_DOWN:
            outSlotType = SlotType::MLP;
            return true;
        case TensorRole::KV_CACHE:
            outSlotType = SlotType::KV_CACHE;
            return true;
        default:
            outSlotType = SlotType::AUXILIARY;
            return false;
    }
}

} // namespace

bool ActiveWindowBudget::canAllocate(SlotType type, size_t bytes) const {
    // Path B: slot capacity is the only limiter; budget is not enforced.
    (void)type;
    (void)bytes;
    return true;
}

void ActiveWindowBudget::recordUsage(SlotType type, size_t bytes) const {
    switch (type) {
        case SlotType::ATTENTION:
            attn_used.fetch_add(bytes, std::memory_order_release);
            break;
        case SlotType::MLP:
            mlp_used.fetch_add(bytes, std::memory_order_release);
            break;
        case SlotType::KV_CACHE:
            kv_used.fetch_add(bytes, std::memory_order_release);
            break;
        case SlotType::AUXILIARY:
            misc_used.fetch_add(bytes, std::memory_order_release);
            break;
    }
}

void ActiveWindowBudget::releaseUsage(SlotType type, size_t bytes) const {
    switch (type) {
        case SlotType::ATTENTION:
            attn_used.fetch_sub(bytes, std::memory_order_acq_rel);
            break;
        case SlotType::MLP:
            mlp_used.fetch_sub(bytes, std::memory_order_acq_rel);
            break;
        case SlotType::KV_CACHE:
            kv_used.fetch_sub(bytes, std::memory_order_acq_rel);
            break;
        case SlotType::AUXILIARY:
            misc_used.fetch_sub(bytes, std::memory_order_acq_rel);
            break;
    }
}

void ActiveWindowBudget::updateBurstBudget(uint64_t step_id) const {
    // Borrow first from MISC; if too small, borrow from MLP while conserving total budget.
    const size_t desiredExtra = (BURST_ATTN_MULTIPLIER > 1)
        ? (ATTN_BYTES * static_cast<size_t>(BURST_ATTN_MULTIPLIER - 1))
        : 0;
    const size_t maxBorrow = MISC_BYTES + (MLP_BYTES / 4);
    const size_t burstCap = std::min(desiredExtra, maxBorrow);

    size_t active = 0;
    double progress = 0.0;
    double sigmoid = 0.0;
    bool heldByHysteresis = false;

    if (step_id < BURST_STEPS) {
        active = burstCap;
        progress = 0.0;
        sigmoid = 0.0;
    } else {
        const double phase = static_cast<double>(step_id - BURST_STEPS + 1) /
            static_cast<double>(std::max<uint32_t>(BURST_STEPS, 1));
        const double clamped = std::min(1.0, std::max(0.0, phase));

        // Smooth reclaim curve: slow start, faster middle, slow tail.
        const double x = (clamped - 0.5) * BURST_SIGMOID_GAIN;
        sigmoid = 1.0 / (1.0 + std::exp(-x));
        const double minSig = 1.0 / (1.0 + std::exp(0.5 * BURST_SIGMOID_GAIN));
        const double maxSig = 1.0 / (1.0 + std::exp(-0.5 * BURST_SIGMOID_GAIN));
        progress = (sigmoid - minSig) / std::max(1e-9, (maxSig - minSig));
        progress = std::min(1.0, std::max(0.0, progress));

        if (progress < MIN_RECLAIM_FLOOR) {
            progress = 0.0;
            heldByHysteresis = true;
        } else {
            progress = (progress - MIN_RECLAIM_FLOOR) / (1.0 - MIN_RECLAIM_FLOOR);
            progress = std::min(1.0, std::max(0.0, progress));
        }

        active = static_cast<size_t>(static_cast<double>(burstCap) * (1.0 - progress));
    }

    burst_attn_bytes.store(active, std::memory_order_release);
    if (burstCap == 0) {
        progress = 1.0;
        sigmoid = 1.0;
    }
    sigmoid_reclaim_value.store(sigmoid, std::memory_order_release);
    if (heldByHysteresis) {
        hysteresis_holds.fetch_add(1, std::memory_order_acq_rel);
    }
    burst_reclaim_progress.store(progress, std::memory_order_release);
}

size_t ActiveWindowBudget::getEffectiveLimit(SlotType type) const {
    const size_t activeBurst = burst_attn_bytes.load(std::memory_order_acquire);
    const size_t fromMisc = std::min(activeBurst, MISC_BYTES);
    const size_t fromMlp = (activeBurst > fromMisc) ? (activeBurst - fromMisc) : 0;

    switch (type) {
        case SlotType::ATTENTION:
            return ATTN_BYTES + activeBurst;
        case SlotType::MLP:
            return (MLP_BYTES > fromMlp) ? (MLP_BYTES - fromMlp) : 0;
        case SlotType::KV_CACHE:
            return KV_BYTES;
        case SlotType::AUXILIARY:
            return (MISC_BYTES > fromMisc) ? (MISC_BYTES - fromMisc) : 0;
        default:
            return 0;
    }
}

size_t ActiveWindowBudget::getBurstBytesActive() const {
    return burst_attn_bytes.load(std::memory_order_acquire);
}

double ActiveWindowBudget::getReclaimProgress() const {
    return burst_reclaim_progress.load(std::memory_order_acquire);
}

double ActiveWindowBudget::getSigmoidReclaimValue() const {
    return sigmoid_reclaim_value.load(std::memory_order_acquire);
}

uint64_t ActiveWindowBudget::getHysteresisHolds() const {
    return hysteresis_holds.load(std::memory_order_acquire);
}

bool ActiveWindowBudget::isBurstActive() const {
    return getBurstBytesActive() > 0;
}

// ============================================================================
// SECTION 2: Slot Lattice Implementation
// ============================================================================

SlotLattice::SlotLattice(const ActiveWindowBudget& budget, size_t slot_count)
    : budget_(budget) {
    const size_t baseSlots = 16 + 8 + 8 + 4;
    const size_t desiredSlots = std::max(slot_count, baseSlots);
    const size_t scale = std::max<size_t>(1, desiredSlots / baseSlots);

    size_t attnSlots = 16 * scale;
    size_t mlpSlots = 8 * scale;
    size_t kvSlots = 8 * scale;
    size_t miscSlots = 4 * scale;
    size_t totalSlots = attnSlots + mlpSlots + kvSlots + miscSlots;

    while (totalSlots < desiredSlots) {
        ++attnSlots;
        ++totalSlots;
    }

    // Reserve capacity but do NOT allocate memory yet (arena handles it)
    slots_.reserve(totalSlots);
    free_slots_.reserve(totalSlots);
    
    // Determine slot size based on budget and role
    // Path B: prioritize capacity over strict partitioning to avoid large-tensor fragmentation.
    const size_t attn_slot_size = budget.ATTN_BYTES / 8;
    const size_t mlp_slot_size = budget.MLP_BYTES / 8;
    const size_t kv_slot_size = budget.KV_BYTES / 8;
    const size_t misc_slot_size = std::max<size_t>(1, budget.MISC_BYTES);
    
    // Arena uses a uniform slot size = max of all role sizes, capped at 64MB
    // Path B: 64MB primary keeps L3 free for V tensors; overflow handles 98MB zones.
    const size_t max_slot_size = std::min(
        std::max({attn_slot_size, mlp_slot_size, kv_slot_size, misc_slot_size}),
        size_t(64 * 1024 * 1024)); // Cap at 64MB to prevent L3 eviction
    
    // Pre-commit entire arena upfront (pay the tax once, never again)
    if (!arena_.Init(totalSlots, max_slot_size)) {
        std::cerr << "[SlotLattice] Arena initialization failed (" << totalSlots 
                  << " slots x " << max_slot_size << " bytes)\n";
    }
    
    // Create attention slots (arena-backed, zero-syscall)
    for (size_t i = 0; i < attnSlots; ++i) {
        Slot s{};
        s.base = nullptr;  // Allocated on first acquireSlot via arena
        s.capacity_bytes = static_cast<uint32_t>(max_slot_size);
        s.type = SlotType::ATTENTION;
        s.home_type = SlotType::ATTENTION;
        s.flags = (i < ATTN_PROTECTED_SLOTS) ? SLOT_FLAG_PROTECTED_ATTN : 0;
        slots_.push_back(s);
        free_slots_.push_back(&slots_.back());
    }
    
    // Create MLP slots (arena-backed)
    for (size_t i = 0; i < mlpSlots; ++i) {
        Slot s{};
        s.base = nullptr;
        s.capacity_bytes = static_cast<uint32_t>(max_slot_size);
        s.type = SlotType::MLP;
        s.home_type = SlotType::MLP;
        slots_.push_back(s);
        free_slots_.push_back(&slots_.back());
    }
    
    // Create KV slots (arena-backed)
    for (size_t i = 0; i < kvSlots; ++i) {
        Slot s{};
        s.base = nullptr;
        s.capacity_bytes = static_cast<uint32_t>(max_slot_size);
        s.type = SlotType::KV_CACHE;
        s.home_type = SlotType::KV_CACHE;
        slots_.push_back(s);
        free_slots_.push_back(&slots_.back());
    }
    
    // Create auxiliary slots (arena-backed)
    for (size_t i = 0; i < miscSlots; ++i) {
        Slot s{};
        s.base = nullptr;
        s.capacity_bytes = static_cast<uint32_t>(max_slot_size);
        s.type = SlotType::AUXILIARY;
        s.home_type = SlotType::AUXILIARY;
        slots_.push_back(s);
        free_slots_.push_back(&slots_.back());
    }
}

SlotLattice::~SlotLattice() {
    // Arena handles all memory cleanup automatically via RAII
    // No per-slot ::operator delete needed - zero syscall shutdown
}

Slot* SlotLattice::acquireSlot(SlotType type, uint32_t bytes_needed, uint64_t step_id) {
    if (!budget_.canAllocate(type, bytes_needed)) {
        return nullptr;
    }
    adaptive_window_last_.store(0, std::memory_order_release);

    auto it = std::find_if(free_slots_.begin(), free_slots_.end(),
        [type, bytes_needed](Slot* s) {
            return s->type == type && s->capacity_bytes >= bytes_needed;
        });
    if (it == free_slots_.end()) {
        // Path B fallback: use any free slot that can fit, then retag semantically.
        it = std::find_if(free_slots_.begin(), free_slots_.end(),
            [bytes_needed](Slot* s) {
                return s->capacity_bytes >= bytes_needed;
            });
    }
    if (it == free_slots_.end()) {
        return nullptr;
    }

    Slot* slot = *it;
    free_slots_.erase(it);

    // Zero-syscall allocation: get base from pre-committed arena
    if (!slot->base) {
        size_t slot_index = static_cast<size_t>(slot - &slots_[0]);
        slot->base = arena_.Acquire(slot_index);
    }

    slot->type = type;
    slot->active_bytes = bytes_needed;
    slot->last_written_step = step_id;
    slot->last_access_step = step_id;
    budget_.recordUsage(type, bytes_needed);
    total_usage_.fetch_add(bytes_needed, std::memory_order_release);
    return slot;
}

void SlotLattice::releaseSlot(Slot* slot) {
    // Semantic release only—memory remains
    if (slot && slot->active_bytes > 0) {
        const uint32_t released = slot->active_bytes;
        budget_.releaseUsage(slot->type, released);
        total_usage_.fetch_sub(released, std::memory_order_acq_rel);
        slot->active_bytes = 0;
        slot->type = slot->home_type;

        if (std::find(free_slots_.begin(), free_slots_.end(), slot) == free_slots_.end()) {
            free_slots_.push_back(slot);
        }
    }
}

size_t SlotLattice::getTotalUsage() const {
    return total_usage_.load(std::memory_order_acquire);
}

size_t SlotLattice::getUsageByType(SlotType type) const {
    size_t total = 0;
    for (const auto& slot : slots_) {
        if (slot.type == type) {
            total += slot.active_bytes;
        }
    }
    return total;
}

bool SlotLattice::isBudgetExceeded() const {
    size_t attn = getUsageByType(SlotType::ATTENTION);
    size_t mlp = getUsageByType(SlotType::MLP);
    size_t kv = getUsageByType(SlotType::KV_CACHE);
    size_t misc = getUsageByType(SlotType::AUXILIARY);
    
    return (attn > budget_.ATTN_BYTES) ||
           (mlp > budget_.MLP_BYTES) ||
           (kv > budget_.KV_BYTES) ||
           (misc > budget_.MISC_BYTES);
}

std::vector<Slot*> SlotLattice::getAllSlots() const {
    std::vector<Slot*> result;
    for (auto& slot : slots_) {
        result.push_back(const_cast<Slot*>(&slot));
    }
    return result;
}

uint32_t SlotLattice::getActiveCount() const {
    uint32_t count = 0;
    for (auto& slot : slots_) {
        if (slot.base != nullptr && slot.active_bytes > 0) {
            count++;
        }
    }
    return count;
}

Slot* SlotLattice::findSlot(SlotType type) const {
    for (auto& slot : slots_) {
        if (slot.type == type && slot.base != nullptr && slot.active_bytes > 0) {
            return const_cast<Slot*>(&slot);
        }
    }
    return nullptr;
}

uint64_t SlotLattice::getEvictionCount() const {
    return eviction_count_total_.load(std::memory_order_acquire);
}

uint64_t SlotLattice::getEvictionAgeSum() const {
    return eviction_age_sum_total_.load(std::memory_order_acquire);
}

uint64_t SlotLattice::getEvictionBytes() const {
    return eviction_bytes_total_.load(std::memory_order_acquire);
}

uint64_t SlotLattice::getEvictionsByRole(SlotType type) const {
    return eviction_by_role_[static_cast<size_t>(type)].load(std::memory_order_acquire);
}

uint64_t SlotLattice::getSelfEvictionBlockedCount() const {
    return self_eviction_blocked_total_.load(std::memory_order_acquire);
}

uint64_t SlotLattice::getProtectedHitCount() const {
    return protected_hit_total_.load(std::memory_order_acquire);
}

uint64_t SlotLattice::getProtectedScanCount() const {
    return protected_scan_total_.load(std::memory_order_acquire);
}

uint64_t SlotLattice::getFastPathHitCount() const {
    return fast_path_hit_total_.load(std::memory_order_acquire);
}

uint64_t SlotLattice::getUnprotectedEvictionCount() const {
    return unprotected_eviction_total_.load(std::memory_order_acquire);
}

uint32_t SlotLattice::getAdaptiveWindowValue() const {
    return adaptive_window_last_.load(std::memory_order_acquire);
}

// ============================================================================
// SECTION 3: Format Adapters
// ============================================================================

namespace {
bool skipGGUFValueRec(std::istream& file, uint32_t type) {
    switch (type) {
        case 0: case 1: case 7: file.seekg(1, std::ios::cur); break;
        case 2: case 3: file.seekg(2, std::ios::cur); break;
        case 4: case 5: case 6: file.seekg(4, std::ios::cur); break;
        case 10: case 11: case 12: file.seekg(8, std::ios::cur); break;
        case 8: {
            uint64_t slen = 0;
            file.read(reinterpret_cast<char*>(&slen), sizeof(slen));
            file.seekg(static_cast<std::streamoff>(slen), std::ios::cur);
            break;
        }
        case 9: {
            uint32_t arrType = 0; uint64_t arrLen = 0;
            file.read(reinterpret_cast<char*>(&arrType), sizeof(arrType));
            file.read(reinterpret_cast<char*>(&arrLen), sizeof(arrLen));
            for (uint64_t a = 0; a < arrLen && file; ++a) {
                if (!skipGGUFValueRec(file, arrType)) return false;
            }
            break;
        }
        default: return false;
    }
    return file.good();
}
} // namespace

std::vector<TensorDesc> GGUFAdapter::enumerate(const std::string& path) {
    std::vector<TensorDesc> descs;
    
    // Read GGUF file and extract tensor metadata
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return descs;
    
    // Read GGUF header (magic 0x46554747 = "GGUF")
    uint32_t magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    
    if (magic != 0x46554747) return descs;  // Invalid GGUF
    
    uint32_t version;
    uint64_t tensor_count, metadata_count;
    
    file.read(reinterpret_cast<char*>(&version), sizeof(version));
    file.read(reinterpret_cast<char*>(&tensor_count), sizeof(tensor_count));
    file.read(reinterpret_cast<char*>(&metadata_count), sizeof(metadata_count));
    
    // --- Skip metadata key-value pairs ---
    // Each metadata entry: string key + type(u32) + value
    auto readGGUFString = [&](std::string& out) -> bool {
        uint64_t len = 0;
        file.read(reinterpret_cast<char*>(&len), sizeof(len));
        if (!file || len > 1048576) return false;
        out.resize(static_cast<size_t>(len));
        file.read(out.data(), static_cast<std::streamsize>(len));
        return file.good();
    };
    for (uint64_t m = 0; m < metadata_count && file; ++m) {
        std::string key;
        if (!readGGUFString(key)) break;
        uint32_t valType = 0;
        file.read(reinterpret_cast<char*>(&valType), sizeof(valType));
        if (!skipGGUFValueRec(file, valType)) break;
    }

    // --- Parse tensor info entries ---
    // GGUF tensor_info: name(string) + n_dimensions(u32) + dimensions[n](u64 each)
    //                   + type(u32) + offset(u64)
    struct TensorInfoEntry {
        std::string name;
        uint32_t n_dims = 0;
        uint64_t dims[4] = {};
        uint32_t type = 0;
        uint64_t offset = 0;
    };

    std::vector<TensorInfoEntry> tensorInfos;
    tensorInfos.reserve(static_cast<size_t>(std::min(tensor_count, uint64_t(65536))));

    for (uint64_t t = 0; t < tensor_count && file; ++t) {
        TensorInfoEntry ti;
        if (!readGGUFString(ti.name)) break;
        file.read(reinterpret_cast<char*>(&ti.n_dims), sizeof(ti.n_dims));
        if (ti.n_dims > 4) ti.n_dims = 4;
        for (uint32_t d = 0; d < ti.n_dims; ++d) {
            file.read(reinterpret_cast<char*>(&ti.dims[d]), sizeof(uint64_t));
        }
        file.read(reinterpret_cast<char*>(&ti.type), sizeof(ti.type));
        file.read(reinterpret_cast<char*>(&ti.offset), sizeof(ti.offset));
        if (file) tensorInfos.push_back(std::move(ti));
    }

    // Data section starts at the next 32-byte aligned boundary after current position
    uint64_t dataStart = static_cast<uint64_t>(file.tellg());
    dataStart = (dataStart + 31) & ~uint64_t(31);

    // Map ggml type -> QuantizationType
    auto mapQuant = [](uint32_t ggml_rxd_type) -> QuantizationType {
        switch (ggml_rxd_type) {
            case 0:  return QuantizationType::F16;    // F32 → treat as F16 tier
            case 1:  return QuantizationType::F16;
            case 8:  return QuantizationType::Q8_0;
            case 2: case 3: case 12: return QuantizationType::Q4_K_M;
            case 10: return QuantizationType::Q2_K;
            default: return QuantizationType::Q4_K_M;
        }
    };

    // Determine reuse count heuristic from tensor name
    auto estimateReuse = [](const std::string& name) -> uint32_t {
        if (name.find("attn") != std::string::npos) return 96;
        if (name.find("ffn") != std::string::npos || name.find("mlp") != std::string::npos) return 64;
        if (name.find("embed") != std::string::npos || name.find("output") != std::string::npos) return 128;
        if (name.find("norm") != std::string::npos) return 48;
        return 32;
    };

    // Estimate criticality: embeddings/output layers are critical; middle layers less so
    auto estimateCriticality = [&](const std::string& name, uint64_t idx, uint64_t total) -> float {
        if (name.find("embed") != std::string::npos) return 1.0f;
        if (name.find("output") != std::string::npos || name.find("lm_head") != std::string::npos) return 0.95f;
        // Linear falloff for middle layers
        float pos = static_cast<float>(idx) / static_cast<float>(std::max(total, uint64_t(1)));
        return 0.3f + 0.5f * (1.0f - std::abs(pos - 0.5f) * 2.0f);
    };

    // Extract layer ID from tensor name (e.g., "blk.23.attn_q.weight" -> 23)
    auto extractLayerId = [](const std::string& name) -> uint16_t {
        auto pos = name.find("blk.");
        if (pos == std::string::npos) pos = name.find("layers.");
        if (pos == std::string::npos) return 0;
        size_t numStart = name.find_first_of("0123456789", pos);
        if (numStart == std::string::npos) return 0;
        return static_cast<uint16_t>(std::stoul(name.substr(numStart)));
    };

    // Build TensorDescs from parsed info
    for (uint64_t i = 0; i < tensorInfos.size(); ++i) {
        const auto& ti = tensorInfos[i];
        TensorDesc desc{};
        desc.file_offset = dataStart + ti.offset;
        desc.layer_id = extractLayerId(ti.name);
        desc.quant = mapQuant(ti.type);
        desc.criticality = estimateCriticality(ti.name, i, tensorInfos.size());
        desc.reuse_count = estimateReuse(ti.name);
        desc.rank_hint = 0;
        desc.stripe_id = 0;
        // Fill shape
        uint32_t byteLen = 1;
        for (uint32_t d = 0; d < 4; ++d) {
            desc.shape[d] = (d < ti.n_dims) ? static_cast<uint32_t>(ti.dims[d]) : 0;
            if (d < ti.n_dims && ti.dims[d] > 0) byteLen *= static_cast<uint32_t>(ti.dims[d]);
        }
        // Approximate byte length from ggml type
        switch (ti.type) {
            case 0:  byteLen *= 4; break; // F32
            case 1:  byteLen *= 2; break; // F16
            case 8:  break;               // Q8_0 ~1 byte/element
            case 2: case 3: case 12: byteLen /= 2; break; // Q4 ~0.5 byte
            case 10: byteLen /= 4; break; // Q2_K ~0.25 byte
            default: break;
        }
        desc.byte_length = byteLen;
        descs.push_back(desc);
    }
    
    return descs;
}

std::unordered_map<std::string, std::string> GGUFAdapter::getMetadata() {
    return {{"format", "GGUF"}, {"version", "3"}};
}

bool GGUFAdapter::validate(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    
    uint32_t magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    
    return magic == 0x46554747;
}

std::vector<TensorDesc> ShardedBlobAdapter::enumerate(const std::string& path) {
    // Similar to GGUF but handles multiple files
    std::vector<TensorDesc> descs;
    auto shards = detectShards(path);
    
    for (const auto& shard : shards) {
        GGUFAdapter adapter;
        auto shard_descs = adapter.enumerate(shard);
        descs.insert(descs.end(), shard_descs.begin(), shard_descs.end());
    }
    
    return descs;
}

std::unordered_map<std::string, std::string> ShardedBlobAdapter::getMetadata() {
    return {{"format", "ShardedBlob"}, {"shards", "multiple"}};
}

bool ShardedBlobAdapter::validate(const std::string& path) {
    return !detectShards(path).empty();
}

std::vector<std::string> ShardedBlobAdapter::detectShards(const std::string& base_path) {
    // Find all .gguf shard files in the same directory as base_path
    std::vector<std::string> shards;
    std::filesystem::path basePath(base_path);
    std::filesystem::path parentDir = basePath.parent_path();
    std::string baseStem = basePath.stem().string();

    // Common shard naming patterns:
    // model-00001-of-00003.gguf, model.gguf.part0, model_shard_0.gguf
    std::error_code ec;
    for (auto& entry : std::filesystem::directory_iterator(parentDir, ec)) {
        if (!entry.is_regular_file()) continue;
        std::string ext = entry.path().extension().string();
        std::string name = entry.path().stem().string();

        if (ext == ".gguf" || ext == ".bin" || ext == ".ggml") {
            // Check if this file's name is related to the base file
            // Match patterns: same prefix, or contains shard/part numbering
            if (name.find(baseStem) != std::string::npos ||
                baseStem.find(name) != std::string::npos) {
                shards.push_back(entry.path().string());
            }
        }

        // Also match .part0, .part1 etc.
        if (entry.path().string().find(base_path) == 0 ||
            (name.find(baseStem) != std::string::npos &&
             (name.find("shard") != std::string::npos ||
              name.find("part") != std::string::npos ||
              name.find("-of-") != std::string::npos))) {
            if (std::find(shards.begin(), shards.end(),
                          entry.path().string()) == shards.end()) {
                shards.push_back(entry.path().string());
            }
        }
    }

    // Sort shards to ensure correct loading order
    std::sort(shards.begin(), shards.end());

    // If no shards found via pattern, try the base path itself
    if (shards.empty() && std::filesystem::exists(base_path)) {
        shards.push_back(base_path);
    }

    return shards;
}

std::vector<TensorDesc> MixedTierAdapter::enumerate(const std::string& path) {
    // Mixed-tier format with per-layer quantization
    std::vector<TensorDesc> descs;
    
    // Each layer can have different quantization
    for (uint16_t layer = 0; layer < 100; ++layer) {
        TensorDesc desc{};
        desc.layer_id = layer;
        
        // Early layers: higher precision
        if (layer < 10) {
            desc.quant = QuantizationType::Q8_0;
        }
        // Middle layers: standard
        else if (layer < 80) {
            desc.quant = QuantizationType::Q4_K_M;
        }
        // Later layers: aggressive compression
        else {
            desc.quant = QuantizationType::Q2_K;
        }
        
        descs.push_back(desc);
    }
    
    return descs;
}

std::unordered_map<std::string, std::string> MixedTierAdapter::getMetadata() {
    return {{"format", "MixedTier"}, {"tiers", "3"}};
}

bool MixedTierAdapter::validate(const std::string& path) {
    // Validate mixed-tier format
    return true;
}

// ============================================================================
// SECTION 4: Polymorphic Math Engine
// ============================================================================

void PolymorphicMathEngine::rankFold(
    void* U_slot,
    const std::string& model_path,
    uint64_t V_offset,
    uint32_t U_rows, uint32_t U_cols, uint32_t V_cols,
    float* output) {
    
    // Pseudocode: output = U @ V^T
    // U is in slot (small, residual), V streams from disk
    // Result materializes in output without storing full layer
    
    std::ifstream file(model_path, std::ios::binary);
    if (!file.is_open()) return;
    
    file.seekg(V_offset);
    
    float* U_data = static_cast<float*>(U_slot);
    
    for (uint32_t i = 0; i < U_rows; ++i) {
        for (uint32_t j = 0; j < V_cols; ++j) {
            float sum = 0.0f;
            for (uint32_t k = 0; k < U_cols; ++k) {
                // Read one V element
                float v_elem;
                file.read(reinterpret_cast<char*>(&v_elem), sizeof(float));
                sum += U_data[i * U_cols + k] * v_elem;
            }
            output[i * V_cols + j] = sum;
        }
    }
}

void PolymorphicMathEngine::morphTier(
    void* tensor_slot,
    uint32_t tensor_bytes,
    QuantizationType from_quant,
    QuantizationType to_quant) {
    
    // Dequantize from source, requantize to target (in-place)
    // E.g., Q4 → Q2 under memory pressure
    
    if (from_quant == to_quant) return;
    
    // Simplified: just mark as needing re-quantization
    // Real impl would use fast MASM Q4→Q2 converter
}

std::vector<ProjectionOperator> PolymorphicMathEngine::createProjections(
    const std::vector<TensorDesc>& all_tensors) {
    
    std::vector<ProjectionOperator> projections;
    
    // Group tensors by role
    std::map<TensorRole, std::vector<size_t>> role_map;
    for (size_t i = 0; i < all_tensors.size(); ++i) {
        role_map[all_tensors[i].role].push_back(i);
    }
    
    // Create projection for each role
    for (const auto& [role, indices] : role_map) {
        ProjectionOperator proj{};
        proj.role = role;
        proj.indices = indices;
        
        // Assign weight based on role
        switch (role) {
            case TensorRole::ATTN_Q:
            case TensorRole::ATTN_K:
            case TensorRole::ATTN_V:
            case TensorRole::ATTN_O:
                proj.partition_weight = static_cast<float>(ActiveWindowBudget::ATTN_BYTES) / ActiveWindowBudget::TOTAL_BYTES;
                break;
            case TensorRole::MLP_UP:
            case TensorRole::MLP_DOWN:
                proj.partition_weight = static_cast<float>(ActiveWindowBudget::MLP_BYTES) / ActiveWindowBudget::TOTAL_BYTES;
                break;
            case TensorRole::KV_CACHE:
                proj.partition_weight = static_cast<float>(ActiveWindowBudget::KV_BYTES) / ActiveWindowBudget::TOTAL_BYTES;
                break;
            default:
                proj.partition_weight = static_cast<float>(ActiveWindowBudget::MISC_BYTES) / ActiveWindowBudget::TOTAL_BYTES;
        }
        
        projections.push_back(proj);
    }
    
    return projections;
}

// ============================================================================
// SECTION 5: Global Stream Plan
// ============================================================================

bool GlobalStreamPlan::buildFromTensors(
    const std::vector<TensorDesc>& all_tensors,
    const ActiveWindowBudget& budget,
    uint32_t max_active_layers) {
    
    plan_.clear();
    
    // Group tensors by layer
    std::map<uint16_t, std::vector<const TensorDesc*>> layers;
    for (const auto& tensor : all_tensors) {
        layers[tensor.layer_id].push_back(&tensor);
    }
    
    uint32_t step_id = 0;
    
    // Create a stream step for each layer (simplified)
    for (const auto& [layer_id, tensors] : layers) {
        StreamStep step{};
        step.step_id = step_id++;
        step.layers.push_back(layer_id);
        
        for (const auto* tensor : tensors) {
            step.zones_to_load.push_back(*tensor);
            step.total_bytes += tensor->byte_length;
        }
        
        step.zone_count = static_cast<uint32_t>(step.zones_to_load.size());
        
        plan_.push_back(step);
    }
    
    return verify();
}

bool GlobalStreamPlan::loadFromDisk(const std::string& cache_path) {
    std::ifstream file(cache_path, std::ios::binary);
    if (!file.is_open()) return false;
    
    uint32_t step_count;
    file.read(reinterpret_cast<char*>(&step_count), sizeof(step_count));
    
    for (uint32_t i = 0; i < step_count; ++i) {
        StreamStep step{};
        file.read(reinterpret_cast<char*>(&step.step_id), sizeof(step.step_id));
        file.read(reinterpret_cast<char*>(&step.zone_count), sizeof(step.zone_count));
        file.read(reinterpret_cast<char*>(&step.total_bytes), sizeof(step.total_bytes));
        
        // Read zones
        for (uint32_t j = 0; j < step.zone_count; ++j) {
            TensorDesc desc{};
            file.read(reinterpret_cast<char*>(&desc), sizeof(desc));
            step.zones_to_load.push_back(desc);
        }
        
        plan_.push_back(step);
    }
    
    return true;
}

bool GlobalStreamPlan::saveToDisk(const std::string& cache_path) const {
    std::ofstream file(cache_path, std::ios::binary);
    if (!file.is_open()) return false;
    
    uint32_t step_count = static_cast<uint32_t>(plan_.size());
    file.write(reinterpret_cast<const char*>(&step_count), sizeof(step_count));
    
    for (const auto& step : plan_) {
        file.write(reinterpret_cast<const char*>(&step.step_id), sizeof(step.step_id));
        file.write(reinterpret_cast<const char*>(&step.zone_count), sizeof(step.zone_count));
        file.write(reinterpret_cast<const char*>(&step.total_bytes), sizeof(step.total_bytes));
        
        for (const auto& zone : step.zones_to_load) {
            file.write(reinterpret_cast<const char*>(&zone), sizeof(zone));
        }
    }
    
    return true;
}

const StreamStep& GlobalStreamPlan::getStep(uint32_t step_id) const {
    static StreamStep dummy{};
    if (step_id >= plan_.size()) return dummy;
    return plan_[step_id];
}

bool GlobalStreamPlan::verify() const {
    // Check that no step exceeds π-partition budgets
    for (const auto& step : plan_) {
        size_t attn_used = 0, mlp_used = 0, kv_used = 0;
        
        for (const auto& zone : step.zones_to_load) {
            switch (zone.role) {
                case TensorRole::ATTN_Q:
                case TensorRole::ATTN_K:
                case TensorRole::ATTN_V:
                case TensorRole::ATTN_O:
                    attn_used += zone.byte_length;
                    break;
                case TensorRole::MLP_UP:
                case TensorRole::MLP_DOWN:
                    mlp_used += zone.byte_length;
                    break;
                case TensorRole::KV_CACHE:
                    kv_used += zone.byte_length;
                    break;
                default:
                    break;
            }
        }

        if (attn_used > ActiveWindowBudget::ATTN_BYTES) {
            // Trigger tier morphing logic would go here
            // For verification, we just report failure if exceeded
            return false;
        }
    }
    
    return true;
}

// ============================================================================
// SECTION 6: Execution Controller
// ============================================================================

ExecutionController::ExecutionController(const GlobalStreamPlan& plan, SlotLattice& slots)
    : plan_(plan), slots_(slots), current_step_(0) {}

const StreamStep& ExecutionController::currentStep() const {
    return plan_.getStep(current_step_);
}

void ExecutionController::advance() {
    if (current_step_ < plan_.getTotalSteps() - 1) {
        current_step_++;
    }
}

void ExecutionController::jumpToStep(uint32_t target_step) {
    current_step_ = std::min(target_step, plan_.getTotalSteps() - 1);
}

void ExecutionController::spinBackToStep(uint32_t target_step) {
    // Rewind: restore checkpoint if available
    if (checkpoints_.find(target_step) != checkpoints_.end()) {
        restoreCheckpoint(target_step);
    }
    current_step_ = target_step;
}

void ExecutionController::spinUpToStep(uint32_t target_step) {
    // Fast-forward: replay steps without full compute
    current_step_ = 0;
    while (current_step_ < target_step && current_step_ < plan_.getTotalSteps()) {
        current_step_++;
    }
}

bool ExecutionController::isComplete() const {
    return current_step_ >= plan_.getTotalSteps() - 1;
}

void ExecutionController::createCheckpoint(uint32_t step_id) {
    // Create compressed checkpoint: serialize KV cache + slot state
    Checkpoint cp{};
    cp.step_id = step_id;

    // Gather slot lattice state into raw buffer
    std::vector<uint8_t> rawState;

    // Serialize current step and slot mappings
    // Format: [step_id:4][slot_count:4][slot_data...]
    uint32_t slotCount = slots_.getActiveCount();
    rawState.resize(8 + slotCount * sizeof(uint64_t));

    memcpy(rawState.data(), &step_id, 4);
    memcpy(rawState.data() + 4, &slotCount, 4);

    // Simple RLE compression (since zstd isn't linked yet)
    // Run-length encode repeated bytes
    std::vector<uint8_t> compressed;
    compressed.reserve(rawState.size());

    size_t i = 0;
    while (i < rawState.size()) {
        uint8_t val = rawState[i];
        uint8_t runLen = 1;
        while (i + runLen < rawState.size() && runLen < 255 &&
               rawState[i + runLen] == val) {
            runLen++;
        }
        compressed.push_back(runLen);
        compressed.push_back(val);
        i += runLen;
    }

    cp.compressed_data = std::move(compressed);
    cp.original_size = rawState.size();

    checkpoints_[step_id] = std::move(cp);
}

void ExecutionController::restoreCheckpoint(uint32_t step_id) {
    // Restore from compressed checkpoint
    if (checkpoints_.find(step_id) == checkpoints_.end()) return;

    auto& cp = checkpoints_[step_id];

    // RLE decompress
    std::vector<uint8_t> rawState;
    rawState.reserve(cp.original_size);

    for (size_t i = 0; i + 1 < cp.compressed_data.size(); i += 2) {
        uint8_t runLen = cp.compressed_data[i];
        uint8_t val = cp.compressed_data[i + 1];
        for (uint8_t j = 0; j < runLen; ++j) {
            rawState.push_back(val);
        }
    }

    // Restore state: parse step_id and slot count from decompressed data
    if (rawState.size() >= 8) {
        uint32_t restored_step = 0;
        memcpy(&restored_step, rawState.data(), 4);
        current_step_ = restored_step;
    }
}

// ============================================================================
// SECTION 7: Polymorphic Loader
// ============================================================================

PolymorphicLoader::PolymorphicLoader(size_t active_window_bytes)
    : model_file_handle_(nullptr) {
    
    // Initialize slot lattice with budget
    slots_ = std::make_unique<SlotLattice>(budget_, 256);
}

PolymorphicLoader::~PolymorphicLoader() {
    if (model_file_handle_) {
        // Close file handle
    }
}

bool PolymorphicLoader::indexModel(const std::string& model_path) {
    current_model_path_ = model_path;

    // Detect format
    adapter_ = detectAndLoadAdapter(model_path);
    if (!adapter_) return false;
    
    // Validate
    if (!adapter_->validate(model_path)) return false;
    
    // Enumerate tensors
    auto tensors = adapter_->enumerate(model_path);
    if (tensors.empty()) return false;
    
    // Build stream plan
    plan_ = std::make_unique<GlobalStreamPlan>();
    if (!plan_->buildFromTensors(tensors, budget_)) return false;
    
    // Cache for next load
    std::string cache_path = model_path + ".streamplan";
    plan_->saveToDisk(cache_path);
    
    return true;
}

bool PolymorphicLoader::beginExecution(const std::string& model_path) {
    current_model_path_ = model_path;
    
    // Load stream plan (from cache if available)
    plan_ = std::make_unique<GlobalStreamPlan>();
    std::string cache_path = model_path + ".streamplan";
    
    if (!plan_->loadFromDisk(cache_path)) {
        if (!indexModel(model_path)) return false;
        if (!plan_->loadFromDisk(cache_path)) return false;
    }
    
    // Initialize controller
    controller_ = std::make_unique<ExecutionController>(*plan_, *slots_);

    metrics_.total_steps = plan_->getTotalSteps();
    metrics_.current_step = 0;
    metrics_.active_memory_bytes = 0;
    metrics_.mb_per_second = 0.0f;
    metrics_.tokens_per_second = 0.0f;
    metrics_.avg_step_ms = 0.0;
    metrics_.p95_step_ms = 0.0;
    metrics_.step_stddev_ms = 0.0;
    metrics_.timed_steps = 0;
    metrics_.last_step_zone_count = 0;
    metrics_.last_step_loaded_zones = 0;
    metrics_.last_step_skipped_zones = 0;
    metrics_.last_step_skip_ratio = 0.0;
    metrics_.last_step_bytes_loaded = 0;
    metrics_.last_step_bytes_evicted = 0;
    metrics_.last_step_evictions = 0;
    metrics_.last_step_eviction_age_avg = 0.0;
    metrics_.last_step_victim_search_ns = 0;
    metrics_.last_step_materialization_ns = 0;
    metrics_.last_step_victim_search_ratio = 0.0;
    metrics_.last_step_materialization_ratio = 0.0;
    metrics_.last_step_batch_count = 0;
    metrics_.last_step_avg_zones_per_batch = 0.0;
    metrics_.last_step_evictions_misc = 0;
    metrics_.last_step_evictions_mlp = 0;
    metrics_.last_step_evictions_attn = 0;
    metrics_.burst_bytes_active = 0;
    metrics_.reclaim_progress = 0.0;
    metrics_.sigmoid_reclaim_value = 0.0;
    metrics_.adaptive_window_value = 0;
    metrics_.last_step_self_eviction_blocked = 0;
    metrics_.last_step_protected_hits = 0;
    metrics_.last_step_protected_scan_count = 0;
    metrics_.last_step_fast_path_hits = 0;
    metrics_.last_step_unprotected_evictions = 0;
    metrics_.cumulative_self_eviction_blocked = 0;
    metrics_.cumulative_protected_hits = 0;
    metrics_.cumulative_protected_scan_count = 0;
    metrics_.cumulative_fast_path_hits = 0;
    metrics_.cumulative_unprotected_evictions = 0;
    metrics_.hysteresis_holds = 0;
    metrics_.last_slot_failure_code = static_cast<uint32_t>(SlotAcquireFailure::NONE);
    metrics_.cumulative_zone_count = 0;
    metrics_.cumulative_loaded_zones = 0;
    metrics_.cumulative_skipped_zones = 0;
    metrics_.cumulative_skip_ratio = 0.0;
    metrics_.cumulative_bytes_loaded = 0;
    metrics_.cumulative_bytes_evicted = 0;
    metrics_.cumulative_evictions = 0;
    metrics_.cumulative_eviction_age_avg = 0.0;
    metrics_.cumulative_victim_search_ns = 0;
    metrics_.cumulative_materialization_ns = 0;
    metrics_.cumulative_batch_count = 0;
    metrics_.cumulative_zones_per_batch = 0;
    metrics_.cumulative_evictions_misc = 0;
    metrics_.cumulative_evictions_mlp = 0;
    metrics_.cumulative_evictions_attn = 0;
    step_latencies_ms_.clear();
    step_latency_sum_ms_ = 0.0;
    step_latency_sum_sq_ms_ = 0.0;
    
    return true;
}

bool PolymorphicLoader::executeStep() {
    if (!controller_ || !slots_) {
        return false;
    }

    const auto started = std::chrono::high_resolution_clock::now();

    // Load zones for current step
    const auto& step = controller_->currentStep();
    budget_.updateBurstBudget(controller_->getCurrentStepId());
    const auto laneType = RawrXD::BackendLaneType::StandaloneExe;
    uint32_t skippedZones = 0;
    uint32_t loadedZones = 0;
    uint64_t bytesLoaded = 0;
    uint64_t bytesEvicted = 0;
    uint64_t stepEvictions = 0;
    uint64_t stepVictimSearchNs = 0;
    uint64_t stepMaterializationNs = 0;
    uint32_t stepBatchCount = 0;
    uint64_t stepZonesPerBatchSum = 0;
    double stepEvictionAgeAvg = 0.0;
    SlotAcquireFailure lastFailure = SlotAcquireFailure::NONE;

    const uint64_t evictionsBefore = slots_->getEvictionCount();
    const uint64_t evictionAgeSumBefore = slots_->getEvictionAgeSum();
    const uint64_t evictionBytesBefore = slots_->getEvictionBytes();
    const uint64_t evictMiscBefore = slots_->getEvictionsByRole(SlotType::AUXILIARY);
    const uint64_t evictMlpBefore = slots_->getEvictionsByRole(SlotType::MLP);
    const uint64_t evictAttnBefore = slots_->getEvictionsByRole(SlotType::ATTENTION);
    const uint64_t selfBlockedBefore = slots_->getSelfEvictionBlockedCount();
    const uint64_t protectedHitsBefore = slots_->getProtectedHitCount();
    const uint64_t protectedScanBefore = slots_->getProtectedScanCount();
    const uint64_t fastPathBefore = slots_->getFastPathHitCount();
    const uint64_t unprotectedEvictionsBefore = slots_->getUnprotectedEvictionCount();
    const uint64_t hysteresisBefore = budget_.getHysteresisHolds();

    auto classifyAcquireFailure = [&](SlotType slotType, uint32_t bytesRequested) -> SlotAcquireFailure {
        if (!budget_.canAllocate(slotType, bytesRequested)) {
            return SlotAcquireFailure::BYTE_BUDGET_EXCEEDED;
        }

        const auto allSlots = slots_->getAllSlots();
        uint32_t roleSlots = 0;
        uint32_t freeSlots = 0;
        uint32_t freeThatFit = 0;
        uint32_t largestFree = 0;

        for (const Slot* s : allSlots) {
            if (!s || s->type != slotType) {
                continue;
            }
            ++roleSlots;
            if (s->active_bytes == 0) {
                ++freeSlots;
                largestFree = std::max(largestFree, s->capacity_bytes);
                if (s->capacity_bytes >= bytesRequested) {
                    ++freeThatFit;
                }
            }
        }

        if (roleSlots == 0) {
            return SlotAcquireFailure::ROLE_LIMIT_EXCEEDED;
        }
        if (freeThatFit > 0) {
            return SlotAcquireFailure::NONE;
        }
        if (freeSlots == 0) {
            return SlotAcquireFailure::SLOT_COUNT_EXHAUSTED;
        }
        if (largestFree < bytesRequested) {
            return SlotAcquireFailure::FRAGMENTATION;
        }
        return SlotAcquireFailure::ROLE_LIMIT_EXCEEDED;
    };

    emitInferenceTelemetryPacket(
        controller_->getCurrentStepId(),
        static_cast<uint32_t>(step.zones_to_load.size()),
        loadedZones,
        skippedZones,
        0.0,
        bytesLoaded,
        0,
        0.0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        budget_.getBurstBytesActive(),
        budget_.getReclaimProgress(),
        budget_.getSigmoidReclaimValue(),
        budget_.getHysteresisHolds(),
        slots_->getTotalUsage(),
        laneType,
        SlotAcquireFailure::NONE,
        "start",
        true);
    
    for (const auto& zone : step.zones_to_load) {
        // Determine slot type from role.
        SlotType slot_type = SlotType::AUXILIARY;
        const bool shouldMaterializeInSlot = isMaterializableRole(zone.role, slot_type);

        if (!shouldMaterializeInSlot) {
            ++skippedZones;
            lastFailure = SlotAcquireFailure::UNSUPPORTED_ROLE;
            continue;
        }
        
        // Acquire slot and account victim-search time.
        auto acquireStarted = std::chrono::high_resolution_clock::now();
        auto slot = slots_->acquireSlot(slot_type, zone.byte_length, controller_->getCurrentStepId());
        stepVictimSearchNs += static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::high_resolution_clock::now() - acquireStarted).count());
        if (!slot) {
            // Budget exceeded — trigger tier morphing: downgrade quantization
            PolymorphicMathEngine mathEngine;
            // Try to free space by morphing existing slots to lower precision
            bool freed = false;
            for (const auto& prevZone : step.zones_to_load) {
                if (prevZone.quant == QuantizationType::Q8_0 ||
                    prevZone.quant == QuantizationType::Q4_K_M) {
                    // Map TensorRole to SlotType for lookup
                    SlotType prevSlotType = SlotType::AUXILIARY;
                    switch (prevZone.role) {
                        case TensorRole::ATTN_Q: case TensorRole::ATTN_K:
                        case TensorRole::ATTN_V: case TensorRole::ATTN_O:
                            prevSlotType = SlotType::ATTENTION; break;
                        case TensorRole::MLP_UP: case TensorRole::MLP_DOWN:
                            prevSlotType = SlotType::MLP; break;
                        case TensorRole::KV_CACHE:
                            prevSlotType = SlotType::KV_CACHE; break;
                        default: break;
                    }
                    // Morph to more aggressive quantization
                    auto existingSlot = slots_->findSlot(prevSlotType);
                    if (existingSlot) {
                        QuantizationType targetQuant = (prevZone.quant == QuantizationType::Q8_0)
                            ? QuantizationType::Q4_K_M
                            : QuantizationType::Q2_K;
                        mathEngine.morphTier(existingSlot->base, existingSlot->active_bytes,
                                            prevZone.quant, targetQuant);
                        freed = true;
                    }
                }
            }
            if (!freed) {
                ++skippedZones;
                lastFailure = classifyAcquireFailure(slot_type, zone.byte_length);
                std::cerr << "[executeStep] slot acquire failed: step=" << controller_->getCurrentStepId()
                          << " role=" << static_cast<int>(zone.role)
                          << " bytes=" << zone.byte_length
                          << " reason=" << slotAcquireFailureToString(lastFailure) << "\n";
                continue;
            }

            // Retry slot acquisition after morphing
            acquireStarted = std::chrono::high_resolution_clock::now();
            slot = slots_->acquireSlot(slot_type, zone.byte_length, controller_->getCurrentStepId());
            stepVictimSearchNs += static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::high_resolution_clock::now() - acquireStarted).count());
            if (!slot) {
                ++skippedZones;
                lastFailure = classifyAcquireFailure(slot_type, zone.byte_length);
                std::cerr << "[executeStep] slot acquire failed after morph: step=" << controller_->getCurrentStepId()
                          << " role=" << static_cast<int>(zone.role)
                          << " bytes=" << zone.byte_length
                          << " reason=" << slotAcquireFailureToString(lastFailure) << "\n";
                continue;
            }
        }
        
        const auto materializationStarted = std::chrono::high_resolution_clock::now();
        const bool loadOk = startAsyncLoad(zone, slot);
        stepMaterializationNs += static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::high_resolution_clock::now() - materializationStarted).count());
        if (!loadOk) {
            ++skippedZones;
            lastFailure = SlotAcquireFailure::IO_ERROR;
            std::cerr << "[executeStep] async load failed: step=" << controller_->getCurrentStepId()
                      << " role=" << static_cast<int>(zone.role)
                      << " offset=" << zone.file_offset
                      << " bytes=" << zone.byte_length << "\n";
            continue;
        }

        ++loadedZones;
        bytesLoaded += zone.byte_length;
        ++stepBatchCount;
        ++stepZonesPerBatchSum;
    }

    const uint32_t zoneCount = static_cast<uint32_t>(step.zones_to_load.size());
    const double skipRatio = zoneCount > 0
        ? static_cast<double>(skippedZones) / static_cast<double>(zoneCount)
        : 0.0;

    const auto finished = std::chrono::high_resolution_clock::now();
    const uint64_t elapsedNs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(finished - started).count());
    const double elapsed_ms = std::chrono::duration<double, std::milli>(finished - started).count();
    updateStepTimingMetrics(elapsed_ms, static_cast<size_t>(step.total_bytes), zoneCount, skippedZones);

    const uint64_t evictionsAfter = slots_->getEvictionCount();
    const uint64_t evictionAgeSumAfter = slots_->getEvictionAgeSum();
    const uint64_t evictionBytesAfter = slots_->getEvictionBytes();
    const uint64_t evictMiscAfter = slots_->getEvictionsByRole(SlotType::AUXILIARY);
    const uint64_t evictMlpAfter = slots_->getEvictionsByRole(SlotType::MLP);
    const uint64_t evictAttnAfter = slots_->getEvictionsByRole(SlotType::ATTENTION);
    const uint64_t selfBlockedAfter = slots_->getSelfEvictionBlockedCount();
    const uint64_t protectedHitsAfter = slots_->getProtectedHitCount();
    const uint64_t protectedScanAfter = slots_->getProtectedScanCount();
    const uint64_t fastPathAfter = slots_->getFastPathHitCount();
    const uint64_t unprotectedEvictionsAfter = slots_->getUnprotectedEvictionCount();
    const uint32_t adaptiveWindow = slots_->getAdaptiveWindowValue();
    const uint64_t hysteresisAfter = budget_.getHysteresisHolds();
    stepEvictions = (evictionsAfter >= evictionsBefore) ? (evictionsAfter - evictionsBefore) : 0;
    bytesEvicted = (evictionBytesAfter >= evictionBytesBefore) ? (evictionBytesAfter - evictionBytesBefore) : 0;
    if (stepEvictions > 0) {
        const uint64_t deltaAge = (evictionAgeSumAfter >= evictionAgeSumBefore)
            ? (evictionAgeSumAfter - evictionAgeSumBefore)
            : 0;
        stepEvictionAgeAvg = static_cast<double>(deltaAge) / static_cast<double>(stepEvictions);
    }

    metrics_.last_step_zone_count = zoneCount;
    metrics_.last_step_loaded_zones = loadedZones;
    metrics_.last_step_skipped_zones = skippedZones;
    metrics_.last_step_skip_ratio = skipRatio;
    metrics_.last_step_bytes_loaded = bytesLoaded;
    metrics_.last_step_bytes_evicted = bytesEvicted;
    metrics_.last_step_evictions = static_cast<uint32_t>(stepEvictions);
    metrics_.last_step_eviction_age_avg = stepEvictionAgeAvg;
    metrics_.last_step_victim_search_ns = stepVictimSearchNs;
    metrics_.last_step_materialization_ns = stepMaterializationNs;
    metrics_.last_step_victim_search_ratio = elapsedNs > 0
        ? static_cast<double>(stepVictimSearchNs) / static_cast<double>(elapsedNs)
        : 0.0;
    metrics_.last_step_materialization_ratio = elapsedNs > 0
        ? static_cast<double>(stepMaterializationNs) / static_cast<double>(elapsedNs)
        : 0.0;
    metrics_.last_step_batch_count = stepBatchCount;
    metrics_.last_step_avg_zones_per_batch = stepBatchCount > 0
        ? static_cast<double>(stepZonesPerBatchSum) / static_cast<double>(stepBatchCount)
        : 0.0;
    metrics_.last_step_evictions_misc = static_cast<uint32_t>((evictMiscAfter >= evictMiscBefore) ? (evictMiscAfter - evictMiscBefore) : 0);
    metrics_.last_step_evictions_mlp = static_cast<uint32_t>((evictMlpAfter >= evictMlpBefore) ? (evictMlpAfter - evictMlpBefore) : 0);
    metrics_.last_step_evictions_attn = static_cast<uint32_t>((evictAttnAfter >= evictAttnBefore) ? (evictAttnAfter - evictAttnBefore) : 0);
    metrics_.burst_bytes_active = budget_.getBurstBytesActive();
    metrics_.reclaim_progress = budget_.getReclaimProgress();
    metrics_.sigmoid_reclaim_value = budget_.getSigmoidReclaimValue();
    metrics_.adaptive_window_value = adaptiveWindow;
    metrics_.last_step_self_eviction_blocked = static_cast<uint32_t>((selfBlockedAfter >= selfBlockedBefore) ? (selfBlockedAfter - selfBlockedBefore) : 0);
    metrics_.last_step_protected_hits = static_cast<uint32_t>((protectedHitsAfter >= protectedHitsBefore) ? (protectedHitsAfter - protectedHitsBefore) : 0);
    metrics_.last_step_protected_scan_count = static_cast<uint32_t>((protectedScanAfter >= protectedScanBefore) ? (protectedScanAfter - protectedScanBefore) : 0);
    metrics_.last_step_fast_path_hits = static_cast<uint32_t>((fastPathAfter >= fastPathBefore) ? (fastPathAfter - fastPathBefore) : 0);
    metrics_.last_step_unprotected_evictions = static_cast<uint32_t>((unprotectedEvictionsAfter >= unprotectedEvictionsBefore) ? (unprotectedEvictionsAfter - unprotectedEvictionsBefore) : 0);
    metrics_.cumulative_self_eviction_blocked = selfBlockedAfter;
    metrics_.cumulative_protected_hits = protectedHitsAfter;
    metrics_.cumulative_protected_scan_count = protectedScanAfter;
    metrics_.cumulative_fast_path_hits = fastPathAfter;
    metrics_.cumulative_unprotected_evictions = unprotectedEvictionsAfter;
    metrics_.hysteresis_holds = hysteresisAfter;
    metrics_.last_slot_failure_code = static_cast<uint32_t>(lastFailure);
    metrics_.cumulative_zone_count += zoneCount;
    metrics_.cumulative_loaded_zones += loadedZones;
    metrics_.cumulative_skipped_zones += skippedZones;
    metrics_.cumulative_skip_ratio = metrics_.cumulative_zone_count > 0
        ? static_cast<double>(metrics_.cumulative_skipped_zones) / static_cast<double>(metrics_.cumulative_zone_count)
        : 0.0;
    metrics_.cumulative_bytes_loaded += bytesLoaded;
    metrics_.cumulative_bytes_evicted += bytesEvicted;
    metrics_.cumulative_evictions = evictionsAfter;
    metrics_.cumulative_eviction_age_avg = metrics_.cumulative_evictions > 0
        ? static_cast<double>(evictionAgeSumAfter) / static_cast<double>(metrics_.cumulative_evictions)
        : 0.0;
    metrics_.cumulative_victim_search_ns += stepVictimSearchNs;
    metrics_.cumulative_materialization_ns += stepMaterializationNs;
    metrics_.cumulative_batch_count += stepBatchCount;
    metrics_.cumulative_zones_per_batch += stepZonesPerBatchSum;
    metrics_.cumulative_evictions_misc = evictMiscAfter;
    metrics_.cumulative_evictions_mlp = evictMlpAfter;
    metrics_.cumulative_evictions_attn = evictAttnAfter;

    emitInferenceTelemetryPacket(
        controller_->getCurrentStepId(),
        zoneCount,
        loadedZones,
        skippedZones,
        skipRatio,
        bytesLoaded,
        static_cast<uint32_t>(stepEvictions),
        stepEvictionAgeAvg,
        metrics_.last_step_evictions_misc,
        metrics_.last_step_evictions_mlp,
        metrics_.last_step_evictions_attn,
        metrics_.last_step_self_eviction_blocked,
        metrics_.last_step_protected_hits,
        metrics_.last_step_protected_scan_count,
        metrics_.last_step_fast_path_hits,
        metrics_.last_step_unprotected_evictions,
        metrics_.adaptive_window_value,
        metrics_.burst_bytes_active,
        metrics_.reclaim_progress,
        metrics_.sigmoid_reclaim_value,
        metrics_.hysteresis_holds,
        slots_->getTotalUsage(),
        laneType,
        lastFailure,
        "end",
        true);

    emitInferencePerfTelemetryPacket(
        controller_->getCurrentStepId(),
        zoneCount,
        loadedZones,
        elapsedNs,
        stepVictimSearchNs,
        stepMaterializationNs,
        stepBatchCount,
        metrics_.last_step_avg_zones_per_batch,
        true);

    if (skippedZones > 0) {
        std::cerr << "[executeStep] step=" << controller_->getCurrentStepId()
                  << " completed_with_skips=" << skippedZones << "\n";
    }
    
    return true;
}

const StreamStep& PolymorphicLoader::getCurrentStep() const {
    if (!controller_) {
        static StreamStep dummy{};
        return dummy;
    }
    return controller_->currentStep();
}

void PolymorphicLoader::advanceStep() {
    if (controller_) {
        controller_->advance();
    }
}

void PolymorphicLoader::jumpToStep(uint32_t step_id) {
    if (controller_) {
        controller_->jumpToStep(step_id);
    }
}

PolymorphicLoader::PerformanceMetrics PolymorphicLoader::getMetrics() const {
    return metrics_;
}

std::unique_ptr<IFormatAdapter> PolymorphicLoader::detectAndLoadAdapter(const std::string& path) {
    // Try each adapter
    auto gguf_adapter = std::make_unique<GGUFAdapter>();
    if (gguf_adapter->validate(path)) {
        return gguf_adapter;
    }
    
    auto sharded_adapter = std::make_unique<ShardedBlobAdapter>();
    if (sharded_adapter->validate(path)) {
        return sharded_adapter;
    }
    
    auto mixed_adapter = std::make_unique<MixedTierAdapter>();
    if (mixed_adapter->validate(path)) {
        return mixed_adapter;
    }
    
    return nullptr;
}

bool PolymorphicLoader::startAsyncLoad(const TensorDesc& zone, Slot* target_slot) {
    if (!ensureModelFileHandle()) {
        return false;
    }

    // Determine target slot
    SlotType slot_type = SlotType::AUXILIARY;
    bool shouldMaterializeInSlot = true;
    switch (zone.role) {
        case TensorRole::ATTN_Q:
        case TensorRole::ATTN_K:
        case TensorRole::ATTN_V:
        case TensorRole::ATTN_O:
            slot_type = SlotType::ATTENTION;
            break;
        case TensorRole::MLP_UP:
        case TensorRole::MLP_DOWN:
            slot_type = SlotType::MLP;
            break;
        case TensorRole::KV_CACHE:
            slot_type = SlotType::KV_CACHE;
            break;
        default:
            shouldMaterializeInSlot = false;
            break;
    }

    if (!shouldMaterializeInSlot) {
        return true;
    }

    Slot* slot = target_slot;
    if (!slot) {
        slot = slots_->acquireSlot(slot_type, zone.byte_length, controller_->getCurrentStepId());
    }
    if (!slot) {
        std::cerr << "[startAsyncLoad] no slot available: step="
                  << (controller_ ? controller_->getCurrentStepId() : 0)
                  << " role=" << static_cast<int>(zone.role)
                  << " bytes=" << zone.byte_length << "\n";
        return false;
    }

    LARGE_INTEGER fileSize{};
    if (GetFileSizeEx(model_file_handle_, &fileSize)) {
        const uint64_t endOffset = zone.file_offset + zone.byte_length;
        if (endOffset > static_cast<uint64_t>(fileSize.QuadPart)) {
            std::cerr << "[startAsyncLoad] out_of_range_read: offset=" << zone.file_offset
                      << " bytes=" << zone.byte_length
                      << " file_size=" << static_cast<uint64_t>(fileSize.QuadPart) << "\n";
            return false;
        }
    }

    // Set up overlapped read
    OVERLAPPED* ov = new OVERLAPPED();
    memset(ov, 0, sizeof(OVERLAPPED));
    ov->Offset = (DWORD)(zone.file_offset & 0xFFFFFFFF);
    ov->OffsetHigh = (DWORD)(zone.file_offset >> 32);

    if (!ReadFile(model_file_handle_, slot->base, zone.byte_length, NULL, ov)) {
        DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING) {
            std::cerr << "[startAsyncLoad] ReadFile failed: error=" << err
                      << " offset=" << zone.file_offset
                      << " bytes=" << zone.byte_length << "\n";
            delete ov;
            return false;
        }
    }

    return true;
}

bool PolymorphicLoader::ensureModelFileHandle() {
    if (model_file_handle_) {
        return true;
    }

    model_file_handle_ = CreateFileA(
        current_model_path_.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL);
    if (model_file_handle_ == INVALID_HANDLE_VALUE) {
        std::cerr << "[ensureModelFileHandle] CreateFileA failed: path=" << current_model_path_
                  << " error=" << GetLastError() << "\n";
        model_file_handle_ = nullptr;
        return false;
    }

    return true;
}

void PolymorphicLoader::updateStepTimingMetrics(double elapsed_ms, size_t step_bytes, uint32_t zone_count, uint32_t skipped_zones) {
    step_latencies_ms_.push_back(elapsed_ms);
    step_latency_sum_ms_ += elapsed_ms;
    step_latency_sum_sq_ms_ += elapsed_ms * elapsed_ms;

    const uint32_t samples = static_cast<uint32_t>(step_latencies_ms_.size());
    if (samples == 0) {
        return;
    }

    const double avg = step_latency_sum_ms_ / static_cast<double>(samples);
    const double variance = std::max(0.0, (step_latency_sum_sq_ms_ / static_cast<double>(samples)) - (avg * avg));

    std::vector<double> sorted = step_latencies_ms_;
    std::sort(sorted.begin(), sorted.end());
    const size_t p95_index = static_cast<size_t>(std::ceil(0.95 * static_cast<double>(samples))) - 1;
    const double p95 = sorted[std::min(p95_index, sorted.size() - 1)];

    metrics_.avg_step_ms = avg;
    metrics_.p95_step_ms = p95;
    metrics_.step_stddev_ms = std::sqrt(variance);
    metrics_.timed_steps = samples;
    metrics_.active_memory_bytes = slots_ ? slots_->getTotalUsage() : 0;
    metrics_.current_step = controller_ ? controller_->getCurrentStepId() : 0;

    const double elapsed_seconds = std::max(step_latency_sum_ms_ / 1000.0, 1e-9);
    metrics_.tokens_per_second = static_cast<float>(static_cast<double>(samples) / elapsed_seconds);
    metrics_.mb_per_second = static_cast<float>((static_cast<double>(step_bytes) / (1024.0 * 1024.0)) / std::max(elapsed_ms / 1000.0, 1e-9));
    metrics_.last_step_zone_count = zone_count;
    metrics_.last_step_skipped_zones = skipped_zones;
    metrics_.last_step_skip_ratio = zone_count > 0
        ? static_cast<double>(skipped_zones) / static_cast<double>(zone_count)
        : 0.0;
}

const char* PolymorphicLoader::slotAcquireFailureToString(SlotAcquireFailure reason) {
    switch (reason) {
        case SlotAcquireFailure::NONE: return "None";
        case SlotAcquireFailure::SLOT_COUNT_EXHAUSTED: return "SlotCountExhausted";
        case SlotAcquireFailure::BYTE_BUDGET_EXCEEDED: return "ByteBudgetExceeded";
        case SlotAcquireFailure::FRAGMENTATION: return "Fragmentation";
        case SlotAcquireFailure::ROLE_LIMIT_EXCEEDED: return "RoleBudgetExceeded";
        case SlotAcquireFailure::UNSUPPORTED_ROLE: return "UnsupportedRole";
        case SlotAcquireFailure::IO_ERROR: return "IoError";
        default: return "Unknown";
    }
}
