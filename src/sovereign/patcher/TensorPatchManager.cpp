#include "TensorPatchManager.hpp"
#include "SessionStore.hpp"
#include <cstring>
#include <chrono>

namespace RawrXD {
namespace Sovereign {

// =============================================================================
// Construction / Destruction
// =============================================================================

TensorPatchManager::TensorPatchManager() 
    : current_epoch_(0)
    , active_patches_(0)
    , total_patches_(0)
    , telemetry_cb_(nullptr)
{
    // Initialize table to zero
    std::memset(table_, 0, sizeof(table_));
}

TensorPatchManager::~TensorPatchManager() {
    Shutdown();
}

// =============================================================================
// Initialization
// =============================================================================

bool TensorPatchManager::Initialize(TelemetryCallback callback) {
    telemetry_cb_ = callback;
    
    // Initialize session store for checkpointing
    session_store_ = std::make_unique<SessionStore>();
    if (!session_store_->Initialize()) {
        return false;
    }
    
    return true;
}

void TensorPatchManager::Shutdown() {
    // Clear all active patches
    for (size_t i = 0; i < TABLE_CAPACITY; ++i) {
        table_[i].active.store(false, std::memory_order_release);
        table_[i].patch.store(nullptr, std::memory_order_release);
    }
    
    active_patches_.store(0, std::memory_order_relaxed);
    session_store_.reset();
}

// =============================================================================
// Core API: RegisterPatch
// =============================================================================

NEVMP_Status TensorPatchManager::RegisterPatch(const void* nevmp_data, size_t buffer_size) {
    if (!nevmp_data || buffer_size < sizeof(NEVMP_Header)) {
        return NEVMP_Status::ERR_INVALID_PAYLOAD;
    }
    
    const auto* header = static_cast<const NEVMP_Header*>(nevmp_data);
    
    // Validate header
    if (!header->IsValid()) {
        if (header->magic != NEVMP_MAGIC) {
            DispatchTelemetry(0, 0, -1, 0);
            return NEVMP_Status::ERR_INVALID_MAGIC;
        }
        if (header->version != NEVMP_VERSION) {
            DispatchTelemetry(0, 0, -2, 0);
            return NEVMP_Status::ERR_INVALID_VERSION;
        }
        DispatchTelemetry(0, 0, -4, 0);
        return NEVMP_Status::ERR_INVALID_PAYLOAD;
    }
    
    // Validate payload boundaries
    size_t required_size = sizeof(NEVMP_Header) + header->payload_size;
    if (buffer_size < required_size) {
        DispatchTelemetry(header->target_addr, header->epoch_id, -4, 
                         static_cast<uint32_t>(buffer_size));
        return NEVMP_Status::ERR_INVALID_PAYLOAD;
    }
    
    // Verify checksum
    const void* payload = static_cast<const uint8_t*>(nevmp_data) + sizeof(NEVMP_Header);
    uint64_t expected_checksum = NEVMP_Header::CalculateChecksum(payload, header->payload_size);
    if (header->checksum != expected_checksum) {
        DispatchTelemetry(header->target_addr, header->epoch_id, -3, 
                         static_cast<uint32_t>(header->payload_size));
        return NEVMP_Status::ERR_INVALID_CHECKSUM;
    }
    
    // Find or claim slot
    PatchSlot* slot = FindOrClaimSlot(header->target_addr);
    if (!slot) {
        return NEVMP_Status::ERR_MEMORY_ALLOC;
    }
    
    // Check epoch versioning (reject stale patches)
    uint64_t current_epoch = current_epoch_.load(std::memory_order_acquire);
    if (header->epoch_id <= slot->epoch_id.load(std::memory_order_acquire)) {
        DispatchTelemetry(header->target_addr, header->epoch_id, -2, 
                         static_cast<uint32_t>(header->payload_size));
        return NEVMP_Status::ERR_INVALID_VERSION;
    }
    
    // Atomic hot-swap
    const auto* full_patch = static_cast<const NEVMP_Patch*>(nevmp_data);
    
    slot->epoch_id.store(header->epoch_id, std::memory_order_release);
    slot->target_hash.store(header->target_addr, std::memory_order_release);
    slot->patch.store(full_patch, std::memory_order_release);
    slot->active.store(true, std::memory_order_release);
    
    // Update epoch
    current_epoch_.store(header->epoch_id, std::memory_order_release);
    
    // Update counters
    if (!slot->active.exchange(true, std::memory_order_acq_rel)) {
        active_patches_.fetch_add(1, std::memory_order_relaxed);
    }
    total_patches_.fetch_add(1, std::memory_order_relaxed);
    
    // Success telemetry
    DispatchTelemetry(header->target_addr, header->epoch_id, 0, 
                     static_cast<uint32_t>(header->payload_size));
    
    return NEVMP_Status::OK;
}

// =============================================================================
// Hot Path: Resolve (sub-nanosecond)
// =============================================================================

bool TensorPatchManager::Resolve(uint64_t tensor_hash, ResolvedPatch& out_patch) const noexcept {
    if (!tensor_hash) return false;
    
    size_t index = HashToIndex(tensor_hash);
    size_t probes = 0;
    
    while (probes < TABLE_CAPACITY) {
        const PatchSlot& slot = table_[index];
        
        uint64_t slot_hash = slot.target_hash.load(std::memory_order_acquire);
        
        if (slot_hash == tensor_hash) {
            // Found matching hash
            if (!slot.active.load(std::memory_order_acquire)) {
                return false;
            }
            
            const NEVMP_Patch* patch = slot.patch.load(std::memory_order_acquire);
            if (!patch) return false;
            
            out_patch.delta_payload = patch->GetPayload();
            out_patch.vector_count = patch->header.vector_count;
            out_patch.epoch = slot.epoch_id.load(std::memory_order_relaxed);
            out_patch.target_addr = tensor_hash;
            out_patch.valid = true;
            return true;
        }
        
        if (slot_hash == 0) {
            // Empty slot - target not patched
            return false;
        }
        
        // Linear probing
        index = (index + 1) & (TABLE_CAPACITY - 1);
        ++probes;
    }
    
    return false;
}

// =============================================================================
// Titan Integration: ApplyToAperture
// =============================================================================

NEVMP_Status TensorPatchManager::ApplyToAperture(uint64_t tensor_hash, 
                                                  void* aperture_ptr, 
                                                  size_t aperture_size) {
    if (!aperture_ptr || aperture_size == 0) {
        return NEVMP_Status::ERR_INVALID_PAYLOAD;
    }
    
    ResolvedPatch patch;
    if (!Resolve(tensor_hash, patch)) {
        return NEVMP_Status::ERR_APPLY_FAILED;
    }
    
    // Validate payload fits in aperture
    size_t payload_bytes = patch.vector_count * sizeof(double);
    if (payload_bytes > aperture_size) {
        return NEVMP_Status::ERR_INVALID_PAYLOAD;
    }
    
    // Call MASM loader for non-temporal application
    const NEVMP_Patch* nevmp = reinterpret_cast<const NEVMP_Patch*>(
        reinterpret_cast<const uint8_t*>(patch.delta_payload) - sizeof(NEVMP_Header)
    );
    
    int32_t result = NEVMP_LoadAndApply(&nevmp->header, aperture_ptr, payload_bytes);
    if (result != 0) {
        return static_cast<NEVMP_Status>(result);
    }
    
    return NEVMP_Status::OK;
}

// =============================================================================
// Rollback
// =============================================================================

bool TensorPatchManager::Rollback(uint64_t target_epoch) {
    // Find checkpoint for target epoch
    if (!session_store_) {
        return false;
    }
    
    // TODO: Implement checkpoint retrieval and restoration
    // This would involve:
    // 1. Loading checkpoint from SessionStore
    // 2. Calling NEVMP_Rollback to restore aperture state
    // 3. Updating current_epoch_
    
    return false;
}

// =============================================================================
// Validation
// =============================================================================

NEVMP_Status TensorPatchManager::Validate(const void* nevmp_data, size_t buffer_size) const {
    if (!nevmp_data || buffer_size < sizeof(NEVMP_Header)) {
        return NEVMP_Status::ERR_INVALID_PAYLOAD;
    }
    
    const auto* header = static_cast<const NEVMP_Header*>(nevmp_data);
    
    if (!header->IsValid()) {
        if (header->magic != NEVMP_MAGIC) {
            return NEVMP_Status::ERR_INVALID_MAGIC;
        }
        if (header->version != NEVMP_VERSION) {
            return NEVMP_Status::ERR_INVALID_VERSION;
        }
        return NEVMP_Status::ERR_INVALID_PAYLOAD;
    }
    
    size_t required_size = sizeof(NEVMP_Header) + header->payload_size;
    if (buffer_size < required_size) {
        return NEVMP_Status::ERR_INVALID_PAYLOAD;
    }
    
    return NEVMP_Status::OK;
}

// =============================================================================
// Internal Methods
// =============================================================================

PatchSlot* TensorPatchManager::FindOrClaimSlot(uint64_t tensor_hash) {
    size_t index = HashToIndex(tensor_hash);
    size_t probes = 0;
    
    PatchSlot* first_empty = nullptr;
    
    while (probes < TABLE_CAPACITY) {
        PatchSlot& slot = table_[index];
        uint64_t slot_hash = slot.target_hash.load(std::memory_order_acquire);
        
        if (slot_hash == tensor_hash) {
            // Found existing slot for this tensor
            return &slot;
        }
        
        if (slot_hash == 0 && !first_empty) {
            // Remember first empty slot
            first_empty = &slot;
        }
        
        index = (index + 1) & (TABLE_CAPACITY - 1);
        ++probes;
    }
    
    // Return first empty slot if found, otherwise nullptr (table full)
    return first_empty;
}

void TensorPatchManager::DispatchTelemetry(uint64_t hash, uint64_t epoch, 
                                           int32_t status, uint32_t bytes) {
    if (!telemetry_cb_) return;
    
    PatchTelemetry evt;
    evt.tensor_hash = hash;
    evt.epoch_version = epoch;
    evt.status_code = status;
    evt.payload_bytes = bytes;
    evt.timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
    
    telemetry_cb_(evt);
}

size_t TensorPatchManager::GetActivePatchCount() const {
    return active_patches_.load(std::memory_order_relaxed);
}

// =============================================================================
// NEVMP_Header Implementation
// =============================================================================

uint64_t NEVMP_Header::CalculateChecksum(const void* payload, size_t size) {
    // Simple CRC64-ISO implementation
    // In production, use hardware-accelerated CRC (CRC32/64 instructions)
    
    static const uint64_t CRC64_ISO_POLY = 0xD800000000000000ULL;
    
    uint64_t crc = ~0ULL;  // Initial value
    const uint8_t* data = static_cast<const uint8_t*>(payload);
    
    for (size_t i = 0; i < size; ++i) {
        crc ^= static_cast<uint64_t>(data[i]) << 56;
        for (int j = 0; j < 8; ++j) {
            crc = (crc << 1) ^ ((crc & 0x8000000000000000ULL) ? CRC64_ISO_POLY : 0);
        }
    }
    
    return ~crc;
}

// =============================================================================
// ScopedPatch Implementation
// =============================================================================

ScopedPatch::ScopedPatch(TensorPatchManager& manager, uint64_t tensor_hash)
    : manager_(manager)
    , tensor_hash_(tensor_hash)
    , active_(false)
{
    active_ = manager_.Resolve(tensor_hash_, patch_);
}

ScopedPatch::~ScopedPatch() {
    // Automatic cleanup if needed
}

} // namespace Sovereign
} // namespace RawrXD
