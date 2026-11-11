#include "LoRABeaconInterface.h"
#include <cstring>
#include <cstdlib>
#include <new>
#include <mutex>
#include <fstream>
#include <filesystem>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Static Beacon Storage (Memory-Mapped for MASM)
// ============================================================================
// These are placed in a dedicated section for easy memory mapping
// Exported for MASM access via EXTERNDEF

#pragma data_seg(".lorabeacon")
LORA_ALIGN_64 LoRABeaconState g_beacon_state = {0};
LORA_ALIGN_64 LoRABeaconChain g_beacon_chain = {0};
#pragma data_seg()

// Aligned storage for matrices (statically allocated)
LORA_ALIGN_32 static float g_matrix_a_storage[LORA_MAX_RANK * LORA_MAX_HIDDEN_DIM];
LORA_ALIGN_32 static float g_matrix_b_storage[LORA_MAX_HIDDEN_DIM * LORA_MAX_RANK];

// Function pointer for MASM implementation
LoRAApplyFunc g_lora_apply_asm = nullptr;

// ============================================================================
// C Interface Implementation
// ============================================================================

LoRABeaconState* lora_get_beacon(void) {
    return &g_beacon_state;
}

LoRABeaconChain* lora_get_beacon_chain(void) {
    return &g_beacon_chain;
}

int lora_update_beacon(
    const float* A_data,
    const float* B_data,
    uint32_t rank,
    uint32_t hidden_dim,
    float scale_factor
) {
    // Validate dimensions
    if (rank == 0 || rank > LORA_MAX_RANK) return -1;
    if (hidden_dim == 0 || hidden_dim > LORA_MAX_HIDDEN_DIM) return -2;
    if (!A_data || !B_data) return -3;
    
    // Set status to UPDATING (lock out MASM)
    g_beacon_state.status = LORA_BEACON_UPDATING;
    
    // Memory fence to ensure status is visible
    _mm_sfence();
    
    // Copy data to aligned storage
    size_t a_size = rank * hidden_dim;
    size_t b_size = hidden_dim * rank;
    
    std::memcpy(g_matrix_a_storage, A_data, a_size * sizeof(float));
    std::memcpy(g_matrix_b_storage, B_data, b_size * sizeof(float));
    
    // Update beacon state
    g_beacon_state.version = 1;
    g_beacon_state.rank = rank;
    g_beacon_state.hidden_dim = hidden_dim;
    g_beacon_state.ptr_A = g_matrix_a_storage;
    g_beacon_state.ptr_B = g_matrix_b_storage;
    g_beacon_state.scale_factor = scale_factor;
    g_beacon_state.next_adapter = nullptr;
    g_beacon_state.composite_weight = 1.0f;
    
    // Memory fence before activating
    _mm_sfence();
    
    // Activate beacon
    g_beacon_state.status = LORA_BEACON_ACTIVE;
    
    return 0;
}

void lora_clear_beacon(void) {
    g_beacon_state.status = LORA_BEACON_INACTIVE;
    _mm_sfence();
}

void lora_set_beacon_status(uint32_t status) {
    g_beacon_state.status = status;
    _mm_sfence();
}

uint32_t lora_get_beacon_status(void) {
    return g_beacon_state.status;
}

// ============================================================================
// Memory Allocation
// ============================================================================

void* lora_aligned_alloc(size_t size, size_t alignment) {
#ifdef _WIN32
    return _aligned_malloc(size, alignment);
#else
    void* ptr = nullptr;
    posix_memalign(&ptr, alignment, size);
    return ptr;
#endif
}

void lora_aligned_free(void* ptr) {
#ifdef _WIN32
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}

int lora_is_aligned_avx512(const void* ptr) {
    return ((uintptr_t)ptr & 0x3F) == 0;  // Check 64-byte alignment
}

#ifdef __cplusplus
} // extern "C"

namespace RawrXD {

// ============================================================================
// AlignedBuffer Implementation
// ============================================================================

template<size_t Alignment>
AlignedBuffer<Alignment>::AlignedBuffer(size_t num_floats) 
    : m_size(num_floats) {
    size_t bytes = num_floats * sizeof(float);
    m_original = lora_aligned_alloc(bytes + Alignment, Alignment);
    if (!m_original) {
        throw std::bad_alloc();
    }
    
    // Align to boundary
    uintptr_t addr = (uintptr_t)m_original + Alignment;
    addr &= ~(Alignment - 1);
    m_data = (float*)addr;
    
    std::memset(m_data, 0, bytes);
}

template<size_t Alignment>
AlignedBuffer<Alignment>::~AlignedBuffer() {
    if (m_original) {
        lora_aligned_free(m_original);
    }
}

template<size_t Alignment>
AlignedBuffer<Alignment>::AlignedBuffer(AlignedBuffer&& other) noexcept
    : m_data(other.m_data)
    , m_original(other.m_original)
    , m_size(other.m_size) {
    other.m_data = nullptr;
    other.m_original = nullptr;
    other.m_size = 0;
}

template<size_t Alignment>
AlignedBuffer<Alignment>& AlignedBuffer<Alignment>::operator=(AlignedBuffer&& other) noexcept {
    if (this != &other) {
        if (m_original) {
            lora_aligned_free(m_original);
        }
        m_data = other.m_data;
        m_original = other.m_original;
        m_size = other.m_size;
        other.m_data = nullptr;
        other.m_original = nullptr;
        other.m_size = 0;
    }
    return *this;
}

template<size_t Alignment>
bool AlignedBuffer<Alignment>::is_aligned() const {
    return lora_is_aligned_avx512(m_data);
}

// Explicit instantiations
template class AlignedBuffer<32>;
template class AlignedBuffer<64>;

// ============================================================================
// BeaconAdapterManager Implementation
// ============================================================================

BeaconAdapterManager& BeaconAdapterManager::instance() {
    static BeaconAdapterManager instance;
    return instance;
}

BeaconAdapterManager::BeaconAdapterManager() {
    // Initialize beacon pointer
    m_beacon = lora_get_beacon();
    
    // Set up cache directory
    const char* user_profile = std::getenv("USERPROFILE");
    if (user_profile) {
        m_cache_dir = std::filesystem::path(user_profile) / ".rawrxd" / "adapters";
    } else {
        m_cache_dir = std::filesystem::temp_directory_path() / "rawrxd_adapters";
    }
    std::filesystem::create_directories(m_cache_dir);
}

BeaconAdapterManager::~BeaconAdapterManager() {
    deactivate_adapter();
}

bool BeaconAdapterManager::load_adapter(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_adapter_buffers.find(name) != m_adapter_buffers.end()) {
        return true;  // Already loaded
    }
    
    std::filesystem::path lora_path = m_cache_dir / (name + ".lora");
    
    // Parse binary .lora file
    std::ifstream file(lora_path, std::ios::binary);
    if (!file) {
        return false;
    }
    
    // Read header
    char header[8];
    file.read(header, 8);
    if (std::memcmp(header, "RAWRLORA", 8) != 0) {
        return false;
    }
    
    uint32_t version;
    file.read(reinterpret_cast<char*>(&version), sizeof(version));
    if (version != 1) {
        return false;
    }
    
    uint32_t rank, in_features, out_features;
    file.read(reinterpret_cast<char*>(&rank), sizeof(rank));
    file.read(reinterpret_cast<char*>(&in_features), sizeof(in_features));
    file.read(reinterpret_cast<char*>(&out_features), sizeof(out_features));
    
    if (rank > LORA_MAX_RANK || out_features > LORA_MAX_HIDDEN_DIM) {
        return false;
    }
    
    // Allocate aligned buffers
    AlignedBuffer<32> buffer_A(rank * in_features);
    AlignedBuffer<32> buffer_B(out_features * rank);
    
    // Read data
    file.read(reinterpret_cast<char*>(buffer_A.data()), 
              rank * in_features * sizeof(float));
    file.read(reinterpret_cast<char*>(buffer_B.data()), 
              out_features * rank * sizeof(float));
    
    if (!file) {
        return false;
    }
    
    m_adapter_buffers[name] = std::make_pair(
        std::move(buffer_A), 
        std::move(buffer_B)
    );
    
    return true;
}

void BeaconAdapterManager::unload_adapter(const std::string& name) {
    std::unique_lock<std::mutex> lock(m_mutex);
    
    if (m_active_adapter == name) {
        lock.unlock();  // Release before calling deactivate_adapter
        deactivate_adapter();
        lock.lock();
    }
    
    m_adapter_buffers.erase(name);
}

bool BeaconAdapterManager::activate_adapter(const std::string& name) {
    std::unique_lock<std::mutex> lock(m_mutex);
    
    auto it = m_adapter_buffers.find(name);
    if (it == m_adapter_buffers.end()) {
        // Try to load first
        lock.unlock();
        if (!load_adapter(name)) {
            return false;
        }
        lock.lock();
        it = m_adapter_buffers.find(name);
        if (it == m_adapter_buffers.end()) {
            return false;
        }
    }
    
    // Update beacon atomically via C interface
    auto& [buffer_A, buffer_B] = it->second;
    
    // Get dimensions from manifest or infer from buffer sizes
    uint32_t rank = 8;  // Default, should be read from manifest
    uint32_t hidden_dim = 768;  // Default
    
    int result = lora_update_beacon(
        buffer_A.data(),
        buffer_B.data(),
        rank,
        hidden_dim,
        1.0f  // Full scale
    );
    
    if (result == 0) {
        m_active_adapter = name;
        return true;
    }
    
    return false;
}

void BeaconAdapterManager::deactivate_adapter() {
    std::lock_guard<std::mutex> lock(m_mutex);
    lora_clear_beacon();
    m_active_adapter.clear();
}

bool BeaconAdapterManager::is_active() const {
    return lora_get_beacon_status() == LORA_BEACON_ACTIVE;
}

std::filesystem::path BeaconAdapterManager::get_cache_dir() const {
    return m_cache_dir;
}

} // namespace RawrXD

#endif // __cplusplus
