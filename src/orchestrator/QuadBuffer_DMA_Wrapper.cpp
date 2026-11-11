// =============================================================================
// QuadBuffer_DMA_Wrapper.cpp
// C++ Integration Layer for RawrXD QuadBuffer DMA Orchestrator
// Interfaces MASM quad-buffer core with Phase 2/3/4/5 system
// =============================================================================

#include <windows.h>
#include <cstdint>
#include <chrono>
#include <atomic>
#include <thread>
#include <vector>

#pragma warning(disable: 4996)

// =============================================================================
// EXTERN DECLARATIONS - RawrXD_QuadBuffer_Streamer.asm exports (REAL)
// =============================================================================

extern "C" {
    // Real QuadBuffer API from RawrXD_QuadBuffer_Streamer.asm
    int64_t QB_Init(uint64_t max_vram_bytes, uint64_t max_ram_bytes);
    int64_t QB_Shutdown(void);
    int64_t QB_LoadModel(const wchar_t* file_path, uint32_t format_hint);
    int64_t QB_StreamTensor(uint64_t tensor_name_hash, void* p_dest, uint64_t max_bytes, uint32_t timeout_ms);
    int64_t QB_ReleaseTensor(uint64_t tensor_name_hash);
    int64_t QB_GetStats(uint64_t* p_stats_out);  // 8 QWORDs
    int64_t QB_ForceEviction(uint64_t target_bytes_to_free);
    int64_t QB_SetVRAMLimit(uint64_t new_limit_bytes);
    void*   QB_GetEngineDescriptor(void);

    // Streaming QuadBuffer (SPSC ring + GDI render) from RawrXD_Streaming_QuadBuffer.asm
    int64_t SQB_Init(uint32_t slot_count, uint64_t slot_bytes);
    int64_t SQB_Shutdown(void);
    HWND    SQB_CreateRenderWnd(HWND parent, int32_t width, int32_t height, uint32_t child_id);
    int64_t SQB_DestroyRenderWnd(void);
    int64_t SQB_PushFrame(const void* p_data, uint64_t data_len);
    int64_t SQB_GetFrameStats(uint64_t* p_out);  // 4 QWORDs
    int64_t SQB_SetTargetFPS(uint32_t fps);

    // Prefetch kernel from quadbuffer_prefetch.asm
    void    rawrxd_prefetch_tensor_async(void* tensor_data, uint32_t layer_id, uint32_t slot_index);
    uint64_t rawrxd_rotate_buffer_slots(void* current_active_ptr, void* next_ready_ptr, uint64_t rdtsc_threshold);
}

// =============================================================================
// CONSTANTS & ENUMS
// =============================================================================

enum BufferState {
    BUF_STATE_EMPTY     = 0,
    BUF_STATE_LOADING   = 1,
    BUF_STATE_READY     = 2,
    BUF_STATE_COMPUTING = 3
};

const uint64_t YTFN_SENTINEL = 0x7FFFFFFFFFFFFFFF;  // Trap sentinel
const uint32_t QUAD_BUFFER_COUNT = 4;
const uint64_t PAGE_SIZE = 0x40000000;              // 1GB
const uint32_t PAGE_SHIFT = 30;

// Phase integration constants
const uint64_t PHASE2_LAYER_SIZE = 0x1000000;       // 16MB per layer
const uint64_t PHASE3_TENSOR_STRIDE = 0x100000;     // Phase 3 stride
const uint64_t PHASE4_DMA_BATCH_SIZE = 8;           // Phase 4 batches

// =============================================================================
// CLASS: QuadBufferOrchestrator
// High-level C++ wrapper for MASM quad-buffer implementation
// =============================================================================

class QuadBufferOrchestrator {
private:
    void* orchestrator_ctx;
    std::thread iocp_thread;
    std::atomic<bool> running;
    uint64_t total_layers;
    uint64_t layer_size;
    std::chrono::high_resolution_clock::time_point init_time;
    
    // Phase integration interfaces
    void* phase2_context;
    void* phase3_context;
    void* phase4_context;
    void* phase5_context;
    
    // Metrics snapshot
    struct MetricsSnapshot {
        uint64_t hdd_read_bytes;
        uint64_t dma_write_bytes;
        uint64_t stall_cycles;
        uint32_t trap_count;
        uint32_t trap_resolved_count;
        std::chrono::system_clock::time_point timestamp;
    };
    std::vector<MetricsSnapshot> metrics_history;
    
public:
    // =================================================================
    // Constructor / Destructor
    // =================================================================
    
    QuadBufferOrchestrator() 
        : orchestrator_ctx(nullptr), running(false), total_layers(0),
          layer_size(0), phase2_context(nullptr), phase3_context(nullptr),
          phase4_context(nullptr), phase5_context(nullptr) {
        init_time = std::chrono::high_resolution_clock::now();
    }
    
    ~QuadBufferOrchestrator() {
        if (orchestrator_ctx) {
            Shutdown();
        }
    }
    
    // =================================================================
    // Lifecycle Management
    // =================================================================
    
    bool Initialize(
        const wchar_t* model_file_path,
        uint64_t layer_size_bytes,
        uint32_t num_layers,
        void* vram_base_address,
        void* phase2_ctx = nullptr,
        void* phase3_ctx = nullptr,
        void* phase4_ctx = nullptr,
        void* phase5_ctx = nullptr
    ) {
        // Store phase contexts for integration
        phase2_context = phase2_ctx;
        phase3_context = phase3_ctx;
        phase4_context = phase4_ctx;
        phase5_context = phase5_ctx;

        // Store metadata
        total_layers = num_layers;
        layer_size = layer_size_bytes;

        // Initialize real MASM quad-buffer system (16GB VRAM / 64GB RAM default)
        int64_t rc = QB_Init(17179869184ULL, 68719476736ULL);
        if (rc != 0) {
            return false;
        }

        // Load model file (auto-detect format)
        rc = QB_LoadModel(model_file_path, 0);
        if (rc != 0) {
            QB_Shutdown();
            return false;
        }

        // Initialize SPSC streaming ring (4 slots x 4MB)
        rc = SQB_Init(4, 4 * 1024 * 1024);
        if (rc != 0) {
            QB_Shutdown();
            return false;
        }

        orchestrator_ctx = reinterpret_cast<void*>(1); // Mark as initialized
        running = true;
        return true;
    }

    void Shutdown(void) {
        if (!running) return;
        running = false;

        SQB_Shutdown();
        QB_Shutdown();
        orchestrator_ctx = nullptr;
    }

    // =================================================================
    // Buffer Access Interface
    // =================================================================

    // Stream tensor by hash into destination buffer
    // Returns bytes streamed or negative error code
    int64_t StreamTensor(uint64_t tensor_hash, void* dest, uint64_t max_bytes, uint32_t timeout_ms = 0) {
        return QB_StreamTensor(tensor_hash, dest, max_bytes, timeout_ms);
    }

    // Release tensor reference (allows eviction)
    int64_t ReleaseTensor(uint64_t tensor_hash) {
        return QB_ReleaseTensor(tensor_hash);
    }

    // =================================================================
    // Phase Integration Helpers
    // =================================================================

    // Phase 2 Integration: Prefetch layer into slot via ASM prefetch kernel
    void Phase2_PrefetchLayer(void* tensor_data, uint32_t layer_id, uint32_t slot_index) {
        rawrxd_prefetch_tensor_async(tensor_data, layer_id, slot_index);
    }

    // Phase 3 Integration: Rotate buffer slots after compute completes
    uint64_t Phase3_RotateSlots(void* current_active, void* next_ready, uint64_t rdtsc_threshold) {
        return rawrxd_rotate_buffer_slots(current_active, next_ready, rdtsc_threshold);
    }

    // Phase 4 Integration: Force eviction if VRAM pressure
    int64_t Phase4_ForceEviction(uint64_t bytes_to_free) {
        return QB_ForceEviction(bytes_to_free);
    }

    // Phase 5 Integration: Report metrics to orchestrator
    void Phase5_ReportMetrics(void) {
        SnapshotMetrics();
    }

    // =================================================================
    // Status Queries
    // =================================================================

    // Get current buffer state from real QB engine
    struct BufferStatus {
        uint64_t used_vram;
        uint64_t used_ram;
        uint64_t cache_hits;
        uint64_t cache_misses;
        uint64_t evictions;
        uint64_t total_streamed;
        uint32_t tensor_count;
        uint32_t block_count;
        double efficiency_percent;
    };

    BufferStatus GetBufferStatus(void) {
        BufferStatus status = {};
        uint64_t stats[8] = {0};
        QB_GetStats(stats);
        status.used_vram        = stats[0];
        status.used_ram         = stats[1];
        status.cache_hits       = stats[2];
        status.cache_misses     = stats[3];
        status.evictions        = stats[4];
        status.total_streamed   = stats[5];
        status.tensor_count     = static_cast<uint32_t>(stats[6]);
        status.block_count      = static_cast<uint32_t>(stats[7]);

        uint64_t total = status.cache_hits + status.cache_misses;
        if (total > 0) {
            status.efficiency_percent = (status.cache_hits * 100.0) / total;
        }
        return status;
    }

    // =================================================================
    // Streaming Render Interface (SPSC Ring + GDI)
    // =================================================================

    HWND CreateRenderWindow(HWND parent, int32_t width, int32_t height, uint32_t child_id) {
        return SQB_CreateRenderWnd(parent, width, height, child_id);
    }

    int64_t PushRenderFrame(const void* data, uint64_t len) {
        return SQB_PushFrame(data, len);
    }

    int64_t GetFrameStats(uint64_t* out_stats) {
        return SQB_GetFrameStats(out_stats);
    }

    int64_t SetRenderFPS(uint32_t fps) {
        return SQB_SetTargetFPS(fps);
    }

    // =================================================================
    // Metrics Interface
    // =================================================================

    struct Metrics {
        uint64_t used_vram;
        uint64_t used_ram;
        uint64_t cache_hits;
        uint64_t cache_misses;
        uint64_t evictions;
        uint64_t total_streamed;
        uint64_t uptime_microseconds;
        double hit_rate_percent;
    };

    Metrics GetMetrics(void) {
        Metrics m = {};
        uint64_t stats[8] = {0};
        QB_GetStats(stats);
        m.used_vram      = stats[0];
        m.used_ram       = stats[1];
        m.cache_hits     = stats[2];
        m.cache_misses   = stats[3];
        m.evictions      = stats[4];
        m.total_streamed = stats[5];

        auto now = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            now - init_time);
        m.uptime_microseconds = elapsed.count();

        uint64_t total = m.cache_hits + m.cache_misses;
        if (total > 0) {
            m.hit_rate_percent = (m.cache_hits * 100.0) / total;
        }
        return m;
    }

    void ResetMetrics(void) {
        metrics_history.clear();
    }

    const std::vector<MetricsSnapshot>& GetMetricsHistory(void) const {
        return metrics_history;
    }

    // =================================================================
    // Diagnostics
    // =================================================================

    void PrintStatus(void) {
        auto status = GetBufferStatus();
        auto metrics = GetMetrics();

        printf("[QuadBuffer] Status:\n");
        printf("  VRAM: %llu / RAM: %llu\n", status.used_vram, status.used_ram);
        printf("  Tensors: %u  Blocks: %u\n", status.tensor_count, status.block_count);
        printf("  Hits: %llu  Misses: %llu  Evictions: %llu\n",
               metrics.cache_hits, metrics.cache_misses, metrics.evictions);
        printf("  Hit Rate: %.1f%%\n", metrics.hit_rate_percent);
        printf("  Total Streamed: %llu bytes\n", metrics.total_streamed);
        printf("  Uptime: %.2f seconds\n", metrics.uptime_microseconds / 1e6);
    }

private:
    // =================================================================
    // Metrics Snapshot
    // =================================================================

    void SnapshotMetrics(void) {
        MetricsSnapshot snap;
        uint64_t stats[8] = {0};
        QB_GetStats(stats);
        snap.hdd_read_bytes   = stats[5]; // total_streamed as proxy
        snap.dma_write_bytes  = stats[0]; // used_vram as proxy
        snap.stall_cycles     = stats[4]; // evictions as proxy
        snap.trap_count       = static_cast<uint32_t>(stats[3]); // misses as proxy
        snap.trap_resolved_count = static_cast<uint32_t>(stats[2]); // hits as proxy
        snap.timestamp = std::chrono::system_clock::now();

        metrics_history.push_back(snap);

        // Keep only last 1000 snapshots to avoid memory bloat
        if (metrics_history.size() > 1000) {
            metrics_history.erase(metrics_history.begin());
        }
    }
};

// =============================================================================
// GLOBAL INSTANCE & C WRAPPER FUNCTIONS
// =============================================================================

static QuadBufferOrchestrator* g_orchestrator = nullptr;

// C interface for system integration
extern "C" {

    void* QuadBuffer_Create(void) {
        if (!g_orchestrator) {
            g_orchestrator = new QuadBufferOrchestrator();
        }
        return g_orchestrator;
    }

    bool QuadBuffer_Initialize(
        void* handle,
        const wchar_t* model_file,
        uint64_t layer_size,
        uint32_t num_layers,
        void* vram_base,
        void* phase2_ctx,
        void* phase3_ctx,
        void* phase4_ctx,
        void* phase5_ctx
    ) {
        if (!handle) return false;
        auto* qb = static_cast<QuadBufferOrchestrator*>(handle);
        return qb->Initialize(model_file, layer_size, num_layers, vram_base,
                            phase2_ctx, phase3_ctx, phase4_ctx, phase5_ctx);
    }

    int64_t QuadBuffer_StreamTensor(void* handle, uint64_t tensor_hash, void* dest, uint64_t max_bytes, uint32_t timeout_ms) {
        if (!handle) return -1;
        auto* qb = static_cast<QuadBufferOrchestrator*>(handle);
        return qb->StreamTensor(tensor_hash, dest, max_bytes, timeout_ms);
    }

    int64_t QuadBuffer_ReleaseTensor(void* handle, uint64_t tensor_hash) {
        if (!handle) return -1;
        auto* qb = static_cast<QuadBufferOrchestrator*>(handle);
        return qb->ReleaseTensor(tensor_hash);
    }

    void QuadBuffer_PrefetchLayer(void* handle, void* tensor_data, uint32_t layer_id, uint32_t slot_index) {
        if (!handle) return;
        auto* qb = static_cast<QuadBufferOrchestrator*>(handle);
        qb->Phase2_PrefetchLayer(tensor_data, layer_id, slot_index);
    }

    uint64_t QuadBuffer_RotateSlots(void* handle, void* current_active, void* next_ready, uint64_t rdtsc_threshold) {
        if (!handle) return 0;
        auto* qb = static_cast<QuadBufferOrchestrator*>(handle);
        return qb->Phase3_RotateSlots(current_active, next_ready, rdtsc_threshold);
    }

    int64_t QuadBuffer_ForceEviction(void* handle, uint64_t bytes_to_free) {
        if (!handle) return -1;
        auto* qb = static_cast<QuadBufferOrchestrator*>(handle);
        return qb->Phase4_ForceEviction(bytes_to_free);
    }

    void QuadBuffer_ReportMetrics(void* handle) {
        if (!handle) return;
        auto* qb = static_cast<QuadBufferOrchestrator*>(handle);
        qb->Phase5_ReportMetrics();
    }

    void QuadBuffer_Destroy(void* handle) {
        if (!handle) return;
        auto* qb = static_cast<QuadBufferOrchestrator*>(handle);
        qb->Shutdown();
        delete qb;
        g_orchestrator = nullptr;
    }
}

