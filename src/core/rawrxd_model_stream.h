//=============================================================================
// rawrxd_model_stream.h
// Zero-Dependency Model Streaming System
// Memory-mapped, chunked, resumable model loading
//=============================================================================
#pragma once

#include "rawrxd_core.h"

#ifdef __cplusplus
extern "C" {
#endif

//=============================================================================
// Streaming Configuration
//=============================================================================

#define RAWRXD_STREAM_CHUNK_SIZE (64 * 1024 * 1024)  // 64MB chunks
#define RAWRXD_STREAM_MAX_CONCURRENT 4
#define RAWRXD_STREAM_PREFETCH_AHEAD 2
#define RAWRXD_STREAM_BUFFER_COUNT 3

//=============================================================================
// Stream State
//=============================================================================

typedef enum {
    RAWRXD_STREAM_IDLE = 0,
    RAWRXD_STREAM_OPENING,
    RAWRXD_STREAM_METADATA,
    RAWRXD_STREAM_TENSORS,
    RAWRXD_STREAM_PREFETCH,
    RAWRXD_STREAM_READY,
    RAWRXD_STREAM_ERROR,
    RAWRXD_STREAM_CLOSED
} rawrxd_stream_state;

typedef enum {
    RAWRXD_PRIORITY_CRITICAL = 0,  // Token embeddings, first layer
    RAWRXD_PRIORITY_HIGH = 1,      // Early layers
    RAWRXD_PRIORITY_NORMAL = 2,    // Middle layers
    RAWRXD_PRIORITY_LOW = 3,       // Late layers
    RAWRXD_PRIORITY_BACKGROUND = 4 // Optional tensors
} rawrxd_tensor_priority;

//=============================================================================
// Stream Context
//=============================================================================

typedef struct rawrxd_stream_chunk {
    u8* data;
    size_t offset;
    size_t size;
    size_t filled;
    bool ready;
    bool error;
    u32 refcount;
} rawrxd_stream_chunk;

typedef struct rawrxd_tensor_stream {
    // Tensor info
    u32 tensor_id;
    rawrxd_tensor_priority priority;
    u64 tensor_offset;
    u64 tensor_size;
    u32 ggml_type;
    u32 dims[4];
    u32 ndims;
    
    // Streaming state
    u64 bytes_loaded;
    u64 bytes_total;
    bool complete;
    bool error;
    u32 error_code;
    
    // Memory
    void* mapped_addr;
    size_t mapped_size;
    
    // Callback
    void (*on_progress)(struct rawrxd_tensor_stream* stream, void* user);
    void* user_data;
} rawrxd_tensor_stream;

typedef struct rawrxd_model_stream {
    // File handle
    void* file_handle;
    void* file_mapping;
    void* base_addr;
    u64 file_size;
    
    // GGUF metadata
    rawrxd_gguf_header header;
    rawrxd_gguf_tensor* tensors;
    u32 tensor_count;
    rawrxd_strmap* metadata;
    
    // Streaming state
    rawrxd_stream_state state;
    u32 active_streams;
    u32 completed_streams;
    u32 error_count;
    
    // Chunk ring buffer
    rawrxd_stream_chunk chunks[RAWRXD_STREAM_BUFFER_COUNT];
    u32 read_idx;
    u32 write_idx;
    
    // Async I/O
    void* io_context;      // Platform-specific
    void* io_events[8];
    u32 pending_ops;
    
    // Threading
    rawrxd_thread* worker_thread;
    rawrxd_mutex* state_mutex;
    rawrxd_cond* state_cond;
    volatile bool shutdown;
    
    // Progress
    u64 bytes_loaded;
    u64 bytes_total;
    double load_start_time;
    double last_progress_time;
    
    // Callbacks
    void (*on_tensor_loaded)(struct rawrxd_model_stream* stream, u32 tensor_id, void* user);
    void (*on_progress)(struct rawrxd_model_stream* stream, double percent, void* user);
    void (*on_complete)(struct rawrxd_model_stream* stream, bool success, void* user);
    void* callback_user;
    
    // Error info
    char error_msg[256];
} rawrxd_model_stream;

//=============================================================================
// Stream API
//=============================================================================

// Open model for streaming
RAWRXD_EXPORT rawrxd_model_stream* rawrxd_stream_open(const char* path);

// Close and cleanup
RAWRXD_EXPORT void rawrxd_stream_close(rawrxd_model_stream* stream);

// Start streaming with priority order
RAWRXD_EXPORT rawrxd_result rawrxd_stream_start(rawrxd_model_stream* stream, 
                                                const u32* tensor_order,
                                                u32 tensor_count);

// Pause/resume streaming
RAWRXD_EXPORT void rawrxd_stream_pause(rawrxd_model_stream* stream);
RAWRXD_EXPORT void rawrxd_stream_resume(rawrxd_model_stream* stream);

// Get tensor when ready (blocking with timeout)
RAWRXD_EXPORT rawrxd_tensor_stream* rawrxd_stream_get_tensor(rawrxd_model_stream* stream,
                                                              u32 tensor_id,
                                                              u32 timeout_ms);

// Release tensor reference
RAWRXD_EXPORT void rawrxd_stream_release_tensor(rawrxd_tensor_stream* tensor);

// Query state
RAWRXD_EXPORT rawrxd_stream_state rawrxd_stream_get_state(rawrxd_model_stream* stream);
RAWRXD_EXPORT double rawrxd_stream_get_progress(rawrxd_model_stream* stream);
RAWRXD_EXPORT u64 rawrxd_stream_get_bytes_loaded(rawrxd_model_stream* stream);
RAWRXD_EXPORT u64 rawrxd_stream_get_bytes_total(rawrxd_model_stream* stream);
RAWRXD_EXPORT double rawrxd_stream_get_throughput_mbps(rawrxd_model_stream* stream);

// Wait for completion
RAWRXD_EXPORT rawrxd_result rawrxd_stream_wait(rawrxd_model_stream* stream, u32 timeout_ms);

// Cancel streaming
RAWRXD_EXPORT void rawrxd_stream_cancel(rawrxd_model_stream* stream);

//=============================================================================
// Memory-Mapped I/O
//=============================================================================

// Platform-agnostic mmap
RAWRXD_EXPORT void* rawrxd_mmap_file(const char* path, u64* size, bool writable);
RAWRXD_EXPORT void rawrxd_munmap_file(void* addr, u64 size);
RAWRXD_EXPORT void* rawrxd_mmap_anon(u64 size);

// Prefetch hints
RAWRXD_EXPORT void rawrxd_prefetch(void* addr, u64 size);
RAWRXD_EXPORT void rawrxd_madvise_sequential(void* addr, u64 size);
RAWRXD_EXPORT void rawrxd_madvise_random(void* addr, u64 size);
RAWRXD_EXPORT void rawrxd_madvise_willneed(void* addr, u64 size);
RAWRXD_EXPORT void rawrxd_madvise_dontneed(void* addr, u64 size);

//=============================================================================
// Async I/O (Windows: IOCP, Linux: io_uring)
//=============================================================================

typedef struct rawrxd_aiocb {
    void* buffer;
    u64 offset;
    u32 size;
    u32 completed;
    u32 error;
    void* user_data;
} rawrxd_aiocb;

typedef struct rawrxd_aio_context {
    void* handle;
    rawrxd_aiocb** pending;
    u32 pending_count;
    u32 max_pending;
} rawrxd_aio_context;

RAWRXD_EXPORT rawrxd_aio_context* rawrxd_aio_create(void* file_handle);
RAWRXD_EXPORT void rawrxd_aio_destroy(rawrxd_aio_context* ctx);
RAWRXD_EXPORT rawrxd_result rawrxd_aio_submit_read(rawrxd_aio_context* ctx,
                                                     void* buffer,
                                                     u64 offset,
                                                     u32 size,
                                                     void* user_data);
RAWRXD_EXPORT i32 rawrxd_aio_poll(rawrxd_aio_context* ctx, u32 timeout_ms);
RAWRXD_EXPORT rawrxd_result rawrxd_aio_wait(rawrxd_aio_context* ctx, 
                                            rawrxd_aiocb** completed,
                                            u32* count,
                                            u32 timeout_ms);

//=============================================================================
// Tensor Priority Loading
//=============================================================================

// Priority-based tensor loading order
RAWRXD_EXPORT u32* rawrxd_stream_compute_priority_order(rawrxd_model_stream* stream,
                                                         const char* architecture);

// Common architectures
RAWRXD_EXPORT u32* rawrxd_stream_order_llama(rawrxd_model_stream* stream);
RAWRXD_EXPORT u32* rawrxd_stream_order_qwen(rawrxd_model_stream* stream);
RAWRXD_EXPORT u32* rawrxd_stream_order_phi(rawrxd_model_stream* stream);
RAWRXD_EXPORT u32* rawrxd_stream_order_gemma(rawrxd_model_stream* stream);

// Custom layer-wise loading
RAWRXD_EXPORT u32* rawrxd_stream_order_layers_first(rawrxd_model_stream* stream,
                                                     u32 n_layers);
RAWRXD_EXPORT u32* rawrxd_stream_order_embeddings_first(rawrxd_model_stream* stream);

//=============================================================================
// Resumable Loading
//=============================================================================

typedef struct rawrxd_stream_checkpoint {
    char model_path[512];
    u64 bytes_loaded;
    u32 tensors_complete;
    double timestamp;
    u8 hash[32];  // SHA256 of loaded portion
} rawrxd_stream_checkpoint;

// Save/load checkpoints
RAWRXD_EXPORT rawrxd_result rawrxd_stream_save_checkpoint(rawrxd_model_stream* stream,
                                                          const char* path);
RAWRXD_EXPORT rawrxd_result rawrxd_stream_load_checkpoint(rawrxd_model_stream* stream,
                                                          const char* path);

// Resume from checkpoint
RAWRXD_EXPORT rawrxd_model_stream* rawrxd_stream_resume(const char* model_path,
                                                         const char* checkpoint_path);

//=============================================================================
// Bandwidth Adaptation
//=============================================================================

typedef struct rawrxd_bandwidth_estimator {
    double samples[16];
    u32 sample_count;
    u32 sample_idx;
    double smoothed_mbps;
    double variance;
} rawrxd_bandwidth_estimator;

RAWRXD_EXPORT void rawrxd_bw_init(rawrxd_bandwidth_estimator* est);
RAWRXD_EXPORT void rawrxd_bw_sample(rawrxd_bandwidth_estimator* est, 
                                     u64 bytes, double seconds);
RAWRXD_EXPORT double rawrxd_bw_estimate(rawrxd_bandwidth_estimator* est);
RAWRXD_EXPORT u32 rawrxd_bw_optimal_chunk_size(rawrxd_bandwidth_estimator* est);

//=============================================================================
// Hot-Loading (Load while inferring)
//=============================================================================

typedef struct rawrxd_hotload_context {
    rawrxd_model_stream* stream;
    rawrxd_model* model;
    u32 loaded_layers;
    u32 total_layers;
    volatile bool can_infer;
    rawrxd_mutex* lock;
} rawrxd_hotload_context;

// Start hot-loading (returns immediately, loads in background)
RAWRXD_EXPORT rawrxd_hotload_context* rawrxd_hotload_start(const char* path);

// Check if layer is ready
RAWRXD_EXPORT bool rawrxd_hotload_layer_ready(rawrxd_hotload_context* ctx, u32 layer);

// Wait for layer
RAWRXD_EXPORT rawrxd_result rawrxd_hotload_wait_layer(rawrxd_hotload_context* ctx, 
                                                       u32 layer,
                                                       u32 timeout_ms);

// Get partial model (for inference during loading)
RAWRXD_EXPORT rawrxd_model* rawrxd_hotload_get_partial(rawrxd_hotload_context* ctx);

// Complete loading
RAWRXD_EXPORT rawrxd_model* rawrxd_hotload_finish(rawrxd_hotload_context* ctx);

// Cancel hot-loading
RAWRXD_EXPORT void rawrxd_hotload_cancel(rawrxd_hotload_context* ctx);

#ifdef __cplusplus
}
#endif
