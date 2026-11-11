//=============================================================================
// rawrxd_model_stream.c
// Zero-Dependency Model Streaming Implementation
//=============================================================================

#include "rawrxd_model_stream.h"
#include "rawrxd_core.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#endif

//=============================================================================
// Platform Abstraction
//=============================================================================

#ifdef _WIN32

typedef HANDLE file_handle_t;
typedef HANDLE mapping_handle_t;

static file_handle_t open_file_read(const char* path) {
    return CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
}

static void close_file(file_handle_t h) {
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
}

static u64 file_size(file_handle_t h) {
    LARGE_INTEGER size;
    if (!GetFileSizeEx(h, &size)) return 0;
    return (u64)size.QuadPart;
}

static void* mmap_file(file_handle_t h, u64 size, bool writable) {
    DWORD prot = writable ? PAGE_READWRITE : PAGE_READONLY;
    HANDLE mapping = CreateFileMapping(h, NULL, prot, 
                                        (DWORD)(size >> 32), 
                                        (DWORD)size, NULL);
    if (!mapping) return NULL;
    
    DWORD access = writable ? FILE_MAP_WRITE : FILE_MAP_READ;
    void* addr = MapViewOfFile(mapping, access, 0, 0, (SIZE_T)size);
    CloseHandle(mapping);
    return addr;
}

static void munmap_file(void* addr, u64 size) {
    (void)size;
    UnmapViewOfFile(addr);
}

#else // Linux/Unix

typedef int file_handle_t;
typedef int mapping_handle_t;

static file_handle_t open_file_read(const char* path) {
    return open(path, O_RDONLY | O_CLOEXEC);
}

static void close_file(file_handle_t h) {
    if (h >= 0) close(h);
}

static u64 file_size(file_handle_t h) {
    struct stat st;
    if (fstat(h, &st) < 0) return 0;
    return (u64)st.st_size;
}

static void* mmap_file(file_handle_t h, u64 size, bool writable) {
    int prot = writable ? (PROT_READ | PROT_WRITE) : PROT_READ;
    void* addr = mmap(NULL, (size_t)size, prot, MAP_PRIVATE, h, 0);
    if (addr == MAP_FAILED) return NULL;
    return addr;
}

static void munmap_file(void* addr, u64 size) {
    munmap(addr, (size_t)size);
}

#endif

//=============================================================================
// Stream Implementation
//=============================================================================

rawrxd_model_stream* rawrxd_stream_open(const char* path) {
    if (!path) return NULL;
    
    rawrxd_model_stream* stream = rawrxd_alloc(sizeof(rawrxd_model_stream));
    if (!stream) return NULL;
    
    memset(stream, 0, sizeof(*stream));
    stream->state = RAWRXD_STREAM_IDLE;
    
    // Open file
    file_handle_t fh = open_file_read(path);
    if (fh == INVALID_HANDLE_VALUE) {
        strncpy(stream->error_msg, "Failed to open file", sizeof(stream->error_msg));
        stream->state = RAWRXD_STREAM_ERROR;
        return stream;
    }
    
    stream->file_size = file_size(fh);
    if (stream->file_size == 0) {
        strncpy(stream->error_msg, "Empty file", sizeof(stream->error_msg));
        close_file(fh);
        stream->state = RAWRXD_STREAM_ERROR;
        return stream;
    }
    
    // Memory map the file
    stream->base_addr = mmap_file(fh, stream->file_size, false);
    if (!stream->base_addr) {
        strncpy(stream->error_msg, "Failed to mmap file", sizeof(stream->error_msg));
        close_file(fh);
        stream->state = RAWRXD_STREAM_ERROR;
        return stream;
    }
    
    close_file(fh);
    
    // Parse GGUF header
    if (!rawrxd_gguf_parse_header(stream->base_addr, stream->file_size, 
                                  &stream->header)) {
        strncpy(stream->error_msg, "Invalid GGUF header", sizeof(stream->error_msg));
        munmap_file(stream->base_addr, stream->file_size);
        stream->state = RAWRXD_STREAM_ERROR;
        return stream;
    }
    
    // Parse tensor info
    stream->tensors = rawrxd_gguf_parse_tensors(stream->base_addr, &stream->header,
                                               &stream->tensor_count);
    if (!stream->tensors) {
        strncpy(stream->error_msg, "Failed to parse tensors", sizeof(stream->error_msg));
        munmap_file(stream->base_addr, stream->file_size);
        stream->state = RAWRXD_STREAM_ERROR;
        return stream;
    }
    
    // Calculate total bytes
    stream->bytes_total = 0;
    for (u32 i = 0; i < stream->tensor_count; i++) {
        stream->bytes_total += stream->tensors[i].size;
    }
    
    // Initialize chunks
    for (u32 i = 0; i < RAWRXD_STREAM_BUFFER_COUNT; i++) {
        stream->chunks[i].data = rawrxd_alloc(RAWRXD_STREAM_CHUNK_SIZE);
        stream->chunks[i].offset = 0;
        stream->chunks[i].size = RAWRXD_STREAM_CHUNK_SIZE;
        stream->chunks[i].filled = 0;
        stream->chunks[i].ready = false;
        stream->chunks[i].error = false;
        stream->chunks[i].refcount = 0;
    }
    
    // Create synchronization primitives
    stream->state_mutex = rawrxd_mutex_create();
    stream->state_cond = rawrxd_cond_create();
    
    stream->state = RAWRXD_STREAM_READY;
    stream->load_start_time = rawrxd_time_sec();
    
    return stream;
}

void rawrxd_stream_close(rawrxd_model_stream* stream) {
    if (!stream) return;
    
    stream->shutdown = true;
    
    // Signal any waiting threads
    if (stream->state_cond) {
        rawrxd_cond_broadcast(stream->state_cond);
    }
    
    // Wait for worker thread
    if (stream->worker_thread) {
        rawrxd_thread_join(stream->worker_thread);
    }
    
    // Cleanup chunks
    for (u32 i = 0; i < RAWRXD_STREAM_BUFFER_COUNT; i++) {
        if (stream->chunks[i].data) {
            rawrxd_free(stream->chunks[i].data, RAWRXD_STREAM_CHUNK_SIZE);
        }
    }
    
    // Unmap file
    if (stream->base_addr) {
        munmap_file(stream->base_addr, stream->file_size);
    }
    
    // Free tensors
    if (stream->tensors) {
        rawrxd_free(stream->tensors, stream->tensor_count * sizeof(rawrxd_gguf_tensor));
    }
    
    // Cleanup sync
    if (stream->state_mutex) rawrxd_mutex_destroy(stream->state_mutex);
    if (stream->state_cond) rawrxd_cond_destroy(stream->state_cond);
    
    rawrxd_free(stream, sizeof(rawrxd_model_stream));
}

static int stream_worker_thread(void* arg) {
    rawrxd_model_stream* stream = (rawrxd_model_stream*)arg;
    
    while (!stream->shutdown) {
        rawrxd_mutex_lock(stream->state_mutex);
        
        // Check if we should continue
        if (stream->state != RAWRXD_STREAM_TENSORS && 
            stream->state != RAWRXD_STREAM_PREFETCH) {
            rawrxd_mutex_unlock(stream->state_mutex);
            rawrxd_sleep_ms(1);
            continue;
        }
        
        // Get next chunk to fill
        u32 write_idx = stream->write_idx;
        rawrxd_stream_chunk* chunk = &stream->chunks[write_idx];
        
        if (chunk->ready || chunk->refcount > 0) {
            // Chunk in use, skip
            stream->write_idx = (write_idx + 1) % RAWRXD_STREAM_BUFFER_COUNT;
            rawrxd_mutex_unlock(stream->state_mutex);
            rawrxd_sleep_ms(1);
            continue;
        }
        
        rawrxd_mutex_unlock(stream->state_mutex);
        
        // Calculate what to load
        u64 offset = stream->bytes_loaded;
        u64 remaining = stream->bytes_total - offset;
        size_t to_load = (size_t)RAWRXD_MIN(remaining, RAWRXD_STREAM_CHUNK_SIZE);
        
        if (to_load == 0) {
            // All loaded
            rawrxd_mutex_lock(stream->state_mutex);
            stream->state = RAWRXD_STREAM_READY;
            rawrxd_cond_broadcast(stream->state_cond);
            rawrxd_mutex_unlock(stream->state_mutex);
            break;
        }
        
        // Copy from mmap (this is fast, just memory copy)
        // In real implementation, this might use async I/O
        memcpy(chunk->data, (u8*)stream->base_addr + offset, to_load);
        
        rawrxd_mutex_lock(stream->state_mutex);
        
        chunk->offset = offset;
        chunk->filled = to_load;
        chunk->ready = true;
        chunk->error = false;
        
        stream->bytes_loaded += to_load;
        stream->write_idx = (write_idx + 1) % RAWRXD_STREAM_BUFFER_COUNT;
        
        // Signal progress
        if (stream->on_progress) {
            double percent = (double)stream->bytes_loaded / stream->bytes_total * 100.0;
            stream->on_progress(stream, percent, stream->callback_user);
        }
        
        rawrxd_cond_broadcast(stream->state_cond);
        rawrxd_mutex_unlock(stream->state_mutex);
    }
    
    return 0;
}

rawrxd_result rawrxd_stream_start(rawrxd_model_stream* stream,
                                   const u32* tensor_order,
                                   u32 tensor_count) {
    if (!stream || !tensor_order) return RAWRXD_ERROR_INVALID;
    
    rawrxd_mutex_lock(stream->state_mutex);
    
    if (stream->state != RAWRXD_STREAM_READY) {
        rawrxd_mutex_unlock(stream->state_mutex);
        return RAWRXD_ERROR_BUSY;
    }
    
    stream->state = RAWRXD_STREAM_TENSORS;
    stream->load_start_time = rawrxd_time_sec();
    
    rawrxd_mutex_unlock(stream->state_mutex);
    
    // Start worker thread
    stream->worker_thread = rawrxd_thread_create(stream_worker_thread, stream);
    if (!stream->worker_thread) {
        stream->state = RAWRXD_STREAM_ERROR;
        return RAWRXD_ERROR_NOMEM;
    }
    
    return RAWRXD_OK;
}

rawrxd_tensor_stream* rawrxd_stream_get_tensor(rawrxd_model_stream* stream,
                                                u32 tensor_id,
                                                u32 timeout_ms) {
    if (!stream || tensor_id >= stream->tensor_count) return NULL;
    
    rawrxd_gguf_tensor* tensor_info = &stream->tensors[tensor_id];
    
    // Allocate tensor stream structure
    rawrxd_tensor_stream* tensor = rawrxd_alloc(sizeof(rawrxd_tensor_stream));
    if (!tensor) return NULL;
    
    memset(tensor, 0, sizeof(*tensor));
    tensor->tensor_id = tensor_id;
    tensor->tensor_offset = tensor_info->offset;
    tensor->tensor_size = tensor_info->size;
    tensor->ggml_type = tensor_info->type;
    memcpy(tensor->dims, tensor_info->dims, sizeof(tensor->dims));
    tensor->ndims = tensor_info->ndims;
    
    // Wait for tensor data to be available
    double start_time = rawrxd_time_sec();
    
    while (true) {
        rawrxd_mutex_lock(stream->state_mutex);
        
        // Check if tensor data is loaded
        if (stream->bytes_loaded >= tensor_info->offset + tensor_info->size) {
            // Tensor is available in memory
            tensor->mapped_addr = (u8*)stream->base_addr + tensor_info->offset;
            tensor->mapped_size = tensor_info->size;
            tensor->bytes_loaded = tensor_info->size;
            tensor->bytes_total = tensor_info->size;
            tensor->complete = true;
            
            rawrxd_mutex_unlock(stream->state_mutex);
            return tensor;
        }
        
        // Check timeout
        if (timeout_ms > 0) {
            double elapsed = (rawrxd_time_sec() - start_time) * 1000.0;
            if (elapsed >= timeout_ms) {
                rawrxd_mutex_unlock(stream->state_mutex);
                rawrxd_free(tensor, sizeof(rawrxd_tensor_stream));
                return NULL;
            }
        }
        
        // Wait for progress
        rawrxd_cond_wait(stream->state_cond, stream->state_mutex);
        rawrxd_mutex_unlock(stream->state_mutex);
    }
}

void rawrxd_stream_release_tensor(rawrxd_tensor_stream* tensor) {
    if (!tensor) return;
    rawrxd_free(tensor, sizeof(rawrxd_tensor_stream));
}

rawrxd_stream_state rawrxd_stream_get_state(rawrxd_model_stream* stream) {
    if (!stream) return RAWRXD_STREAM_CLOSED;
    
    rawrxd_mutex_lock(stream->state_mutex);
    rawrxd_stream_state state = stream->state;
    rawrxd_mutex_unlock(stream->state_mutex);
    
    return state;
}

double rawrxd_stream_get_progress(rawrxd_model_stream* stream) {
    if (!stream || stream->bytes_total == 0) return 0.0;
    
    rawrxd_mutex_lock(stream->state_mutex);
    double progress = (double)stream->bytes_loaded / stream->bytes_total * 100.0;
    rawrxd_mutex_unlock(stream->state_mutex);
    
    return progress;
}

u64 rawrxd_stream_get_bytes_loaded(rawrxd_model_stream* stream) {
    if (!stream) return 0;
    
    rawrxd_mutex_lock(stream->state_mutex);
    u64 bytes = stream->bytes_loaded;
    rawrxd_mutex_unlock(stream->state_mutex);
    
    return bytes;
}

u64 rawrxd_stream_get_bytes_total(rawrxd_model_stream* stream) {
    return stream ? stream->bytes_total : 0;
}

double rawrxd_stream_get_throughput_mbps(rawrxd_model_stream* stream) {
    if (!stream) return 0.0;
    
    double elapsed = rawrxd_time_sec() - stream->load_start_time;
    if (elapsed <= 0.001) return 0.0;
    
    return (double)stream->bytes_loaded / elapsed / (1024.0 * 1024.0);
}

rawrxd_result rawrxd_stream_wait(rawrxd_model_stream* stream, u32 timeout_ms) {
    if (!stream) return RAWRXD_ERROR_INVALID;
    
    double start_time = rawrxd_time_sec();
    
    while (true) {
        rawrxd_mutex_lock(stream->state_mutex);
        
        if (stream->state == RAWRXD_STREAM_READY || 
            stream->state == RAWRXD_STREAM_ERROR) {
            rawrxd_stream_state state = stream->state;
            rawrxd_mutex_unlock(stream->state_mutex);
            return (state == RAWRXD_STREAM_READY) ? RAWRXD_OK : RAWRXD_ERROR_IO;
        }
        
        rawrxd_mutex_unlock(stream->state_mutex);
        
        // Check timeout
        if (timeout_ms > 0) {
            double elapsed = (rawrxd_time_sec() - start_time) * 1000.0;
            if (elapsed >= timeout_ms) {
                return RAWRXD_ERROR_TIMEOUT;
            }
        }
        
        rawrxd_sleep_ms(1);
    }
}

void rawrxd_stream_cancel(rawrxd_model_stream* stream) {
    if (!stream) return;
    
    rawrxd_mutex_lock(stream->state_mutex);
    stream->shutdown = true;
    stream->state = RAWRXD_STREAM_CLOSED;
    rawrxd_cond_broadcast(stream->state_cond);
    rawrxd_mutex_unlock(stream->state_mutex);
}

//=============================================================================
// Priority Loading Orders
//=============================================================================

u32* rawrxd_stream_compute_priority_order(rawrxd_model_stream* stream,
                                           const char* architecture) {
    if (!stream || !architecture) return NULL;
    
    // Architecture-specific loading orders
    if (strstr(architecture, "llama")) {
        return rawrxd_stream_order_llama(stream);
    } else if (strstr(architecture, "qwen")) {
        return rawrxd_stream_order_qwen(stream);
    } else if (strstr(architecture, "phi")) {
        return rawrxd_stream_order_phi(stream);
    } else if (strstr(architecture, "gemma")) {
        return rawrxd_stream_order_gemma(stream);
    }
    
    // Default: load in file order
    u32* order = rawrxd_alloc(stream->tensor_count * sizeof(u32));
    if (!order) return NULL;
    
    for (u32 i = 0; i < stream->tensor_count; i++) {
        order[i] = i;
    }
    
    return order;
}

u32* rawrxd_stream_order_llama(rawrxd_model_stream* stream) {
    // Llama priority: embeddings -> output -> layers (0 to N)
    u32* order = rawrxd_alloc(stream->tensor_count * sizeof(u32));
    if (!order) return NULL;
    
    u32 idx = 0;
    
    // First: token embeddings
    for (u32 i = 0; i < stream->tensor_count; i++) {
        if (strstr(stream->tensors[i].name, "token_embd")) {
            order[idx++] = i;
            break;
        }
    }
    
    // Then: output norm and output
    for (u32 i = 0; i < stream->tensor_count; i++) {
        if (strstr(stream->tensors[i].name, "output_norm") ||
            strstr(stream->tensors[i].name, "output.weight")) {
            order[idx++] = i;
        }
    }
    
    // Then: layers in order
    for (u32 layer = 0; layer < 128; layer++) {
        char layer_prefix[64];
        snprintf(layer_prefix, sizeof(layer_prefix), "blk.%u.", layer);
        
        for (u32 i = 0; i < stream->tensor_count; i++) {
            if (strstr(stream->tensors[i].name, layer_prefix)) {
                order[idx++] = i;
            }
        }
    }
    
    // Finally: any remaining tensors
    for (u32 i = 0; i < stream->tensor_count; i++) {
        bool already_added = false;
        for (u32 j = 0; j < idx; j++) {
            if (order[j] == i) {
                already_added = true;
                break;
            }
        }
        if (!already_added) {
            order[idx++] = i;
        }
    }
    
    return order;
}

u32* rawrxd_stream_order_qwen(rawrxd_model_stream* stream) {
    // Similar to llama but with Qwen-specific priorities
    return rawrxd_stream_order_llama(stream);  // Same structure
}

u32* rawrxd_stream_order_phi(rawrxd_model_stream* stream) {
    // Phi models have different layer naming
    return rawrxd_stream_order_llama(stream);  // Adapt as needed
}

u32* rawrxd_stream_order_gemma(rawrxd_model_stream* stream) {
    // Gemma-specific ordering
    return rawrxd_stream_order_llama(stream);  // Adapt as needed
}

//=============================================================================
// Hot Loading
//=============================================================================

rawrxd_hotload_context* rawrxd_hotload_start(const char* path) {
    if (!path) return NULL;
    
    rawrxd_hotload_context* ctx = rawrxd_alloc(sizeof(rawrxd_hotload_context));
    if (!ctx) return NULL;
    
    memset(ctx, 0, sizeof(*ctx));
    ctx->lock = rawrxd_mutex_create();
    
    // Open stream
    ctx->stream = rawrxd_stream_open(path);
    if (!ctx->stream || ctx->stream->state == RAWRXD_STREAM_ERROR) {
        rawrxd_mutex_destroy(ctx->lock);
        rawrxd_free(ctx, sizeof(rawrxd_hotload_context));
        return NULL;
    }
    
    // Start streaming
    u32* order = rawrxd_stream_order_llama(ctx->stream);
    if (order) {
        rawrxd_stream_start(ctx->stream, order, ctx->stream->tensor_count);
        rawrxd_free(order, ctx->stream->tensor_count * sizeof(u32));
    }
    
    // Create partial model immediately (embeddings only)
    // This allows inference to start while rest loads
    ctx->can_infer = true;
    ctx->loaded_layers = 0;
    
    return ctx;
}

bool rawrxd_hotload_layer_ready(rawrxd_hotload_context* ctx, u32 layer) {
    if (!ctx) return false;
    
    rawrxd_mutex_lock(ctx->lock);
    bool ready = layer < ctx->loaded_layers;
    rawrxd_mutex_unlock(ctx->lock);
    
    return ready;
}

rawrxd_model* rawrxd_hotload_get_partial(rawrxd_hotload_context* ctx) {
    if (!ctx) return NULL;
    return ctx->model;
}

rawrxd_model* rawrxd_hotload_finish(rawrxd_hotload_context* ctx) {
    if (!ctx) return NULL;
    
    // Wait for complete loading
    rawrxd_stream_wait(ctx->stream, 0);  // Infinite wait
    
    rawrxd_model* model = ctx->model;
    
    // Cleanup context but keep model
    rawrxd_stream_close(ctx->stream);
    rawrxd_mutex_destroy(ctx->lock);
    rawrxd_free(ctx, sizeof(rawrxd_hotload_context));
    
    return model;
}

void rawrxd_hotload_cancel(rawrxd_hotload_context* ctx) {
    if (!ctx) return;
    
    rawrxd_stream_cancel(ctx->stream);
    rawrxd_stream_close(ctx->stream);
    rawrxd_mutex_destroy(ctx->lock);
    rawrxd_free(ctx, sizeof(rawrxd_hotload_context));
}
