//==============================================================================
// ModelDownloadSubsystem.h - Phase 15B: Auto-Download + HuggingFace Integration
//
// Self-expanding model ecosystem:
// - Download GGUF files from HuggingFace / direct URLs
// - Resume partial downloads
// - Verify SHA256 checksums
// - Auto-detect quantization format
// - Install into registry with one click
// - Real-time progress reporting
//==============================================================================

#ifndef MODEL_DOWNLOAD_SUBSYSTEM_H
#define MODEL_DOWNLOAD_SUBSYSTEM_H

#include <windows.h>
#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
// Constants
//==============================================================================

#define DOWNLOAD_SUBSYSTEM_VERSION "15.1.0"
#define MAX_DOWNLOAD_URL 2048
#define MAX_DOWNLOAD_PATH 512
#define MAX_HF_MODEL_ID 256
#define DOWNLOAD_CHUNK_SIZE 8192
#define DOWNLOAD_PROGRESS_INTERVAL_MS 100
#define MAX_CONCURRENT_DOWNLOADS 4

// Download states
#define DOWNLOAD_STATE_IDLE       0
#define DOWNLOAD_STATE_PENDING    1
#define DOWNLOAD_STATE_DOWNLOADING 2
#define DOWNLOAD_STATE_PAUSED     3
#define DOWNLOAD_STATE_COMPLETED  4
#define DOWNLOAD_STATE_FAILED     5
#define DOWNLOAD_STATE_VERIFYING  6

//==============================================================================
// Download Configuration
//==============================================================================

typedef struct DownloadConfig {
    char url[MAX_DOWNLOAD_URL];           // Direct URL or HuggingFace model ID
    char output_path[MAX_DOWNLOAD_PATH];  // Where to save
    char expected_sha256[65];             // Optional SHA256 for verification
    char model_name[MAX_HF_MODEL_ID];     // Display name
    char backend_type[32];                // "native", "ollama", etc.
    unsigned int capabilities;            // Model capabilities bitmask
    int auto_install;                     // Auto-add to registry after download
    int resume_if_partial;              // Resume partial downloads
    int use_hf_hub;                       // Use HuggingFace Hub API
    char hf_token[256];                   // Optional HF auth token
} DownloadConfig;

//==============================================================================
// Download Progress
//==============================================================================

typedef struct DownloadProgress {
    int download_id;                      // Unique download ID
    int state;                            // Current state
    uint64_t bytes_downloaded;            // Bytes so far
    uint64_t bytes_total;                 // Total size (0 if unknown)
    uint64_t bytes_per_second;            // Current speed
    int percent_complete;                 // 0-100
    char status_message[256];             // Human-readable status
    uint64_t start_time_ms;               // When download started
    uint64_t eta_ms;                      // Estimated time remaining
} DownloadProgress;

//==============================================================================
// Download Callback
//==============================================================================

typedef void (*DownloadProgressCallback)(const DownloadProgress* progress, void* user_data);
typedef void (*DownloadCompleteCallback)(int download_id, int success, const char* error_message, void* user_data);

//==============================================================================
// Subsystem Lifecycle
//==============================================================================

// Initialize download subsystem
int ModelDownload_Init(const char* models_directory);

// Shutdown download subsystem
int ModelDownload_Shutdown(void);

// Check if subsystem is ready
int ModelDownload_IsReady(void);

//==============================================================================
// Download Operations
//==============================================================================

// Start a new download
// Returns download ID (>0) on success, negative error code on failure
int ModelDownload_Start(const DownloadConfig* config);

// Start download from HuggingFace Hub
// model_id format: "organization/model-name" or "organization/model-name:file.gguf"
int ModelDownload_StartFromHuggingFace(const char* model_id, const char* output_dir, 
                                        const DownloadConfig* extra_config);

// Pause a download
int ModelDownload_Pause(int download_id);

// Resume a paused download
int ModelDownload_Resume(int download_id);

// Cancel a download
int ModelDownload_Cancel(int download_id);

// Get current progress
int ModelDownload_GetProgress(int download_id, DownloadProgress* out_progress);

// Set progress callback for a download
int ModelDownload_SetProgressCallback(int download_id, DownloadProgressCallback callback, void* user_data);

// Set completion callback
int ModelDownload_SetCompleteCallback(int download_id, DownloadCompleteCallback callback, void* user_data);

//==============================================================================
// Batch Operations
//==============================================================================

// Download multiple models sequentially
int ModelDownload_StartBatch(const DownloadConfig* configs, int count);

// Get status of all active downloads
int ModelDownload_ListActive(int* out_ids, int max_ids, int* out_count);

// Cancel all downloads
int ModelDownload_CancelAll(void);

//==============================================================================
// Verification & Installation
//==============================================================================

// Verify downloaded file against SHA256
int ModelDownload_VerifySHA256(const char* file_path, const char* expected_hash);

// Calculate SHA256 of file
int ModelDownload_CalculateSHA256(const char* file_path, char* out_hash, size_t hash_size);

// Install downloaded model into registry
// Auto-detects quantization, parameters, etc.
int ModelDownload_InstallToRegistry(const char* file_path, const char* model_name, 
                                     const char* backend_type, unsigned int capabilities);

// Auto-install after download completes
int ModelDownload_EnableAutoInstall(int download_id);

//==============================================================================
// HuggingFace Hub Integration
//==============================================================================

// Resolve HuggingFace model ID to direct download URL
// Supports formats: "org/model", "org/model:file.gguf", "org/model@revision"
int ModelDownload_ResolveHFUrl(const char* model_id, char* out_url, size_t url_size);

// List available GGUF files for a HuggingFace model
// Returns array of filenames
int ModelDownload_ListHFFiles(const char* model_id, char** out_files, int max_files, int* out_count);

// Get model info from HuggingFace Hub
int ModelDownload_GetHFModelInfo(const char* model_id, char* out_info_json, size_t info_size);

//==============================================================================
// Utility Functions
//==============================================================================

// Format bytes to human readable string (e.g., "1.5 GB")
void ModelDownload_FormatBytes(uint64_t bytes, char* out_str, size_t str_size);

// Format speed to human readable string (e.g., "45.2 MB/s")
void ModelDownload_FormatSpeed(uint64_t bytes_per_sec, char* out_str, size_t str_size);

// Format duration to human readable string (e.g., "2m 30s")
void ModelDownload_FormatDuration(uint64_t ms, char* out_str, size_t str_size);

// Get default models directory
const char* ModelDownload_GetDefaultDirectory(void);

// Set download speed limit (bytes/sec, 0 = unlimited)
int ModelDownload_SetSpeedLimit(uint64_t bytes_per_sec);

// Get last error message
const char* ModelDownload_GetLastError(void);

//==============================================================================
// Event Types (for ExecutionJournal integration)
//==============================================================================

#define EVENT_MODEL_DOWNLOAD_STARTED    100
#define EVENT_MODEL_DOWNLOAD_PROGRESS   101
#define EVENT_MODEL_DOWNLOAD_COMPLETED  102
#define EVENT_MODEL_DOWNLOAD_FAILED     103
#define EVENT_MODEL_DOWNLOAD_CANCELLED  104
#define EVENT_MODEL_DOWNLOAD_VERIFIED   105
#define EVENT_MODEL_INSTALLED           106

#ifdef __cplusplus
}
#endif

#endif // MODEL_DOWNLOAD_SUBSYSTEM_H
