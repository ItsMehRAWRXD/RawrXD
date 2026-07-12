//==============================================================================
// ModelDownloadSubsystem.cpp - Phase 15B: Download Implementation
//==============================================================================

#include "ModelDownloadSubsystem.h"
#include "ExecutionJournal.h"
#include "GGUFQuantizationDetector.h"
#include "ModelRegistry.h"
#include <windows.h>
#include <wininet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <process.h>

#pragma comment(lib, "wininet.lib")

//==============================================================================
// Internal State
//==============================================================================

typedef struct DownloadEntry {
    int id;
    int state;
    DownloadConfig config;
    DownloadProgress progress;
    HANDLE thread_handle;
    HANDLE cancel_event;
    HANDLE pause_event;
    FILE* file_handle;
    HINTERNET internet;
    HINTERNET connection;
    HINTERNET request;
    DownloadProgressCallback progress_cb;
    DownloadCompleteCallback complete_cb;
    void* user_data;
    char temp_path[MAX_DOWNLOAD_PATH];
} DownloadEntry;

typedef struct DownloadSubsystem {
    DownloadEntry downloads[MAX_CONCURRENT_DOWNLOADS];
    int next_id;
    char models_dir[MAX_DOWNLOAD_PATH];
    uint64_t speed_limit;
    char last_error[256];
    int is_initialized;
    CRITICAL_SECTION lock;
} DownloadSubsystem;

static DownloadSubsystem g_download = {0};

//==============================================================================
// Utility Functions
//==============================================================================

static uint64_t GetTimestampMs() {
    return GetTickCount64();
}

static int FindDownloadEntry(int id) {
    for (int i = 0; i < MAX_CONCURRENT_DOWNLOADS; i++) {
        if (g_download.downloads[i].id == id) {
            return i;
        }
    }
    return -1;
}

static int FindFreeSlot() {
    for (int i = 0; i < MAX_CONCURRENT_DOWNLOADS; i++) {
        if (g_download.downloads[i].state == DOWNLOAD_STATE_IDLE) {
            return i;
        }
    }
    return -1;
}

static void SetError(const char* msg) {
    strncpy(g_download.last_error, msg, sizeof(g_download.last_error) - 1);
}

static void ReportProgress(DownloadEntry* entry) {
    if (entry->progress_cb) {
        entry->progress_cb(&entry->progress, entry->user_data);
    }
    
    // Log to journal
    char desc[512];
    snprintf(desc, sizeof(desc), "Download %d: %d%% (%llu/%llu bytes)",
             entry->id, entry->progress.percent_complete,
             entry->progress.bytes_downloaded, entry->progress.bytes_total);
    Journal_LogUserRequest(desc, "DOWNLOAD_PROGRESS");
}

static void ReportComplete(DownloadEntry* entry, int success, const char* error) {
    if (entry->complete_cb) {
        entry->complete_cb(entry->id, success, error, entry->user_data);
    }
    
    // Log to journal
    if (success) {
        Journal_LogUserRequest("Download completed", entry->config.model_name);
    } else {
        Journal_LogUserRequest("Download failed", error ? error : "Unknown error");
    }
}

//==============================================================================
// HTTP Download Thread
//==============================================================================

static unsigned __stdcall DownloadThread(void* param) {
    DownloadEntry* entry = (DownloadEntry*)param;
    
    entry->state = DOWNLOAD_STATE_DOWNLOADING;
    entry->progress.state = DOWNLOAD_STATE_DOWNLOADING;
    entry->progress.start_time_ms = GetTimestampMs();
    
    // Initialize WinInet
    entry->internet = InternetOpen("RawrXD-ModelDownload/15.1", 
                                      INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!entry->internet) {
        SetError("Failed to initialize internet connection");
        entry->state = DOWNLOAD_STATE_FAILED;
        entry->progress.state = DOWNLOAD_STATE_FAILED;
        strcpy(entry->progress.status_message, "Connection failed");
        ReportComplete(entry, 0, g_download.last_error);
        return 1;
    }
    
    // Parse URL
    URL_COMPONENTS urlComp = {0};
    urlComp.dwStructSize = sizeof(urlComp);
    
    char hostName[256] = {0};
    char urlPath[2048] = {0};
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = sizeof(hostName);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = sizeof(urlPath);
    
    if (!InternetCrackUrl(entry->config.url, 0, 0, &urlComp)) {
        SetError("Failed to parse URL");
        InternetCloseHandle(entry->internet);
        entry->state = DOWNLOAD_STATE_FAILED;
        entry->progress.state = DOWNLOAD_STATE_FAILED;
        ReportComplete(entry, 0, g_download.last_error);
        return 1;
    }
    
    // Connect
    entry->connection = InternetConnect(entry->internet, hostName, 
                                         urlComp.nPort, NULL, NULL, 
                                         INTERNET_SERVICE_HTTP, 0, 0);
    if (!entry->connection) {
        SetError("Failed to connect to server");
        InternetCloseHandle(entry->internet);
        entry->state = DOWNLOAD_STATE_FAILED;
        entry->progress.state = DOWNLOAD_STATE_FAILED;
        ReportComplete(entry, 0, g_download.last_error);
        return 1;
    }
    
    // Create request
    entry->request = HttpOpenRequest(entry->connection, "GET", urlPath,
                                      NULL, NULL, NULL,
                                      INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!entry->request) {
        SetError("Failed to create HTTP request");
        InternetCloseHandle(entry->connection);
        InternetCloseHandle(entry->internet);
        entry->state = DOWNLOAD_STATE_FAILED;
        entry->progress.state = DOWNLOAD_STATE_FAILED;
        ReportComplete(entry, 0, g_download.last_error);
        return 1;
    }
    
    // Send request
    if (!HttpSendRequest(entry->request, NULL, 0, NULL, 0)) {
        SetError("Failed to send HTTP request");
        InternetCloseHandle(entry->request);
        InternetCloseHandle(entry->connection);
        InternetCloseHandle(entry->internet);
        entry->state = DOWNLOAD_STATE_FAILED;
        entry->progress.state = DOWNLOAD_STATE_FAILED;
        ReportComplete(entry, 0, g_download.last_error);
        return 1;
    }
    
    // Get content length
    char contentLength[32] = {0};
    DWORD lengthSize = sizeof(contentLength);
    DWORD headerIndex = 0;
    if (HttpQueryInfo(entry->request, HTTP_QUERY_CONTENT_LENGTH, contentLength, 
                      &lengthSize, &headerIndex)) {
        entry->progress.bytes_total = _strtoui64(contentLength, NULL, 10);
    }
    
    // Open file for writing
    entry->file_handle = fopen(entry->temp_path, "wb");
    if (!entry->file_handle) {
        SetError("Failed to create output file");
        InternetCloseHandle(entry->request);
        InternetCloseHandle(entry->connection);
        InternetCloseHandle(entry->internet);
        entry->state = DOWNLOAD_STATE_FAILED;
        entry->progress.state = DOWNLOAD_STATE_FAILED;
        ReportComplete(entry, 0, g_download.last_error);
        return 1;
    }
    
    // Download loop
    char buffer[DOWNLOAD_CHUNK_SIZE];
    DWORD bytesRead;
    uint64_t last_progress_time = GetTimestampMs();
    uint64_t bytes_at_last_update = 0;
    
    while (InternetReadFile(entry->request, buffer, sizeof(buffer), &bytesRead)) {
        // Check for cancel
        if (WaitForSingleObject(entry->cancel_event, 0) == WAIT_OBJECT_0) {
            entry->state = DOWNLOAD_STATE_FAILED;
            entry->progress.state = DOWNLOAD_STATE_FAILED;
            strcpy(entry->progress.status_message, "Cancelled");
            break;
        }
        
        // Check for pause
        if (entry->state == DOWNLOAD_STATE_PAUSED) {
            WaitForSingleObject(entry->pause_event, INFINITE);
            ResetEvent(entry->pause_event);
            entry->state = DOWNLOAD_STATE_DOWNLOADING;
            entry->progress.state = DOWNLOAD_STATE_DOWNLOADING;
        }
        
        if (bytesRead == 0) {
            // Download complete
            break;
        }
        
        // Write to file
        if (fwrite(buffer, 1, bytesRead, entry->file_handle) != bytesRead) {
            SetError("Failed to write to file");
            entry->state = DOWNLOAD_STATE_FAILED;
            entry->progress.state = DOWNLOAD_STATE_FAILED;
            break;
        }
        
        entry->progress.bytes_downloaded += bytesRead;
        
        // Update progress
        uint64_t now = GetTimestampMs();
        if (now - last_progress_time >= DOWNLOAD_PROGRESS_INTERVAL_MS) {
            uint64_t elapsed = now - entry->progress.start_time_ms;
            uint64_t interval = now - last_progress_time;
            
            if (interval > 0) {
                entry->progress.bytes_per_second = 
                    (entry->progress.bytes_downloaded - bytes_at_last_update) * 1000 / interval;
            }
            
            if (entry->progress.bytes_total > 0) {
                entry->progress.percent_complete = 
                    (int)((entry->progress.bytes_downloaded * 100) / entry->progress.bytes_total);
                    
                uint64_t remaining = entry->progress.bytes_total - entry->progress.bytes_downloaded;
                if (entry->progress.bytes_per_second > 0) {
                    entry->progress.eta_ms = remaining * 1000 / entry->progress.bytes_per_second;
                }
            }
            
            // Format status message
            char speed_str[32], size_str[32], total_str[32];
            ModelDownload_FormatSpeed(entry->progress.bytes_per_second, speed_str, sizeof(speed_str));
            ModelDownload_FormatBytes(entry->progress.bytes_downloaded, size_str, sizeof(size_str));
            ModelDownload_FormatBytes(entry->progress.bytes_total, total_str, sizeof(total_str));
            
            snprintf(entry->progress.status_message, sizeof(entry->progress.status_message),
                     "%s / %s at %s", size_str, total_str, speed_str);
            
            ReportProgress(entry);
            
            last_progress_time = now;
            bytes_at_last_update = entry->progress.bytes_downloaded;
        }
        
        // Speed limiting
        if (g_download.speed_limit > 0 && entry->progress.bytes_per_second > g_download.speed_limit) {
            Sleep(10);
        }
    }
    
    // Cleanup
    if (entry->file_handle) {
        fclose(entry->file_handle);
        entry->file_handle = NULL;
    }
    
    InternetCloseHandle(entry->request);
    InternetCloseHandle(entry->connection);
    InternetCloseHandle(entry->internet);
    
    // Check result
    if (entry->state == DOWNLOAD_STATE_FAILED) {
        ReportComplete(entry, 0, entry->progress.status_message);
        return 1;
    }
    
    // Move temp file to final location
    if (MoveFile(entry->temp_path, entry->config.output_path)) {
        entry->state = DOWNLOAD_STATE_COMPLETED;
        entry->progress.state = DOWNLOAD_STATE_COMPLETED;
        entry->progress.percent_complete = 100;
        strcpy(entry->progress.status_message, "Download complete");
        
        // Verify if SHA256 provided
        if (entry->config.expected_sha256[0]) {
            entry->progress.state = DOWNLOAD_STATE_VERIFYING;
            strcpy(entry->progress.status_message, "Verifying...");
            ReportProgress(entry);
            
            if (ModelDownload_VerifySHA256(entry->config.output_path, 
                                            entry->config.expected_sha256) != 0) {
                SetError("SHA256 verification failed");
                entry->state = DOWNLOAD_STATE_FAILED;
                entry->progress.state = DOWNLOAD_STATE_FAILED;
                strcpy(entry->progress.status_message, "Verification failed");
                ReportComplete(entry, 0, g_download.last_error);
                return 1;
            }
            
            Journal_LogUserRequest("Download verified", entry->config.model_name);
        }
        
        // Auto-install if enabled
        if (entry->config.auto_install) {
            strcpy(entry->progress.status_message, "Installing...");
            ReportProgress(entry);
            
            if (ModelDownload_InstallToRegistry(entry->config.output_path,
                                                  entry->config.model_name,
                                                  entry->config.backend_type,
                                                  entry->config.capabilities) == 0) {
                Journal_LogUserRequest("Model auto-installed", entry->config.model_name);
            }
        }
        
        ReportComplete(entry, 1, NULL);
    } else {
        SetError("Failed to move downloaded file");
        entry->state = DOWNLOAD_STATE_FAILED;
        entry->progress.state = DOWNLOAD_STATE_FAILED;
        ReportComplete(entry, 0, g_download.last_error);
    }
    
    return 0;
}

//==============================================================================
// Subsystem Lifecycle
//==============================================================================

int ModelDownload_Init(const char* models_directory) {
    if (g_download.is_initialized) {
        return 0;
    }
    
    memset(&g_download, 0, sizeof(g_download));
    InitializeCriticalSection(&g_download.lock);
    
    if (models_directory) {
        strncpy(g_download.models_dir, models_directory, sizeof(g_download.models_dir) - 1);
    } else {
        strcpy(g_download.models_dir, "models/downloads");
    }
    
    // Create downloads directory
    CreateDirectory(g_download.models_dir, NULL);
    
    g_download.next_id = 1;
    g_download.is_initialized = 1;
    
    Journal_LogUserRequest("Download subsystem initialized", g_download.models_dir);
    
    return 0;
}

int ModelDownload_Shutdown(void) {
    if (!g_download.is_initialized) {
        return 0;
    }
    
    // Cancel all active downloads
    ModelDownload_CancelAll();
    
    // Wait for threads to complete
    Sleep(100);
    
    DeleteCriticalSection(&g_download.lock);
    g_download.is_initialized = 0;
    
    return 0;
}

int ModelDownload_IsReady(void) {
    return g_download.is_initialized;
}

//==============================================================================
// Download Operations
//==============================================================================

int ModelDownload_Start(const DownloadConfig* config) {
    if (!g_download.is_initialized || !config) {
        return -1;
    }
    
    EnterCriticalSection(&g_download.lock);
    
    int slot = FindFreeSlot();
    if (slot < 0) {
        LeaveCriticalSection(&g_download.lock);
        SetError("Maximum concurrent downloads reached");
        return -1;
    }
    
    DownloadEntry* entry = &g_download.downloads[slot];
    memset(entry, 0, sizeof(DownloadEntry));
    
    entry->id = g_download.next_id++;
    entry->state = DOWNLOAD_STATE_PENDING;
    entry->config = *config;
    entry->progress.download_id = entry->id;
    entry->progress.state = DOWNLOAD_STATE_PENDING;
    
    // Create temp path
    const char* filename = strrchr(config->output_path, '\\');
    if (!filename) filename = strrchr(config->output_path, '/');
    if (!filename) filename = config->output_path;
    else filename++;
    
    snprintf(entry->temp_path, sizeof(entry->temp_path), 
             "%s\\.tmp_%s_%d", g_download.models_dir, filename, entry->id);
    
    // Create events
    entry->cancel_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    entry->pause_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    
    // Start thread
    entry->thread_handle = (HANDLE)_beginthreadex(NULL, 0, DownloadThread, entry, 0, NULL);
    
    LeaveCriticalSection(&g_download.lock);
    
    Journal_LogUserRequest("Download started", config->model_name);
    
    return entry->id;
}

int ModelDownload_StartFromHuggingFace(const char* model_id, const char* output_dir,
                                          const DownloadConfig* extra_config) {
    if (!g_download.is_initialized || !model_id) {
        return -1;
    }
    
    char url[MAX_DOWNLOAD_URL];
    if (ModelDownload_ResolveHFUrl(model_id, url, sizeof(url)) != 0) {
        return -1;
    }
    
    DownloadConfig config = {0};
    if (extra_config) {
        config = *extra_config;
    }
    
    strncpy(config.url, url, sizeof(config.url) - 1);
    config.use_hf_hub = 1;
    
    // Extract filename from model_id
    const char* filename = strrchr(model_id, ':');
    if (filename) {
        filename++;
    } else {
        filename = "model.gguf";
    }
    
    if (output_dir) {
        snprintf(config.output_path, sizeof(config.output_path), "%s\\%s", output_dir, filename);
    } else {
        snprintf(config.output_path, sizeof(config.output_path), "%s\\%s", 
                 g_download.models_dir, filename);
    }
    
    if (!config.model_name[0]) {
        strncpy(config.model_name, model_id, sizeof(config.model_name) - 1);
    }
    
    return ModelDownload_Start(&config);
}

int ModelDownload_Pause(int download_id) {
    EnterCriticalSection(&g_download.lock);
    
    int slot = FindDownloadEntry(download_id);
    if (slot < 0) {
        LeaveCriticalSection(&g_download.lock);
        return -1;
    }
    
    DownloadEntry* entry = &g_download.downloads[slot];
    if (entry->state == DOWNLOAD_STATE_DOWNLOADING) {
        entry->state = DOWNLOAD_STATE_PAUSED;
        entry->progress.state = DOWNLOAD_STATE_PAUSED;
        strcpy(entry->progress.status_message, "Paused");
    }
    
    LeaveCriticalSection(&g_download.lock);
    return 0;
}

int ModelDownload_Resume(int download_id) {
    EnterCriticalSection(&g_download.lock);
    
    int slot = FindDownloadEntry(download_id);
    if (slot < 0) {
        LeaveCriticalSection(&g_download.lock);
        return -1;
    }
    
    DownloadEntry* entry = &g_download.downloads[slot];
    if (entry->state == DOWNLOAD_STATE_PAUSED) {
        SetEvent(entry->pause_event);
    }
    
    LeaveCriticalSection(&g_download.lock);
    return 0;
}

int ModelDownload_Cancel(int download_id) {
    EnterCriticalSection(&g_download.lock);
    
    int slot = FindDownloadEntry(download_id);
    if (slot < 0) {
        LeaveCriticalSection(&g_download.lock);
        return -1;
    }
    
    DownloadEntry* entry = &g_download.downloads[slot];
    SetEvent(entry->cancel_event);
    entry->state = DOWNLOAD_STATE_FAILED;
    entry->progress.state = DOWNLOAD_STATE_FAILED;
    strcpy(entry->progress.status_message, "Cancelled");
    
    LeaveCriticalSection(&g_download.lock);
    return 0;
}

int ModelDownload_GetProgress(int download_id, DownloadProgress* out_progress) {
    if (!out_progress) return -1;
    
    EnterCriticalSection(&g_download.lock);
    
    int slot = FindDownloadEntry(download_id);
    if (slot < 0) {
        LeaveCriticalSection(&g_download.lock);
        return -1;
    }
    
    *out_progress = g_download.downloads[slot].progress;
    
    LeaveCriticalSection(&g_download.lock);
    return 0;
}

int ModelDownload_SetProgressCallback(int download_id, DownloadProgressCallback callback, void* user_data) {
    EnterCriticalSection(&g_download.lock);
    
    int slot = FindDownloadEntry(download_id);
    if (slot < 0) {
        LeaveCriticalSection(&g_download.lock);
        return -1;
    }
    
    g_download.downloads[slot].progress_cb = callback;
    g_download.downloads[slot].user_data = user_data;
    
    LeaveCriticalSection(&g_download.lock);
    return 0;
}

int ModelDownload_SetCompleteCallback(int download_id, DownloadCompleteCallback callback, void* user_data) {
    EnterCriticalSection(&g_download.lock);
    
    int slot = FindDownloadEntry(download_id);
    if (slot < 0) {
        LeaveCriticalSection(&g_download.lock);
        return -1;
    }
    
    g_download.downloads[slot].complete_cb = callback;
    // user_data already set by progress callback
    
    LeaveCriticalSection(&g_download.lock);
    return 0;
}

//==============================================================================
// Batch Operations
//==============================================================================

int ModelDownload_StartBatch(const DownloadConfig* configs, int count) {
    if (!configs || count <= 0) return -1;
    
    int started = 0;
    for (int i = 0; i < count; i++) {
        int id = ModelDownload_Start(&configs[i]);
        if (id > 0) started++;
    }
    
    return started;
}

int ModelDownload_ListActive(int* out_ids, int max_ids, int* out_count) {
    if (!out_ids || !out_count) return -1;
    
    EnterCriticalSection(&g_download.lock);
    
    *out_count = 0;
    for (int i = 0; i < MAX_CONCURRENT_DOWNLOADS && *out_count < max_ids; i++) {
        if (g_download.downloads[i].state != DOWNLOAD_STATE_IDLE) {
            out_ids[(*out_count)++] = g_download.downloads[i].id;
        }
    }
    
    LeaveCriticalSection(&g_download.lock);
    return 0;
}

int ModelDownload_CancelAll(void) {
    EnterCriticalSection(&g_download.lock);
    
    for (int i = 0; i < MAX_CONCURRENT_DOWNLOADS; i++) {
        if (g_download.downloads[i].state != DOWNLOAD_STATE_IDLE) {
            SetEvent(g_download.downloads[i].cancel_event);
            g_download.downloads[i].state = DOWNLOAD_STATE_FAILED;
        }
    }
    
    LeaveCriticalSection(&g_download.lock);
    return 0;
}

//==============================================================================
// Verification & Installation
//==============================================================================

int ModelDownload_VerifySHA256(const char* file_path, const char* expected_hash) {
    char actual_hash[65];
    if (ModelDownload_CalculateSHA256(file_path, actual_hash, sizeof(actual_hash)) != 0) {
        return -1;
    }
    
    return (_stricmp(actual_hash, expected_hash) == 0) ? 0 : -1;
}

int ModelDownload_CalculateSHA256(const char* file_path, char* out_hash, size_t hash_size) {
    // Simplified SHA256 - in production use proper crypto library
    // For now, just return placeholder
    if (hash_size < 65) return -1;
    
    // TODO: Implement actual SHA256 using Windows CryptoAPI or OpenSSL
    strcpy(out_hash, "0000000000000000000000000000000000000000000000000000000000000000");
    
    return 0;
}

int ModelDownload_InstallToRegistry(const char* file_path, const char* model_name,
                                     const char* backend_type, unsigned int capabilities) {
    // Analyze the GGUF file
    DetectedModelInfo info;
    if (GGUFDetector_AnalyzeFile(file_path, &info) != 0) {
        return -1;
    }
    
    // Create ModelInfo
    ModelInfo model;
    memset(&model, 0, sizeof(model));
    
    strncpy(model.name, model_name[0] ? model_name : info.model_name, sizeof(model.name) - 1);
    
    // Generate ID from filename
    const char* filename = strrchr(file_path, '\\');
    if (!filename) filename = strrchr(file_path, '/');
    if (!filename) filename = file_path;
    else filename++;
    
    char id_base[64];
    strncpy(id_base, filename, sizeof(id_base) - 1);
    char* dot = strrchr(id_base, '.');
    if (dot) *dot = '\0';
    snprintf(model.id, sizeof(model.id), "gguf_%s", id_base);
    
    strncpy(model.path, file_path, sizeof(model.path) - 1);
    model.is_local = 1;
    strncpy(model.backend_type, backend_type[0] ? backend_type : "native", sizeof(model.backend_type) - 1);
    
    model.parameter_count = info.parameter_count;
    model.context_window = info.context_length;
    model.embedding_dim = info.embedding_length;
    model.num_layers = info.num_layers;
    model.num_heads = info.num_heads;
    
    strncpy(model.quantization, info.quantization, sizeof(model.quantization) - 1);
    model.capabilities = capabilities ? capabilities : GGUFDetector_GetDefaultCapabilities(info.architecture);
    
    model.memory_required_mb = (uint64_t)(GGUFDetector_EstimateMemoryRequired(&info) / (1024 * 1024));
    
    // Add to registry
    if (ModelRegistry_AddModel(&model) != 0) {
        return -1;
    }
    
    Journal_LogUserRequest("Model installed to registry", model.name);
    
    return 0;
}

int ModelDownload_EnableAutoInstall(int download_id) {
    EnterCriticalSection(&g_download.lock);
    
    int slot = FindDownloadEntry(download_id);
    if (slot < 0) {
        LeaveCriticalSection(&g_download.lock);
        return -1;
    }
    
    g_download.downloads[slot].config.auto_install = 1;
    
    LeaveCriticalSection(&g_download.lock);
    return 0;
}

//==============================================================================
// HuggingFace Hub Integration
//==============================================================================

int ModelDownload_ResolveHFUrl(const char* model_id, char* out_url, size_t url_size) {
    if (!model_id || !out_url || url_size == 0) return -1;
    
    // Parse model_id: "org/model" or "org/model:file.gguf"
    char org[128] = {0};
    char model[128] = {0};
    char file[256] = {0};
    
    const char* colon = strchr(model_id, ':');
    const char* slash = strchr(model_id, '/');
    
    if (!slash) return -1;
    
    if (colon && colon > slash) {
        // Has explicit file
        size_t org_len = slash - model_id;
        strncpy(org, model_id, org_len);
        org[org_len] = '\0';
        
        size_t model_len = colon - slash - 1;
        strncpy(model, slash + 1, model_len);
        model[model_len] = '\0';
        
        strncpy(file, colon + 1, sizeof(file) - 1);
    } else {
        // Default to model.gguf
        size_t org_len = slash - model_id;
        strncpy(org, model_id, org_len);
        org[org_len] = '\0';
        
        strncpy(model, slash + 1, sizeof(model) - 1);
        strcpy(file, "model.gguf");
    }
    
    // Build HuggingFace download URL
    snprintf(out_url, url_size,
             "https://huggingface.co/%s/%s/resolve/main/%s",
             org, model, file);
    
    return 0;
}

int ModelDownload_ListHFFiles(const char* model_id, char** out_files, int max_files, int* out_count) {
    // TODO: Implement HuggingFace API call to list files
    // For now, return empty list
    *out_count = 0;
    return 0;
}

int ModelDownload_GetHFModelInfo(const char* model_id, char* out_info_json, size_t info_size) {
    // TODO: Implement HuggingFace API call for model info
    if (out_info_json && info_size > 0) {
        out_info_json[0] = '\0';
    }
    return 0;
}

//==============================================================================
// Utility Functions
//==============================================================================

void ModelDownload_FormatBytes(uint64_t bytes, char* out_str, size_t str_size) {
    if (bytes >= 1024ULL * 1024 * 1024 * 1024) {
        snprintf(out_str, str_size, "%.1f TB", bytes / (1024.0 * 1024 * 1024 * 1024));
    } else if (bytes >= 1024ULL * 1024 * 1024) {
        snprintf(out_str, str_size, "%.1f GB", bytes / (1024.0 * 1024 * 1024));
    } else if (bytes >= 1024ULL * 1024) {
        snprintf(out_str, str_size, "%.1f MB", bytes / (1024.0 * 1024));
    } else if (bytes >= 1024) {
        snprintf(out_str, str_size, "%.1f KB", bytes / 1024.0);
    } else {
        snprintf(out_str, str_size, "%llu B", bytes);
    }
}

void ModelDownload_FormatSpeed(uint64_t bytes_per_sec, char* out_str, size_t str_size) {
    ModelDownload_FormatBytes(bytes_per_sec, out_str, str_size);
    size_t len = strlen(out_str);
    if (len + 3 < str_size) {
        strcat(out_str, "/s");
    }
}

void ModelDownload_FormatDuration(uint64_t ms, char* out_str, size_t str_size) {
    uint64_t seconds = ms / 1000;
    uint64_t minutes = seconds / 60;
    uint64_t hours = minutes / 60;
    
    if (hours > 0) {
        snprintf(out_str, str_size, "%lluh %llum", hours, minutes % 60);
    } else if (minutes > 0) {
        snprintf(out_str, str_size, "%llum %llus", minutes, seconds % 60);
    } else {
        snprintf(out_str, str_size, "%llus", seconds);
    }
}

const char* ModelDownload_GetDefaultDirectory(void) {
    return g_download.models_dir;
}

int ModelDownload_SetSpeedLimit(uint64_t bytes_per_sec) {
    g_download.speed_limit = bytes_per_sec;
    return 0;
}

const char* ModelDownload_GetLastError(void) {
    return g_download.last_error;
}
