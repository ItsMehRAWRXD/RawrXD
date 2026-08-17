// VAL064_TelemetryExport.cpp
// Implementation of telemetry export for RawrXD

#include "VAL064_TelemetryExport.hpp"
#include <iostream>
#include <fstream>

#ifdef _WIN32
#include <windows.h>
#endif

namespace val064 {

bool TelemetryExporter::Initialize() {
    if (initialized_) {
        return true;
    }
    
#ifdef _WIN32
    // Create shared memory section
    shm_handle_ = CreateFileMappingA(
        INVALID_HANDLE_VALUE,    // Use paging file
        nullptr,                 // Default security
        PAGE_READWRITE,        // Read/write access
        0,                       // Maximum object size (high-order DWORD)
        sizeof(TelemetryData),   // Maximum object size (low-order DWORD)
        VAL064_SHM_NAME          // Name of mapping object
    );
    
    if (!shm_handle_) {
        DWORD error = GetLastError();
        if (error == ERROR_ALREADY_EXISTS) {
            // Open existing shared memory
            shm_handle_ = OpenFileMappingA(
                FILE_MAP_ALL_ACCESS,
                FALSE,
                VAL064_SHM_NAME
            );
        }
        
        if (!shm_handle_) {
            std::cerr << "[VAL064] Failed to create/open shared memory: " << error << std::endl;
            return false;
        }
    }
    
    // Map view of file
    shm_view_ = MapViewOfFile(
        shm_handle_,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        sizeof(TelemetryData)
    );
    
    if (!shm_view_) {
        std::cerr << "[VAL064] Failed to map view of shared memory" << std::endl;
        CloseHandle(shm_handle_);
        shm_handle_ = nullptr;
        return false;
    }
    
    // Initialize the shared memory
    auto* data = static_cast<TelemetryData*>(shm_view_);
    data->version = VAL064_TELEMETRY_VERSION;
    data->sequence = 0;
    data->valid = false;
    data->error_message[0] = '\0';
    
    std::cout << "[VAL064] Telemetry exporter initialized (shared memory)" << std::endl;
#endif
    
    initialized_ = true;
    return true;
}

void TelemetryExporter::Shutdown() {
    if (!initialized_) {
        return;
    }
    
#ifdef _WIN32
    if (shm_view_) {
        UnmapViewOfFile(shm_view_);
        shm_view_ = nullptr;
    }
    
    if (shm_handle_) {
        CloseHandle(shm_handle_);
        shm_handle_ = nullptr;
    }
#endif
    
    initialized_ = false;
    std::cout << "[VAL064] Telemetry exporter shutdown" << std::endl;
}

bool TelemetryExporter::Export(const TelemetryData& data) {
    if (!initialized_ || !shm_view_) {
        // Fall back to file-based export
        std::ofstream file("evidence/performance/telemetry_live.json");
        if (file.is_open()) {
            file << "{\n";
            file << "  \"prefill_tps\": " << data.prefill_tps << ",\n";
            file << "  \"decode_tps\": " << data.decode_tps << ",\n";
            file << "  \"first_token_ms\": " << data.first_token_ms << ",\n";
            file << "  \"peak_vram_mb\": " << data.peak_vram_mb << ",\n";
            file << "  \"peak_ram_mb\": " << data.peak_ram_mb << ",\n";
            file << "  \"prompt_tokens\": " << data.prompt_tokens << ",\n";
            file << "  \"generated_tokens\": " << data.generated_tokens << ",\n";
            file << "  \"valid\": " << (data.valid ? "true" : "false") << "\n";
            file << "}\n";
            return true;
        }
        return false;
    }
    
#ifdef _WIN32
    auto* shared = static_cast<TelemetryData*>(shm_view_);
    
    // Copy data to shared memory
    shared->version = data.version;
    shared->sequence = sequence_.fetch_add(1) + 1;
    shared->prefill_tps = data.prefill_tps;
    shared->decode_tps = data.decode_tps;
    shared->first_token_ms = data.first_token_ms;
    shared->peak_vram_mb = data.peak_vram_mb;
    shared->peak_ram_mb = data.peak_ram_mb;
    shared->prompt_tokens = data.prompt_tokens;
    shared->generated_tokens = data.generated_tokens;
    shared->timestamp_ns = std::chrono::steady_clock::now().time_since_epoch().count();
    shared->valid = data.valid;
    
    if (data.error_message[0]) {
        strncpy_s(shared->error_message, sizeof(shared->error_message), 
                  data.error_message, _TRUNCATE);
    } else {
        shared->error_message[0] = '\0';
    }
    
    // Memory barrier to ensure writes are visible
    _mm_sfence();
#endif
    
    return true;
}

bool TelemetryExporter::ExportMetrics(
    double prefill_tps,
    double decode_tps,
    double first_token_ms,
    double peak_vram_mb,
    double peak_ram_mb,
    int prompt_tokens,
    int generated_tokens
) {
    TelemetryData data;
    data.prefill_tps = prefill_tps;
    data.decode_tps = decode_tps;
    data.first_token_ms = first_token_ms;
    data.peak_vram_mb = peak_vram_mb;
    data.peak_ram_mb = peak_ram_mb;
    data.prompt_tokens = prompt_tokens;
    data.generated_tokens = generated_tokens;
    data.valid = true;
    
    return Export(data);
}

} // namespace val064
