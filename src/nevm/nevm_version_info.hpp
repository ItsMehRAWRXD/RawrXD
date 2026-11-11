//============================================================================
// nevm_version_info.hpp
// RawrXD N-EVM - Version and Build Information
// Captures reproducible benchmark metadata
//============================================================================

#pragma once

#include <string>
#include <sstream>
#include <iomanip>
#include <json/json.h>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#endif

namespace RawrXD {
namespace NEVM {

//============================================================================
// Build Information
//============================================================================

struct BuildInfo {
    std::string git_commit;
    std::string git_branch;
    std::string build_timestamp;
    std::string compiler;
    std::string compiler_version;
    std::string build_type;  // Debug, Release, etc.
    std::string cmake_flags;
};

//============================================================================
// Hardware Information
//============================================================================

struct CPUInfo {
    std::string vendor;
    std::string brand;
    int physical_cores;
    int logical_cores;
    std::vector<std::string> features;
    
    bool has_avx2;
    bool has_avx512;
    bool has_vnni;
    bool has_amx;
};

struct GPUInfo {
    std::string name;
    size_t total_vram;
    std::string driver_version;
    int compute_capability_major;
    int compute_capability_minor;
};

struct HardwareInfo {
    CPUInfo cpu;
    GPUInfo gpu;
    uint64_t total_ram;
    uint64_t total_vram;
    std::string os_name;
    std::string os_version;
};

//============================================================================
// Benchmark Metadata
//============================================================================

struct BenchmarkMetadata {
    // Build info
    BuildInfo build;
    
    // Hardware info
    HardwareInfo hardware;
    
    // Model info
    std::string model_name;
    std::string model_quantization;
    size_t model_size_bytes;
    int num_layers;
    int hidden_dim;
    int num_heads;
    int vocab_size;
    int context_length;
    
    // Benchmark config
    int batch_size;
    int num_threads;
    uint32_t random_seed;
    std::string precision_mode;
    bool use_flash_attention;
    bool use_kv_cache;
    
    // Timestamp
    std::string start_time;
    std::string end_time;
    
    Json::Value ToJSON() const {
        Json::Value root;
        
        // Build info
        Json::Value build_json;
        build_json["git_commit"] = build.git_commit;
        build_json["git_branch"] = build.git_branch;
        build_json["timestamp"] = build.build_timestamp;
        build_json["compiler"] = build.compiler;
        build_json["compiler_version"] = build.compiler_version;
        build_json["build_type"] = build.build_type;
        root["build"] = build_json;
        
        // Hardware info
        Json::Value hw_json;
        
        Json::Value cpu_json;
        cpu_json["vendor"] = hardware.cpu.vendor;
        cpu_json["brand"] = hardware.cpu.brand;
        cpu_json["physical_cores"] = hardware.cpu.physical_cores;
        cpu_json["logical_cores"] = hardware.cpu.logical_cores;
        cpu_json["has_avx2"] = hardware.cpu.has_avx2;
        cpu_json["has_avx512"] = hardware.cpu.has_avx512;
        cpu_json["has_vnni"] = hardware.cpu.has_vnni;
        
        Json::Value features(Json::arrayValue);
        for (const auto& f : hardware.cpu.features) {
            features.append(f);
        }
        cpu_json["features"] = features;
        hw_json["cpu"] = cpu_json;
        
        Json::Value gpu_json;
        gpu_json["name"] = hardware.gpu.name;
        gpu_json["total_vram_mb"] = static_cast<Json::Int64>(hardware.gpu.total_vram / (1024 * 1024));
        gpu_json["driver_version"] = hardware.gpu.driver_version;
        hw_json["gpu"] = gpu_json;
        
        hw_json["total_ram_mb"] = static_cast<Json::Int64>(hardware.total_ram / (1024 * 1024));
        hw_json["os_name"] = hardware.os_name;
        hw_json["os_version"] = hardware.os_version;
        
        root["hardware"] = hw_json;
        
        // Model info
        Json::Value model_json;
        model_json["name"] = model_name;
        model_json["quantization"] = model_quantization;
        model_json["size_mb"] = static_cast<Json::Int64>(model_size_bytes / (1024 * 1024));
        model_json["num_layers"] = num_layers;
        model_json["hidden_dim"] = hidden_dim;
        model_json["num_heads"] = num_heads;
        model_json["vocab_size"] = vocab_size;
        model_json["context_length"] = context_length;
        root["model"] = model_json;
        
        // Benchmark config
        Json::Value config_json;
        config_json["batch_size"] = batch_size;
        config_json["num_threads"] = num_threads;
        config_json["random_seed"] = random_seed;
        config_json["precision_mode"] = precision_mode;
        config_json["use_flash_attention"] = use_flash_attention;
        config_json["use_kv_cache"] = use_kv_cache;
        root["config"] = config_json;
        
        // Timestamps
        root["start_time"] = start_time;
        root["end_time"] = end_time;
        
        return root;
    }
};

//============================================================================
// Version Info Collector
//============================================================================

class VersionInfoCollector {
public:
    static BuildInfo CollectBuildInfo() {
        BuildInfo info;
        
        // These would be populated by build system
        #ifdef NEVM_GIT_COMMIT
        info.git_commit = NEVM_GIT_COMMIT;
        #else
        info.git_commit = "unknown";
        #endif
        
        #ifdef NEVM_GIT_BRANCH
        info.git_branch = NEVM_GIT_BRANCH;
        #else
        info.git_branch = "unknown";
        #endif
        
        #ifdef NEVM_BUILD_TIMESTAMP
        info.build_timestamp = NEVM_BUILD_TIMESTAMP;
        #else
        info.build_timestamp = GetCurrentTimestamp();
        #endif
        
        #ifdef _MSC_VER
        info.compiler = "MSVC";
        info.compiler_version = std::to_string(_MSC_VER);
        #elif defined(__GNUC__)
        info.compiler = "GCC";
        info.compiler_version = std::to_string(__GNUC__) + "." + 
                               std::to_string(__GNUC_MINOR__) + "." +
                               std::to_string(__GNUC_PATCHLEVEL__);
        #elif defined(__clang__)
        info.compiler = "Clang";
        info.compiler_version = std::to_string(__clang_major__) + "." +
                               std::to_string(__clang_minor__) + "." +
                               std::to_string(__clang_patchlevel__);
        #else
        info.compiler = "Unknown";
        info.compiler_version = "unknown";
        #endif
        
        #ifdef NDEBUG
        info.build_type = "Release";
        #else
        info.build_type = "Debug";
        #endif
        
        return info;
    }
    
    static HardwareInfo CollectHardwareInfo() {
        HardwareInfo info;
        info.cpu = CollectCPUInfo();
        info.gpu = CollectGPUInfo();
        info.total_ram = GetTotalRAM();
        info.total_vram = info.gpu.total_vram;
        info.os_name = GetOSName();
        info.os_version = GetOSVersion();
        return info;
    }
    
    static std::string GetCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

private:
    static CPUInfo CollectCPUInfo() {
        CPUInfo info;
        info.physical_cores = std::thread::hardware_concurrency() / 2;
        info.logical_cores = std::thread::hardware_concurrency();
        
        #ifdef _WIN32
        // Check CPU features using CPUID
        int cpuInfo[4] = {0};
        __cpuid(cpuInfo, 1);
        
        info.has_avx2 = (cpuInfo[2] & (1 << 28)) != 0;  // AVX
        // Would need more checks for AVX-512, VNNI, etc.
        
        // Get brand string
        char brand[0x40] = {0};
        __cpuid(reinterpret_cast<int*>(brand), 0x80000002);
        __cpuid(reinterpret_cast<int*>(brand + 16), 0x80000003);
        __cpuid(reinterpret_cast<int*>(brand + 32), 0x80000004);
        info.brand = brand;
        
        // Build feature list
        if (info.has_avx2) info.features.push_back("AVX2");
        // Add more features as detected
        #endif
        
        return info;
    }
    
    static GPUInfo CollectGPUInfo() {
        GPUInfo info;
        info.name = "Unknown";
        info.total_vram = 0;
        info.driver_version = "unknown";
        
        // Would query GPU APIs (CUDA, Vulkan, etc.)
        
        return info;
    }
    
    static uint64_t GetTotalRAM() {
        #ifdef _WIN32
        MEMORYSTATUSEX status;
        status.dwLength = sizeof(status);
        GlobalMemoryStatusEx(&status);
        return status.ullTotalPhys;
        #else
        return 0;
        #endif
    }
    
    static std::string GetOSName() {
        #ifdef _WIN32
        return "Windows";
        #elif defined(__linux__)
        return "Linux";
        #elif defined(__APPLE__)
        return "macOS";
        #else
        return "Unknown";
        #endif
    }
    
    static std::string GetOSVersion() {
        #ifdef _WIN32
        OSVERSIONINFOEXW osvi;
        ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXW));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
        
        // Would use RtlGetVersion for accurate version
        return "unknown";
        #else
        return "unknown";
        #endif
    }
};

} // namespace NEVM
} // namespace RawrXD
