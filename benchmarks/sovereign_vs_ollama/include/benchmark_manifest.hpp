// Benchmark Manifest System
// Ensures reproducibility and fair comparison
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#else
#include <sys/utsname.h>
#include <pwd.h>
#endif

namespace rawrxd::benchmark {

// ============================================================================
// System Information
// ============================================================================
struct SystemInfo {
    std::string cpu_vendor;
    std::string cpu_brand;
    int cpu_physical_cores = 0;
    int cpu_logical_cores = 0;
    double cpu_base_freq_ghz = 0.0;
    double cpu_max_freq_ghz = 0.0;
    
    uint64_t ram_total_bytes = 0;
    uint64_t ram_available_bytes = 0;
    
    std::string gpu_name;
    std::string gpu_vendor;
    uint64_t gpu_vram_bytes = 0;
    std::string gpu_driver_version;
    
    std::string os_name;
    std::string os_version;
    std::string os_arch;
    
    std::string compiler_name;
    std::string compiler_version;
    
    static SystemInfo Detect();
    std::string ToJson() const;
};

// ============================================================================
// Benchmark Manifest
// ============================================================================
struct BenchmarkManifest {
    // Run identification
    std::string run_id;
    std::string timestamp;
    std::string git_commit;
    std::string git_branch;
    bool git_dirty = false;
    
    // System info
    SystemInfo system;
    
    // Backend configuration
    BackendType backend;
    std::string backend_version;
    std::string backend_endpoint;
    
    // Model configuration
    std::string model_name;
    std::string model_path;
    std::string model_quantization;
    size_t model_size_bytes = 0;
    std::string model_sha256;
    
    // Runtime configuration
    int context_length = 4096;
    int max_tokens = 512;
    float temperature = 0.0f;  // 0 for reproducibility
    int seed = 42;           // Fixed seed
    int threads = 0;         // 0 = auto
    int gpu_layers = 99;
    std::string gpu_backend = "vulkan";
    
    // Swarm configuration
    int swarm_size = 16;
    std::string swarm_strategy = "round_robin";
    
    // Benchmark configuration
    int warmup_runs = 10;
    int measured_runs = 50;
    int stability_duration_minutes = 10;
    
    // Version tracking (NEW)
    std::string benchmark_version = "2.0.0";  // Suite version
    std::string prompt_suite_version = "1.0.0";  // Workload prompts version
    std::string prompt_suite_sha256;  // SHA256 of workload file
    std::string workload_file_path;  // Path to workload JSON
    
    // Build info
    std::string build_type;      // Release, Debug, RelWithDebInfo
    std::string cmake_flags;
    std::string cxx_flags;
    
    // Environment
    std::map<std::string, std::string> environment_vars;
    std::vector<std::string> loaded_libraries;
    
    // Validation
    bool cpu_affinity_set = false;
    bool gpu_isolated = false;
    bool turbo_boost_disabled = false;
    bool hyperthreading_disabled = false;
    
    static BenchmarkManifest Create(const BenchmarkConfig& config);
    std::string ToJson() const;
    bool SaveToFile(const std::string& path) const;
    static std::optional<BenchmarkManifest> LoadFromFile(const std::string& path);
    
private:
    static std::string GenerateRunId();
    static std::string GetGitCommit();
    static std::string GetGitBranch();
    static bool IsGitDirty();
};

// ============================================================================
// SystemInfo Implementation
// ============================================================================
#ifdef _WIN32
inline SystemInfo SystemInfo::Detect() {
    SystemInfo info;
    
    // CPU info via CPUID
    int cpuInfo[4] = {0};
    char vendor[13] = {0};
    
    __cpuid(cpuInfo, 0);
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[3], 4);
    memcpy(vendor + 8, &cpuInfo[2], 4);
    info.cpu_vendor = vendor;
    
    // Get CPU brand string
    char brand[49] = {0};
    __cpuid(cpuInfo, 0x80000000);
    if (cpuInfo[0] >= 0x80000004) {
        for (int i = 0; i < 3; ++i) {
            __cpuid(cpuInfo, 0x80000002 + i);
            memcpy(brand + i * 16, cpuInfo, 16);
        }
    }
    info.cpu_brand = brand;
    
    // Core counts
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    info.cpu_logical_cores = sysInfo.dwNumberOfProcessors;
    
    // Physical cores (approximate)
    info.cpu_physical_cores = info.cpu_logical_cores / 2;
    
    // Memory
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        info.ram_total_bytes = memStatus.ullTotalPhys;
        info.ram_available_bytes = memStatus.ullAvailPhys;
    }
    
    // OS info
    info.os_name = "Windows";
    
    OSVERSIONINFOEXW osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXW));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
    
    #pragma warning(push)
    #pragma warning(disable: 4996)
    if (GetVersionExW((OSVERSIONINFO*)&osvi)) {
        std::stringstream ss;
        ss << osvi.dwMajorVersion << "." << osvi.dwMinorVersion << "." << osvi.dwBuildNumber;
        info.os_version = ss.str();
    }
    #pragma warning(pop)
    
    #ifdef _WIN64
    info.os_arch = "x64";
    #else
    info.os_arch = "x86";
    #endif
    
    // Compiler info
    #ifdef _MSC_VER
    info.compiler_name = "MSVC";
    std::stringstream ss;
    ss << (_MSC_VER / 100) << "." << (_MSC_VER % 100);
    info.compiler_version = ss.str();
    #elif defined(__clang__)
    info.compiler_name = "Clang";
    info.compiler_version = __clang_version__;
    #elif defined(__GNUC__)
    info.compiler_name = "GCC";
    std::stringstream ss;
    ss << __GNUC__ << "." << __GNUC_MINOR__ << "." << __GNUC_PATCHLEVEL__;
    info.compiler_version = ss.str();
    #endif
    
    return info;
}
#else
inline SystemInfo SystemInfo::Detect() {
    SystemInfo info;
    
    struct utsname unameData;
    if (uname(&unameData) == 0) {
        info.os_name = unameData.sysname;
        info.os_version = unameData.release;
        info.os_arch = unameData.machine;
    }
    
    // TODO: Linux/Mac implementation
    
    return info;
}
#endif

inline std::string SystemInfo::ToJson() const {
    JsonWriter writer;
    writer.BeginObject();
    
    writer.BeginObject("cpu");
    writer.WriteString("vendor", cpu_vendor);
    writer.WriteString("brand", cpu_brand);
    writer.WriteInt("physical_cores", cpu_physical_cores);
    writer.WriteInt("logical_cores", cpu_logical_cores);
    writer.WriteDouble("base_freq_ghz", cpu_base_freq_ghz);
    writer.WriteDouble("max_freq_ghz", cpu_max_freq_ghz);
    writer.EndObject();
    
    writer.BeginObject("memory");
    writer.WriteDouble("total_gb", ram_total_bytes / (1024.0 * 1024.0 * 1024.0));
    writer.WriteDouble("available_gb", ram_available_bytes / (1024.0 * 1024.0 * 1024.0));
    writer.EndObject();
    
    writer.BeginObject("gpu");
    writer.WriteString("name", gpu_name);
    writer.WriteString("vendor", gpu_vendor);
    writer.WriteDouble("vram_gb", gpu_vram_bytes / (1024.0 * 1024.0 * 1024.0));
    writer.WriteString("driver_version", gpu_driver_version);
    writer.EndObject();
    
    writer.BeginObject("os");
    writer.WriteString("name", os_name);
    writer.WriteString("version", os_version);
    writer.WriteString("arch", os_arch);
    writer.EndObject();
    
    writer.BeginObject("compiler");
    writer.WriteString("name", compiler_name);
    writer.WriteString("version", compiler_version);
    writer.EndObject();
    
    writer.EndObject();
    return writer.Str();
}

// ============================================================================
// BenchmarkManifest Implementation
// ============================================================================
inline BenchmarkManifest BenchmarkManifest::Create(const BenchmarkConfig& config) {
    BenchmarkManifest manifest;
    
    manifest.run_id = GenerateRunId();
    manifest.timestamp = GetTimestamp();
    manifest.git_commit = GetGitCommit();
    manifest.git_branch = GetGitBranch();
    manifest.git_dirty = IsGitDirty();
    
    manifest.system = SystemInfo::Detect();
    
    manifest.backend = config.backend;
    manifest.backend_endpoint = config.sovereign_endpoint;
    if (config.backend == BackendType::OLLAMA) {
        manifest.backend_endpoint = config.ollama_url;
    }
    
    manifest.model_name = config.model_name;
    manifest.context_length = config.context_length;
    manifest.max_tokens = config.max_tokens;
    manifest.temperature = config.temperature;
    manifest.seed = config.seed;
    manifest.threads = config.threads;
    manifest.gpu_layers = config.gpu_layers;
    manifest.gpu_backend = config.gpu_backend;
    
    manifest.swarm_size = config.swarm_size;
    
    manifest.warmup_runs = config.warmup_runs;
    manifest.measured_runs = config.measured_runs;
    
    #ifdef NDEBUG
    manifest.build_type = "Release";
    #else
    manifest.build_type = "Debug";
    #endif
    
    // Capture environment
    #ifdef _WIN32
    manifest.environment_vars["PROCESSOR_IDENTIFIER"] = getenv("PROCESSOR_IDENTIFIER") ? getenv("PROCESSOR_IDENTIFIER") : "";
    manifest.environment_vars["NUMBER_OF_PROCESSORS"] = getenv("NUMBER_OF_PROCESSORS") ? getenv("NUMBER_OF_PROCESSORS") : "";
    #endif
    
    return manifest;
}

inline std::string BenchmarkManifest::ToJson() const {
    JsonWriter writer;
    writer.BeginObject();
    
    writer.WriteString("run_id", run_id);
    writer.WriteString("timestamp", timestamp);
    writer.WriteString("git_commit", git_commit);
    writer.WriteString("git_branch", git_branch);
    writer.WriteBool("git_dirty", git_dirty);
    
    writer.BeginObject("system");
    writer.WriteRaw(system.ToJson());
    writer.EndObject();
    
    writer.BeginObject("backend");
    writer.WriteString("type", BackendTypeToString(backend));
    writer.WriteString("version", backend_version);
    writer.WriteString("endpoint", backend_endpoint);
    writer.EndObject();
    
    writer.BeginObject("model");
    writer.WriteString("name", model_name);
    writer.WriteString("path", model_path);
    writer.WriteString("quantization", model_quantization);
    writer.WriteDouble("size_gb", model_size_bytes / (1024.0 * 1024.0 * 1024.0));
    writer.WriteString("sha256", model_sha256);
    writer.EndObject();
    
    writer.BeginObject("runtime");
    writer.WriteInt("context_length", context_length);
    writer.WriteInt("max_tokens", max_tokens);
    writer.WriteDouble("temperature", temperature);
    writer.WriteInt("seed", seed);
    writer.WriteInt("threads", threads);
    writer.WriteInt("gpu_layers", gpu_layers);
    writer.WriteString("gpu_backend", gpu_backend);
    writer.EndObject();
    
    writer.BeginObject("swarm");
    writer.WriteInt("size", swarm_size);
    writer.WriteString("strategy", swarm_strategy);
    writer.EndObject();
    
    writer.BeginObject("benchmark");
    writer.WriteInt("warmup_runs", warmup_runs);
    writer.WriteInt("measured_runs", measured_runs);
    writer.WriteInt("stability_duration_minutes", stability_duration_minutes);
    writer.WriteString("benchmark_version", benchmark_version);
    writer.WriteString("prompt_suite_version", prompt_suite_version);
    writer.WriteString("prompt_suite_sha256", prompt_suite_sha256);
    writer.WriteString("workload_file_path", workload_file_path);
    writer.EndObject();
    
    writer.BeginObject("build");
    writer.WriteString("type", build_type);
    writer.WriteString("cmake_flags", cmake_flags);
    writer.WriteString("cxx_flags", cxx_flags);
    writer.EndObject();
    
    writer.BeginObject("validation");
    writer.WriteBool("cpu_affinity_set", cpu_affinity_set);
    writer.WriteBool("gpu_isolated", gpu_isolated);
    writer.WriteBool("turbo_boost_disabled", turbo_boost_disabled);
    writer.WriteBool("hyperthreading_disabled", hyperthreading_disabled);
    writer.EndObject();
    
    writer.EndObject();
    return writer.Str();
}

inline bool BenchmarkManifest::SaveToFile(const std::string& path) const {
    std::ofstream file(path);
    if (!file) return false;
    file << ToJson();
    return file.good();
}

inline std::optional<BenchmarkManifest> BenchmarkManifest::LoadFromFile(const std::string& path) {
    std::ifstream file(path);
    if (!file) return std::nullopt;
    
    // TODO: Parse JSON and populate manifest
    return std::nullopt;
}

inline std::string BenchmarkManifest::GenerateRunId() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    std::stringstream ss;
    ss << "run_" << ms << "_" << (rand() % 10000);
    return ss.str();
}

inline std::string BenchmarkManifest::GetGitCommit() {
    // Try to get git commit hash
    std::array<char, 128> buffer;
    std::string result;
    
    #ifdef _WIN32
    FILE* pipe = _popen("git rev-parse --short HEAD 2>nul", "r");
    #else
    FILE* pipe = popen("git rev-parse --short HEAD 2>/dev/null", "r");
    #endif
    
    if (pipe) {
        while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
            result += buffer.data();
        }
        #ifdef _WIN32
        _pclose(pipe);
        #else
        pclose(pipe);
        #endif
    }
    
    // Trim whitespace
    result.erase(result.find_last_not_of(" \n\r\t") + 1);
    return result.empty() ? "unknown" : result;
}

inline std::string BenchmarkManifest::GetGitBranch() {
    std::array<char, 128> buffer;
    std::string result;
    
    #ifdef _WIN32
    FILE* pipe = _popen("git rev-parse --abbrev-ref HEAD 2>nul", "r");
    #else
    FILE* pipe = popen("git rev-parse --abbrev-ref HEAD 2>/dev/null", "r");
    #endif
    
    if (pipe) {
        while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
            result += buffer.data();
        }
        #ifdef _WIN32
        _pclose(pipe);
        #else
        pclose(pipe);
        #endif
    }
    
    result.erase(result.find_last_not_of(" \n\r\t") + 1);
    return result.empty() ? "unknown" : result;
}

inline bool BenchmarkManifest::IsGitDirty() {
    #ifdef _WIN32
    FILE* pipe = _popen("git status --porcelain 2>nul", "r");
    #else
    FILE* pipe = popen("git status --porcelain 2>/dev/null", "r");
    #endif
    
    if (pipe) {
        char buffer[128];
        bool has_output = fgets(buffer, sizeof(buffer), pipe) != nullptr;
        #ifdef _WIN32
        _pclose(pipe);
        #else
        pclose(pipe);
        #endif
        return has_output;
    }
    return false;
}

} // namespace rawrxd::benchmark
