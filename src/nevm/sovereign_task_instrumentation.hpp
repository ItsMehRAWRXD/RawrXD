//============================================================================
// sovereign_task_instrumentation.hpp
// RawrXD N-EVM - SOVEREIGN_TASK Macro with PageFaultMonitor Integration
//============================================================================

#pragma once

#include <chrono>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>#include <iostream>
#include <cstdlib>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif
namespace RawrXD {
namespace NEVM {
namespace Sovereign {

//============================================================================
// PageFaultMonitor - Lightweight Memory Performance Tracker
//============================================================================

class PageFaultMonitor {
public:
    struct MemoryStats {
        size_t page_faults_start;
        size_t page_faults_end;
        size_t working_set_start;
        size_t working_set_end;
        size_t peak_working_set;
        double delta_faults;      // Δ = faults_end - faults_start
        double delta_working_set; // Δ = working_set_end - working_set_start
        bool delta_zero;          // Δ == 0 (optimal)
    };

    PageFaultMonitor() : initialized_(false) {}

    void Start() {
        #ifdef _WIN32
        // Get process handle
        process_handle_ = GetCurrentProcess();
        
        // Capture initial memory stats
        MEMORYSTATUSEX mem_status;
        mem_status.dwLength = sizeof(mem_status);
        GlobalMemoryStatusEx(&mem_status);
        
        PROCESS_MEMORY_COUNTERS mem_counters;
        if (GetProcessMemoryInfo(process_handle_, &mem_counters, sizeof(mem_counters))) {
            stats_.page_faults_start = mem_counters.PageFaultCount;
            stats_.working_set_start = mem_counters.WorkingSetSize;
            stats_.peak_working_set = mem_counters.PeakWorkingSetSize;
            initialized_ = true;
        }
        #else
        // Linux implementation
        stats_.page_faults_start = ReadLinuxPageFaults();
        stats_.working_set_start = ReadLinuxWorkingSet();
        initialized_ = true;
        #endif
        
        start_time_ = std::chrono::high_resolution_clock::now();
    }

    void Stop() {
        if (!initialized_) return;

        #ifdef _WIN32
        PROCESS_MEMORY_COUNTERS mem_counters;
        if (GetProcessMemoryInfo(process_handle_, &mem_counters, sizeof(mem_counters))) {
            stats_.page_faults_end = mem_counters.PageFaultCount;
            stats_.working_set_end = mem_counters.WorkingSetSize;
            if (mem_counters.PeakWorkingSetSize > stats_.peak_working_set) {
                stats_.peak_working_set = mem_counters.PeakWorkingSetSize;
            }
        }
        #else
        stats_.page_faults_end = ReadLinuxPageFaults();
        stats_.working_set_end = ReadLinuxWorkingSet();
        #endif

        end_time_ = std::chrono::high_resolution_clock::now();
        
        // Calculate deltas
        stats_.delta_faults = static_cast<double>(stats_.page_faults_end - stats_.page_faults_start);
        stats_.delta_working_set = static_cast<double>(stats_.working_set_end - stats_.working_set_start);
        stats_.delta_zero = (stats_.delta_faults == 0);
    }

    const MemoryStats& GetStats() const { return stats_; }
    
    double GetDurationMs() const {
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
            end_time_ - start_time_);
        return duration.count() / 1000.0;
    }

    bool IsDeltaZero() const {
        return stats_.delta_zero;
    }

    std::string GetReport(const std::string& task_name) const {
        std::ostringstream oss;
        oss << "[PageFaultMonitor] Task: " << task_name << "\n";
        oss << "  Duration: " << std::fixed << std::setprecision(3) << GetDurationMs() << " ms\n";
        oss << "  Page Faults: " << stats_.page_faults_start << " -> " << stats_.page_faults_end;
        oss << " (delta=" << stats_.delta_faults << ")\n";
        oss << "  Working Set: " << (stats_.working_set_start / 1024 / 1024) << " MB -> ";
        oss << (stats_.working_set_end / 1024 / 1024) << " MB\n";
        oss << "  Peak Working Set: " << (stats_.peak_working_set / 1024 / 1024) << " MB\n";
        oss << "  Delta Zero: " << (stats_.delta_zero ? "YES ✓" : "NO") << "\n";
        return oss.str();
    }

    void LogToSession(const std::string& task_name, const std::string& log_file = "sovereign_session.log") const {
        std::ofstream log(log_file, std::ios::app);
        if (log.is_open()) {
            auto now = std::chrono::system_clock::now();
            auto time_t_now = std::chrono::system_clock::to_time_t(now);
            
            log << "[" << std::put_time(std::localtime(&time_t_now), "%Y-%m-%d %H:%M:%S") << "] ";
            log << "SOVEREIGN_TASK: " << task_name << " | ";
            log << "duration_ms=" << std::fixed << std::setprecision(3) << GetDurationMs() << " | ";
            log << "delta_faults=" << stats_.delta_faults << " | ";
            log << "delta_zero=" << (stats_.delta_zero ? "true" : "false") << " | ";
            log << "working_set_mb=" << (stats_.working_set_end / 1024 / 1024) << "\n";
        }
    }

private:
    #ifdef _WIN32
    HANDLE process_handle_;
    #endif
    
    MemoryStats stats_;
    std::chrono::high_resolution_clock::time_point start_time_;
    std::chrono::high_resolution_clock::time_point end_time_;
    bool initialized_;

    #ifndef _WIN32
    size_t ReadLinuxPageFaults() {
        std::ifstream stat("/proc/self/stat");
        if (stat.is_open()) {
            std::string line;
            std::getline(stat, line);
            // Parse field 10 (minor page faults) from /proc/self/stat
            size_t pos = 0;
            int field = 0;
            size_t faults = 0;
            std::istringstream iss(line);
            std::string token;
            while (iss >> token) {
                if (++field == 10) {
                    faults = std::stoull(token);
                    break;
                }
            }
            return faults;
        }
        return 0;
    }

    size_t ReadLinuxWorkingSet() {
        std::ifstream status("/proc/self/status");
        if (status.is_open()) {
            std::string line;
            while (std::getline(status, line)) {
                if (line.find("VmRSS:") == 0) {
                    size_t start = line.find_first_of("0123456789");
                    size_t end = line.find_last_of("0123456789");
                    if (start != std::string::npos) {
                        return std::stoull(line.substr(start, end - start + 1)) * 1024;
                    }
                }
            }
        }
        return 0;
    }
    #endif
};

//============================================================================
// SOVEREIGN_TASK Macro - Automatic Memory Performance Instrumentation
//============================================================================

// RAII wrapper for automatic monitoring
class SovereignTaskScope {
public:
    SovereignTaskScope(const std::string& task_name, const std::string& log_file = "sovereign_session.log")
        : task_name_(task_name), log_file_(log_file) {
        monitor_.Start();
    }
    
    ~SovereignTaskScope() {
        monitor_.Stop();
        monitor_.LogToSession(task_name_, log_file_);
        
        // Also output to console in verbose mode
        if (GetenvBool("SOVEREIGN_VERBOSE")) {
            std::cout << monitor_.GetReport(task_name_);
        }
    }
    
    const PageFaultMonitor& GetMonitor() const { return monitor_; }
    bool IsDeltaZero() const { return monitor_.IsDeltaZero(); }
    
private:
    PageFaultMonitor monitor_;
    std::string task_name_;
    std::string log_file_;
    
    bool GetenvBool(const char* name) {
        const char* val = std::getenv(name);
        if (!val) return false;
        std::string s(val);
        return s == "1" || s == "true";
    }
};

// Main SOVEREIGN_TASK macro - instruments any code block
#define SOVEREIGN_TASK(task_name) \
    for (RawrXD::NEVM::Sovereign::SovereignTaskScope _sov_task_scope(task_name, \
        RawrXD::NEVM::Sovereign::GetSessionLogFile()); _sov_task_scope.IsDeltaZero() || true; )

// Simpler version without automatic delta check
#define SOVEREIGN_TASK_SIMPLE(task_name) \
    RawrXD::NEVM::Sovereign::SovereignTaskScope _sov_task_scope(task_name, \
        RawrXD::NEVM::Sovereign::GetSessionLogFile())

// Conditional task - only executes if condition is met
#define SOVEREIGN_TASK_IF(task_name, condition) \
    if (condition) \
        for (RawrXD::NEVM::Sovereign::SovereignTaskScope _sov_task_scope(task_name, \
            RawrXD::NEVM::Sovereign::GetSessionLogFile()); _sov_task_scope.IsDeltaZero() || true; )

// Session log file management
inline std::string GetSessionLogFile() {
    const char* log_file = std::getenv("SOVEREIGN_SESSION_LOG");
    if (log_file) return log_file;
    
    // Generate default log file with timestamp
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << "sovereign_session_" << std::put_time(std::localtime(&time_t_now), "%Y%m%d_%H%M%S") << ".log";
    return oss.str();
}

// Set session log file via environment
inline void SetSessionLogFile(const std::string& log_file) {
    #ifdef _WIN32
    _putenv_s("SOVEREIGN_SESSION_LOG", log_file.c_str());
    #else
    setenv("SOVEREIGN_SESSION_LOG", log_file.c_str(), 1);
    #endif
}

// Enable verbose output
inline void SetVerbose(bool verbose) {
    #ifdef _WIN32
    _putenv_s("SOVEREIGN_VERBOSE", verbose ? "1" : "0");
    #else
    setenv("SOVEREIGN_VERBOSE", verbose ? "1" : "0", 1);
    #endif
}

} // namespace Sovereign
} // namespace NEVM
} // namespace RawrXD

//============================================================================
// Usage Examples
//============================================================================

/*
// Example 1: Basic task instrumentation
void LoadModel(const std::string& model_path) {
    SOVEREIGN_TASK("LoadModel");
    
    // Your model loading code here
    // PageFaultMonitor automatically tracks memory performance
}

// Example 2: Task with return value
bool InitializeEngine() {
    SOVEREIGN_TASK("InitializeEngine");
    
    // Initialization code
    return true;  // Monitor stops and logs when scope exits
}

// Example 3: Conditional task
void OptionalCleanup() {
    SOVEREIGN_TASK_IF("OptionalCleanup", needs_cleanup) {
        // Cleanup code only runs if needs_cleanup is true
    }
}

// Example 4: Nested tasks
void OuterTask() {
    SOVEREIGN_TASK("OuterTask");
    
    InnerTask();  // Each task gets its own monitor
    
    // Outer task monitor continues
}

void InnerTask() {
    SOVEREIGN_TASK("InnerTask");
    
    // Inner task code
}

// Example 5: Check delta zero
void CriticalTask() {
    SOVEREIGN_TASK_SIMPLE("CriticalTask");
    
    // Critical code
    
    if (!_sov_task_scope.IsDeltaZero()) {
        // Handle memory anomaly
    }
}

// Session log output format:
// [2026-07-20 14:30:45] SOVEREIGN_TASK: LoadModel | duration_ms=125.432 | delta_faults=0 | delta_zero=true | working_set_mb=512
// [2026-07-20 14:30:46] SOVEREIGN_TASK: InitializeEngine | duration_ms=45.123 | delta_faults=2 | delta_zero=false | working_set_mb=1024
*/
