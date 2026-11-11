#pragma once
// SNAP Process Guard: dependency-free C++20 Windows process enumeration,
// verification, and cleanup for RawrXD Agent ESP integration.
//
// This component provides:
//  - Native Windows process enumeration (no external deps)
//  - Process verification against executable path and accessibility
//  - Optional termination of verified stale processes
//  - Job Object wrapper for automatic child cleanup (optional)
//
// Build: MSVC C++20 /clr:off or MinGW C++20
// No third-party dependencies.

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <optional>
#include <string_view>
#include <filesystem>
#include <atomic>
#include <mutex>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "version.lib")

namespace snap::process {

// ============================================================================
// Process information structure
// ============================================================================

struct ProcessInfo {
    DWORD pid = 0;
    DWORD ppid = 0;
    std::wstring exe_path;
    std::wstring exe_name;
    SIZE_T working_set_bytes = 0;
    bool accessible = false;
    bool path_match = false;
    bool is_self = false;
    bool is_job_assigned = false;

    // Human-readable format for logging
    std::string to_string() const {
        char buf[512];
        std::snprintf(buf, sizeof(buf),
            "pid=%u ppid=%u exe=%S accessible=%d path_match=%d is_self=%d ws=%.1f MB",
            pid, ppid, exe_path.c_str(), accessible ? 1 : 0, path_match ? 1 : 0, is_self ? 1 : 0,
            working_set_bytes / (1024.0 * 1024.0));
        return std::string(buf);
    }
};

// ============================================================================
// Process enumerator
// ============================================================================

class ProcessEnumerator {
public:
    // Enumerate all processes matching the given executable path (case-insensitive).
    // If target_exe is empty, enumerates all processes.
    static std::vector<ProcessInfo> enumerate(const std::wstring& target_exe = L"");

    // Find all processes with matching executable name.
    static std::vector<ProcessInfo> find_by_name(const std::wstring& exe_name);

    // Find self process info.
    static ProcessInfo self();

    // Get detailed info for a specific PID.
    static bool get_process_info(DWORD pid, ProcessInfo& out);

private:
    static bool is_path_match(const std::wstring& a, const std::wstring& b);
    static bool get_process_name(HANDLE hproc, std::wstring& out_name, std::wstring& out_path);
    static SIZE_T get_working_set(HANDLE hproc);
};

// ============================================================================
// Process verifier (host-owned, model-independent)
// ============================================================================

struct VerificationResult {
    bool verified = false;
    std::wstring reason;
    ProcessInfo info;
};

// Verification policy for stale process detection.
struct VerificationPolicy {
    bool require_accessible = true;        // Must be able to open with PROCESS_QUERY_LIMITED_INFORMATION
    bool require_path_match = true;        // Must match expected executable path
    bool allow_self = false;               // Allow current process
    bool require_job_assigned = false;     // Must belong to RawrXD job
    std::wstring expected_exe;             // Required executable path
};

class ProcessVerifier {
public:
    explicit ProcessVerifier(const VerificationPolicy& policy = {});

    // Verify a single process against policy.
    VerificationResult verify(DWORD pid) const;

    // Verify all processes matching the executable.
    std::vector<VerificationResult> verify_all() const;

private:
    VerificationPolicy policy_;
};

// ============================================================================
// Job Object wrapper for automatic child cleanup (optional)
// ============================================================================

class JobObject {
public:
    JobObject();
    ~JobObject();

    // Non-copyable
    JobObject(const JobObject&) = delete;
    JobObject& operator=(const JobObject&) = delete;
    JobObject(JobObject&&) noexcept;
    JobObject& operator=(JobObject&&) noexcept;

    // Create the job object with KILL_ON_JOB_CLOSE.
    bool create(const std::wstring& name = L"");

    // Assign current process to the job (for child inheritance).
    bool assign_self();

    // Assign a specific process to the job.
    bool assign_process(DWORD pid);

    // Check if job is valid.
    explicit operator bool() const { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }

    // Get the job handle for direct use.
    HANDLE handle() const { return handle_; }

private:
    HANDLE handle_ = nullptr;
    bool owns_ = false;
};

// ============================================================================
// Process termination (host-owned, explicit confirmation required)
// ============================================================================

struct TerminationResult {
    bool success = false;
    DWORD pid = 0;
    std::wstring reason;
    DWORD exit_code = 0;
};

// Termination policy - explicit confirmation required.
struct TerminationPolicy {
    bool require_confirmation = true;      // Must be explicitly confirmed
    bool use_graceful_first = true;        // Try graceful cancellation first
    DWORD graceful_timeout_ms = 5000;      // Timeout for graceful shutdown
    bool allow_self = false;               // Allow terminating self
};

class ProcessTerminator {
public:
    explicit ProcessTerminator(const TerminationPolicy& policy = {});

    // Attempt to terminate a process.
    // Requires explicit confirmation unless policy.require_confirmation is false.
    TerminationResult terminate(DWORD pid, bool confirmed = false) const;

    // Attempt graceful termination via CTRL_C_EVENT to the process group.
    bool try_graceful(DWORD pid, DWORD timeout_ms) const;

private:
    TerminationPolicy policy_;
};

// ============================================================================
// Stale process scanner with Agent ESP event emission
// ============================================================================

struct StaleProcessReport {
    std::vector<ProcessInfo> candidates;
    std::vector<std::wstring> warnings;
    bool contention_detected = false;
};

class StaleProcessScanner {
public:
    // Configuration for stale process detection.
    struct Config {
        std::wstring target_exe;           // Executable to scan for
        SIZE_T ram_warning_mb = 1024;      // Warn if working set exceeds this (MB)
        bool check_job_membership = true;  // Check job object membership
        bool emit_esp_events = true;       // Emit Agent ESP events
    };

    explicit StaleProcessScanner(const Config& config = {});

    // Scan for stale processes matching target executable.
    StaleProcessReport scan() const;

    // Emit Agent ESP events for the scan results (if enabled).
    void emit_esp_events(const StaleProcessReport& report) const;

private:
    Config config_;
};

// ============================================================================
// CLI entry point (snap_process_guard_cli.cpp provides the main)
// ============================================================================

// Run the CLI with the given arguments.
// Returns 0 on success, non-zero on error.
int run_cli(int argc, wchar_t* argv[]);

}  // namespace snap::process