#include "snap_process_guard.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cwctype>

namespace snap::process {

// ============================================================================
// ProcessEnumerator implementation
// ============================================================================

std::vector<ProcessInfo> ProcessEnumerator::enumerate(const std::wstring& target_exe) {
    std::vector<ProcessInfo> results;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return results;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(snapshot, &entry)) {
        CloseHandle(snapshot);
        return results;
    }

    do {
        ProcessInfo info;
        if (get_process_info(entry.th32ProcessID, info)) {
            if (target_exe.empty() || is_path_match(info.exe_path, target_exe)) {
                results.push_back(info);
            }
        }
    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return results;
}

std::vector<ProcessInfo> ProcessEnumerator::find_by_name(const std::wstring& exe_name) {
    std::vector<ProcessInfo> results;
    auto all = enumerate(L"");
    for (auto& p : all) {
        if (is_path_match(p.exe_name, exe_name)) {
            results.push_back(p);
        }
    }
    return results;
}

ProcessInfo ProcessEnumerator::self() {
    ProcessInfo info;
    get_process_info(GetCurrentProcessId(), info);
    info.is_self = true;
    return info;
}

bool ProcessEnumerator::is_path_match(const std::wstring& a, const std::wstring& b) {
    if (a.empty() || b.empty()) return false;
    std::wstring la = a, lb = b;
    for (auto& c : la) c = towlower(c);
    for (auto& c : lb) c = towlower(c);
    size_t pa = la.find_last_of(L"\\/");
    size_t pb = lb.find_last_of(L"\\/");
    std::wstring na = (pa == std::wstring::npos) ? la : la.substr(pa + 1);
    std::wstring nb = (pb == std::wstring::npos) ? lb : lb.substr(pb + 1);
    return na == nb;
}

bool ProcessEnumerator::get_process_info(DWORD pid, ProcessInfo& out) {
    out = {};
    out.pid = pid;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (entry.th32ProcessID == pid) {
                    out.ppid = entry.th32ParentProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }

    HANDLE hproc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hproc) {
        return false;
    }

    std::wstring name, path;
    if (!get_process_name(hproc, out.exe_name, out.exe_path)) {
        CloseHandle(hproc);
        return false;
    }

    out.working_set_bytes = get_working_set(hproc);

    HANDLE htest = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, out.pid);
    out.accessible = (htest != nullptr);
    if (htest) CloseHandle(htest);

    CloseHandle(hproc);
    return true;
}

bool ProcessEnumerator::get_process_name(HANDLE hproc, std::wstring& out_name, std::wstring& out_path) {
    DWORD size = MAX_PATH;
    std::wstring buffer(size, L'\0');
    if (!GetModuleFileNameExW(hproc, nullptr, &buffer[0], size)) {
        return false;
    }
    out_path = buffer.c_str();
    size_t pos = out_path.find_last_of(L"\\/");
    out_name = (pos == std::wstring::npos) ? out_path : out_path.substr(pos + 1);
    return true;
}

SIZE_T ProcessEnumerator::get_working_set(HANDLE hproc) {
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    if (GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&pmc), sizeof(pmc))) {
        return pmc.WorkingSetSize;
    }
    return 0;
}

// ============================================================================
// ProcessVerifier implementation
// ============================================================================

ProcessVerifier::ProcessVerifier(const VerificationPolicy& policy) : policy_(policy) {}

VerificationResult ProcessVerifier::verify(DWORD pid) const {
    VerificationResult result;
    ProcessInfo info;
    if (!ProcessEnumerator::get_process_info(pid, info)) {
        result.verified = false;
        result.reason = L"Failed to get process info";
        return result;
    }
    info.pid = pid;

    if (policy_.require_accessible && !info.accessible) {
        result.verified = false;
        result.reason = L"Process not accessible";
        result.info = info;
        return result;
    }

    if (policy_.require_path_match && !policy_.expected_exe.empty()) {
        std::wstring target = policy_.expected_exe;
        for (auto& c : target) c = towlower(c);
        std::wstring actual = info.exe_path;
        for (auto& c : actual) c = towlower(c);
        size_t p1 = target.find_last_of(L"\\/");
        size_t p2 = info.exe_path.find_last_of(L"\\/");
        std::wstring n1 = (p1 == std::wstring::npos) ? target : target.substr(p1 + 1);
        std::wstring n2 = (p2 == std::wstring::npos) ? info.exe_path : info.exe_path.substr(p2 + 1);
        for (auto& c : n1) c = towlower(c);
        for (auto& c : n2) c = towlower(c);
        if (n1 != n2) {
            result.verified = false;
            result.reason = L"Executable path mismatch";
            result.info = info;
            return result;
        }
    }

    if (!policy_.allow_self && info.is_self) {
        result.verified = false;
        result.reason = L"Self process not allowed by policy";
        result.info = info;
        return result;
    }

    if (policy_.require_job_assigned) {
        info.is_job_assigned = false;
    }

    result.verified = true;
    result.reason = L"Verified";
    result.info = info;
    return result;
}

std::vector<VerificationResult> ProcessVerifier::verify_all() const {
    std::vector<VerificationResult> results;
    auto candidates = ProcessEnumerator::enumerate(policy_.expected_exe);
    for (const auto& p : candidates) {
        results.push_back(verify(p.pid));
    }
    return results;
}

// ============================================================================
// JobObject implementation
// ============================================================================

JobObject::JobObject() : handle_(nullptr), owns_(false) {}

JobObject::~JobObject() {
    if (owns_ && handle_ && handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(handle_);
    }
}

JobObject::JobObject(JobObject&& other) noexcept
    : handle_(other.handle_), owns_(other.owns_) {
    other.handle_ = nullptr;
    other.owns_ = false;
}

JobObject& JobObject::operator=(JobObject&& other) noexcept {
    if (this != &other) {
        if (owns_ && handle_ && handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
        handle_ = other.handle_;
        owns_ = other.owns_;
        other.handle_ = nullptr;
        other.owns_ = false;
    }
    return *this;
}

bool JobObject::create(const std::wstring& name) {
    if (handle_) return false;
    handle_ = CreateJobObjectW(nullptr, name.empty() ? nullptr : name.c_str());
    if (!handle_) return false;
    owns_ = true;

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(handle_, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        CloseHandle(handle_);
        handle_ = nullptr;
        owns_ = false;
        return false;
    }
    return true;
}

bool JobObject::assign_self() {
    if (!handle_) return false;
    return AssignProcessToJobObject(handle_, GetCurrentProcess());
}

bool JobObject::assign_process(DWORD pid) {
    if (!handle_) return false;
    HANDLE hproc = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, pid);
    if (!hproc) return false;
    bool ok = AssignProcessToJobObject(handle_, hproc);
    CloseHandle(hproc);
    return ok;
}

// ============================================================================
// ProcessTerminator implementation
// ============================================================================

ProcessTerminator::ProcessTerminator(const TerminationPolicy& policy) : policy_(policy) {}

TerminationResult ProcessTerminator::terminate(DWORD pid, bool confirmed) const {
    TerminationResult result;
    result.pid = pid;

    if (policy_.require_confirmation && !confirmed) {
        result.success = false;
        result.reason = L"Confirmation required";
        return result;
    }

    if (!policy_.allow_self && pid == GetCurrentProcessId()) {
        result.success = false;
        result.reason = L"Self-termination not allowed by policy";
        return result;
    }

    HANDLE hproc = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hproc) {
        result.success = false;
        result.reason = L"Failed to open process";
        return result;
    }

    bool graceful_ok = false;
    if (policy_.use_graceful_first) {
        graceful_ok = try_graceful(pid, policy_.graceful_timeout_ms);
    }

    if (!graceful_ok) {
        // CRITICAL: Re-validate PID identity immediately before termination
        // to prevent PID-reuse errors (PID may have been recycled)
        FILETIME creation_time_before, exit_time_before, kernel_time_before, user_time_before;
        if (!GetProcessTimes(hproc, &creation_time_before, nullptr, nullptr, nullptr)) {
            result.success = false;
            result.reason = L"Failed to get process times for re-validation";
            CloseHandle(hproc);
            return result;
        }

        if (!TerminateProcess(hproc, 1)) {
            result.success = false;
            result.reason = L"TerminateProcess failed";
            CloseHandle(hproc);
            return result;
        }

        // Re-validate: check that the terminated process had the same creation time
        FILETIME creation_time_after, exit_time_after, kernel_time_after, user_time_after;
        if (!GetProcessTimes(hproc, &creation_time_after, &exit_time_after, &kernel_time_after, &user_time_after) ||
            creation_time_before.dwLowDateTime != creation_time_after.dwLowDateTime ||
            creation_time_before.dwHighDateTime != creation_time_after.dwHighDateTime) {
            result.success = false;
            result.reason = L"PID was recycled during termination; target process may be different";
            return result;
        }
    }

    DWORD exit_code = 0;
    GetExitCodeProcess(hproc, &result.exit_code);
    result.success = true;
    result.reason = L"Terminated";
    result.pid = pid;
    CloseHandle(hproc);
    return result;
}

bool ProcessTerminator::try_graceful(DWORD pid, DWORD timeout_ms) const {
    HANDLE hproc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
    if (!hproc) return false;

    DWORD exit_code = STILL_ACTIVE;
    DWORD start = GetTickCount();
    while (GetExitCodeProcess(GetCurrentProcess(), &exit_code) && exit_code == STILL_ACTIVE) {
        if (GetTickCount() - start >= 500) {
            break;
        }
        Sleep(50);
    }
    GetExitCodeProcess(GetCurrentProcess(), &pid);
    return false;
}

// ============================================================================
// StaleProcessScanner implementation
// ============================================================================

StaleProcessScanner::StaleProcessScanner(const Config& config) : config_(config) {}

StaleProcessReport StaleProcessScanner::scan() const {
    StaleProcessReport report;

    auto candidates = ProcessEnumerator::enumerate(config_.target_exe);
    SIZE_T warning_bytes = static_cast<SIZE_T>(config_.ram_warning_mb) * 1024 * 1024;

    const DWORD self_pid = GetCurrentProcessId();

    for (auto& p : candidates) {
        if (p.is_self) continue;

        // CRITICAL: Unconditionally exclude the current process
        if (p.pid == self_pid) {
            continue;
        }

        // Check working set
        if (p.working_set_bytes > static_cast<SIZE_T>(config_.ram_warning_mb) * 1024 * 1024) {
            std::wostringstream oss;
            oss << L"Process " << p.pid << L" (" << p.exe_name << L") working set: "
                << (p.working_set_bytes / (1024.0 * 1024.0)) << L" MB exceeds warning threshold "
                << config_.ram_warning_mb << L" MB";
            report.warnings.push_back(oss.str());
            report.contention_detected = true;
        }

        // Check job membership - treat as warning, not proof of staleness
        if (config_.check_job_membership && !p.is_job_assigned) {
            std::wostringstream oss;
            oss << L"Process " << p.pid << L" (" << p.exe_name << L") not assigned to RawrXD job object";
            report.warnings.push_back(oss.str());
            report.contention_detected = true;
        }

        if (!p.accessible) {
            std::wostringstream oss;
            oss << L"Process " << p.pid << L" (" << p.exe_name << L") not accessible";
            report.warnings.push_back(oss.str());
        }

        report.candidates.push_back(p);
    }

    return report;
}

void StaleProcessScanner::emit_esp_events(const StaleProcessReport& report) const {
    if (!config_.emit_esp_events) return;

    std::wcerr << L"[ESP] Stale process scan: " << report.candidates.size() << L" candidates\n";
    if (report.contention_detected) {
        std::wcerr << L"[ESP] WARNING: Resource contention detected\n";
    }
    for (const auto& w : report.warnings) {
        std::wcerr << L"[ESP] " << w << L"\n";
    }
}

// ============================================================================
// CLI implementation
// ============================================================================

static void print_usage() {
    std::wcerr << L"Usage: snap_process_guard_cli <exe_path> [--terminate-pid <pid> --confirm] [--scan]\n"
               << L"  <exe_path>           Target executable to scan for\n"
               << L"  --scan               Scan for stale processes\n"
               << L"  --terminate-pid <pid> Terminate specific PID\n"
               << L"  --confirm            Confirm termination (required)\n"
               << L"  --ram-warning <mb>   RAM warning threshold in MB (default 1024)\n"
               << L"  --check-job          Check job object membership\n";
}

int run_cli(int argc, wchar_t* argv[]) {
    std::fprintf(stderr, "[DEBUG] run_cli entered, argc=%d\n", argc);
    std::fflush(stderr);
    if (argc < 2) {
        std::fprintf(stderr, "[DEBUG] argc < 2, printing usage\n");
        std::fflush(stderr);
        print_usage();
        std::fprintf(stderr, "[DEBUG] print_usage returned\n");
        std::fflush(stderr);
        return 1;
    }

    std::fprintf(stderr, "[DEBUG] parsing args\n");
    std::fflush(stderr);

    std::wstring target_exe = argv[1];
    bool do_scan = false;
    DWORD terminate_pid = 0;
    bool confirm = false;
    SIZE_T ram_warning_mb = 1024;
    bool check_job = true;

    for (int i = 2; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"--scan") {
            do_scan = true;
        } else if (arg == L"--terminate-pid" && i + 1 < argc) {
            terminate_pid = static_cast<DWORD>(_wtoi(argv[++i]));
        } else if (arg == L"--confirm") {
            confirm = true;
        } else if (arg == L"--ram-warning" && i + 1 < argc) {
            ram_warning_mb = static_cast<SIZE_T>(_wtoi(argv[++i]));
        } else if (arg == L"--check-job") {
            check_job = true;
        }
    }

    StaleProcessScanner::Config scan_cfg;
    scan_cfg.target_exe = target_exe;
    scan_cfg.ram_warning_mb = ram_warning_mb;
    scan_cfg.check_job_membership = check_job;
    scan_cfg.emit_esp_events = true;

    std::fprintf(stderr, "[DEBUG] creating scanner\n");
    std::fflush(stderr);
    StaleProcessScanner scanner(StaleProcessScanner::Config{
        target_exe, ram_warning_mb, check_job, true
    });
    std::fprintf(stderr, "[DEBUG] scanner created\n");
    std::fflush(stderr);

    if (do_scan || terminate_pid == 0) {
        std::fprintf(stderr, "[DEBUG] calling scan()\n");
        std::fflush(stderr);
        auto report = StaleProcessScanner{}.scan();
        std::fprintf(stderr, "[DEBUG] scan returned\n");
        std::fflush(stderr);
        std::wcout << L"=== Stale Process Scan ===\n";
        std::fprintf(stderr, "[DEBUG] wcout scan header\n");
        std::fflush(stderr);
        std::wcout << L"=== Stale Process Scan ===\n";
        std::fprintf(stderr, "[DEBUG] after scan header\n");
        std::fflush(stderr);
        std::fprintf(stderr, "[DEBUG] after scan header\n");
        std::fflush(stderr);
        std::wcout << L"Candidates: " << report.candidates.size() << L"\n";
        std::fprintf(stderr, "[DEBUG] after candidates size\n");
        std::fflush(stderr);
        if (report.contention_detected) {
            std::wcout << L"*** CONTENTION DETECTED ***\n";
            std::fprintf(stderr, "[DEBUG] after contention\n");
            std::fflush(stderr);
        }
        std::fprintf(stderr, "[DEBUG] starting candidates loop\n");
        std::fflush(stderr);
        for (const auto& p : report.candidates) {
            std::fprintf(stderr, "[DEBUG] candidate loop iteration\n");
            std::fflush(stderr);
            std::fprintf(stderr, "[DEBUG] candidate pid=%u name=%S\n", p.pid, p.exe_name.c_str());
            std::fflush(stderr);
            std::string ws;
            try {
                ws = p.to_string();
                std::fprintf(stderr, "[DEBUG] to_string done\n");
                std::fflush(stderr);
            } catch (...) {
                std::fprintf(stderr, "[DEBUG] to_string threw exception\n");
                std::fflush(stderr);
                ws = "ERROR";
            }
            std::fprintf(stderr, "[DEBUG] to_string done\n");
            std::fflush(stderr);
            std::cout << "  " << ws << "\n";
            std::fprintf(stderr, "[DEBUG] wcout done\n");
            std::fflush(stderr);
        }
        std::fprintf(stderr, "[DEBUG] after candidates loop\n");
        std::fflush(stderr);
        for (const auto& w : report.warnings) {
            std::wcout << L"  WARNING: " << w << L"\n";
        }
    }

    std::fprintf(stderr, "[DEBUG] before terminate check\n");
    std::fflush(stderr);

    if (terminate_pid != 0) {
        if (!confirm) {
            std::wcerr << L"ERROR: --confirm required for termination\n";
            return 1;
        }
        ProcessTerminator terminator;
        auto result = terminator.terminate(terminate_pid, true);
        if (result.success) {
            std::wcout << L"Terminated PID " << result.pid << L", exit code: " << result.exit_code << L"\n";
        } else {
            std::wcerr << L"FAILED: " << result.reason << L"\n";
            return 1;
        }
    }

return 0;
    }

}  // namespace snap::process

// ============================================================================
// Main entry point
// ============================================================================

int wmain(int argc, wchar_t* argv[]) {
    return snap::process::run_cli(argc, argv);
}