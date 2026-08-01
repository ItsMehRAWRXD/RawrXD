#pragma once
#include <string>
#include <vector>
#include <chrono>
#include <mutex>
#include <functional>

namespace RawrXD::Ops {

struct CrashReport {
    std::string module;
    std::string fault_reason;
    std::string stacktrace;
    std::string gpu_info;
    std::chrono::system_clock::time_point timestamp;
    bool recovered = false;
};

class CrashTelemetry {
public:
    void Initialize();
    void RecordCrash(const std::string& module, const std::string& stacktrace);
    void RecordCrash(const std::string& module, const std::string& fault_reason, const std::string& stacktrace);
    void UploadPending();
    void Disable();
    bool IsEnabled() const { return enabled_; }
    std::vector<CrashReport> GetRecent(int count = 50) const;
    void SetCrashCallback(std::function<void(const CrashReport&)> cb);

private:
    bool enabled_ = true;
    std::vector<CrashReport> pending_;
    std::vector<CrashReport> history_;
    mutable std::mutex mutex_;
    std::function<void(const CrashReport&)> crash_callback_;
};

} // namespace RawrXD::Ops
