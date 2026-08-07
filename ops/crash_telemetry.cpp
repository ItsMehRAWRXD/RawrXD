#include "crash_telemetry.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace RawrXD::Ops {

void CrashTelemetry::Initialize() {
    std::lock_guard<std::mutex> lock(mutex_);
    enabled_ = true;
    // Load any pending crash reports from disk
    std::ifstream file("crash_pending.json");
    if (file.is_open()) {
        // Parse and load pending reports
        file.close();
    }
}

void CrashTelemetry::RecordCrash(const std::string& module, const std::string& stacktrace) {
    RecordCrash(module, "Unknown fault", stacktrace);
}

void CrashTelemetry::RecordCrash(const std::string& module, const std::string& fault_reason, const std::string& stacktrace) {
    if (!enabled_) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    CrashReport report;
    report.module = module;
    report.fault_reason = fault_reason;
    report.stacktrace = stacktrace;
    report.timestamp = std::chrono::system_clock::now();
    report.recovered = false;
    
    pending_.push_back(report);
    history_.push_back(report);
    
    if (crash_callback_) {
        crash_callback_(report);
    }
}

void CrashTelemetry::UploadPending() {
    std::lock_guard<std::mutex> lock(mutex_);
    // In production, this would upload to a telemetry endpoint
    // For now, we save to disk
    std::ofstream file("crash_uploaded.log", std::ios::app);
    for (const auto& report : pending_) {
        auto time_t = std::chrono::system_clock::to_time_t(report.timestamp);
        file << "CRASH: " << report.module << " | "
             << report.fault_reason << " | "
             << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << "\n";
    }
    pending_.clear();
}

void CrashTelemetry::Disable() {
    std::lock_guard<std::mutex> lock(mutex_);
    enabled_ = false;
}

std::vector<CrashReport> CrashTelemetry::GetRecent(int count) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<CrashReport> result;
    int start = std::max(0, (int)history_.size() - count);
    for (int i = start; i < (int)history_.size(); ++i) {
        result.push_back(history_[i]);
    }
    return result;
}

void CrashTelemetry::SetCrashCallback(std::function<void(const CrashReport&)> cb) {
    crash_callback_ = std::move(cb);
}

} // namespace RawrXD::Ops
