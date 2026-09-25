#include "DiagnosticsEngine.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <map>
#include <mutex>
#include <algorithm>

namespace rawrxd::diagnostics {

class DiagnosticsEngine::Impl {
public:
    mutable std::mutex mutex_;
    bool initialized_ = false;
    std::vector<DiagnosticRecord> records_;
    std::vector<DiagnosticRule> rules_;
    std::map<std::string, std::chrono::steady_clock::time_point> timers_;
    DiagnosticsEngine::RecordCallback record_cb_;
    std::function<void(const DiagnosticRecord&)> fatal_handler_;
    uint64_t next_id_ = 1;

    bool MatchesRule(const DiagnosticRecord& rec, const DiagnosticRule& rule) const {
        if (rule.min_severity.has_value() && rec.severity < rule.min_severity.value()) return false;
        if (rule.category_filter.has_value() && rec.category != rule.category_filter.value()) return false;
        if (rule.message_regex.has_value() && rec.message.find(rule.message_regex.value()) == std::string::npos) return false;
        return true;
    }

    void ProcessRecord(const DiagnosticRecord& rec) {
        for (const auto& rule : rules_) {
            if (MatchesRule(rec, rule)) {
                if (rule.suppress) return;
                if (rule.trigger_breakpoint) {
                    // Breakpoint placeholder
                }
            }
        }
        if (record_cb_) record_cb_(rec);
        if (rec.severity == Severity::Fatal && fatal_handler_) {
            fatal_handler_(rec);
        }
    }
};

DiagnosticsEngine::DiagnosticsEngine() : impl_(std::make_unique<Impl>()) {}
DiagnosticsEngine::~DiagnosticsEngine() = default;

bool DiagnosticsEngine::Initialize(const std::string& /*config_json*/) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->initialized_.store(true);
    return true;
}

void DiagnosticsEngine::Shutdown() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->initialized_.store(false);
    impl_->records_.clear();
}

bool DiagnosticsEngine::IsInitialized() const {
    return impl_->initialized_.load();
}

void DiagnosticsEngine::Log(Severity severity, Category category, const std::string& message,
                                const std::string& source_loc) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    DiagnosticRecord rec;
    rec.id = impl_->next_id_++;
    rec.severity = severity;
    rec.category = category;
    rec.message = message;
    rec.source_location = source_loc;
    rec.timestamp_us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    impl_->records_.push_back(rec);
    impl_->ProcessRecord(rec);
}

void DiagnosticsEngine::LogVerbose(const std::string& msg, const std::string& src) {
    Log(Severity::Verbose, Category::General, msg, src);
}

void DiagnosticsEngine::LogInfo(const std::string& msg, const std::string& src) {
    Log(Severity::Info, Category::General, msg, src);
}

void DiagnosticsEngine::LogWarning(const std::string& msg, const std::string& src) {
    Log(Severity::Warning, Category::General, msg, src);
}

void DiagnosticsEngine::LogError(const std::string& msg, const std::string& src) {
    Log(Severity::Error, Category::General, msg, src);
}

void DiagnosticsEngine::LogFatal(const std::string& msg, const std::string& src) {
    Log(Severity::Fatal, Category::General, msg, src);
}

void DiagnosticsEngine::AddRule(const DiagnosticRule& rule) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->rules_.push_back(rule);
}

void DiagnosticsEngine::ClearRules() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->rules_.clear();
}

bool DiagnosticsEngine::ShouldSuppress(Severity sev, Category cat, const std::string& msg) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    DiagnosticRecord rec;
    rec.severity = sev;
    rec.category = cat;
    rec.message = msg;
    for (const auto& rule : impl_->rules_) {
        if (impl_->MatchesRule(rec, rule) && rule.suppress) return true;
    }
    return false;
}

std::vector<DiagnosticRecord> DiagnosticsEngine::GetRecords(Severity min_severity, Category cat) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<DiagnosticRecord> out;
    for (const auto& r : impl_->records_) {
        if (r.severity >= min_severity && r.category == cat) out.push_back(r);
    }
    return out;
}

std::vector<DiagnosticRecord> DiagnosticsEngine::GetRecentRecords(size_t count) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    size_t n = std::min(count, impl_->records_.size());
    return std::vector<DiagnosticRecord>(impl_->records_.end() - n, impl_->records_.end());
}

size_t DiagnosticsEngine::GetCount(Severity min_severity) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    size_t count = 0;
    for (const auto& r : impl_->records_) {
        if (r.severity >= min_severity) count++;
    }
    return count;
}

size_t DiagnosticsEngine::GetErrorCount() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    size_t count = 0;
    for (const auto& r : impl_->records_) {
        if (r.severity >= Severity::Error) count++;
    }
    return count;
}

size_t DiagnosticsEngine::GetWarningCount() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    size_t count = 0;
    for (const auto& r : impl_->records_) {
        if (r.severity == Severity::Warning) count++;
    }
    return count;
}

void DiagnosticsEngine::SetRecordCallback(RecordCallback cb) {
    impl_->record_cb_ = std::move(cb);
}

void DiagnosticsEngine::SetFatalHandler(std::function<void(const DiagnosticRecord&)> handler) {
    impl_->fatal_handler_ = std::move(handler);
}

bool DiagnosticsEngine::SaveToFile(const std::string& path) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::ofstream ofs(path);
    if (!ofs) return false;
    ofs << ExportJSON();
    return ofs.good();
}

bool DiagnosticsEngine::LoadFromFile(const std::string& /*path*/) {
    // TODO: implement JSON deserialization
    return false;
}

std::string DiagnosticsEngine::ExportJSON() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::ostringstream oss;
    oss << "[\n";
    for (size_t i = 0; i < impl_->records_.size(); ++i) {
        const auto& r = impl_->records_[i];
        oss << "  {\n";
        oss << "    \"id\": " << r.id << ",\n";
        oss << "    \"severity\": \"" << SeverityToString(r.severity) << "\",\n";
        oss << "    \"category\": \"" << CategoryToString(r.category) << "\",\n";
        oss << "    \"message\": \"" << r.message << "\",\n";
        oss << "    \"source\": \"" << r.source_location << "\"\n";
        oss << "  }";
        if (i + 1 < impl_->records_.size()) oss << ",";
        oss << "\n";
    }
    oss << "]\n";
    return oss.str();
}

const char* DiagnosticsEngine::SeverityToString(Severity s) {
    switch (s) {
        case Severity::Verbose: return "verbose";
        case Severity::Info: return "info";
        case Severity::Warning: return "warning";
        case Severity::Error: return "error";
        case Severity::Fatal: return "fatal";
        default: return "unknown";
    }
}

const char* DiagnosticsEngine::CategoryToString(Category c) {
    switch (c) {
        case Category::General: return "general";
        case Category::Initialization: return "initialization";
        case Category::ModelLoading: return "model_loading";
        case Category::Inference: return "inference";
        case Category::Quantization: return "quantization";
        case Category::GPU: return "gpu";
        case Category::Memory: return "memory";
        case Category::Network: return "network";
        case Category::Configuration: return "configuration";
        case Category::Performance: return "performance";
        case Category::Security: return "security";
        case Category::Validation: return "validation";
        default: return "unknown";
    }
}

Severity DiagnosticsEngine::SeverityFromString(const std::string& s) {
    if (s == "verbose") return Severity::Verbose;
    if (s == "info") return Severity::Info;
    if (s == "warning") return Severity::Warning;
    if (s == "error") return Severity::Error;
    if (s == "fatal") return Severity::Fatal;
    return Severity::Info;
}

Category DiagnosticsEngine::CategoryFromString(const std::string& s) {
    if (s == "general") return Category::General;
    if (s == "initialization") return Category::Initialization;
    if (s == "model_loading") return Category::ModelLoading;
    if (s == "inference") return Category::Inference;
    if (s == "quantization") return Category::Quantization;
    if (s == "gpu") return Category::GPU;
    if (s == "memory") return Category::Memory;
    if (s == "network") return Category::Network;
    if (s == "configuration") return Category::Configuration;
    if (s == "performance") return Category::Performance;
    if (s == "security") return Category::Security;
    if (s == "validation") return Category::Validation;
    return Category::General;
}

void DiagnosticsEngine::BeginTimer(const std::string& name) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->timers_[name] = std::chrono::steady_clock::now();
}

void DiagnosticsEngine::EndTimer(const std::string& name) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->timers_.find(name);
    if (it != impl_->timers_.end()) {
        // Keep end timestamp in map for GetElapsedMs
        impl_->timers_[name] = std::chrono::steady_clock::now();
    }
}

std::optional<float> DiagnosticsEngine::GetElapsedMs(const std::string& name) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->timers_.find(name);
    if (it == impl_->timers_.end()) return std::nullopt;
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(now - it->second);
    return elapsed.count() / 1000.0f;
}

void DiagnosticsEngine::ResetTimers() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->timers_.clear();
}

} // namespace rawrxd::diagnostics
