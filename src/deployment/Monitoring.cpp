#include "rawrxd/deployment/Monitoring.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <fstream>

namespace rawrxd {
namespace deployment {

// MetricsCollector implementation
MetricsCollector& MetricsCollector::GetInstance() {
    static MetricsCollector instance;
    return instance;
}

bool MetricsCollector::Initialize(const std::string& endpoint, const std::string& jobName) {
    endpoint_ = endpoint;
    jobName_ = jobName;
    return true;
}

void MetricsCollector::Counter(const std::string& name, double value,
                                const std::map<std::string, std::string>& labels) {
    RecordObservation(name, MetricType::COUNTER, value, labels);
}

void MetricsCollector::Gauge(const std::string& name, double value,
                              const std::map<std::string, std::string>& labels) {
    RecordObservation(name, MetricType::GAUGE, value, labels);
}

void MetricsCollector::Histogram(const std::string& name, double value,
                                  const std::map<std::string, std::string>& labels) {
    RecordObservation(name, MetricType::HISTOGRAM, value, labels);
}

void MetricsCollector::Summary(const std::string& name, double value,
                                const std::map<std::string, std::string>& labels) {
    RecordObservation(name, MetricType::SUMMARY, value, labels);
}

std::unique_ptr<MetricsCollector::Timer> MetricsCollector::NewTimer(
    const std::string& name, const std::map<std::string, std::string>& labels) {
    return std::make_unique<Timer>(name, this, labels);
}

void MetricsCollector::RecordObservation(const std::string& name, MetricType type,
                                        double value, const std::map<std::string, std::string>& labels) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto& dataVec = metrics_[name];
    
    // Find existing entry with same labels
    auto it = std::find_if(dataVec.begin(), dataVec.end(),
        [&labels](const MetricData& data) {
            return data.labels == labels;
        });
    
    if (it != dataVec.end()) {
        // Update existing
        if (type == MetricType::COUNTER) {
            it->value += value;
        } else {
            it->value = value;
        }
        it->observations.push_back(value);
    } else {
        // Create new
        MetricData data;
        data.type = type;
        data.value = value;
        data.labels = labels;
        data.observations.push_back(value);
        dataVec.push_back(data);
    }
}

std::string MetricsCollector::ExportPrometheusFormat() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::stringstream ss;
    ss << "# HELP rawrxd_metrics RawrXD metrics\n";
    ss << "# TYPE rawrxd_metrics gauge\n";
    
    for (const auto& pair : metrics_) {
        const std::string& name = pair.first;
        const auto& dataVec = pair.second;
        
        for (const auto& data : dataVec) {
            ss << name;
            
            // Add labels
            if (!data.labels.empty()) {
                ss << "{";
                bool first = true;
                for (const auto& label : data.labels) {
                    if (!first) ss << ",";
                    ss << label.first << "=\"" << label.second << "\"";
                    first = false;
                }
                ss << "}";
            }
            
            ss << " " << data.value << "\n";
        }
    }
    
    return ss.str();
}

std::string MetricsCollector::ExportJSON() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::stringstream ss;
    ss << "{\n";
    
    bool first = true;
    for (const auto& pair : metrics_) {
        if (!first) ss << ",\n";
        first = false;
        
        ss << "  \"" << pair.first << "\": [\n";
        
        bool firstData = true;
        for (const auto& data : pair.second) {
            if (!firstData) ss << ",\n";
            firstData = false;
            
            ss << "    {\n";
            ss << "      \"value\": " << data.value << ",\n";
            ss << "      \"labels\": {";
            
            bool firstLabel = true;
            for (const auto& label : data.labels) {
                if (!firstLabel) ss << ", ";
                firstLabel = false;
                ss << "\"" << label.first << "\": \"" << label.second << "\"";
            }
            
            ss << "}\n";
            ss << "    }";
        }
        
        ss << "\n  ]";
    }
    
    ss << "\n}\n";
    return ss.str();
}

void MetricsCollector::ExportToFile(const std::string& path) {
    std::ofstream file(path);
    if (file.is_open()) {
        file << ExportPrometheusFormat();
        file.close();
    }
}

double MetricsCollector::GetMetricValue(const std::string& name,
                                        const std::map<std::string, std::string>& labels) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = metrics_.find(name);
    if (it != metrics_.end()) {
        for (const auto& data : it->second) {
            if (data.labels == labels) {
                return data.value;
            }
        }
    }
    
    return 0.0;
}

void MetricsCollector::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    metrics_.clear();
}

// Timer implementation
MetricsCollector::Timer::Timer(const std::string& name, MetricsCollector* collector,
                                const std::map<std::string, std::string>& labels)
    : name_(name), collector_(collector), labels_(labels) {
    start_ = std::chrono::high_resolution_clock::now();
}

MetricsCollector::Timer::~Timer() {
    if (!stopped_) {
        Stop();
    }
}

void MetricsCollector::Timer::Stop() {
    if (stopped_) return;
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration<double, std::milli>(end - start_).count();
    
    collector_->Histogram(name_, duration, labels_);
    stopped_ = true;
}

double MetricsCollector::Timer::ElapsedMs() const {
    auto now = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double, std::milli>(now - start_).count();
}

// HealthChecker implementation
HealthChecker::~HealthChecker() {
    Stop();
}

HealthChecker& HealthChecker::GetInstance() {
    static HealthChecker instance;
    return instance;
}

void HealthChecker::RegisterCheck(const std::string& name,
                                   std::function<HealthStatus()> check,
                                   std::chrono::seconds interval,
                                   std::chrono::seconds timeout) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    HealthCheck hc;
    hc.name = name;
    hc.check = check;
    hc.interval = interval;
    hc.timeout = timeout;
    
    checks_[name] = hc;
}

void HealthChecker::UnregisterCheck(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    checks_.erase(name);
}

HealthChecker::HealthStatus HealthChecker::GetHealth() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    bool hasUnhealthy = false;
    bool hasDegraded = false;
    
    for (const auto& pair : results_) {
        if (pair.second == HealthStatus::UNHEALTHY) {
            hasUnhealthy = true;
        } else if (pair.second == HealthStatus::DEGRADED) {
            hasDegraded = true;
        }
    }
    
    if (hasUnhealthy) return HealthStatus::UNHEALTHY;
    if (hasDegraded) return HealthStatus::DEGRADED;
    return HealthStatus::HEALTHY;
}

std::map<std::string, HealthChecker::HealthStatus> HealthChecker::GetCheckResults() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return results_;
}

void HealthChecker::Start() {
    if (running_.exchange(true)) return;
    
    monitorThread_ = std::thread(&HealthChecker::MonitorLoop, this);
}

void HealthChecker::Stop() {
    running_ = false;
    if (monitorThread_.joinable()) {
        monitorThread_.join();
    }
}

std::string HealthChecker::GetHealthJSON() const {
    auto status = GetHealth();
    auto results = GetCheckResults();
    
    std::stringstream ss;
    ss << "{\n";
    ss << "  \"status\": \"";
    switch (status) {
        case HealthStatus::HEALTHY: ss << "healthy"; break;
        case HealthStatus::DEGRADED: ss << "degraded"; break;
        case HealthStatus::UNHEALTHY: ss << "unhealthy"; break;
    }
    ss << "\",\n";
    ss << "  \"checks\": {\n";
    
    bool first = true;
    for (const auto& pair : results) {
        if (!first) ss << ",\n";
        first = false;
        
        ss << "    \"" << pair.first << "\": \"";
        switch (pair.second) {
            case HealthStatus::HEALTHY: ss << "healthy"; break;
            case HealthStatus::DEGRADED: ss << "degraded"; break;
            case HealthStatus::UNHEALTHY: ss << "unhealthy"; break;
        }
        ss << "\"";
    }
    
    ss << "\n  }\n";
    ss << "}\n";
    
    return ss.str();
}

void HealthChecker::MonitorLoop() {
    while (running_) {
        std::map<std::string, HealthCheck> checksCopy;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            checksCopy = checks_;
        }
        
        for (auto& pair : checksCopy) {
            auto status = RunCheck(pair.second);
            
            std::lock_guard<std::mutex> lock(mutex_);
            results_[pair.first] = status;
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

HealthChecker::HealthStatus HealthChecker::RunCheck(const HealthCheck& check) {
    // Run check with timeout
    std::future<HealthStatus> future = std::async(std::launch::async, check.check);
    
    auto status = future.wait_for(check.timeout);
    if (status == std::future_status::timeout) {
        return HealthStatus::UNHEALTHY;
    }
    
    try {
        return future.get();
    } catch (...) {
        return HealthStatus::UNHEALTHY;
    }
}

// Tracer implementation
Tracer& Tracer::GetInstance() {
    static Tracer instance;
    return instance;
}

bool Tracer::Initialize(const std::string& serviceName, const std::string& collectorEndpoint) {
    serviceName_ = serviceName;
    collectorEndpoint_ = collectorEndpoint;
    return true;
}

Tracer::Span* Tracer::StartSpan(const std::string& operationName, const std::string& parentSpanId) {
    auto span = std::make_unique<Span>();
    span->traceId = GenerateTraceId();
    span->spanId = GenerateSpanId();
    span->parentSpanId = parentSpanId;
    span->operationName = operationName;
    span->startTime = std::chrono::system_clock::now();
    span->finished = false;
    
    Span* spanPtr = span.get();
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        spans_.push_back(std::move(span));
    }
    
    currentSpan_ = spanPtr;
    return spanPtr;
}

void Tracer::FinishSpan(Span* span) {
    if (!span) return;
    
    span->endTime = std::chrono::system_clock::now();
    span->finished = true;
    
    if (currentSpan_ == span) {
        currentSpan_ = nullptr;
    }
}

void Tracer::SetTag(Span* span, const std::string& key, const std::string& value) {
    if (!span) return;
    span->tags[key] = value;
}

void Tracer::Log(Span* span, const std::string& event, const std::string& message) {
    if (!span) return;
    span->logs.emplace_back(event, message);
}

Tracer::Span* Tracer::GetCurrentSpan() {
    return currentSpan_;
}

void Tracer::ExportSpans() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Export finished spans to collector
    for (const auto& span : spans_) {
        if (span->finished) {
            // Send to collector
        }
    }
}

void Tracer::ClearFinishedSpans() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    spans_.erase(
        std::remove_if(spans_.begin(), spans_.end(),
            [](const auto& span) { return span->finished; }),
        spans_.end());
}

std::string Tracer::GenerateTraceId() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < 32; ++i) {
        ss << dis(gen);
    }
    return ss.str();
}

std::string Tracer::GenerateSpanId() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < 16; ++i) {
        ss << dis(gen);
    }
    return ss.str();
}

// StructuredLogger implementation
StructuredLogger::~StructuredLogger() {
    running_ = false;
    if (writerThread_.joinable()) {
        writerThread_.join();
    }
}

StructuredLogger& StructuredLogger::GetInstance() {
    static StructuredLogger instance;
    return instance;
}

bool StructuredLogger::Initialize(const std::string& logPath, LogLevel minLevel,
                                   bool consoleOutput, bool fileOutput) {
    logPath_ = logPath;
    minLevel_ = minLevel;
    consoleOutput_ = consoleOutput;
    fileOutput_ = fileOutput;
    
    running_ = true;
    writerThread_ = std::thread(&StructuredLogger::WriterLoop, this);
    
    return true;
}

void StructuredLogger::Trace(const std::string& message, const std::map<std::string, std::string>& fields) {
    Log(LogLevel::TRACE, message, fields);
}

void StructuredLogger::Debug(const std::string& message, const std::map<std::string, std::string>& fields) {
    Log(LogLevel::DEBUG, message, fields);
}

void StructuredLogger::Info(const std::string& message, const std::map<std::string, std::string>& fields) {
    Log(LogLevel::INFO, message, fields);
}

void StructuredLogger::Warn(const std::string& message, const std::map<std::string, std::string>& fields) {
    Log(LogLevel::WARN, message, fields);
}

void StructuredLogger::Error(const std::string& message, const std::map<std::string, std::string>& fields) {
    Log(LogLevel::ERROR, message, fields);
}

void StructuredLogger::Fatal(const std::string& message, const std::map<std::string, std::string>& fields) {
    Log(LogLevel::FATAL, message, fields);
}

void StructuredLogger::Log(LogLevel level, const std::string& message,
                           const std::map<std::string, std::string>& fields) {
    if (level < minLevel_) return;
    
    LogEntry entry;
    entry.timestamp = std::chrono::system_clock::now();
    entry.level = level;
    entry.message = message;
    entry.fields = fields;
    
    // Get trace info if available
    auto currentSpan = Tracer::GetInstance().GetCurrentSpan();
    if (currentSpan) {
        entry.traceId = currentSpan->traceId;
        entry.spanId = currentSpan->spanId;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    logQueue_.push(entry);
}

void StructuredLogger::SetMinLevel(LogLevel level) {
    minLevel_ = level;
}

void StructuredLogger::Flush() {
    // Process all queued entries
    while (!logQueue_.empty()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

std::vector<StructuredLogger::LogEntry> StructuredLogger::GetRecentLogs(int count) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<LogEntry> recent;
    auto tempQueue = logQueue_;
    
    while (!tempQueue.empty() && recent.size() < static_cast<size_t>(count)) {
        recent.push_back(tempQueue.front());
        tempQueue.pop();
    }
    
    return recent;
}

void StructuredLogger::WriterLoop() {
    while (running_) {
        std::queue<LogEntry> batch;
        
        {
            std::lock_guard<std::mutex> lock(mutex_);
            batch = std::move(logQueue_);
            logQueue_ = std::queue<LogEntry>();
        }
        
        while (!batch.empty()) {
            WriteEntry(batch.front());
            batch.pop();
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void StructuredLogger::WriteEntry(const LogEntry& entry) {
    std::string formatted = FormatEntry(entry);
    
    if (consoleOutput_) {
        std::cout << formatted << std::endl;
    }
    
    if (fileOutput_) {
        std::ofstream file(logPath_ + "/server.log", std::ios::app);
        if (file.is_open()) {
            file << formatted << std::endl;
            file.close();
        }
    }
}

std::string StructuredLogger::FormatEntry(const LogEntry& entry) {
    std::stringstream ss;
    
    auto time_t = std::chrono::system_clock::to_time_t(entry.timestamp);
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    ss << " [" << LevelToString(entry.level) << "] ";
    ss << entry.message;
    
    if (!entry.fields.empty()) {
        ss << " {";
        bool first = true;
        for (const auto& field : entry.fields) {
            if (!first) ss << ", ";
            first = false;
            ss << field.first << "=" << field.second;
        }
        ss << "}";
    }
    
    return ss.str();
}

std::string StructuredLogger::LevelToString(LogLevel level) {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARN: return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}

// AlertManager implementation
AlertManager& AlertManager::GetInstance() {
    static AlertManager instance;
    return instance;
}

bool AlertManager::Initialize(const std::string& configPath) {
    configPath_ = configPath;
    // Load rules from config
    return true;
}

void AlertManager::AddRule(const AlertRule& rule) {
    std::lock_guard<std::mutex> lock(mutex_);
    rules_.push_back(rule);
}

void AlertManager::EvaluateRules(const std::map<std::string, double>& metrics) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& rule : rules_) {
        if (EvaluateCondition(rule.condition, metrics)) {
            // Check if alert already fired
            bool alreadyFired = false;
            for (const auto& alert : alerts_) {
                if (alert.ruleName == rule.name && !alert.resolved) {
                    alreadyFired = true;
                    break;
                }
            }
            
            if (!alreadyFired) {
                Alert alert;
                alert.id = std::to_string(std::hash<std::string>{}(rule.name + std::to_string(std::time(nullptr))));
                alert.ruleName = rule.name;
                alert.severity = rule.severity;
                alert.message = "Alert: " + rule.condition + " triggered";
                alert.firedAt = std::chrono::system_clock::now();
                alert.resolved = false;
                
                alerts_.push_back(alert);
                SendNotification(alert);
            }
        }
    }
}

std::vector<AlertManager::Alert> AlertManager::GetActiveAlerts() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Alert> active;
    for (const auto& alert : alerts_) {
        if (!alert.resolved) {
            active.push_back(alert);
        }
    }
    return active;
}

std::vector<AlertManager::Alert> AlertManager::GetAlertHistory(int limit) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Alert> history;
    int count = 0;
    for (auto it = alerts_.rbegin(); it != alerts_.rend() && count < limit; ++it, ++count) {
        history.push_back(*it);
    }
    return history;
}

void AlertManager::ResolveAlert(const std::string& alertId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& alert : alerts_) {
        if (alert.id == alertId && !alert.resolved) {
            alert.resolved = true;
            alert.resolvedAt = std::chrono::system_clock::now();
            break;
        }
    }
}

void AlertManager::SendNotification(const Alert& alert) {
    for (const auto& notification : alert.notifications) {
        if (notification.find("@") != std::string::npos) {
            SendEmail(alert, notification);
        } else if (notification.find("slack.com") != std::string::npos) {
            SendSlack(alert, notification);
        }
    }
}

bool AlertManager::EvaluateCondition(const std::string& condition,
                                      const std::map<std::string, double>& metrics) {
    // Simple condition evaluation (e.g., "latency_p95 > 1000")
    // Parse condition and evaluate
    return false; // Placeholder
}

void AlertManager::SendEmail(const Alert& alert, const std::string& email) {
    // Send email notification
}

void AlertManager::SendSlack(const Alert& alert, const std::string& webhook) {
    // Send Slack notification
}

} // namespace deployment
} // namespace rawrxd
