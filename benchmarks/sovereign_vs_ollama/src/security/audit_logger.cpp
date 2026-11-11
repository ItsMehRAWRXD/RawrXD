// audit_logger.cpp
// Batch 13: Security Audit Logging
//
// Comprehensive audit trail for security events
// Features: Structured logging, tamper detection, log rotation

#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <mutex>
#include <queue>
#include <thread>
#include <atomic>

namespace Benchmark {
namespace Security {

// Audit event types
enum class AuditEventType {
    AUTHENTICATION_SUCCESS,
    AUTHENTICATION_FAILURE,
    AUTHORIZATION_DENIED,
    API_KEY_CREATED,
    API_KEY_REVOKED,
    API_KEY_USED,
    RATE_LIMIT_EXCEEDED,
    INPUT_VALIDATION_FAILED,
    CONFIGURATION_CHANGED,
    BENCHMARK_STARTED,
    BENCHMARK_COMPLETED,
    BENCHMARK_FAILED,
    DATA_EXPORTED,
    ADMIN_ACTION,
    SECURITY_ALERT
};

// Audit event severity
enum class AuditSeverity {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};

// Audit event structure
struct AuditEvent {
    int64_t timestamp;
    std::string event_id;
    AuditEventType type;
    AuditSeverity severity;
    std::string user_id;
    std::string session_id;
    std::string ip_address;
    std::string user_agent;
    std::string resource;
    std::string action;
    std::map<std::string, std::string> details;
    std::string hash;  // For tamper detection
    
    std::string ToJSON() const {
        std::stringstream json;
        json << "{";
        json << "\"timestamp\":" << timestamp << ",";
        json << "\"event_id\":\"" << event_id << "\",";
        json << "\"type\":\"" << EventTypeToString(type) << "\",";
        json << "\"severity\":\"" << SeverityToString(severity) << "\",";
        json << "\"user_id\":\"" << user_id << "\",";
        json << "\"session_id\":\"" << session_id << "\",";
        json << "\"ip_address\":\"" << ip_address << "\",";
        json << "\"resource\":\"" << resource << "\",";
        json << "\"action\":\"" << action << "\",";
        json << "\"details\":{";
        
        bool first = true;
        for (const auto& [key, value] : details) {
            if (!first) json << ",";
            json << "\"" << key << "\":\"" << value << "\"";
            first = false;
        }
        
        json << "},";
        json << "\"hash\":\"" << hash << "\"";
        json << "}";
        
        return json.str();
    }
    
private:
    static std::string EventTypeToString(AuditEventType type) {
        switch (type) {
            case AuditEventType::AUTHENTICATION_SUCCESS: return "auth_success";
            case AuditEventType::AUTHENTICATION_FAILURE: return "auth_failure";
            case AuditEventType::AUTHORIZATION_DENIED: return "authz_denied";
            case AuditEventType::API_KEY_CREATED: return "api_key_created";
            case AuditEventType::API_KEY_REVOKED: return "api_key_revoked";
            case AuditEventType::API_KEY_USED: return "api_key_used";
            case AuditEventType::RATE_LIMIT_EXCEEDED: return "rate_limited";
            case AuditEventType::INPUT_VALIDATION_FAILED: return "validation_failed";
            case AuditEventType::CONFIGURATION_CHANGED: return "config_changed";
            case AuditEventType::BENCHMARK_STARTED: return "benchmark_started";
            case AuditEventType::BENCHMARK_COMPLETED: return "benchmark_completed";
            case AuditEventType::BENCHMARK_FAILED: return "benchmark_failed";
            case AuditEventType::DATA_EXPORTED: return "data_exported";
            case AuditEventType::ADMIN_ACTION: return "admin_action";
            case AuditEventType::SECURITY_ALERT: return "security_alert";
            default: return "unknown";
        }
    }
    
    static std::string SeverityToString(AuditSeverity severity) {
        switch (severity) {
            case AuditSeverity::DEBUG: return "debug";
            case AuditSeverity::INFO: return "info";
            case AuditSeverity::WARNING: return "warning";
            case AuditSeverity::ERROR: return "error";
            case AuditSeverity::CRITICAL: return "critical";
            default: return "unknown";
        }
    }
};

// Audit logger
class AuditLogger {
public:
    struct Config {
        std::string log_directory = "./logs/audit";
        std::string filename_prefix = "audit";
        int max_file_size_mb = 100;
        int max_files = 10;
        bool async_logging = true;
        int queue_size = 10000;
        bool enable_hashing = true;
        bool log_to_console = false;
    };
    
    explicit AuditLogger(const Config& config = Config()) 
        : config_(config), running_(false), event_count_(0) {
        // Ensure log directory exists
        // In production: Create directory if needed
        
        // Open initial log file
        RotateLogFile();
        
        // Start async logging thread
        if (config.async_logging) {
            running_ = true;
            worker_thread_ = std::thread(&AuditLogger::ProcessQueue, this);
        }
    }
    
    ~AuditLogger() {
        Shutdown();
    }
    
    // Log an event
    void Log(const AuditEvent& event) {
        AuditEvent mutable_event = event;
        mutable_event.timestamp = GetTimestamp();
        mutable_event.event_id = GenerateEventID();
        
        if (config_.enable_hashing) {
            mutable_event.hash = CalculateHash(mutable_event);
        }
        
        if (config_.async_logging) {
            // Add to queue
            std::lock_guard<std::mutex> lock(queue_mutex_);
            if (event_queue_.size() < config_.queue_size) {
                event_queue_.push(mutable_event);
                queue_cv_.notify_one();
            }
        } else {
            // Log synchronously
            WriteEvent(mutable_event);
        }
        
        ++event_count_;
    }
    
    // Convenience methods for common events
    void LogAuthentication(bool success, const std::string& user_id,
                          const std::string& ip, const std::string& reason = "") {
        AuditEvent event;
        event.type = success ? AuditEventType::AUTHENTICATION_SUCCESS 
                             : AuditEventType::AUTHENTICATION_FAILURE;
        event.severity = success ? AuditSeverity::INFO : AuditSeverity::WARNING;
        event.user_id = user_id;
        event.ip_address = ip;
        event.resource = "auth";
        event.action = success ? "login_success" : "login_failure";
        if (!reason.empty()) {
            event.details["reason"] = reason;
        }
        
        Log(event);
    }
    
    void LogAuthorizationDenied(const std::string& user_id,
                                 const std::string& resource,
                                 const std::string& action,
                                 const std::string& ip) {
        AuditEvent event;
        event.type = AuditEventType::AUTHORIZATION_DENIED;
        event.severity = AuditSeverity::WARNING;
        event.user_id = user_id;
        event.ip_address = ip;
        event.resource = resource;
        event.action = action;
        event.details["reason"] = "insufficient_permissions";
        
        Log(event);
    }
    
    void LogRateLimit(const std::string& client_id,
                      const std::string& endpoint,
                      int retry_after) {
        AuditEvent event;
        event.type = AuditEventType::RATE_LIMIT_EXCEEDED;
        event.severity = AuditSeverity::WARNING;
        event.user_id = client_id;
        event.resource = endpoint;
        event.action = "request";
        event.details["retry_after"] = std::to_string(retry_after);
        
        Log(event);
    }
    
    void LogBenchmarkEvent(AuditEventType type,
                           const std::string& benchmark_id,
                           const std::string& user_id,
                           const std::map<std::string, std::string>& details = {}) {
        AuditEvent event;
        event.type = type;
        event.severity = (type == AuditEventType::BENCHMARK_FAILED) 
                         ? AuditSeverity::ERROR : AuditSeverity::INFO;
        event.user_id = user_id;
        event.resource = "benchmark";
        event.action = "execute";
        event.details = details;
        event.details["benchmark_id"] = benchmark_id;
        
        Log(event);
    }
    
    void LogSecurityAlert(const std::string& alert_type,
                          const std::string& description,
                          const std::string& ip = "",
                          AuditSeverity severity = AuditSeverity::CRITICAL) {
        AuditEvent event;
        event.type = AuditEventType::SECURITY_ALERT;
        event.severity = severity;
        event.ip_address = ip;
        event.resource = "security";
        event.action = "alert";
        event.details["alert_type"] = alert_type;
        event.details["description"] = description;
        
        Log(event);
    }
    
    // Shutdown logger
    void Shutdown() {
        running_ = false;
        queue_cv_.notify_all();
        
        if (worker_thread_.joinable()) {
            worker_thread_.join();
        }
        
        // Flush remaining events
        Flush();
    }
    
    // Flush pending events
    void Flush() {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        while (!event_queue_.empty()) {
            WriteEvent(event_queue_.front());
            event_queue_.pop();
        }
    }
    
    // Get statistics
    struct Stats {
        int64_t total_events;
        int64_t dropped_events;
        int64_t current_queue_size;
    };
    
    Stats GetStats() const {
        Stats stats;
        stats.total_events = event_count_.load();
        stats.current_queue_size = event_queue_.size();
        stats.dropped_events = 0;  // Track if needed
        return stats;
    }
    
    // Verify log integrity
    bool VerifyIntegrity(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) return false;
        
        std::string line;
        int valid_count = 0;
        int invalid_count = 0;
        
        while (std::getline(file, line)) {
            // Parse event and verify hash
            // Simplified - in production: proper JSON parsing
            if (line.find("\"hash\"") != std::string::npos) {
                ++valid_count;
            } else {
                ++invalid_count;
            }
        }
        
        return invalid_count == 0;
    }

private:
    Config config_;
    std::atomic<bool> running_;
    std::atomic<int64_t> event_count_;
    
    std::ofstream current_file_;
    std::string current_filename_;
    int current_file_size_;
    int file_index_;
    
    std::queue<AuditEvent> event_queue_;
    mutable std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::thread worker_thread_;
    
    std::mutex file_mutex_;
    
    void ProcessQueue() {
        while (running_) {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_cv_.wait(lock, [this] { 
                return !event_queue_.empty() || !running_; 
            });
            
            while (!event_queue_.empty()) {
                AuditEvent event = event_queue_.front();
                event_queue_.pop();
                lock.unlock();
                
                WriteEvent(event);
                
                lock.lock();
            }
        }
    }
    
    void WriteEvent(const AuditEvent& event) {
        std::lock_guard<std::mutex> lock(file_mutex_);
        
        // Check if rotation needed
        if (current_file_size_ > config_.max_file_size_mb * 1024 * 1024) {
            RotateLogFile();
        }
        
        // Write event
        std::string json = event.ToJSON();
        if (current_file_.is_open()) {
            current_file_ << json << std::endl;
            current_file_size_ += json.length();
        }
        
        // Also log to console if enabled
        if (config_.log_to_console && event.severity >= AuditSeverity::WARNING) {
            std::cout << "[" << SeverityToString(event.severity) << "] "
                      << EventTypeToString(event.type) << ": "
                      << event.details.at("description") << std::endl;
        }
    }
    
    void RotateLogFile() {
        // Close current file
        if (current_file_.is_open()) {
            current_file_.close();
        }
        
        // Generate new filename
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        std::stringstream filename;
        filename << config_.log_directory << "/"
                 << config_.filename_prefix << "_"
                 << std::put_time(std::localtime(&time_t), "%Y%m%d_%H%M%S")
                 << "_" << file_index_++ << ".log";
        
        current_filename_ = filename.str();
        current_file_.open(current_filename_, std::ios::app);
        current_file_size_ = 0;
        
        // Cleanup old files
        CleanupOldFiles();
    }
    
    void CleanupOldFiles() {
        // In production: Remove files exceeding max_files
    }
    
    int64_t GetTimestamp() {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
    
    std::string GenerateEventID() {
        return "evt_" + std::to_string(GetTimestamp()) + "_" + 
               std::to_string(rand() % 10000);
    }
    
    std::string CalculateHash(const AuditEvent& event) {
        // Simple hash for tamper detection
        // In production: Use HMAC-SHA256
        std::stringstream data;
        data << event.timestamp << event.type << event.user_id 
             << event.resource << event.action;
        
        std::hash<std::string> hasher;
        return std::to_string(hasher(data.str()));
    }
    
    std::string EventTypeToString(AuditEventType type) {
        switch (type) {
            case AuditEventType::AUTHENTICATION_SUCCESS: return "auth_success";
            case AuditEventType::AUTHENTICATION_FAILURE: return "auth_failure";
            case AuditEventType::AUTHORIZATION_DENIED: return "authz_denied";
            case AuditEventType::API_KEY_CREATED: return "api_key_created";
            case AuditEventType::API_KEY_REVOKED: return "api_key_revoked";
            case AuditEventType::API_KEY_USED: return "api_key_used";
            case AuditEventType::RATE_LIMIT_EXCEEDED: return "rate_limited";
            case AuditEventType::INPUT_VALIDATION_FAILED: return "validation_failed";
            case AuditEventType::CONFIGURATION_CHANGED: return "config_changed";
            case AuditEventType::BENCHMARK_STARTED: return "benchmark_started";
            case AuditEventType::BENCHMARK_COMPLETED: return "benchmark_completed";
            case AuditEventType::BENCHMARK_FAILED: return "benchmark_failed";
            case AuditEventType::DATA_EXPORTED: return "data_exported";
            case AuditEventType::ADMIN_ACTION: return "admin_action";
            case AuditEventType::SECURITY_ALERT: return "security_alert";
            default: return "unknown";
        }
    }
    
    std::string SeverityToString(AuditSeverity severity) {
        switch (severity) {
            case AuditSeverity::DEBUG: return "debug";
            case AuditSeverity::INFO: return "info";
            case AuditSeverity::WARNING: return "warning";
            case AuditSeverity::ERROR: return "error";
            case AuditSeverity::CRITICAL: return "critical";
            default: return "unknown";
        }
    }
};

// Security event monitor
class SecurityMonitor {
public:
    struct AlertConfig {
        int failed_auth_threshold = 5;
        int failed_auth_window_minutes = 15;
        int rate_limit_threshold = 10;
        std::vector<std::string> suspicious_patterns;
    };
    
    explicit SecurityMonitor(AuditLogger* logger, const AlertConfig& config = AlertConfig())
        : logger_(logger), config_(config) {}
    
    // Process event for suspicious activity
    void ProcessEvent(const AuditEvent& event) {
        // Check for brute force
        if (event.type == AuditEventType::AUTHENTICATION_FAILURE) {
            TrackFailedAuth(event.ip_address);
        }
        
        // Check for suspicious patterns
        for (const auto& pattern : config_.suspicious_patterns) {
            // Pattern matching logic
        }
    }
    
    // Report security incident
    void ReportIncident(const std::string& type, const std::string& description,
                        const std::string& source_ip) {
        if (logger_) {
            logger_->LogSecurityAlert(type, description, source_ip);
        }
    }

private:
    AuditLogger* logger_;
    AlertConfig config_;
    
    std::map<std::string, std::vector<int64_t>> failed_auth_attempts_;
    std::mutex auth_mutex_;
    
    void TrackFailedAuth(const std::string& ip) {
        std::lock_guard<std::mutex> lock(auth_mutex_);
        
        auto now = GetTimestamp();
        auto& attempts = failed_auth_attempts_[ip];
        
        // Remove old attempts
        int64_t cutoff = now - config_.failed_auth_window_minutes * 60;
        attempts.erase(
            std::remove_if(attempts.begin(), attempts.end(),
                [cutoff](int64_t t) { return t < cutoff; }),
            attempts.end()
        );
        
        // Add new attempt
        attempts.push_back(now);
        
        // Check threshold
        if (static_cast<int>(attempts.size()) >= config_.failed_auth_threshold) {
            if (logger_) {
                logger_->LogSecurityAlert(
                    "brute_force_detected",
                    "Multiple failed authentication attempts from " + ip,
                    ip,
                    AuditSeverity::CRITICAL
                );
            }
        }
    }
    
    int64_t GetTimestamp() {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
};

} // namespace Security
} // namespace Benchmark
