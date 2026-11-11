// Phase D.7 Batch 4/5: Threat Detection
// Behavioral Analysis and Intrusion Detection
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <functional>

namespace Sovereign {
namespace Security {

// ============================================================================
// Threat Types
// ============================================================================

enum class ThreatSeverity {
    INFO = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

enum class ThreatCategory {
    MALWARE = 0,
    INTRUSION = 1,
    DATA_EXFILTRATION = 2,
    PRIVILEGE_ESCALATION = 3,
    LATERAL_MOVEMENT = 4,
    DENIAL_OF_SERVICE = 5,
    INSIDER_THREAT = 6,
    ANOMALY = 7,
    POLICY_VIOLATION = 8
};

struct ThreatIndicator {
    std::string indicator_id;
    std::string type;  // "ip", "domain", "hash", "signature"
    std::string value;
    ThreatCategory category;
    ThreatSeverity severity;
    std::string source;
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    int confidence = 0;  // 0-100
    std::vector<std::string> related_threats;
};

struct SecurityEvent {
    std::string event_id;
    std::string event_type;
    std::string source;
    std::string target;
    std::map<std::string, std::string> details;
    std::chrono::steady_clock::time_point timestamp;
    std::string raw_log;
    std::vector<std::string> tags;
    bool processed = false;
};

struct DetectedThreat {
    std::string threat_id;
    std::string name;
    ThreatCategory category;
    ThreatSeverity severity;
    std::string description;
    std::vector<std::string> affected_resources;
    std::vector<std::string> indicators;
    std::chrono::steady_clock::time_point detected_at;
    std::chrono::steady_clock::time_point mitigated_at;
    bool mitigated = false;
    std::string mitigation_action;
    double confidence = 0.0;
};

// ============================================================================
// Behavioral Analysis
// ============================================================================

class BehavioralAnalyzer {
public:
    struct Config {
        int baseline_window_hours = 168;  // 1 week
        double anomaly_threshold = 3.0;   // Standard deviations
        bool enable_user_profiling = true;
        bool enable_entity_profiling = true;
        int profile_update_interval_hours = 24;
    };
    
    struct BehaviorProfile {
        std::string entity_id;
        std::string entity_type;  // "user", "service", "ip", "host"
        std::map<std::string, double> normal_metrics;
        std::map<std::string, double> std_deviations;
        std::vector<std::string> typical_peers;
        std::vector<std::string> typical_resources;
        std::chrono::steady_clock::time_point last_updated;
        int data_points = 0;
    };
    
    struct BehaviorAnomaly {
        std::string entity_id;
        std::string metric_name;
        double expected_value = 0.0;
        double actual_value = 0.0;
        double deviation = 0.0;
        std::chrono::steady_clock::time_point detected_at;
        std::string context;
    };
    
    explicit BehavioralAnalyzer(const Config& config);
    
    bool Initialize();
    
    // Profile management
    bool CreateProfile(const std::string& entity_id, const std::string& entity_type);
    bool UpdateProfile(const BehaviorProfile& profile);
    bool DeleteProfile(const std::string& entity_id);
    BehaviorProfile GetProfile(const std::string& entity_id) const;
    
    // Analysis
    std::vector<BehaviorAnomaly> AnalyzeEvent(const SecurityEvent& event);
    std::vector<BehaviorAnomaly> AnalyzeEntity(const std::string& entity_id,
                                                std::chrono::hours lookback);
    
    // Learning
    bool LearnFromEvents(const std::vector<SecurityEvent>& events);
    bool IsBaselineEstablished(const std::string& entity_id) const;
    
private:
    Config config_;
    
    mutable std::mutex profiles_mutex_;
    std::map<std::string, BehaviorProfile> profiles_;
    
    double CalculateDeviation(const BehaviorProfile& profile,
                             const std::string& metric,
                             double value);
    void UpdateProfileStats(BehaviorProfile& profile,
                          const std::string& metric,
                          double value);
};

// ============================================================================
// Intrusion Detection System
// ============================================================================

class IntrusionDetectionSystem {
public:
    struct Config {
        bool enable_network_ids = true;
        bool enable_host_ids = true;
        bool enable_container_ids = true;
        int detection_threshold = 5;
        int alert_cooldown_seconds = 300;
        std::vector<std::string> protected_assets;
    };
    
    struct IDSRule {
        std::string rule_id;
        std::string name;
        std::string description;
        std::string pattern;  // Snort/Suricata style or custom
        std::string log_type;
        ThreatSeverity severity;
        bool enabled = true;
        int threshold_count = 1;
        std::chrono::seconds threshold_window{60};
    };
    
    struct IDSAlert {
        std::string alert_id;
        std::string rule_id;
        std::string source_ip;
        std::string destination_ip;
        int destination_port = 0;
        std::string protocol;
        std::string payload_sample;
        std::chrono::steady_clock::time_point timestamp;
        int match_count = 0;
        bool escalated = false;
    };
    
    explicit IntrusionDetectionSystem(const Config& config);
    ~IntrusionDetectionSystem();
    
    bool Initialize();
    void Shutdown();
    
    // Rule management
    bool AddRule(const IDSRule& rule);
    bool UpdateRule(const std::string& rule_id, const IDSRule& rule);
    bool DeleteRule(const std::string& rule_id);
    bool EnableRule(const std::string& rule_id);
    bool DisableRule(const std::string& rule_id);
    std::vector<IDSRule> GetRules() const;
    
    // Detection
    std::vector<IDSAlert> ProcessNetworkTraffic(const std::string& packet_data);
    std::vector<IDSAlert> ProcessSystemCall(const std::string& syscall_data);
    std::vector<IDSAlert> ProcessLogEntry(const std::string& log_entry);
    
    // Alert management
    std::vector<IDSAlert> GetActiveAlerts() const;
    bool AcknowledgeAlert(const std::string& alert_id);
    bool EscalateAlert(const std::string& alert_id);
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    std::thread detection_thread_;
    
    mutable std::mutex rules_mutex_;
    std::map<std::string, IDSRule> rules_;
    
    mutable std::mutex alerts_mutex_;
    std::vector<IDSAlert> alerts_;
    
    void DetectionLoop();
    bool MatchRule(const IDSRule& rule, const std::string& data);
    void GenerateAlert(const IDSRule& rule, const std::string& context);
};

// ============================================================================
// Threat Intelligence
// ============================================================================

class ThreatIntelligence {
public:
    struct Config {
        int update_interval_minutes = 60;
        std::vector<std::string> feed_urls;
        std::vector<std::string> api_keys;
        bool enable_auto_update = true;
        int max_indicators = 100000;
    };
    
    explicit ThreatIntelligence(const Config& config);
    ~ThreatIntelligence();
    
    bool Initialize();
    void Shutdown();
    
    // Feed management
    bool AddFeed(const std::string& name, const std::string& url);
    bool RemoveFeed(const std::string& name);
    bool UpdateFeeds();
    std::vector<std::string> GetFeedStatus() const;
    
    // Indicator lookup
    bool IsMaliciousIP(const std::string& ip);
    bool IsMaliciousDomain(const std::string& domain);
    bool IsMaliciousHash(const std::string& hash);
    std::vector<ThreatIndicator> LookupIndicator(const std::string& value);
    
    // Enrichment
    std::map<std::string, std::string> EnrichEvent(const SecurityEvent& event);
    std::vector<std::string> GetRelatedIndicators(const std::string& indicator);
    
    // Custom indicators
    bool AddIndicator(const ThreatIndicator& indicator);
    bool RemoveIndicator(const std::string& indicator_id);
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    std::thread update_thread_;
    
    mutable std::mutex indicators_mutex_;
    std::map<std::string, ThreatIndicator> indicators_;
    std::map<std::string, std::vector<std::string>> ip_to_indicators_;
    std::map<std::string, std::vector<std::string>> domain_to_indicators_;
    std::map<std::string, std::vector<std::string>> hash_to_indicators_;
    
    void UpdateLoop();
    bool FetchFeed(const std::string& url, std::vector<ThreatIndicator>& indicators);
    void IndexIndicator(const ThreatIndicator& indicator);
};

// ============================================================================
// Threat Detection Runtime
// ============================================================================

class ThreatDetectionRuntime {
public:
    struct Config {
        BehavioralAnalyzer::Config behavioral;
        IntrusionDetectionSystem::Config ids;
        ThreatIntelligence::Config intelligence;
        bool enable_auto_response = false;
        int response_threshold = 3;  // CRITICAL severity
    };
    
    explicit ThreatDetectionRuntime(const Config& config);
    ~ThreatDetectionRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Event processing
    void ProcessSecurityEvent(const SecurityEvent& event);
    void ProcessNetworkTraffic(const std::string& traffic_data);
    void ProcessLogBatch(const std::vector<std::string>& logs);
    
    // Threat management
    std::vector<DetectedThreat> GetActiveThreats() const;
    std::vector<DetectedThreat> GetThreatHistory(std::chrono::hours lookback) const;
    bool MitigateThreat(const std::string& threat_id);
    
    // Intelligence
    bool UpdateThreatIntelligence();
    std::vector<ThreatIndicator> GetIndicators(ThreatCategory category) const;
    
    // Statistics
    struct ThreatStats {
        int total_events_processed = 0;
        int threats_detected = 0;
        int threats_mitigated = 0;
        std::map<ThreatCategory, int> threats_by_category;
        std::map<ThreatSeverity, int> threats_by_severity;
        double avg_detection_time_ms = 0.0;
    };
    
    ThreatStats GetStats() const;
    
    // Access subsystems
    BehavioralAnalyzer* GetBehavioralAnalyzer();
    IntrusionDetectionSystem* GetIDS();
    ThreatIntelligence* GetThreatIntelligence();
    
private:
    Config config_;
    std::unique_ptr<BehavioralAnalyzer> behavioral_;
    std::unique_ptr<IntrusionDetectionSystem> ids_;
    std::unique_ptr<ThreatIntelligence> intelligence_;
    
    mutable std::mutex threats_mutex_;
    std::vector<DetectedThreat> threats_;
    
    std::atomic<int64_t> events_processed_{0};
    std::atomic<int64_t> threats_detected_{0};
    std::atomic<int64_t> threats_mitigated_{0};
    
    void EvaluateThreats(const SecurityEvent& event,
                       const std::vector<BehavioralAnalyzer::BehaviorAnomaly>& anomalies,
                       const std::vector<IntrusionDetectionSystem::IDSAlert>& alerts);
    bool AutoMitigate(const DetectedThreat& threat);
};

} // namespace Security
} // namespace Sovereign
