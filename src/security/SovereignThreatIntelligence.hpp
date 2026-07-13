// Phase D.19 Batch 2/5: Threat Intelligence
// Threat feeds, IOCs, and threat hunting
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <any>

namespace Sovereign {
namespace Security {

// Forward declarations
struct ThreatIndicator;
struct ThreatActor;
struct IntelligenceReport;

// ============================================================================
// Threat Intelligence Types
// ============================================================================

enum class IndicatorType {
    IP_ADDRESS = 0,
    DOMAIN = 1,
    URL = 2,
    FILE_HASH = 3,
    EMAIL = 4,
    CVE = 5,
    MALWARE_FAMILY = 6,
    ATTACK_PATTERN = 7
};

enum class ThreatSeverity {
    INFO = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

enum class ThreatConfidence {
    UNKNOWN = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3
};

struct ThreatIndicator {
    std::string indicator_id;
    IndicatorType type;
    std::string value;
    ThreatSeverity severity;
    ThreatConfidence confidence;
    std::vector<std::string> labels;
    std::string description;
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    std::chrono::steady_clock::time_point expires_at;
    std::map<std::string, std::any> metadata;
};

struct ThreatActor {
    std::string actor_id;
    std::string name;
    std::vector<std::string> aliases;
    std::vector<std::string> motivations;
    std::vector<std::string> capabilities;
    std::vector<std::string> targeted_sectors;
    std::vector<std::string> targeted_countries;
    std::map<std::string, std::any> metadata;
};

struct IntelligenceReport {
    std::string report_id;
    std::string title;
    std::string source;
    std::vector<ThreatIndicator> indicators;
    std::vector<std::string> threat_actors;
    std::vector<std::string> attack_patterns;
    std::string description;
    std::chrono::steady_clock::time_point published_at;
    std::chrono::steady_clock::time_point valid_until;
    ThreatSeverity severity;
};

// ============================================================================
// Threat Feed Manager
// ============================================================================

class ThreatFeedManager {
public:
    struct Config {
        std::vector<std::string> feed_urls;
        std::chrono::minutes update_interval{60};
        bool auto_update = true;
        int max_indicators = 1000000;
    };
    
    struct FeedStatus {
        std::string feed_name;
        std::string url;
        bool is_active;
        std::chrono::steady_clock::time_point last_update;
        int indicator_count;
        std::string error_message;
    };
    
    explicit ThreatFeedManager(const Config& config);
    ~ThreatFeedManager();
    
    bool Initialize();
    void Shutdown();
    
    // Feed management
    bool AddFeed(const std::string& name, const std::string& url);
    bool RemoveFeed(const std::string& name);
    bool EnableFeed(const std::string& name);
    bool DisableFeed(const std::string& name);
    
    // Updates
    bool UpdateFeed(const std::string& name);
    bool UpdateAllFeeds();
    
    // Queries
    std::vector<FeedStatus> GetFeedStatus() const;
    std::vector<ThreatIndicator> GetIndicatorsByType(IndicatorType type) const;
    std::vector<ThreatIndicator> GetIndicatorsBySeverity(ThreatSeverity severity) const;
    
private:
    Config config_;
    std::map<std::string, FeedStatus> feeds_;
    std::map<std::string, std::vector<ThreatIndicator>> indicators_by_feed_;
    mutable std::mutex feeds_mutex_;
    std::thread update_thread_;
    std::atomic<bool> running_{false};
    
    void UpdateLoop();
    std::vector<ThreatIndicator> FetchFeed(const std::string& url);
    bool ParseSTIX(const std::string& data, std::vector<ThreatIndicator>& indicators);
    bool ParseMISP(const std::string& data, std::vector<ThreatIndicator>& indicators);
};

// ============================================================================
// IOC Scanner
// ============================================================================

class IOCScanner {
public:
    struct Config {
        bool scan_network_traffic = true;
        bool scan_files = true;
        bool scan_dns = true;
        bool scan_emails = true;
        bool block_on_detection = false;
    };
    
    struct ScanResult {
        bool is_match;
        std::string matched_indicator_id;
        IndicatorType matched_type;
        std::string matched_value;
        ThreatSeverity severity;
        std::chrono::steady_clock::time_point detected_at;
        std::map<std::string, std::any> context;
    };
    
    explicit IOCScanner(const Config& config);
    ~IOCScanner();
    
    bool Initialize();
    void Shutdown();
    
    // Scanning
    ScanResult ScanIP(const std::string& ip_address);
    ScanResult ScanDomain(const std::string& domain);
    ScanResult ScanURL(const std::string& url);
    ScanResult ScanFileHash(const std::vector<uint8_t>& file_hash);
    ScanResult ScanEmail(const std::string& email);
    
    // Batch scanning
    std::vector<ScanResult> ScanNetworkTraffic(const std::vector<std::string>& connections);
    std::vector<ScanResult> ScanFileHashes(const std::vector<std::vector<uint8_t>>& hashes);
    
    // Real-time monitoring
    bool StartMonitoring();
    bool StopMonitoring();
    void SetDetectionCallback(std::function<void(const ScanResult&)> callback);
    
private:
    Config config_;
    std::map<IndicatorType, std::set<std::string>> ioc_database_;
    mutable std::mutex ioc_mutex_;
    std::thread monitor_thread_;
    std::atomic<bool> running_{false};
    std::function<void(const ScanResult&)> detection_callback_;
    
    void MonitorLoop();
    void LoadIOCs();
};

// ============================================================================
// Threat Hunter
// ============================================================================

class ThreatHunter {
public:
    struct Config {
        int hunt_threads = 4;
        std::chrono::hours lookback_window{168};  // 7 days
        bool enable_ml_detection = true;
    };
    
    struct HuntQuery {
        std::string query_id;
        std::string name;
        std::string description;
        std::string query_string;
        std::vector<std::string> data_sources;
        std::chrono::steady_clock::time_point created_at;
        bool is_active;
    };
    
    struct HuntResult {
        std::string result_id;
        std::string query_id;
        std::vector<std::map<std::string, std::any>> matches;
        double confidence_score;
        std::chrono::steady_clock::time_point executed_at;
        std::chrono::milliseconds execution_time;
    };
    
    explicit ThreatHunter(const Config& config);
    ~ThreatHunter();
    
    bool Initialize();
    void Shutdown();
    
    // Query management
    std::string CreateQuery(const HuntQuery& query);
    bool UpdateQuery(const std::string& query_id, const HuntQuery& query);
    bool DeleteQuery(const std::string& query_id);
    std::vector<HuntQuery> GetQueries() const;
    
    // Hunting
    HuntResult ExecuteQuery(const std::string& query_id);
    std::vector<HuntResult> ExecuteAllQueries();
    
    // Scheduled hunting
    std::string ScheduleQuery(const std::string& query_id, std::chrono::hours interval);
    bool CancelScheduledQuery(const std::string& schedule_id);
    
    // TTPs (Tactics, Techniques, Procedures)
    std::vector<std::string> GetMITREATTCKMappings(const HuntResult& result);
    
private:
    Config config_;
    std::map<std::string, HuntQuery> queries_;
    std::map<std::string, HuntResult> results_;
    mutable std::mutex hunt_mutex_;
    std::thread_pool workers_;
    
    HuntResult ExecuteQueryInternal(const HuntQuery& query);
};

// ============================================================================
// Intelligence Analyzer
// ============================================================================

class IntelligenceAnalyzer {
public:
    struct Config {
        bool enable_correlation = true;
        bool enable_attribution = true;
        double correlation_threshold = 0.7;
    };
    
    struct CorrelationResult {
        std::string correlation_id;
        std::vector<std::string> related_indicators;
        std::vector<std::string> related_actors;
        double correlation_score;
        std::string correlation_type;
        std::chrono::steady_clock::time_point analyzed_at;
    };
    
    explicit IntelligenceAnalyzer(const Config& config);
    ~IntelligenceAnalyzer();
    
    bool Initialize();
    void Shutdown();
    
    // Analysis
    CorrelationResult CorrelateIndicators(const std::vector<std::string>& indicator_ids);
    std::vector<std::string> AttributeToActor(const std::vector<std::string>& indicator_ids);
    
    // Campaign tracking
    std::string IdentifyCampaign(const std::vector<ThreatIndicator>& indicators);
    std::vector<ThreatIndicator> GetCampaignIndicators(const std::string& campaign_id);
    
    // Reporting
    IntelligenceReport GenerateReport(const std::vector<std::string>& indicator_ids);
    bool ExportToSTIX(const IntelligenceReport& report, const std::string& file_path);
    bool ExportToMISP(const IntelligenceReport& report, const std::string& file_path);
    
private:
    Config config_;
    
    double CalculateSimilarity(const ThreatIndicator& a, const ThreatIndicator& b);
    std::vector<std::string> FindRelatedIndicators(const std::string& indicator_id);
};

// ============================================================================
// Threat Intelligence Runtime
// ============================================================================

class ThreatIntelligenceRuntime {
public:
    struct Config {
        ThreatFeedManager::Config feeds;
        IOCScanner::Config scanner;
        ThreatHunter::Config hunter;
        IntelligenceAnalyzer::Config analyzer;
    };
    
    explicit ThreatIntelligenceRuntime(const Config& config);
    ~ThreatIntelligenceRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    ThreatFeedManager* GetFeedManager();
    IOCScanner* GetIOCScanner();
    ThreatHunter* GetThreatHunter();
    IntelligenceAnalyzer* GetAnalyzer();
    
    // High-level API
    bool CheckIOC(const std::string& indicator);
    std::vector<ThreatIndicator> HuntThreats();
    IntelligenceReport GenerateIntelligenceReport(const std::vector<std::string>& indicators);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<ThreatFeedManager> feed_manager_;
    std::unique_ptr<IOCScanner> ioc_scanner_;
    std::unique_ptr<ThreatHunter> threat_hunter_;
    std::unique_ptr<IntelligenceAnalyzer> analyzer_;
};

} // namespace Security
} // namespace Sovereign
