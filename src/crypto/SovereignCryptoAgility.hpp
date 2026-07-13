// Phase D.15 Batch 5/5: Crypto Agility Manager
// Dynamic algorithm selection and migration
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
namespace Crypto {

// Forward declarations
struct CryptoPolicy;
struct AlgorithmStatus;
struct MigrationPlan;

// ============================================================================
// Crypto Agility Types
// ============================================================================

enum class AlgorithmCategory {
    KEM = 0,
    SIGNATURE = 1,
    HASH = 2,
    SYMMETRIC = 3,
    RANDOM = 4,
    KDF = 5
};

enum class AlgorithmStatus {
    APPROVED = 0,
    DEPRECATED = 1,
    LEGACY = 2,
    EXPERIMENTAL = 3,
    COMPROMISED = 4
};

enum class SecurityLevel {
    LEVEL_0 = 0,    // None
    LEVEL_1 = 128,  // Minimum
    LEVEL_2 = 192,  // Medium
    LEVEL_3 = 256,  // High
    LEVEL_4 = 384   // Maximum
};

struct AlgorithmInfo {
    std::string name;
    AlgorithmCategory category;
    AlgorithmStatus status;
    SecurityLevel security_level;
    bool is_quantum_safe;
    bool is_hybrid_capable;
    std::chrono::steady_clock::time_point approved_since;
    std::chrono::steady_clock::time_point deprecated_since;
    std::vector<std::string> standards;  // NIST, ISO, etc.
    std::map<std::string, std::any> parameters;
    std::vector<std::string> known_vulnerabilities;
};

struct CryptoPolicy {
    std::string policy_id;
    std::string name;
    std::string version;
    SecurityLevel minimum_security_level;
    bool require_quantum_safe;
    bool allow_hybrid;
    bool allow_classical_fallback;
    std::vector<std::string> approved_kems;
    std::vector<std::string> approved_signatures;
    std::vector<std::string> approved_hashes;
    std::vector<std::string> approved_symmetric;
    std::chrono::steady_clock::time_point effective_date;
    std::chrono::steady_clock::time_point expiration_date;
    std::map<std::string, std::string> constraints;
};

struct MigrationPlan {
    std::string plan_id;
    std::string source_algorithm;
    std::string target_algorithm;
    AlgorithmCategory category;
    std::chrono::steady_clock::time_point scheduled_date;
    std::chrono::steady_clock::time_point deadline;
    std::vector<std::string> affected_systems;
    std::map<std::string, std::any> rollback_procedures;
    bool is_emergency;
};

// ============================================================================
// Algorithm Registry
// ============================================================================

class AlgorithmRegistry {
public:
    struct Config {
        std::string registry_source;  // URL or file path
        std::chrono::hours update_interval{24};
        bool auto_update = true;
        bool verify_signatures = true;
    };
    
    explicit AlgorithmRegistry(const Config& config);
    ~AlgorithmRegistry();
    
    bool Initialize();
    void Shutdown();
    
    // Algorithm registration
    bool RegisterAlgorithm(const AlgorithmInfo& info);
    bool UpdateAlgorithm(const std::string& name, const AlgorithmInfo& info);
    bool RemoveAlgorithm(const std::string& name);
    
    // Algorithm queries
    AlgorithmInfo GetAlgorithm(const std::string& name) const;
    std::vector<AlgorithmInfo> GetAlgorithmsByCategory(AlgorithmCategory category) const;
    std::vector<AlgorithmInfo> GetAlgorithmsByStatus(AlgorithmStatus status) const;
    std::vector<AlgorithmInfo> GetAlgorithmsBySecurityLevel(SecurityLevel level) const;
    std::vector<AlgorithmInfo> GetQuantumSafeAlgorithms() const;
    std::vector<AlgorithmInfo> GetApprovedAlgorithms() const;
    
    // Status management
    bool UpdateAlgorithmStatus(const std::string& name, AlgorithmStatus new_status);
    bool DeprecateAlgorithm(const std::string& name, const std::string& reason);
    bool MarkCompromised(const std::string& name, const std::string& vulnerability);
    
    // Standards compliance
    std::vector<AlgorithmInfo> GetCompliantAlgorithms(const std::string& standard) const;
    bool CheckCompliance(const std::string& algorithm_name, const std::string& standard) const;
    
    // Registry updates
    bool RefreshFromRemote();
    bool ImportFromFile(const std::string& file_path);
    bool ExportToFile(const std::string& file_path) const;
    
private:
    Config config_;
    std::map<std::string, AlgorithmInfo> algorithms_;
    mutable std::mutex registry_mutex_;
    std::thread update_thread_;
    std::atomic<bool> running_{false};
    
    void UpdateLoop();
    bool FetchRemoteRegistry();
    bool ValidateAlgorithmInfo(const AlgorithmInfo& info);
};

// ============================================================================
// Policy Manager
// ============================================================================

class PolicyManager {
public:
    struct Config {
        std::string default_policy_id;
        bool enforce_policy = true;
        bool allow_override = false;
        std::chrono::seconds policy_check_interval{60};
    };
    
    explicit PolicyManager(const Config& config);
    ~PolicyManager();
    
    bool Initialize();
    void Shutdown();
    
    // Policy management
    bool CreatePolicy(const CryptoPolicy& policy);
    bool UpdatePolicy(const std::string& policy_id, const CryptoPolicy& policy);
    bool DeletePolicy(const std::string& policy_id);
    bool ActivatePolicy(const std::string& policy_id);
    bool DeactivatePolicy(const std::string& policy_id);
    
    // Policy queries
    CryptoPolicy GetPolicy(const std::string& policy_id) const;
    CryptoPolicy GetActivePolicy() const;
    std::vector<CryptoPolicy> GetAllPolicies() const;
    std::vector<CryptoPolicy> GetEffectivePolicies() const;
    
    // Validation
    bool ValidateAgainstPolicy(const std::string& algorithm_name,
                                  const CryptoPolicy& policy) const;
    std::vector<std::string> GetPolicyViolations(const CryptoPolicy& policy) const;
    
    // Compliance checking
    struct ComplianceReport {
        bool compliant;
        std::vector<std::string> violations;
        std::vector<std::string> warnings;
        std::vector<std::string> recommendations;
        std::chrono::steady_clock::time_point generated_at;
    };
    ComplianceReport GenerateComplianceReport(const std::string& system_id) const;
    
private:
    Config config_;
    std::map<std::string, CryptoPolicy> policies_;
    std::string active_policy_id_;
    mutable std::mutex policies_mutex_;
};

// ============================================================================
// Migration Manager
// ============================================================================

class MigrationManager {
public:
    struct Config {
        bool auto_migrate = false;
        std::chrono::days migration_window{30};
        bool require_approval = true;
        int max_parallel_migrations = 5;
        bool enable_rollback = true;
    };
    
    enum class MigrationState {
        PLANNED = 0,
        APPROVED = 1,
        IN_PROGRESS = 2,
        COMPLETED = 3,
        FAILED = 4,
        ROLLED_BACK = 5
    };
    
    struct MigrationStatus {
        std::string migration_id;
        MigrationState state;
        int progress_percent;
        std::chrono::steady_clock::time_point started_at;
        std::chrono::steady_clock::time_point completed_at;
        std::vector<std::string> completed_systems;
        std::vector<std::string> pending_systems;
        std::vector<std::string> failed_systems;
        std::string error_message;
    };
    
    explicit MigrationManager(const Config& config);
    ~MigrationManager();
    
    bool Initialize();
    void Shutdown();
    
    // Migration planning
    std::string CreateMigrationPlan(const MigrationPlan& plan);
    bool ApproveMigration(const std::string& plan_id);
    bool RejectMigration(const std::string& plan_id, const std::string& reason);
    bool CancelMigration(const std::string& plan_id);
    
    // Migration execution
    bool StartMigration(const std::string& plan_id);
    bool PauseMigration(const std::string& plan_id);
    bool ResumeMigration(const std::string& plan_id);
    bool CompleteMigration(const std::string& plan_id);
    bool RollbackMigration(const std::string& plan_id);
    
    // Status monitoring
    MigrationStatus GetMigrationStatus(const std::string& plan_id) const;
    std::vector<MigrationStatus> GetActiveMigrations() const;
    std::vector<MigrationStatus> GetMigrationHistory() const;
    
    // System-level migration
    bool MigrateSystem(const std::string& system_id,
                       const std::string& source_algo,
                       const std::string& target_algo);
    bool VerifyMigration(const std::string& system_id,
                         const std::string& migration_id);
    
private:
    Config config_;
    std::map<std::string, MigrationPlan> plans_;
    std::map<std::string, MigrationStatus> statuses_;
    mutable std::mutex migrations_mutex_;
    std::thread migration_thread_;
    std::atomic<bool> running_{false};
    
    void MigrationLoop();
    bool ExecuteMigrationStep(const std::string& plan_id);
    bool PerformRollback(const std::string& plan_id);
};

// ============================================================================
// Crypto Selector
// ============================================================================

class CryptoSelector {
public:
    struct SelectionCriteria {
        AlgorithmCategory category;
        SecurityLevel minimum_security;
        bool require_quantum_safe = false;
        bool prefer_hybrid = false;
        int max_latency_ms = 0;
        size_t max_key_size = 0;
        std::vector<std::string> preferred_standards;
    };
    
    struct SelectionResult {
        std::string selected_algorithm;
        std::vector<std::string> alternatives;
        std::string selection_reason;
        SecurityLevel achieved_security;
        bool meets_all_criteria;
        std::vector<std::string> unmet_criteria;
    };
    
    explicit CryptoSelector(AlgorithmRegistry* registry, PolicyManager* policy);
    
    // Algorithm selection
    SelectionResult SelectAlgorithm(const SelectionCriteria& criteria);
    std::vector<SelectionResult> SelectAllCategories(SecurityLevel minimum_security);
    
    // Negotiation
    std::string NegotiateAlgorithm(const std::vector<std::string>& client_algorithms,
                                    const std::vector<std::string>& server_algorithms,
                                    AlgorithmCategory category);
    std::vector<std::string> GetCommonAlgorithms(
        const std::vector<std::string>& algorithms1,
        const std::vector<std::string>& algorithms2);
    
    // Fallback handling
    std::string GetFallbackAlgorithm(const std::string& preferred,
                                      AlgorithmCategory category);
    bool IsFallbackSecure(const std::string& algorithm);
    
    // Performance-based selection
    SelectionResult SelectByPerformance(const SelectionCriteria& criteria,
                                         const std::string& benchmark_data);
    
private:
    AlgorithmRegistry* registry_;
    PolicyManager* policy_;
    
    int ScoreAlgorithm(const AlgorithmInfo& info, const SelectionCriteria& criteria);
    bool MeetsCriteria(const AlgorithmInfo& info, const SelectionCriteria& criteria);
};

// ============================================================================
// Threat Monitor
// ============================================================================

class ThreatMonitor {
public:
    struct Config {
        std::vector<std::string> threat_feeds;
        std::chrono::minutes check_interval{60};
        bool auto_deprecate = true;
        bool alert_on_threat = true;
    };
    
    struct Threat {
        std::string threat_id;
        std::string title;
        std::string description;
        std::vector<std::string> affected_algorithms;
        std::string severity;  // LOW, MEDIUM, HIGH, CRITICAL
        std::chrono::steady_clock::time_point discovered_at;
        std::chrono::steady_clock::time_point disclosed_at;
        std::vector<std::string> cve_ids;
        std::string mitigation;
    };
    
    explicit ThreatMonitor(const Config& config);
    ~ThreatMonitor();
    
    bool Initialize();
    void Shutdown();
    
    // Threat monitoring
    std::vector<Threat> CheckThreats();
    std::vector<Threat> GetActiveThreats() const;
    std::vector<Threat> GetThreatsForAlgorithm(const std::string& algorithm) const;
    
    // Response
    bool AssessThreatImpact(const Threat& threat);
    bool TriggerEmergencyDeprecation(const std::string& algorithm,
                                        const std::string& reason);
    std::vector<std::string> GetRecommendedActions(const Threat& threat);
    
    // Feeds
    bool AddThreatFeed(const std::string& feed_url);
    bool RemoveThreatFeed(const std::string& feed_url);
    bool RefreshThreatFeeds();
    
private:
    Config config_;
    std::vector<Threat> active_threats_;
    mutable std::mutex threats_mutex_;
    std::thread monitor_thread_;
    std::atomic<bool> running_{false};
    
    void MonitorLoop();
    std::vector<Threat> FetchThreatFeeds();
    bool ProcessThreat(const Threat& threat);
};

// ============================================================================
// Crypto Agility Runtime
// ============================================================================

class CryptoAgilityRuntime {
public:
    struct Config {
        AlgorithmRegistry::Config registry;
        PolicyManager::Config policy;
        MigrationManager::Config migration;
        ThreatMonitor::Config threat;
    };
    
    explicit CryptoAgilityRuntime(const Config& config);
    ~CryptoAgilityRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    AlgorithmRegistry* GetRegistry();
    PolicyManager* GetPolicyManager();
    MigrationManager* GetMigrationManager();
    CryptoSelector* GetSelector();
    ThreatMonitor* GetThreatMonitor();
    
    // High-level API
    std::string SelectSecureAlgorithm(AlgorithmCategory category,
                                        SecurityLevel minimum_security);
    
    bool ValidateConfiguration(const std::string& algorithm_name);
    
    std::string InitiateMigration(const std::string& source_algorithm,
                                   const std::string& target_algorithm,
                                   AlgorithmCategory category);
    
    // Emergency response
    bool EmergencyDeprecation(const std::string& algorithm_name,
                               const std::string& reason);
    bool EmergencyMigration(const std::vector<std::string>& affected_algorithms);
    
    // Health check
    struct AgilityHealth {
        bool registry_healthy;
        bool policy_compliant;
        int active_migrations;
        int active_threats;
        std::vector<std::string> deprecated_in_use;
        std::vector<std::string> recommendations;
    };
    AgilityHealth GetHealthStatus() const;
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<AlgorithmRegistry> registry_;
    std::unique_ptr<PolicyManager> policy_manager_;
    std::unique_ptr<MigrationManager> migration_manager_;
    std::unique_ptr<CryptoSelector> selector_;
    std::unique_ptr<ThreatMonitor> threat_monitor_;
};

} // namespace Crypto
} // namespace Sovereign
