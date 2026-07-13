// Phase D.7 Batch 5/5: Audit & Forensics
// Immutable Audit Logs and Forensic Analysis
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
// Audit Event Types
// ============================================================================

enum class AuditEventType {
    AUTHENTICATION = 0,
    AUTHORIZATION = 1,
    DATA_ACCESS = 2,
    CONFIGURATION_CHANGE = 3,
    SECURITY_EVENT = 4,
    ADMIN_ACTION = 5,
    SYSTEM_EVENT = 6
};

enum class AuditEventOutcome {
    SUCCESS = 0,
    FAILURE = 1,
    DENIED = 2,
    ERROR = 3
};

struct AuditEvent {
    std::string event_id;
    AuditEventType type;
    std::string timestamp;
    std::string actor_id;
    std::string actor_type;
    std::string action;
    std::string resource;
    std::string resource_type;
    AuditEventOutcome outcome;
    std::map<std::string, std::string> details;
    std::string source_ip;
    std::string session_id;
    std::string request_id;
    std::string previous_hash;  // For chain integrity
    std::string event_hash;     // SHA-256 of event data
    int64_t sequence_number = 0;
};

// ============================================================================
// Immutable Audit Log
// ============================================================================

class ImmutableAuditLog {
public:
    struct Config {
        std::string storage_backend;  // "filesystem", "s3", "blockchain"
        std::string encryption_key_id;
        bool sign_events = true;
        int retention_days = 2555;  // 7 years
        int batch_size = 1000;
        int flush_interval_seconds = 60;
    };
    
    explicit ImmutableAuditLog(const Config& config);
    ~ImmutableAuditLog();
    
    bool Initialize();
    void Shutdown();
    
    // Event logging
    bool LogEvent(const AuditEvent& event);
    bool LogEvents(const std::vector<AuditEvent>& events);
    
    // Retrieval
    std::vector<AuditEvent> QueryEvents(
        const std::string& start_time,
        const std::string& end_time,
        const std::map<std::string, std::string>& filters);
    
    std::vector<AuditEvent> GetEventsByActor(const std::string& actor_id,
                                               const std::string& start_time,
                                               const std::string& end_time);
    
    std::vector<AuditEvent> GetEventsByResource(const std::string& resource,
                                                 const std::string& start_time,
                                                 const std::string& end_time);
    
    // Integrity verification
    bool VerifyIntegrity(const std::string& start_time, const std::string& end_time);
    bool VerifyEvent(const AuditEvent& event);
    std::string CalculateHash(const AuditEvent& event);
    
    // Chain verification
    bool VerifyChain(int64_t start_sequence, int64_t end_sequence);
    std::string GetChainRootHash();
    
    // Export
    bool ExportToFile(const std::string& start_time, const std::string& end_time,
                      const std::string& file_path);
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    std::thread flush_thread_;
    
    std::vector<AuditEvent> buffer_;
    std::mutex buffer_mutex_;
    
    int64_t sequence_counter_ = 0;
    std::mutex sequence_mutex_;
    
    void FlushLoop();
    bool PersistEvents(const std::vector<AuditEvent>& events);
    std::string SignEvent(const AuditEvent& event);
};

// ============================================================================
// Chain of Custody
// ============================================================================

class ChainOfCustody {
public:
    struct CustodyRecord {
        std::string record_id;
        std::string evidence_id;
        std::string evidence_type;
        std::string collected_by;
        std::string collected_from;
        std::string timestamp;
        std::string hash;
        std::string location;
        std::string access_control;
        std::vector<std::string> transfers;
        bool sealed = false;
        std::string sealed_by;
        std::string seal_timestamp;
    };
    
    struct CustodyTransfer {
        std::string transfer_id;
        std::string record_id;
        std::string from_party;
        std::string to_party;
        std::string reason;
        std::string timestamp;
        std::string authorized_by;
        std::string verification_hash;
    };
    
    bool CreateRecord(const CustodyRecord& record);
    bool TransferCustody(const std::string& record_id, const CustodyTransfer& transfer);
    bool SealEvidence(const std::string& record_id, const std::string& sealed_by);
    
    CustodyRecord GetRecord(const std::string& record_id) const;
    std::vector<CustodyTransfer> GetTransferHistory(const std::string& record_id) const;
    bool VerifyIntegrity(const std::string& record_id);
    
private:
    std::map<std::string, CustodyRecord> records_;
    std::map<std::string, std::vector<CustodyTransfer>> transfers_;
    mutable std::mutex records_mutex_;
};

// ============================================================================
// Forensic Analysis
// ============================================================================

class ForensicAnalyzer {
public:
    struct Config {
        int max_timeline_events = 10000;
        bool enable_correlation = true;
        int correlation_window_minutes = 60;
    };
    
    struct TimelineEvent {
        std::string timestamp;
        std::string event_type;
        std::string actor;
        std::string action;
        std::string target;
        std::string outcome;
        std::map<std::string, std::string> details;
        int severity = 0;
    };
    
    struct AttackChain {
        std::string chain_id;
        std::vector<TimelineEvent> events;
        std::string initial_access;
        std::string persistence;
        std::string privilege_escalation;
        std::string lateral_movement;
        std::string exfiltration;
        std::chrono::steady_clock::time_point start_time;
        std::chrono::steady_clock::time_point end_time;
        bool complete = false;
    };
    
    explicit ForensicAnalyzer(const Config& config);
    
    bool Initialize(ImmutableAuditLog* audit_log);
    
    // Timeline reconstruction
    std::vector<TimelineEvent> ReconstructTimeline(
        const std::string& start_time,
        const std::string& end_time,
        const std::vector<std::string>& actors);
    
    // Attack chain analysis
    std::vector<AttackChain> IdentifyAttackChains(
        const std::string& start_time,
        const std::string& end_time);
    
    AttackChain AnalyzeAttackChain(const std::string& chain_id);
    
    // Evidence correlation
    std::vector<std::vector<TimelineEvent>> CorrelateEvents(
        const std::vector<TimelineEvent>& events);
    
    // Impact assessment
    struct ImpactAssessment {
        std::vector<std::string> affected_systems;
        std::vector<std::string> affected_users;
        std::vector<std::string> accessed_data;
        std::chrono::minutes duration{0};
        int severity_score = 0;
        std::vector<std::string> recommended_actions;
    };
    
    ImpactAssessment AssessImpact(const std::string& incident_id);
    
    // Report generation
    struct ForensicReport {
        std::string report_id;
        std::string incident_id;
        std::string generated_at;
        std::string generated_by;
        std::vector<TimelineEvent> timeline;
        std::vector<AttackChain> attack_chains;
        ImpactAssessment impact;
        std::vector<std::string> evidence_refs;
        std::vector<std::string> indicators_of_compromise;
        std::map<std::string, std::string> recommendations;
    };
    
    ForensicReport GenerateReport(const std::string& incident_id);
    bool ExportReport(const ForensicReport& report, const std::string& format,
                      const std::string& output_path);
    
private:
    Config config_;
    ImmutableAuditLog* audit_log_ = nullptr;
    
    std::vector<TimelineEvent> QueryRelevantEvents(
        const std::string& start_time,
        const std::string& end_time);
    
    bool IsPartOfAttackChain(const TimelineEvent& event,
                             const AttackChain& chain);
    
    std::string ClassifyTactic(const TimelineEvent& event);
};

// ============================================================================
// Evidence Collector
// ============================================================================

class EvidenceCollector {
public:
    struct Config {
        int max_evidence_size_mb = 1024;
        std::string storage_path;
        bool compress = true;
        bool encrypt = true;
        std::string encryption_key_id;
    };
    
    struct Evidence {
        std::string evidence_id;
        std::string type;  // "log", "memory", "disk", "network", "config"
        std::string source;
        std::string collected_at;
        std::string collected_by;
        std::string hash;
        int64_t size_bytes = 0;
        std::string storage_path;
        std::map<std::string, std::string> metadata;
        bool encrypted = false;
    };
    
    explicit EvidenceCollector(const Config& config);
    
    bool Initialize();
    
    // Collection
    Evidence CollectLogs(const std::string& source, const std::string& start_time,
                         const std::string& end_time);
    
    Evidence CollectMemoryDump(const std::string& host_id);
    Evidence CollectDiskImage(const std::string& volume_id);
    Evidence CollectNetworkCapture(const std::string& interface_id,
                                   int duration_seconds);
    Evidence CollectConfiguration(const std::string& resource_id);
    
    // Management
    Evidence GetEvidence(const std::string& evidence_id) const;
    std::vector<Evidence> GetEvidenceForIncident(const std::string& incident_id) const;
    bool DeleteEvidence(const std::string& evidence_id);
    
    // Integrity
    bool VerifyIntegrity(const std::string& evidence_id);
    std::string CalculateHash(const std::string& file_path);
    
private:
    Config config_;
    
    std::map<std::string, Evidence> evidence_store_;
    mutable std::mutex evidence_mutex_;
    
    std::string GenerateEvidenceId();
    bool StoreEvidence(Evidence& evidence, const std::vector<uint8_t>& data);
    std::vector<uint8_t> RetrieveEvidence(const Evidence& evidence);
};

// ============================================================================
// Security Operations Center Integration
// ============================================================================

class SOCIntegration {
public:
    struct Config {
        std::string siem_endpoint;
        std::string api_key;
        std::string ticketing_system;
        int alert_batch_size = 100;
        int flush_interval_seconds = 60;
    };
    
    struct SOCCase {
        std::string case_id;
        std::string title;
        std::string description;
        std::string severity;
        std::string status;
        std::vector<std::string> alerts;
        std::vector<std::string> indicators;
        std::string assigned_to;
        std::string created_at;
        std::string updated_at;
    };
    
    explicit SOCIntegration(const Config& config);
    
    bool Initialize();
    
    // Case management
    std::string CreateCase(const std::string& title, const std::string& description,
                           const std::string& severity);
    bool UpdateCase(const std::string& case_id, const std::map<std::string, std::string>& updates);
    bool CloseCase(const std::string& case_id, const std::string& resolution);
    SOCCase GetCase(const std::string& case_id) const;
    
    // Alert forwarding
    bool ForwardAlert(const std::string& alert_data);
    bool ForwardAlerts(const std::vector<std::string>& alerts);
    
    // Indicator sharing
    bool ShareIndicators(const std::vector<std::string>& indicators);
    std::vector<std::string> ReceiveIndicators();
    
private:
    Config config_;
    
    std::vector<std::string> alert_buffer_;
    std::mutex buffer_mutex_;
    std::thread flush_thread_;
    std::atomic<bool> running_{false};
    
    void FlushLoop();
    bool SendToSIEM(const std::vector<std::string>& alerts);
};

// ============================================================================
// Audit & Forensics Runtime
// ============================================================================

class AuditForensicsRuntime {
public:
    struct Config {
        ImmutableAuditLog::Config audit_log;
        ForensicAnalyzer::Config forensics;
        EvidenceCollector::Config evidence;
        SOCIntegration::Config soc;
        bool enable_immutable_storage = true;
        bool enable_blockchain_verification = false;
    };
    
    explicit AuditForensicsRuntime(const Config& config);
    ~AuditForensicsRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Audit logging
    bool LogEvent(const AuditEvent& event);
    bool LogSecurityEvent(const std::string& actor, const std::string& action,
                          const std::string& resource, AuditEventOutcome outcome);
    
    // Query and analysis
    std::vector<AuditEvent> QueryAuditLog(const std::string& start_time,
                                          const std::string& end_time);
    bool VerifyAuditIntegrity(const std::string& start_time, const std::string& end_time);
    
    // Forensics
    ForensicAnalyzer::ForensicReport InvestigateIncident(const std::string& incident_id);
    std::vector<ForensicAnalyzer::AttackChain> AnalyzeAttackChains(
        const std::string& start_time, const std::string& end_time);
    
    // Evidence
    EvidenceCollector::Evidence CollectEvidence(const std::string& type,
                                                 const std::string& source);
    bool PreserveEvidence(const std::string& evidence_id);
    
    // Chain of custody
    bool CreateCustodyRecord(const ChainOfCustody::CustodyRecord& record);
    bool TransferCustody(const std::string& record_id, const std::string& to_party,
                         const std::string& authorized_by);
    
    // SOC integration
    std::string CreateSOCCase(const std::string& title, const std::string& description);
    bool ForwardToSOC(const std::string& alert_data);
    
    // Access subsystems
    ImmutableAuditLog* GetAuditLog();
    ChainOfCustody* GetChainOfCustody();
    ForensicAnalyzer* GetForensicAnalyzer();
    EvidenceCollector* GetEvidenceCollector();
    SOCIntegration* GetSOCIntegration();
    
private:
    Config config_;
    std::unique_ptr<ImmutableAuditLog> audit_log_;
    std::unique_ptr<ChainOfCustody> chain_of_custody_;
    std::unique_ptr<ForensicAnalyzer> forensics_;
    std::unique_ptr<EvidenceCollector> evidence_;
    std::unique_ptr<SOCIntegration> soc_;
};

} // namespace Security
} // namespace Sovereign
