#pragma once

#include "enterprise_license.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace RawrXD::License {

enum class AuditEventType : uint8_t {
    LICENSE_ACTIVATED = 0,
    LICENSE_REVOKED = 1,
    FEATURE_GRANTED = 2,
    FEATURE_DENIED = 3,
    TAMPERING_DETECTED = 4,
    CLOCK_SKEW_DETECTED = 5,
    OFFLINE_VALIDATION = 6,
    GRACE_PERIOD_ENTERED = 7,
    GRACE_PERIOD_EXCEEDED = 8,
    SYSTEM_EVENT = 9,
    UNAUTHORIZED_ACCESS = 10,
    LICENSE_EXPIRED = 11,
    LICENSE_CHECK = 12,
    POLICY_VIOLATION = 13,
    SECURITY_ALERT = 14,
    COMPLIANCE_REPORT = 15,
    UNKNOWN = 16,
    INVALID = 17
};

struct FeatureAuditStats {
    uint32_t featureID = 0;
    uint32_t grantCount = 0;
    uint32_t denyCount = 0;
    uint32_t lastAccessTime = 0;
    float denialRate = 0.0f;
};

struct TierChangeRecord {
    uint32_t timestamp = 0;
    LicenseTierV2 from = LicenseTierV2::Community;
    LicenseTierV2 to = LicenseTierV2::Community;
};

struct AnomalyEvent {
    uint32_t timestamp = 0;
    uint32_t featureID = 0;
    std::string description;
    float severity = 0.0f;
};

struct SIEMExportConfig {
    std::string url;
    std::string token;
    std::string apiKey;
    std::string endpoint;
    bool enabled = false;
};

constexpr uint32_t AUDIT_STATS_WINDOW_SECONDS = 3600U;
constexpr uint32_t AUDIT_ANOMALY_THRESHOLD = 10U;
constexpr uint32_t AUDIT_LOG_ROTATION_SIZE = 1024U * 1024U;

class AuditTrailManager {
public:
    AuditTrailManager();
    ~AuditTrailManager();

    void recordEvent(AuditEventType type, FeatureID feature, bool granted, const char* caller);
    bool getFeatureStats(FeatureID feature, FeatureAuditStats& stats) const;
    std::vector<FeatureAuditStats> getAllFeatureStats() const;
    std::vector<TierChangeRecord> getTierChangeHistory(uint32_t maxRecords) const;
    std::vector<AnomalyEvent> getAnomalies(uint32_t maxEvents) const;
    bool clearAuditTrail(const char* authToken);
    bool exportToFile(const char* path, const char* format);
    bool exportToSIEM(const SIEMExportConfig& config);
    std::string generateComplianceSummary() const;
    std::string toJSON(uint32_t maxEvents = 0) const;

    uint32_t getTotalEvents() const;
    uint32_t getTotalDenials() const;
    uint32_t getTotalGrants() const;
    uint32_t getAnomalyCount() const;
    float getDenialRate(uint32_t windowSeconds = 0) const;
    bool isInAnomalousState() const;

    void analyzeAnomalities();
    bool detectExcessiveDenials();
    bool detectRapidTierChanges();
    bool detectFeaturePatterns();
    void updateFeatureStats(FeatureID feature, bool granted);
    bool persistToFile();
    bool loadFromFile();

private:
    uint32_t m_totalEvents = 0;
    uint32_t m_totalDenials = 0;
    uint32_t m_totalGrants = 0;
    uint32_t m_lastAnomalyAnalysisTime = 0;
    bool m_isAnomalous = false;
    std::string m_auditLogPath;
    std::array<FeatureAuditStats, TOTAL_FEATURES> m_featureStats{};
    std::vector<TierChangeRecord> m_tierHistory;
    std::vector<AnomalyEvent> m_anomalies;
};

class AnomalyDetector {
public:
    AnomalyDetector();
    ~AnomalyDetector();

    bool detectAnomaly(AuditEventType eventType, FeatureID feature, const char* caller);
    float getAnomalalySeverity() const;
    const char* getAnomalyDescription() const;
    void reset();
    void setExcessiveDenialThreshold(uint32_t count);
    void setRapidTierChangeThreshold(uint32_t changesInTime);
    void setFeaturePatternThreshold(float abnormalityScore);
    void getBaselineMetrics(uint32_t& avgGrants, uint32_t& avgDenials) const;
    bool isAnomalous() const;
    float computeAnomalyScore();

private:
    uint32_t m_excessiveDenialThreshold = AUDIT_ANOMALY_THRESHOLD;
    uint32_t m_rapidChangeThreshold = 5;
    float m_patternThreshold = 0.8f;
    float m_currentSeverity = 0.0f;
    bool m_isAnomalous = false;
    uint32_t m_baselineGrants = 100;
    uint32_t m_baselineDenials = 5;
    char m_description[256] = {};
};

class SIEMExporter {
public:
    SIEMExporter();
    ~SIEMExporter();

    std::string formatCEF(AuditEventType eventType, FeatureID feature, const char* caller);
    std::string formatLEEF(AuditEventType eventType, FeatureID feature, const char* caller);
    std::string formatJSON(AuditEventType eventType, FeatureID feature, const char* caller);
    std::string formatSyslog(AuditEventType eventType, FeatureID feature, const char* caller);
    bool sendToSIEM(const SIEMExportConfig& config, const std::string& event);
    bool batchExport(const SIEMExportConfig& config, const std::vector<std::string>& events);
    const char* getEventTypeString(AuditEventType type) const;
    std::string urlEncode(const char* str) const;
    int getSeverityLevel(AuditEventType type) const;
};

class PersistentAuditLog {
public:
    PersistentAuditLog();
    ~PersistentAuditLog();

    bool append(AuditEventType type, FeatureID feature, bool granted, const char* caller);
    bool read(std::vector<LicenseAuditEntry>& entries, uint32_t maxCount);
    bool rotate();
    bool clear(const char* authToken);
    uint32_t getLogSize() const;
    std::vector<LicenseAuditEntry> getEntriesSince(uint32_t timestamp) const;
    const char* getLogPath() const;
    const char* getArchivePath(uint32_t sequence) const;

private:
    uint32_t m_currentSize = 0;
    uint32_t m_logRotationCount = 0;
};

const char* getEventTypeString(AuditEventType type);

extern AuditTrailManager g_auditTrailManager;
extern AnomalyDetector g_anomalyDetector;
extern SIEMExporter g_siemExporter;
extern PersistentAuditLog g_persistentAuditLog;

}  // namespace RawrXD::License
