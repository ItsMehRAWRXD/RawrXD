// RawrXD Usage Analytics
// Phase V.2: Usage analytics and business metrics tracking
// Tracks user behavior, feature adoption, and business KPIs

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>
#include <queue>
#include <optional>

namespace RawrXD {
namespace Monitoring {

// Event types
enum class AnalyticsEventType {
    PAGE_VIEW,
    FEATURE_USED,
    API_CALL,
    MODEL_LOADED,
    INFERENCE_COMPLETED,
    ERROR_OCCURRED,
    USER_ACTION,
    SESSION_START,
    SESSION_END,
    CUSTOM
};

// Analytics event
struct AnalyticsEvent {
    std::string eventId;
    AnalyticsEventType type;
    std::string name;
    std::string userId;
    std::string sessionId;
    std::chrono::system_clock::time_point timestamp;
    std::map<std::string, std::string> properties;
    std::map<std::string, double> metrics;
    std::string source;  // Component that generated the event
    std::string version;  // Product version
};

// User session
struct UserSession {
    std::string sessionId;
    std::string userId;
    std::chrono::system_clock::time_point startedAt;
    std::chrono::system_clock::time_point endedAt;
    std::vector<AnalyticsEvent> events;
    std::map<std::string, std::string> properties;
    bool isActive{true};
    
    std::chrono::seconds getDuration() const;
    uint32_t getEventCount() const;
};

// User profile
struct UserProfile {
    std::string userId;
    std::string organizationId;
    std::chrono::system_clock::time_point firstSeen;
    std::chrono::system_clock::time_point lastSeen;
    uint32_t sessionCount{0};
    std::map<std::string, std::string> attributes;
    std::vector<std::string> tags;
    bool isActive{true};
};

// Feature usage
struct FeatureUsage {
    std::string featureName;
    uint64_t usageCount{0};
    uint64_t uniqueUsers{0};
    std::chrono::system_clock::time_point firstUsed;
    std::chrono::system_clock::time_point lastUsed;
    double averageDuration{0.0};  // Average time spent using feature
    std::map<std::string, uint64_t> byVersion;
};

// Business metric
struct BusinessMetric {
    std::string name;
    std::string description;
    double value;
    std::string unit;  // "count", "percentage", "currency", "time"
    std::chrono::system_clock::time_point timestamp;
    std::map<std::string, std::string> dimensions;
};

// Funnel step
struct FunnelStep {
    std::string name;
    std::string eventName;  // Event that marks completion of this step
    std::optional<std::string> prerequisiteStep;
};

// Funnel analysis
struct FunnelAnalysis {
    std::string funnelName;
    std::vector<FunnelStep> steps;
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point endTime;
    
    struct StepResult {
        std::string stepName;
        uint64_t usersEntered;
        uint64_t usersCompleted;
        double conversionRate;  // Percentage
        double dropOffRate;  // Percentage
        std::chrono::seconds averageTimeToComplete;
    };
    std::vector<StepResult> results;
    double overallConversionRate{0.0};
};

// Cohort definition
struct CohortDefinition {
    std::string name;
    std::string description;
    std::function<bool(const UserProfile&)> matcher;
    std::chrono::system_clock::time_point createdAt;
};

// Cohort analysis
struct CohortAnalysis {
    std::string cohortName;
    std::vector<std::string> userIds;
    std::map<std::string, double> metrics;  // Metric name -> average value
    std::vector<std::vector<double>> retentionMatrix;  // Day -> retention %
};

// Retention analysis
struct RetentionAnalysis {
    std::string metricName;  // e.g., "daily", "weekly", "monthly"
    std::vector<int> days;  // Day numbers (0, 1, 7, 30, etc.)
    std::vector<double> retentionRates;  // Percentage retained
    std::map<std::string, std::vector<double>> byCohort;
};

// Usage analytics engine
class UsageAnalytics {
public:
    UsageAnalytics();
    ~UsageAnalytics();
    
    // Initialization
    bool initialize(const std::string& configPath);
    bool shutdown();
    bool isRunning() const { return running_; }
    
    // Event tracking
    void trackEvent(const AnalyticsEvent& event);
    void trackEvent(AnalyticsEventType type, const std::string& name,
                   const std::map<std::string, std::string>& properties = {},
                   const std::map<std::string, double>& metrics = {});
    void trackPageView(const std::string& page, const std::string& userId = "");
    void trackFeatureUsed(const std::string& feature, const std::string& userId = "");
    void trackAPICall(const std::string& endpoint, int statusCode, double latencyMs);
    void trackModelLoaded(const std::string& modelId, double loadTimeMs);
    void trackInferenceCompleted(const std::string& modelId, double latencyMs, 
                                  uint32_t tokensGenerated);
    void trackError(const std::string& errorType, const std::string& message);
    
    // Session management
    std::string startSession(const std::string& userId);
    void endSession(const std::string& sessionId);
    UserSession getSession(const std::string& sessionId) const;
    std::vector<UserSession> getActiveSessions() const;
    std::vector<UserSession> getUserSessions(const std::string& userId,
                                                std::chrono::hours duration = std::chrono::hours{168}) const;
    
    // User management
    void identifyUser(const std::string& userId, 
                     const std::map<std::string, std::string>& attributes = {});
    UserProfile getUserProfile(const std::string& userId) const;
    std::vector<UserProfile> getAllUsers() const;
    uint32_t getActiveUserCount(std::chrono::hours duration = std::chrono::hours{24}) const;
    
    // Feature analytics
    void registerFeature(const std::string& featureName, const std::string& description);
    FeatureUsage getFeatureUsage(const std::string& featureName,
                                  std::chrono::hours duration = std::chrono::hours{168}) const;
    std::vector<FeatureUsage> getAllFeatureUsage(std::chrono::hours duration = std::chrono::hours{168}) const;
    std::vector<std::string> getMostUsedFeatures(uint32_t limit = 10,
                                                    std::chrono::hours duration = std::chrono::hours{168}) const;
    std::vector<std::string> getUnusedFeatures(std::chrono::hours duration = std::chrono::hours{168}) const;
    
    // Business metrics
    void recordBusinessMetric(const BusinessMetric& metric);
    void recordBusinessMetric(const std::string& name, double value, 
                              const std::string& unit = "count",
                              const std::map<std::string, std::string>& dimensions = {});
    std::vector<BusinessMetric> getBusinessMetrics(const std::string& name,
                                                     std::chrono::hours duration = std::chrono::hours{168}) const;
    double getBusinessMetricAverage(const std::string& name,
                                   std::chrono::hours duration = std::chrono::hours{168}) const;
    
    // Funnel analysis
    void defineFunnel(const std::string& name, const std::vector<FunnelStep>& steps);
    FunnelAnalysis analyzeFunnel(const std::string& name,
                                 std::chrono::hours duration = std::chrono::hours{168}) const;
    std::vector<std::string> listFunnels() const;
    
    // Cohort analysis
    void defineCohort(const CohortDefinition& cohort);
    CohortAnalysis analyzeCohort(const std::string& cohortName,
                                  std::chrono::hours duration = std::chrono::hours{168}) const;
    RetentionAnalysis analyzeRetention(const std::string& cohortName = "",
                                       std::chrono::hours duration = std::chrono::hours{168}) const;
    
    // Real-time analytics
    struct RealTimeMetrics {
        uint32_t activeUsers;
        uint32_t activeSessions;
        uint64_t eventsPerMinute;
        double averageLatencyMs;
        std::map<std::string, uint64_t> eventsByType;
    };
    RealTimeMetrics getRealTimeMetrics() const;
    
    // Query interface
    std::vector<AnalyticsEvent> queryEvents(
        AnalyticsEventType type,
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end,
        const std::map<std::string, std::string>& filters = {}) const;
    
    std::vector<AnalyticsEvent> queryEventsByUser(
        const std::string& userId,
        std::chrono::hours duration = std::chrono::hours{168}) const;
    
    // Aggregation
    struct AggregationResult {
        std::string dimension;
        std::map<std::string, double> values;  // Dimension value -> aggregated metric
    };
    AggregationResult aggregateByDimension(
        const std::string& metricName,
        const std::string& dimension,
        std::chrono::hours duration = std::chrono::hours{168}) const;
    
    // Export
    bool exportEventsToJSON(const std::string& outputPath,
                            std::chrono::hours duration = std::chrono::hours{168}) const;
    bool exportEventsToCSV(const std::string& outputPath,
                           std::chrono::hours duration = std::chrono::hours{168}) const;
    bool exportReport(const std::string& outputPath,
                     std::chrono::hours duration = std::chrono::hours{168}) const;
    
    // Privacy/GDPR
    bool anonymizeUser(const std::string& userId);
    bool deleteUserData(const std::string& userId);
    std::vector<std::string> getUserDataExport(const std::string& userId) const;
    
    // Statistics
    struct AnalyticsStats {
        uint64_t totalEventsTracked;
        uint64_t totalSessions;
        uint32_t activeUsers;
        uint32_t registeredFeatures;
        uint32_t definedFunnels;
        uint32_t definedCohorts;
        std::chrono::seconds uptime;
    };
    AnalyticsStats getStats() const;

private:
    void processEventQueue();
    void cleanupOldSessions();
    std::string generateEventId() const;
    std::string generateSessionId() const;
    
    mutable std::mutex mutex_;
    std::map<std::string, UserProfile> users_;
    std::map<std::string, UserSession> sessions_;
    std::map<std::string, FeatureUsage> features_;
    std::vector<AnalyticsEvent> events_;
    std::map<std::string, std::vector<FunnelStep>> funnels_;
    std::map<std::string, CohortDefinition> cohorts_;
    std::queue<AnalyticsEvent> eventQueue_;
    
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> totalEvents_{0};
    std::atomic<uint64_t> totalSessions_{0};
    std::chrono::steady_clock::time_point startTime_;
    
    std::thread processingThread_;
    std::thread cleanupThread_;
};

// Event builder for fluent API
class EventBuilder {
public:
    EventBuilder(UsageAnalytics* analytics, AnalyticsEventType type, const std::string& name);
    
    EventBuilder& forUser(const std::string& userId);
    EventBuilder& inSession(const std::string& sessionId);
    EventBuilder& withProperty(const std::string& key, const std::string& value);
    EventBuilder& withMetric(const std::string& key, double value);
    EventBuilder& fromSource(const std::string& source);
    
    void track();
    
private:
    UsageAnalytics* analytics_;
    AnalyticsEvent event_;
};

} // namespace Monitoring
} // namespace RawrXD
