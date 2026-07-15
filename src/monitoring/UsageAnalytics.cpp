// RawrXD Usage Analytics Implementation
// Phase V.2: Usage analytics and business metrics tracking

#include "UsageAnalytics.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <random>

namespace RawrXD {
namespace Monitoring {

// ============================================================================
// UserSession Implementation
// ============================================================================

std::chrono::seconds UserSession::getDuration() const {
    if (isActive) {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now() - startedAt);
    }
    return std::chrono::duration_cast<std::chrono::seconds>(endedAt - startedAt);
}

uint32_t UserSession::getEventCount() const {
    return static_cast<uint32_t>(events.size());
}

// ============================================================================
// UsageAnalytics Implementation
// ============================================================================

UsageAnalytics::UsageAnalytics() = default;

UsageAnalytics::~UsageAnalytics() {
    if (running_) {
        shutdown();
    }
}

bool UsageAnalytics::initialize(const std::string& configPath) {
    if (running_) {
        return true;
    }
    
    startTime_ = std::chrono::steady_clock::now();
    running_ = true;
    
    // Start event processing thread
    processingThread_ = std::thread([this]() {
        while (running_) {
            processEventQueue();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
    
    // Start cleanup thread
    cleanupThread_ = std::thread([this]() {
        while (running_) {
            cleanupOldSessions();
            std::this_thread::sleep_for(std::chrono::minutes(10));
        }
    });
    
    return true;
}

bool UsageAnalytics::shutdown() {
    if (!running_) {
        return true;
    }
    
    running_ = false;
    
    if (processingThread_.joinable()) {
        processingThread_.join();
    }
    
    if (cleanupThread_.joinable()) {
        cleanupThread_.join();
    }
    
    return true;
}

// ============================================================================
// Event Tracking
// ============================================================================

void UsageAnalytics::trackEvent(const AnalyticsEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);
    eventQueue_.push(event);
    totalEvents_++;
}

void UsageAnalytics::trackEvent(AnalyticsEventType type, const std::string& name,
                                const std::map<std::string, std::string>& properties,
                                const std::map<std::string, double>& metrics) {
    AnalyticsEvent event;
    event.eventId = generateEventId();
    event.type = type;
    event.name = name;
    event.timestamp = std::chrono::system_clock::now();
    event.properties = properties;
    event.metrics = metrics;
    
    trackEvent(event);
}

void UsageAnalytics::trackPageView(const std::string& page, const std::string& userId) {
    std::map<std::string, std::string> props;
    props["page"] = page;
    
    AnalyticsEvent event;
    event.eventId = generateEventId();
    event.type = AnalyticsEventType::PAGE_VIEW;
    event.name = "page_view";
    event.userId = userId;
    event.timestamp = std::chrono::system_clock::now();
    event.properties = props;
    
    trackEvent(event);
}

void UsageAnalytics::trackFeatureUsed(const std::string& feature, const std::string& userId) {
    std::map<std::string, std::string> props;
    props["feature"] = feature;
    
    AnalyticsEvent event;
    event.eventId = generateEventId();
    event.type = AnalyticsEventType::FEATURE_USED;
    event.name = "feature_used";
    event.userId = userId;
    event.timestamp = std::chrono::system_clock::now();
    event.properties = props;
    
    trackEvent(event);
    
    // Update feature usage
    std::lock_guard<std::mutex> lock(mutex_);
    auto& usage = features_[feature];
    usage.featureName = feature;
    usage.usageCount++;
    usage.lastUsed = std::chrono::system_clock::now();
    if (usage.firstUsed.time_since_epoch().count() == 0) {
        usage.firstUsed = usage.lastUsed;
    }
}

void UsageAnalytics::trackAPICall(const std::string& endpoint, int statusCode, double latencyMs) {
    std::map<std::string, std::string> props;
    props["endpoint"] = endpoint;
    props["status_code"] = std::to_string(statusCode);
    
    std::map<std::string, double> metrics;
    metrics["latency_ms"] = latencyMs;
    
    trackEvent(AnalyticsEventType::API_CALL, "api_call", props, metrics);
}

void UsageAnalytics::trackModelLoaded(const std::string& modelId, double loadTimeMs) {
    std::map<std::string, std::string> props;
    props["model_id"] = modelId;
    
    std::map<std::string, double> metrics;
    metrics["load_time_ms"] = loadTimeMs;
    
    trackEvent(AnalyticsEventType::MODEL_LOADED, "model_loaded", props, metrics);
}

void UsageAnalytics::trackInferenceCompleted(const std::string& modelId, double latencyMs,
                                              uint32_t tokensGenerated) {
    std::map<std::string, std::string> props;
    props["model_id"] = modelId;
    
    std::map<std::string, double> metrics;
    metrics["latency_ms"] = latencyMs;
    metrics["tokens_generated"] = static_cast<double>(tokensGenerated);
    
    trackEvent(AnalyticsEventType::INFERENCE_COMPLETED, "inference_completed", props, metrics);
}

void UsageAnalytics::trackError(const std::string& errorType, const std::string& message) {
    std::map<std::string, std::string> props;
    props["error_type"] = errorType;
    props["message"] = message;
    
    trackEvent(AnalyticsEventType::ERROR_OCCURRED, "error", props);
}

// ============================================================================
// Session Management
// ============================================================================

std::string UsageAnalytics::startSession(const std::string& userId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string sessionId = generateSessionId();
    
    UserSession session;
    session.sessionId = sessionId;
    session.userId = userId;
    session.startedAt = std::chrono::system_clock::now();
    session.isActive = true;
    
    sessions_[sessionId] = session;
    totalSessions_++;
    
    // Update user profile
    auto& user = users_[userId];
    user.userId = userId;
    user.lastSeen = std::chrono::system_clock::now();
    if (user.firstSeen.time_since_epoch().count() == 0) {
        user.firstSeen = user.lastSeen;
    }
    user.sessionCount++;
    
    return sessionId;
}

void UsageAnalytics::endSession(const std::string& sessionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = sessions_.find(sessionId);
    if (it != sessions_.end()) {
        it->second.isActive = false;
        it->second.endedAt = std::chrono::system_clock::now();
    }
}

UserSession UsageAnalytics::getSession(const std::string& sessionId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = sessions_.find(sessionId);
    if (it != sessions_.end()) {
        return it->second;
    }
    return UserSession{};
}

std::vector<UserSession> UsageAnalytics::getActiveSessions() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<UserSession> result;
    for (const auto& [id, session] : sessions_) {
        if (session.isActive) {
            result.push_back(session);
        }
    }
    return result;
}

std::vector<UserSession> UsageAnalytics::getUserSessions(const std::string& userId,
                                                           std::chrono::hours duration) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto cutoff = std::chrono::system_clock::now() - duration;
    std::vector<UserSession> result;
    
    for (const auto& [id, session] : sessions_) {
        if (session.userId == userId && session.startedAt >= cutoff) {
            result.push_back(session);
        }
    }
    
    return result;
}

// ============================================================================
// User Management
// ============================================================================

void UsageAnalytics::identifyUser(const std::string& userId,
                                  const std::map<std::string, std::string>& attributes) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto& user = users_[userId];
    user.userId = userId;
    user.lastSeen = std::chrono::system_clock::now();
    
    for (const auto& [key, value] : attributes) {
        user.attributes[key] = value;
    }
}

UserProfile UsageAnalytics::getUserProfile(const std::string& userId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = users_.find(userId);
    if (it != users_.end()) {
        return it->second;
    }
    return UserProfile{};
}

std::vector<UserProfile> UsageAnalytics::getAllUsers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<UserProfile> result;
    for (const auto& [id, user] : users_) {
        result.push_back(user);
    }
    return result;
}

uint32_t UsageAnalytics::getActiveUserCount(std::chrono::hours duration) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto cutoff = std::chrono::system_clock::now() - duration;
    uint32_t count = 0;
    
    for (const auto& [id, user] : users_) {
        if (user.lastSeen >= cutoff) {
            count++;
        }
    }
    
    return count;
}

// ============================================================================
// Feature Analytics
// ============================================================================

void UsageAnalytics::registerFeature(const std::string& featureName, const std::string& description) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto& feature = features_[featureName];
    feature.featureName = featureName;
}

FeatureUsage UsageAnalytics::getFeatureUsage(const std::string& featureName,
                                              std::chrono::hours duration) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = features_.find(featureName);
    if (it != features_.end()) {
        return it->second;
    }
    return FeatureUsage{};
}

std::vector<FeatureUsage> UsageAnalytics::getAllFeatureUsage(std::chrono::hours duration) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<FeatureUsage> result;
    for (const auto& [name, usage] : features_) {
        result.push_back(usage);
    }
    
    // Sort by usage count
    std::sort(result.begin(), result.end(), [](const FeatureUsage& a, const FeatureUsage& b) {
        return a.usageCount > b.usageCount;
    });
    
    return result;
}

std::vector<std::string> UsageAnalytics::getMostUsedFeatures(uint32_t limit,
                                                                std::chrono::hours duration) const {
    auto allUsage = getAllFeatureUsage(duration);
    
    std::vector<std::string> result;
    for (size_t i = 0; i < std::min(static_cast<size_t>(limit), allUsage.size()); ++i) {
        result.push_back(allUsage[i].featureName);
    }
    
    return result;
}

std::vector<std::string> UsageAnalytics::getUnusedFeatures(std::chrono::hours duration) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto cutoff = std::chrono::system_clock::now() - duration;
    std::vector<std::string> result;
    
    for (const auto& [name, usage] : features_) {
        if (usage.lastUsed < cutoff) {
            result.push_back(name);
        }
    }
    
    return result;
}

// ============================================================================
// Business Metrics
// ============================================================================

void UsageAnalytics::recordBusinessMetric(const BusinessMetric& metric) {
    // Would store business metrics
}

void UsageAnalytics::recordBusinessMetric(const std::string& name, double value,
                                          const std::string& unit,
                                          const std::map<std::string, std::string>& dimensions) {
    BusinessMetric metric;
    metric.name = name;
    metric.value = value;
    metric.unit = unit;
    metric.timestamp = std::chrono::system_clock::now();
    metric.dimensions = dimensions;
    
    recordBusinessMetric(metric);
}

std::vector<BusinessMetric> UsageAnalytics::getBusinessMetrics(const std::string& name,
                                                               std::chrono::hours duration) const {
    // Would retrieve business metrics
    return {};
}

double UsageAnalytics::getBusinessMetricAverage(const std::string& name,
                                                 std::chrono::hours duration) const {
    // Would calculate average
    return 0.0;
}

// ============================================================================
// Funnel Analysis
// ============================================================================

void UsageAnalytics::defineFunnel(const std::string& name, const std::vector<FunnelStep>& steps) {
    std::lock_guard<std::mutex> lock(mutex_);
    funnels_[name] = steps;
}

FunnelAnalysis UsageAnalytics::analyzeFunnel(const std::string& name,
                                            std::chrono::hours duration) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    FunnelAnalysis analysis;
    analysis.funnelName = name;
    
    auto it = funnels_.find(name);
    if (it == funnels_.end()) {
        return analysis;
    }
    
    analysis.steps = it->second;
    analysis.startTime = std::chrono::system_clock::now() - duration;
    analysis.endTime = std::chrono::system_clock::now();
    
    // Would analyze actual funnel data
    // Simplified: create placeholder results
    for (const auto& step : analysis.steps) {
        FunnelAnalysis::StepResult result;
        result.stepName = step.name;
        result.usersEntered = 1000;
        result.usersCompleted = 800;
        result.conversionRate = 80.0;
        result.dropOffRate = 20.0;
        result.averageTimeToComplete = std::chrono::seconds{30};
        analysis.results.push_back(result);
    }
    
    analysis.overallConversionRate = 80.0;
    
    return analysis;
}

std::vector<std::string> UsageAnalytics::listFunnels() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> result;
    for (const auto& [name, steps] : funnels_) {
        result.push_back(name);
    }
    return result;
}

// ============================================================================
// Cohort Analysis
// ============================================================================

void UsageAnalytics::defineCohort(const CohortDefinition& cohort) {
    std::lock_guard<std::mutex> lock(mutex_);
    cohorts_[cohort.name] = cohort;
}

CohortAnalysis UsageAnalytics::analyzeCohort(const std::string& cohortName,
                                            std::chrono::hours duration) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    CohortAnalysis analysis;
    analysis.cohortName = cohortName;
    
    // Would analyze cohort
    return analysis;
}

RetentionAnalysis UsageAnalytics::analyzeRetention(const std::string& cohortName,
                                                   std::chrono::hours duration) const {
    RetentionAnalysis analysis;
    analysis.metricName = cohortName.empty() ? "overall" : cohortName;
    
    // Would calculate retention
    analysis.days = {0, 1, 7, 14, 30};
    analysis.retentionRates = {100.0, 60.0, 40.0, 30.0, 20.0};
    
    return analysis;
}

// ============================================================================
// Real-time Metrics
// ============================================================================

UsageAnalytics::RealTimeMetrics UsageAnalytics::getRealTimeMetrics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    RealTimeMetrics metrics;
    
    // Count active users (unique in last 5 minutes)
    auto fiveMinutesAgo = std::chrono::system_clock::now() - std::chrono::minutes(5);
    std::set<std::string> activeUsers;
    for (const auto& [id, session] : sessions_) {
        if (session.startedAt >= fiveMinutesAgo || session.isActive) {
            activeUsers.insert(session.userId);
        }
    }
    metrics.activeUsers = static_cast<uint32_t>(activeUsers.size());
    
    // Count active sessions
    uint32_t activeSessionCount = 0;
    for (const auto& [id, session] : sessions_) {
        if (session.isActive) {
            activeSessionCount++;
        }
    }
    metrics.activeSessions = activeSessionCount;
    
    // Events per minute (last 5 minutes)
    auto oneMinuteAgo = std::chrono::system_clock::now() - std::chrono::minutes(1);
    uint64_t eventsLastMinute = 0;
    for (const auto& event : events_) {
        if (event.timestamp >= oneMinuteAgo) {
            eventsLastMinute++;
        }
    }
    metrics.eventsPerMinute = eventsLastMinute;
    
    // Average latency (from API calls)
    double totalLatency = 0.0;
    uint64_t latencyCount = 0;
    for (const auto& event : events_) {
        if (event.type == AnalyticsEventType::API_CALL) {
            auto it = event.metrics.find("latency_ms");
            if (it != event.metrics.end()) {
                totalLatency += it->second;
                latencyCount++;
            }
        }
    }
    metrics.averageLatencyMs = latencyCount > 0 ? totalLatency / latencyCount : 0.0;
    
    // Events by type
    for (const auto& event : events_) {
        std::string typeStr;
        switch (event.type) {
            case AnalyticsEventType::PAGE_VIEW: typeStr = "page_view"; break;
            case AnalyticsEventType::FEATURE_USED: typeStr = "feature_used"; break;
            case AnalyticsEventType::API_CALL: typeStr = "api_call"; break;
            case AnalyticsEventType::MODEL_LOADED: typeStr = "model_loaded"; break;
            case AnalyticsEventType::INFERENCE_COMPLETED: typeStr = "inference_completed"; break;
            case AnalyticsEventType::ERROR_OCCURRED: typeStr = "error"; break;
            default: typeStr = "other"; break;
        }
        metrics.eventsByType[typeStr]++;
    }
    
    return metrics;
}

// ============================================================================
// Query Interface
// ============================================================================

std::vector<AnalyticsEvent> UsageAnalytics::queryEvents(
    AnalyticsEventType type,
    std::chrono::system_clock::time_point start,
    std::chrono::system_clock::time_point end,
    const std::map<std::string, std::string>& filters) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<AnalyticsEvent> result;
    for (const auto& event : events_) {
        if (event.type == type && 
            event.timestamp >= start && 
            event.timestamp <= end) {
            // Check filters
            bool matches = true;
            for (const auto& [key, value] : filters) {
                auto it = event.properties.find(key);
                if (it == event.properties.end() || it->second != value) {
                    matches = false;
                    break;
                }
            }
            if (matches) {
                result.push_back(event);
            }
        }
    }
    return result;
}

std::vector<AnalyticsEvent> UsageAnalytics::queryEventsByUser(
    const std::string& userId,
    std::chrono::hours duration) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto cutoff = std::chrono::system_clock::now() - duration;
    std::vector<AnalyticsEvent> result;
    
    for (const auto& event : events_) {
        if (event.userId == userId && event.timestamp >= cutoff) {
            result.push_back(event);
        }
    }
    return result;
}

// ============================================================================
// Aggregation
// ============================================================================

UsageAnalytics::AggregationResult UsageAnalytics::aggregateByDimension(
    const std::string& metricName,
    const std::string& dimension,
    std::chrono::hours duration) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    AggregationResult result;
    result.dimension = dimension;
    
    // Would aggregate by dimension
    return result;
}

// ============================================================================
// Export
// ============================================================================

bool UsageAnalytics::exportEventsToJSON(const std::string& outputPath,
                                         std::chrono::hours duration) const {
    std::ofstream file(outputPath);
    if (!file) return false;
    
    auto cutoff = std::chrono::system_clock::now() - duration;
    
    file << "[\n";
    bool first = true;
    
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& event : events_) {
        if (event.timestamp >= cutoff) {
            if (!first) file << ",\n";
            first = false;
            
            file << "  {\n";
            file << "    \"eventId\": \"" << event.eventId << "\",\n";
            file << "    \"name\": \"" << event.name << "\",\n";
            file << "    \"userId\": \"" << event.userId << "\"\n";
            file << "  }";
        }
    }
    
    file << "\n]\n";
    return true;
}

bool UsageAnalytics::exportEventsToCSV(const std::string& outputPath,
                                      std::chrono::hours duration) const {
    std::ofstream file(outputPath);
    if (!file) return false;
    
    file << "event_id,name,user_id,timestamp\n";
    
    auto cutoff = std::chrono::system_clock::now() - duration;
    
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& event : events_) {
        if (event.timestamp >= cutoff) {
            auto time = std::chrono::system_clock::to_time_t(event.timestamp);
            file << event.eventId << "," << event.name << "," << event.userId << "," << time << "\n";
        }
    }
    return true;
}

bool UsageAnalytics::exportReport(const std::string& outputPath,
                                 std::chrono::hours duration) const {
    std::ofstream file(outputPath);
    if (!file) return false;
    
    auto stats = getStats();
    
    file << "# RawrXD Usage Analytics Report\n\n";
    file << "## Summary\n\n";
    file << "- Total Events: " << stats.totalEventsTracked << "\n";
    file << "- Total Sessions: " << stats.totalSessions << "\n";
    file << "- Active Users: " << stats.activeUsers << "\n";
    file << "- Registered Features: " << stats.registeredFeatures << "\n\n";
    
    file << "## Most Used Features\n\n";
    auto mostUsed = getMostUsedFeatures(10, duration);
    for (const auto& feature : mostUsed) {
        file << "- " << feature << "\n";
    }
    
    return true;
}

// ============================================================================
// Privacy/GDPR
// ============================================================================

bool UsageAnalytics::anonymizeUser(const std::string& userId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Anonymize user profile
    auto it = users_.find(userId);
    if (it != users_.end()) {
        it->second.attributes.clear();
        it->second.tags.clear();
    }
    
    // Anonymize events
    for (auto& event : events_) {
        if (event.userId == userId) {
            event.userId = "anonymous";
        }
    }
    
    return true;
}

bool UsageAnalytics::deleteUserData(const std::string& userId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Remove user profile
    users_.erase(userId);
    
    // Remove sessions
    sessions_.erase(
        std::remove_if(sessions_.begin(), sessions_.end(),
            [&userId](const auto& pair) { return pair.second.userId == userId; }),
        sessions_.end()
    );
    
    // Remove events
    events_.erase(
        std::remove_if(events_.begin(), events_.end(),
            [&userId](const AnalyticsEvent& e) { return e.userId == userId; }),
        events_.end()
    );
    
    return true;
}

std::vector<std::string> UsageAnalytics::getUserDataExport(const std::string& userId) const {
    std::vector<std::string> result;
    
    // Would export all user data
    result.push_back("User Profile");
    result.push_back("Sessions");
    result.push_back("Events");
    
    return result;
}

// ============================================================================
// Statistics
// ============================================================================

UsageAnalytics::AnalyticsStats UsageAnalytics::getStats() const {
    AnalyticsStats stats{};
    stats.totalEventsTracked = totalEvents_.load();
    stats.totalSessions = totalSessions_.load();
    stats.activeUsers = getActiveUserCount(std::chrono::hours{24});
    stats.registeredFeatures = static_cast<uint32_t>(features_.size());
    stats.definedFunnels = static_cast<uint32_t>(funnels_.size());
    stats.definedCohorts = static_cast<uint32_t>(cohorts_.size());
    stats.uptime = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - startTime_);
    return stats;
}

// ============================================================================
// Internal Methods
// ============================================================================

void UsageAnalytics::processEventQueue() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    while (!eventQueue_.empty()) {
        auto event = eventQueue_.front();
        eventQueue_.pop();
        events_.push_back(event);
    }
}

void UsageAnalytics::cleanupOldSessions() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto cutoff = std::chrono::system_clock::now() - std::chrono::hours(24);
    
    // Remove old inactive sessions
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        if (!it->second.isActive && it->second.endedAt < cutoff) {
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

std::string UsageAnalytics::generateEventId() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    ss << "evt-";
    for (int i = 0; i < 12; ++i) {
        ss << std::hex << dis(gen);
    }
    return ss.str();
}

std::string UsageAnalytics::generateSessionId() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    ss << "sess-";
    for (int i = 0; i < 8; ++i) {
        ss << std::hex << dis(gen);
    }
    return ss.str();
}

// ============================================================================
// EventBuilder Implementation
// ============================================================================

EventBuilder::EventBuilder(UsageAnalytics* analytics, AnalyticsEventType type, const std::string& name)
    : analytics_(analytics) {
    event_.eventId = "";  // Will be generated on track
    event_.type = type;
    event_.name = name;
    event_.timestamp = std::chrono::system_clock::now();
}

EventBuilder& EventBuilder::forUser(const std::string& userId) {
    event_.userId = userId;
    return *this;
}

EventBuilder& EventBuilder::inSession(const std::string& sessionId) {
    event_.sessionId = sessionId;
    return *this;
}

EventBuilder& EventBuilder::withProperty(const std::string& key, const std::string& value) {
    event_.properties[key] = value;
    return *this;
}

EventBuilder& EventBuilder::withMetric(const std::string& key, double value) {
    event_.metrics[key] = value;
    return *this;
}

EventBuilder& EventBuilder::fromSource(const std::string& source) {
    event_.source = source;
    return *this;
}

void EventBuilder::track() {
    analytics_->trackEvent(event_);
}

} // namespace Monitoring
} // namespace RawrXD
