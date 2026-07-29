#pragma once
<<<<<<< HEAD
// telemetry_collector.hpp – Qt-free telemetry (C++20 / Win32)
#include "../json_types.hpp"
#include <cstdint>
#include <mutex>
#include <string>
=======

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

/**
 * Privacy-respecting telemetry for feature usage and crash analysis.
 *   - Opt-in only (disabled by default)
 *   - No PII collection
 *   - Anonymous session IDs
 *   - GDPR/CCPA compliant
 */
<<<<<<< HEAD
class TelemetryCollector {
public:
    static TelemetryCollector* instance();

    bool initialize();
    bool isEnabled() const { return m_enabled; }

    void enableTelemetry();
    void disableTelemetry();

    void trackFeatureUsage(const std::string& featureName, const JsonObject& metadata = {});
    void trackCrash(const std::string& crashReason);
    void trackPerformance(const std::string& metricName, double value, const std::string& unit = {});

    JsonObject getAllTelemetryData() const;
    void       clearAllData();
    void       flushData();

    // --- Callbacks (replaces Qt signals) ---
    using VoidCb    = void(*)(void* ctx);
    using FlushCb   = void(*)(void* ctx, int eventCount);

    void setEnabledCb(VoidCb cb, void* ctx)   { m_enabledCb  = cb; m_enabledCtx  = ctx; }
    void setDisabledCb(VoidCb cb, void* ctx)   { m_disabledCb = cb; m_disabledCtx = ctx; }
    void setFlushedCb(FlushCb cb, void* ctx)   { m_flushedCb  = cb; m_flushedCtx  = ctx; }

private:
    TelemetryCollector();
=======
class TelemetryCollector : public void
{

public:
    static TelemetryCollector* instance();
    
    /**
     * @brief Initialize telemetry (checks user consent)
     * @return true if user has opted in
     */
    bool initialize();
    
    /**
     * @brief Check if user has consented to telemetry
     * @return true if telemetry is enabled
     */
    bool isEnabled() const { return m_enabled; }
    
    /**
     * @brief Enable telemetry (stores user consent)
     */
    void enableTelemetry();
    
    /**
     * @brief Disable telemetry (removes consent)
     */
    void disableTelemetry();
    
    /**
     * @brief Track feature usage (no PII)
     * @param featureName Feature identifier (e.g., "model.load", "inference.generate")
     * @param metadata Additional context (no PII allowed)
     */
    void trackFeatureUsage(const std::string& featureName, const void*& metadata = void*());
    
    /**
     * @brief Track application crash (minimal data)
     * @param crashReason Crash reason (sanitized, no PII)
     */
    void trackCrash(const std::string& crashReason);
    
    /**
     * @brief Track performance metric
     * @param metricName Metric identifier (e.g., "inference.latency")
     * @param value Numeric value
     * @param unit Unit of measurement (ms, MB, etc.)
     */
    void trackPerformance(const std::string& metricName, double value, const std::string& unit = std::string());
    
    /**
     * @brief Get all collected telemetry data (for user transparency)
     * @return JSON object with all telemetry
     */
    void* getAllTelemetryData() const;
    
    /**
     * @brief Clear all telemetry data (user-initiated)
     */
    void clearAllData();
    
    /**
     * @brief Flush aggregated data to server (respects opt-in)
     */
    void flushData();

    void telemetryEnabled();
    void telemetryDisabled();
    void dataFlushed(int eventCount);

private:
    explicit TelemetryCollector(void* parent = nullptr);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    ~TelemetryCollector();

    static TelemetryCollector* s_instance;
<<<<<<< HEAD

    bool        m_enabled = false;
    std::string m_sessionId;
    int64_t     m_sessionStartTime = 0;

    mutable std::mutex                          m_mutex;
    std::unordered_map<std::string, int>        m_featureUsage;
    std::vector<JsonObject>                     m_events;

    std::string sanitize(const std::string& input) const;
    void        sendTelemetry(const JsonObject& payload);
    bool        loadUserConsent() const;
    void        saveUserConsent(bool enabled);

    // Callback state
    VoidCb  m_enabledCb  = nullptr;  void* m_enabledCtx  = nullptr;
    VoidCb  m_disabledCb = nullptr;  void* m_disabledCtx = nullptr;
    FlushCb m_flushedCb  = nullptr;  void* m_flushedCtx  = nullptr;
=======
    
    bool m_enabled;
    std::string m_sessionId;  ///< Anonymous session identifier (not persistent)
    std::unordered_map<std::string, int> m_featureUsage;  ///< Feature name -> usage count
    std::vector<void*> m_events;  ///< Buffered events for batch sending
    int64_t m_sessionStartTime;  ///< Session start timestamp
    
    // PRODUCTION-READY: Sanitize data to remove any PII
    std::string sanitize(const std::string& input) const;
    
    // PRODUCTION-READY: Send telemetry to server (non-blocking)
    void sendTelemetry(const void*& payload);
    
    // PRODUCTION-READY: Load user consent from settings
    bool loadUserConsent() const;
    
    // PRODUCTION-READY: Save user consent to settings
    void saveUserConsent(bool enabled);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
};


