#pragma once

/**
 * @file sync_coordinator.hpp
 * @brief Edge-to-cloud synchronization coordinator
 * @details Manages model updates, telemetry upload, and health reporting
 * @version 14.7.3
 * @date 2026-07-14
 */

#include <cstring>
#include <vector>
#include <functional>
#include <memory>
#include <chrono>

namespace rawrxd {
namespace edge {

/**
 * @brief Synchronization mode
 */
enum class SyncMode {
    MANUAL,     ///< User-triggered sync only
    WIFI_ONLY,  ///< Sync only on WiFi connection
    AUTOMATIC   ///< Sync when any connectivity available
};

/**
 * @brief Sync status
 */
enum class SyncStatus {
    IDLE,           ///< No sync in progress
    SYNCING,        ///< Sync in progress
    PENDING,        ///< Changes queued for sync
    ERROR,          ///< Last sync failed
    OFFLINE         ///< No connectivity
};

/**
 * @brief Sync operation type
 */
enum class SyncOperation {
    MODEL_UPDATE,   ///< Download model updates
    TELEMETRY_UPLOAD, ///< Upload usage telemetry
    HEALTH_REPORT,  ///< Upload health status
    CONFIG_UPDATE   ///< Download configuration
};

/**
 * @brief Sync progress
 */
struct SyncProgress {
    SyncOperation operation;
    size_t bytes_transferred;
    size_t bytes_total;
    float percentage;
    std::chrono::seconds elapsed;
    std::chrono::seconds estimated_remaining;
};

/**
 * @brief Sync result
 */
struct SyncResult {
    bool success;
    std::vector<SyncOperation> completed;
    std::vector<SyncOperation> failed;
    std::string error_message;
    size_t bytes_downloaded;
    size_t bytes_uploaded;
    std::chrono::milliseconds duration;
};

/**
 * @brief Model update info
 */
struct ModelUpdate {
    std::string model_id;
    std::string version_from;
    std::string version_to;
    size_t delta_size;          ///< Size of delta update
    size_t full_size;           ///< Size of full model
    bool is_delta;              ///< True if delta update available
    std::string changelog;
    std::chrono::system_clock::time_point release_date;
};

/**
 * @brief Telemetry data point
 */
struct TelemetryData {
    std::string model_id;
    std::chrono::system_clock::time_point timestamp;
    int prompt_tokens;
    int completion_tokens;
    float latency_ms;
    float tokens_per_second;
    std::string device_id;
    std::string session_id;
};

/**
 * @brief Sync configuration
 */
struct SyncConfig {
    SyncMode mode = SyncMode::WIFI_ONLY;
    std::string server_url;
    std::string api_key;
    size_t max_upload_size = 100 * 1024 * 1024;  ///< 100MB
    size_t max_download_size = 2ULL * 1024 * 1024 * 1024;  ///< 2GB
    std::chrono::minutes sync_interval{60};  ///< Auto-sync interval
    bool compress_telemetry = true;
    bool encrypt_transmission = true;
    int max_retries = 3;
    std::chrono::seconds retry_delay{30};
};

/**
 * @brief Edge-to-cloud sync coordinator
 *
 * Manages synchronization between edge device and central server:
 * - Delta model updates
 * - Telemetry upload
 * - Health reporting
 * - Conflict resolution
 */
class EdgeSyncCoordinator {
public:
    EdgeSyncCoordinator();
    ~EdgeSyncCoordinator();

    /**
     * @brief Initialize coordinator
     * @param config Sync configuration
     * @return true if initialization successful
     */
    bool initialize(const SyncConfig& config);

    /**
     * @brief Check for available updates
     * @return Vector of available model updates
     */
    std::vector<ModelUpdate> checkForUpdates();

    /**
     * @brief Sync models with server
     * @param specific_models Only sync specific models (empty = all)
     * @return Sync result
     */
    SyncResult syncModels(const std::vector<std::string>& specific_models = {});

    /**
     * @brief Upload telemetry data
     * @return Sync result
     */
    SyncResult uploadTelemetry();

    /**
     * @brief Report health status
     * @return Sync result
     */
    SyncResult reportHealth();

    /**
     * @brief Perform full sync
     * @return Sync result
     */
    SyncResult syncAll();

    /**
     * @brief Queue telemetry for upload
     * @param data Telemetry data point
     */
    void queueTelemetry(const TelemetryData& data);

    /**
     * @brief Set sync mode
     * @param mode New sync mode
     */
    void setSyncMode(SyncMode mode);

    /**
     * @brief Get current sync mode
     */
    SyncMode getSyncMode() const;

    /**
     * @brief Get current sync status
     */
    SyncStatus getStatus() const;

    /**
     * @brief Check if online
     */
    bool isOnline() const;

    /**
     * @brief Set online status
     * @param online New online status
     */
    void setOnline(bool online);

    /**
     * @brief Set WiFi status
     * @param wifi_connected WiFi connection status
     */
    void setWifiStatus(bool wifi_connected);

    /**
     * @brief Register progress callback
     * @param callback Called during sync operations
     */
    void onProgress(std::function<void(const SyncProgress&)> callback);

    /**
     * @brief Register completion callback
     * @param callback Called when sync completes
     */
    void onComplete(std::function<void(const SyncResult&)> callback);

    /**
     * @brief Cancel current sync
     */
    void cancelSync();

    /**
     * @brief Get pending operations count
     */
    size_t getPendingCount() const;

    /**
     * @brief Clear all pending operations
     */
    void clearPending();

    /**
     * @brief Get last sync time
     */
    std::chrono::system_clock::time_point getLastSyncTime() const;

    /**
     * @brief Get time since last sync
     */
    std::chrono::minutes getTimeSinceLastSync() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief Delta update engine
 */
class DeltaUpdateEngine {
public:
    /**
     * @brief Calculate delta between model versions
     * @param old_version Path to old model
     * @param new_version Path to new model
     * @return Delta binary
     */
    static std::vector<uint8_t> calculateDelta(
        const std::string& old_version,
        const std::string& new_version
    );

    /**
     * @brief Apply delta to old version
     * @param old_version Path to old model
     * @param delta Delta binary
     * @param output_path Path for new model
     * @return true if successful
     */
    static bool applyDelta(
        const std::string& old_version,
        const std::vector<uint8_t>& delta,
        const std::string& output_path
    );

    /**
     * @brief Estimate delta size
     * @param old_version Path to old model
     * @param new_version Path to new model
     * @return Estimated delta size in bytes
     */
    static size_t estimateDeltaSize(
        const std::string& old_version,
        const std::string& new_version
    );
};

/**
 * @brief Conflict resolver
 */
class ConflictResolver {
public:
    /**
     * @brief Resolution strategy
     */
    enum class Strategy {
        SERVER_WINS,    ///< Always use server version
        CLIENT_WINS,    ///< Always use client version
        NEWEST_WINS,    ///< Use newest by timestamp
        MERGE           ///< Attempt to merge
    };

    /**
     * @brief Resolve version conflict
     * @param server_version Server model version
     * @param client_version Client model version
     * @param strategy Resolution strategy
     * @return Which version to use
     */
    static std::string resolve(
        const std::string& server_version,
        const std::string& client_version,
        Strategy strategy
    );
};

} // namespace edge
} // namespace rawrxd
