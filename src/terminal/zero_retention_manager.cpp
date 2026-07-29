/**
 * @file zero_retention_manager.cpp
 * @brief Qt-free implementation of ZeroRetentionManager
 *
 * GDPR/privacy-compliant data retention manager.
 * All Qt types replaced with STL / Win32 equivalents.
 * UUID generation via Win32 CoCreateGuid.
 * Secure deletion via overwrite + std::filesystem::remove.
 */
#include "zero_retention_manager.hpp"
<<<<<<< HEAD
#include "json_types.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#pragma comment(lib, "ole32.lib")

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <mutex>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

// ---- internal helpers (anonymous namespace) ----
namespace {

static std::string timePointToISO8601(std::chrono::system_clock::time_point tp)
{
    auto tt = std::chrono::system_clock::to_time_t(tp);
    struct tm tmBuf;
    gmtime_s(&tmBuf, &tt);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmBuf);
    return std::string(buf);
}

} // anonymous namespace

// ===== Constructor / Destructor =====

ZeroRetentionManager::ZeroRetentionManager()
    : m_cleanupTimer(new std::function<void()>([this]() { performAutoCleanup(); }))
{
    logStructured("INFO", "ZeroRetentionManager initializing",
                  JsonObject{{"component", std::string("ZeroRetentionManager")}});
    logStructured("INFO", "ZeroRetentionManager initialized successfully",
                  JsonObject{{"component", std::string("ZeroRetentionManager")}});
=======


ZeroRetentionManager::ZeroRetentionManager(void* parent)
    : void(parent),
      m_cleanupTimer(new void*(this))
{
    logStructured("INFO", "ZeroRetentionManager initializing", void*{{"component", "ZeroRetentionManager"}});
// Qt connect removed
    logStructured("INFO", "ZeroRetentionManager initialized successfully", void*{{"component", "ZeroRetentionManager"}});
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

ZeroRetentionManager::~ZeroRetentionManager()
{
<<<<<<< HEAD
    logStructured("INFO", "ZeroRetentionManager shutting down",
                  JsonObject{{"component", std::string("ZeroRetentionManager")}});

    // Perform final cleanup
    Config config;
    {
        std::lock_guard<std::mutex> lock(m_configMutex);
=======
    logStructured("INFO", "ZeroRetentionManager shutting down", void*{{"component", "ZeroRetentionManager"}});
    
    m_cleanupTimer->stop();
    
    // Perform final cleanup
    Config config;
    {
        std::lock_guard<std::mutex> configLocker(&m_configMutex);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        config = m_config;
    }

    if (config.dataRetentionDays == 0) {
        purgeAllData(Session);
    }
<<<<<<< HEAD

    delete m_cleanupTimer;
    m_cleanupTimer = nullptr;

    logStructured("INFO", "ZeroRetentionManager shutdown complete",
                  JsonObject{{"component", std::string("ZeroRetentionManager")}});
=======
    
    logStructured("INFO", "ZeroRetentionManager shutdown complete", void*{{"component", "ZeroRetentionManager"}});
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

// ===== Configuration =====

void ZeroRetentionManager::setConfig(const Config& config)
{
<<<<<<< HEAD
    std::lock_guard<std::mutex> lock(m_configMutex);
    m_config = config;

    // Log whether auto-cleanup is enabled (no timer thread — cleanup
    // fires via explicit calls to cleanupExpiredData or performAutoCleanup).
    logStructured("INFO", "Configuration updated", JsonObject{
        {"sessionTtlMinutes", static_cast<int64_t>(config.sessionTtlMinutes)},
        {"dataRetentionDays", static_cast<int64_t>(config.dataRetentionDays)},
=======
    std::lock_guard<std::mutex> locker(&m_configMutex);
    m_config = config;
    
    // Restart cleanup timer with new interval
    if (config.enableAutoCleanup) {
        m_cleanupTimer->start(config.cleanupIntervalMinutes * 60 * 1000);
    } else {
        m_cleanupTimer->stop();
    }
    
    logStructured("INFO", "Configuration updated", void*{
        {"sessionTtlMinutes", config.sessionTtlMinutes},
        {"dataRetentionDays", config.dataRetentionDays},
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        {"enableAutoCleanup", config.enableAutoCleanup},
        {"cleanupIntervalMinutes", static_cast<int64_t>(config.cleanupIntervalMinutes)}
    });
}

ZeroRetentionManager::Config ZeroRetentionManager::getConfig() const
{
<<<<<<< HEAD
    std::lock_guard<std::mutex> lock(m_configMutex);
    return m_config;
}

// ===== Core functionality =====

std::string ZeroRetentionManager::registerData(const std::string& path,
                                               DataClass classification,
                                               int customTtlMinutes)
=======
    std::lock_guard<std::mutex> locker(&m_configMutex);
    return m_config;
}

std::string ZeroRetentionManager::registerData(const std::string& path, DataClass classification, int customTtlMinutes)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
{
    auto startTime = std::chrono::steady_clock::now();

    try {
        std::string id = generateDataId();
<<<<<<< HEAD

=======
        
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        DataEntry entry;
        entry.id             = id;
        entry.path           = path;
        entry.classification = classification;
<<<<<<< HEAD
        entry.createdAt      = std::chrono::system_clock::now();
        entry.expiresAt      = calculateExpiry(classification, customTtlMinutes);
        entry.isAnonymized   = false;

        // Get file size if path exists
        std::error_code ec;
        if (std::filesystem::exists(path, ec)) {
            entry.sizeBytes = static_cast<int64_t>(std::filesystem::file_size(path, ec));
            if (ec) entry.sizeBytes = 0;
=======
        entry.createdAt = std::chrono::system_clock::time_point::currentDateTime();
        entry.expiresAt = calculateExpiry(classification, customTtlMinutes);
        entry.isAnonymized = false;
        
        // Get file size if path exists
        std::filesystem::path fileInfo(path);
        if (fileInfo.exists()) {
            entry.sizeBytes = fileInfo.size();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        } else {
            entry.sizeBytes = 0;
        }

        {
<<<<<<< HEAD
            std::lock_guard<std::mutex> lock(m_dataMutex);
=======
            std::lock_guard<std::mutex> dataMutex(&m_dataMutex);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            m_trackedData[id] = entry;
        }

        {
<<<<<<< HEAD
            std::lock_guard<std::mutex> lock(m_metricsMutex);
            m_metrics.dataEntriesTracked++;
        }

        auto endTime  = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                            endTime - startTime);

        logStructured("INFO", "Data registered for tracking", JsonObject{
            {"id", id},
            {"path", path},
            {"classification", static_cast<int64_t>(classification)},
            {"expiresAt", timePointToISO8601(entry.expiresAt)},
=======
            std::lock_guard<std::mutex> metricsLocker(&m_metricsMutex);
            m_metrics.dataEntriesTracked++;
        }
        
        auto endTime = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
        
        logStructured("INFO", "Data registered for tracking", void*{
            {"id", id},
            {"path", path},
            {"classification", static_cast<int>(classification)},
            {"expiresAt", entry.expiresAt.toString(//ISODate)},
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            {"sizeBytes", entry.sizeBytes}
        });

        Config config;
        {
<<<<<<< HEAD
            std::lock_guard<std::mutex> lock(m_configMutex);
=======
            std::lock_guard<std::mutex> configLocker(&m_configMutex);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            config = m_config;
        }

        if (config.enableAuditLog) {
<<<<<<< HEAD
            logAudit("data_registered", JsonObject{
                {"id", id},
                {"path", path},
                {"classification", static_cast<int64_t>(classification)},
                {"createdAt", timePointToISO8601(entry.createdAt)},
                {"expiresAt", timePointToISO8601(entry.expiresAt)}
=======
            logAudit("data_registered", void*{
                {"id", id},
                {"path", path},
                {"classification", static_cast<int>(classification)},
                {"createdAt", entry.createdAt.toString(//ISODate)},
                {"expiresAt", entry.expiresAt.toString(//ISODate)}
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            });
        }

        return id;

    } catch (const std::exception& e) {
<<<<<<< HEAD
        {
            std::lock_guard<std::mutex> lock(m_metricsMutex);
            m_metrics.errorCount++;
        }
        logStructured("ERROR", "Failed to register data",
                      JsonObject{{"error", std::string(e.what())}});
        errorOccurred(std::string("Registration failed: ") + e.what());
=======
        std::lock_guard<std::mutex> metricsLocker(&m_metricsMutex);
        m_metrics.errorCount++;
        logStructured("ERROR", "Failed to register data", void*{{"error", e.what()}});
        errorOccurred(std::string("Registration failed: %1")));
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        return std::string();
    }
}

bool ZeroRetentionManager::unregisterData(const std::string& id)
{
    try {
<<<<<<< HEAD
        {
            std::lock_guard<std::mutex> lock(m_dataMutex);

            auto it = m_trackedData.find(id);
            if (it == m_trackedData.end()) {
                logStructured("WARN", "Data ID not found for unregistration",
                              JsonObject{{"id", id}});
                return false;
            }

            m_trackedData.erase(it);
        }

        logStructured("INFO", "Data unregistered", JsonObject{{"id", id}});

        Config config;
        {
            std::lock_guard<std::mutex> lock(m_configMutex);
=======
        std::lock_guard<std::mutex> dataMutex(&m_dataMutex);
        
        if (!m_trackedData.contains(id)) {
            logStructured("WARN", "Data ID not found for unregistration", void*{{"id", id}});
            return false;
        }
        
        m_trackedData.remove(id);
        
        logStructured("INFO", "Data unregistered", void*{{"id", id}});
        
        Config config;
        {
            std::lock_guard<std::mutex> configLocker(&m_configMutex);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            config = m_config;
        }

        if (config.enableAuditLog) {
<<<<<<< HEAD
            logAudit("data_unregistered", JsonObject{{"id", id}});
=======
            logAudit("data_unregistered", void*{{"id", id}});
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        }

        return true;

    } catch (const std::exception& e) {
<<<<<<< HEAD
        {
            std::lock_guard<std::mutex> lock(m_metricsMutex);
            m_metrics.errorCount++;
        }
        logStructured("ERROR", "Failed to unregister data",
                      JsonObject{{"error", std::string(e.what())}});
        errorOccurred(std::string("Unregistration failed: ") + e.what());
=======
        std::lock_guard<std::mutex> metricsLocker(&m_metricsMutex);
        m_metrics.errorCount++;
        logStructured("ERROR", "Failed to unregister data", void*{{"error", e.what()}});
        errorOccurred(std::string("Unregistration failed: %1")));
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        return false;
    }
}

bool ZeroRetentionManager::deleteData(const std::string& id, bool immediate)
{
    auto startTime = std::chrono::steady_clock::now();

    try {
        DataEntry entry;
        {
<<<<<<< HEAD
            std::lock_guard<std::mutex> lock(m_dataMutex);
            auto it = m_trackedData.find(id);
            if (it == m_trackedData.end()) {
                logStructured("WARN", "Data ID not found for deletion",
                              JsonObject{{"id", id}});
=======
            std::lock_guard<std::mutex> dataMutex(&m_dataMutex);
            if (!m_trackedData.contains(id)) {
                logStructured("WARN", "Data ID not found for deletion", void*{{"id", id}});
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
                return false;
            }
            entry = it->second;
        }

        // Check if should delete based on retention policy
        if (!immediate && !isExpired(entry)) {
<<<<<<< HEAD
            logStructured("DEBUG", "Data not yet expired, skipping deletion", JsonObject{
                {"id", id},
                {"expiresAt", timePointToISO8601(entry.expiresAt)}
=======
            logStructured("DEBUG", "Data not yet expired, skipping deletion", void*{
                {"id", id},
                {"expiresAt", entry.expiresAt.toString(//ISODate)}
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            });
            return false;
        }

        bool deleteSuccess = secureDelete(entry.path);

        if (deleteSuccess || immediate) {
            {
<<<<<<< HEAD
                std::lock_guard<std::mutex> lock(m_dataMutex);
                m_trackedData.erase(id);
=======
                std::lock_guard<std::mutex> dataMutex(&m_dataMutex);
                m_trackedData.remove(id);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            }

            {
<<<<<<< HEAD
                std::lock_guard<std::mutex> lock(m_metricsMutex);
                m_metrics.dataEntriesDeleted++;
                m_metrics.bytesDeleted += entry.sizeBytes;
            }

            auto endTime  = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                                endTime - startTime);

            logStructured("INFO", "Data deleted", JsonObject{
=======
                std::lock_guard<std::mutex> metricsLocker(&m_metricsMutex);
                m_metrics.dataEntriesDeleted++;
                m_metrics.bytesDeleted += entry.sizeBytes;
            }
            
            auto endTime = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
            
            logStructured("INFO", "Data deleted", void*{
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
                {"id", id},
                {"path", entry.path},
                {"sizeBytes", entry.sizeBytes},
                {"latencyMs", static_cast<int64_t>(duration.count())}
            });

            Config config;
            {
<<<<<<< HEAD
                std::lock_guard<std::mutex> lock(m_configMutex);
=======
                std::lock_guard<std::mutex> configLocker(&m_configMutex);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
                config = m_config;
            }

            if (config.enableAuditLog) {
<<<<<<< HEAD
                logAudit("data_deleted", JsonObject{
=======
                logAudit("data_deleted", void*{
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
                    {"id", id},
                    {"path", entry.path},
                    {"sizeBytes", entry.sizeBytes},
                    {"classification", static_cast<int64_t>(entry.classification)},
                    {"immediate", immediate}
                });
            }
<<<<<<< HEAD

=======
            
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            dataDeleted(id, entry.sizeBytes);
        }

        return deleteSuccess;

    } catch (const std::exception& e) {
<<<<<<< HEAD
        {
            std::lock_guard<std::mutex> lock(m_metricsMutex);
            m_metrics.errorCount++;
        }
        logStructured("ERROR", "Failed to delete data",
                      JsonObject{{"error", std::string(e.what())}});
        errorOccurred(std::string("Deletion failed: ") + e.what());
=======
        std::lock_guard<std::mutex> metricsLocker(&m_metricsMutex);
        m_metrics.errorCount++;
        logStructured("ERROR", "Failed to delete data", void*{{"error", e.what()}});
        errorOccurred(std::string("Deletion failed: %1")));
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        return false;
    }
}

bool ZeroRetentionManager::anonymizeData(const std::string& id)
{
    try {
<<<<<<< HEAD
        std::lock_guard<std::mutex> lock(m_dataMutex);

        auto it = m_trackedData.find(id);
        if (it == m_trackedData.end()) {
            logStructured("WARN", "Data ID not found for anonymization",
                          JsonObject{{"id", id}});
=======
        std::lock_guard<std::mutex> dataMutex(&m_dataMutex);
        
        if (!m_trackedData.contains(id)) {
            logStructured("WARN", "Data ID not found for anonymization", void*{{"id", id}});
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            return false;
        }

        DataEntry& entry = it->second;

        // Read file
<<<<<<< HEAD
        std::ifstream inFile(entry.path, std::ios::binary);
        if (!inFile.is_open()) {
            logStructured("ERROR", "Failed to open file for anonymization",
                          JsonObject{{"path", entry.path}});
            return false;
        }

        std::string content(
            (std::istreambuf_iterator<char>(inFile)),
             std::istreambuf_iterator<char>());
        inFile.close();

        // Simple anonymization: redact PII patterns
        std::regex emailPattern(
            R"([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})");
        std::regex ipPattern(
            R"(\b(?:\d{1,3}\.){3}\d{1,3}\b)");

        content = std::regex_replace(content, emailPattern, "[EMAIL_REDACTED]");
        content = std::regex_replace(content, ipPattern,    "[IP_REDACTED]");

        // Write anonymized content back
        std::ofstream outFile(entry.path, std::ios::binary | std::ios::trunc);
        if (!outFile.is_open()) {
            logStructured("ERROR", "Failed to write anonymized file",
                          JsonObject{{"path", entry.path}});
            return false;
        }
        outFile << content;
        outFile.close();

        entry.isAnonymized   = true;
=======
        std::fstream file(entry.path);
        if (!file.open(QIODevice::ReadWrite | QIODevice::Text)) {
            logStructured("ERROR", "Failed to open file for anonymization", void*{
                {"path", entry.path},
                {"error", file.errorString()}
            });
            return false;
        }
        
        std::string content = file.readAll();
        file.seek(0);
        
        // Simple anonymization: hash PII patterns
        // In production, use more sophisticated anonymization
        std::regex emailPattern(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
        std::regex ipPattern(R"(\b(?:\d{1,3}\.){3}\d{1,3}\b)");
        
        content.replace(emailPattern, "[EMAIL_REDACTED]");
        content.replace(ipPattern, "[IP_REDACTED]");
        
        file.resize(0);
        file.write(content.toUtf8());
        file.close();
        
        entry.isAnonymized = true;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        entry.classification = Anonymous;

        {
<<<<<<< HEAD
            std::lock_guard<std::mutex> mLock(m_metricsMutex);
            m_metrics.anonymizationCount++;
        }

        logStructured("INFO", "Data anonymized", JsonObject{
=======
            std::lock_guard<std::mutex> metricsLocker(&m_metricsMutex);
            m_metrics.anonymizationCount++;
        }
        
        logStructured("INFO", "Data anonymized", void*{
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            {"id", id},
            {"path", entry.path}
        });

        Config config;
        {
<<<<<<< HEAD
            std::lock_guard<std::mutex> cfgLock(m_configMutex);
=======
            std::lock_guard<std::mutex> configLocker(&m_configMutex);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            config = m_config;
        }

        if (config.enableAuditLog) {
<<<<<<< HEAD
            logAudit("data_anonymized", JsonObject{
=======
            logAudit("data_anonymized", void*{
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
                {"id", id},
                {"path", entry.path}
            });
        }

        return true;

    } catch (const std::exception& e) {
<<<<<<< HEAD
        {
            std::lock_guard<std::mutex> mLock(m_metricsMutex);
            m_metrics.errorCount++;
        }
        logStructured("ERROR", "Failed to anonymize data",
                      JsonObject{{"error", std::string(e.what())}});
        errorOccurred(std::string("Anonymization failed: ") + e.what());
=======
        std::lock_guard<std::mutex> metricsLocker(&m_metricsMutex);
        m_metrics.errorCount++;
        logStructured("ERROR", "Failed to anonymize data", void*{{"error", e.what()}});
        errorOccurred(std::string("Anonymization failed: %1")));
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        return false;
    }
}

void ZeroRetentionManager::cleanupExpiredData()
{
    auto startTime = std::chrono::steady_clock::now();
<<<<<<< HEAD
    int deletedCount     = 0;
    int64_t bytesDeleted = 0;

    try {
        std::vector<std::string> expiredIds;

        {
            std::lock_guard<std::mutex> lock(m_dataMutex);
=======
    int deletedCount = 0;
    int64_t bytesDeleted = 0;
    
    try {
        std::vector<std::string> expiredIds;
        
        {
            std::lock_guard<std::mutex> dataMutex(&m_dataMutex);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            for (auto it = m_trackedData.begin(); it != m_trackedData.end(); ++it) {
                if (isExpired(it->second)) {
                    expiredIds.push_back(it->first);
                }
            }
        }
<<<<<<< HEAD

=======
        
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        for (const std::string& id : expiredIds) {
            DataEntry entry = getDataEntry(id);
            if (deleteData(id, false)) {
                deletedCount++;
                bytesDeleted += entry.sizeBytes;
                dataExpired(id);
            }
        }

        auto endTime  = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                            endTime - startTime);
        recordLatency("cleanup", duration);
<<<<<<< HEAD

        logStructured("INFO", "Expired data cleanup completed", JsonObject{
            {"deletedCount", static_cast<int64_t>(deletedCount)},
=======
        
        logStructured("INFO", "Expired data cleanup completed", void*{
            {"deletedCount", deletedCount},
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            {"bytesDeleted", bytesDeleted},
            {"latencyMs", static_cast<int64_t>(duration.count())}
        });
<<<<<<< HEAD

        cleanupCompleted(deletedCount, bytesDeleted);

    } catch (const std::exception& e) {
        {
            std::lock_guard<std::mutex> lock(m_metricsMutex);
            m_metrics.errorCount++;
        }
        logStructured("ERROR", "Cleanup failed",
                      JsonObject{{"error", std::string(e.what())}});
        errorOccurred(std::string("Cleanup failed: ") + e.what());
=======
        
        cleanupCompleted(deletedCount, bytesDeleted);
        
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> metricsLocker(&m_metricsMutex);
        m_metrics.errorCount++;
        logStructured("ERROR", "Cleanup failed", void*{{"error", e.what()}});
        errorOccurred(std::string("Cleanup failed: %1")));
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
}

void ZeroRetentionManager::cleanupSession(const std::string& sessionId)
{
    try {
        std::vector<std::string> sessionDataIds;
<<<<<<< HEAD

        {
            std::lock_guard<std::mutex> lock(m_dataMutex);
=======
        
        {
            std::lock_guard<std::mutex> dataMutex(&m_dataMutex);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            for (auto it = m_trackedData.begin(); it != m_trackedData.end(); ++it) {
                if (it->second.path.find(sessionId) != std::string::npos) {
                    sessionDataIds.push_back(it->first);
                }
            }
        }
<<<<<<< HEAD

=======
        
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        for (const std::string& id : sessionDataIds) {
            deleteData(id, true);
        }

        {
<<<<<<< HEAD
            std::lock_guard<std::mutex> lock(m_metricsMutex);
            m_metrics.sessionsCleanedUp++;
        }

        logStructured("INFO", "Session cleaned up", JsonObject{
=======
            std::lock_guard<std::mutex> metricsLocker(&m_metricsMutex);
            m_metrics.sessionsCleanedUp++;
        }
        
        logStructured("INFO", "Session cleaned up", void*{
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            {"sessionId", sessionId},
            {"itemsDeleted", static_cast<int64_t>(sessionDataIds.size())}
        });

        Config config;
        {
<<<<<<< HEAD
            std::lock_guard<std::mutex> lock(m_configMutex);
=======
            std::lock_guard<std::mutex> configLocker(&m_configMutex);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            config = m_config;
        }

        if (config.enableAuditLog) {
<<<<<<< HEAD
            logAudit("session_cleaned", JsonObject{
=======
            logAudit("session_cleaned", void*{
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
                {"sessionId", sessionId},
                {"itemsDeleted", static_cast<int64_t>(sessionDataIds.size())}
            });
        }
<<<<<<< HEAD

        sessionCleaned(sessionId);

    } catch (const std::exception& e) {
        {
            std::lock_guard<std::mutex> lock(m_metricsMutex);
            m_metrics.errorCount++;
        }
        logStructured("ERROR", "Session cleanup failed",
                      JsonObject{{"error", std::string(e.what())}});
        errorOccurred(std::string("Session cleanup failed: ") + e.what());
=======
        
        sessionCleaned(sessionId);
        
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> metricsLocker(&m_metricsMutex);
        m_metrics.errorCount++;
        logStructured("ERROR", "Session cleanup failed", void*{{"error", e.what()}});
        errorOccurred(std::string("Session cleanup failed: %1")));
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
}

void ZeroRetentionManager::purgeAllData(DataClass classification)
{
    try {
        std::vector<std::string> idsToDelete;
<<<<<<< HEAD

        {
            std::lock_guard<std::mutex> lock(m_dataMutex);
=======
        
        {
            std::lock_guard<std::mutex> dataMutex(&m_dataMutex);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            for (auto it = m_trackedData.begin(); it != m_trackedData.end(); ++it) {
                if (it->second.classification == classification) {
                    idsToDelete.push_back(it->first);
                }
            }
        }
<<<<<<< HEAD

        for (const std::string& id : idsToDelete) {
            deleteData(id, true);
        }

        logStructured("INFO", "Data purged", JsonObject{
            {"classification", static_cast<int64_t>(classification)},
            {"itemsDeleted", static_cast<int64_t>(idsToDelete.size())}
=======
        
        for (const std::string& id : idsToDelete) {
            deleteData(id, true);
        }
        
        logStructured("INFO", "Data purged", void*{
            {"classification", static_cast<int>(classification)},
            {"itemsDeleted", idsToDelete.size()}
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        });

        Config config;
        {
<<<<<<< HEAD
            std::lock_guard<std::mutex> lock(m_configMutex);
=======
            std::lock_guard<std::mutex> configLocker(&m_configMutex);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            config = m_config;
        }

        if (config.enableAuditLog) {
<<<<<<< HEAD
            logAudit("data_purged", JsonObject{
                {"classification", static_cast<int64_t>(classification)},
                {"itemsDeleted", static_cast<int64_t>(idsToDelete.size())}
=======
            logAudit("data_purged", void*{
                {"classification", static_cast<int>(classification)},
                {"itemsDeleted", idsToDelete.size()}
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            });
        }

    } catch (const std::exception& e) {
<<<<<<< HEAD
        {
            std::lock_guard<std::mutex> lock(m_metricsMutex);
            m_metrics.errorCount++;
        }
        logStructured("ERROR", "Data purge failed",
                      JsonObject{{"error", std::string(e.what())}});
        errorOccurred(std::string("Purge failed: ") + e.what());
    }
}

std::vector<ZeroRetentionManager::DataEntry>
ZeroRetentionManager::getTrackedData(DataClass classification) const
{
    std::lock_guard<std::mutex> lock(m_dataMutex);
    std::vector<DataEntry> result;

=======
        std::lock_guard<std::mutex> metricsLocker(&m_metricsMutex);
        m_metrics.errorCount++;
        logStructured("ERROR", "Data purge failed", void*{{"error", e.what()}});
        errorOccurred(std::string("Purge failed: %1")));
    }
}

std::vector<ZeroRetentionManager::DataEntry> ZeroRetentionManager::getTrackedData(DataClass classification) const
{
    std::lock_guard<std::mutex> dataMutex(&m_dataMutex);
    std::vector<DataEntry> result;
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    for (auto it = m_trackedData.begin(); it != m_trackedData.end(); ++it) {
        if (it->second.classification == classification) {
            result.push_back(it->second);
        }
    }

    return result;
}

<<<<<<< HEAD
ZeroRetentionManager::DataEntry
ZeroRetentionManager::getDataEntry(const std::string& id) const
{
    std::lock_guard<std::mutex> lock(m_dataMutex);
    auto it = m_trackedData.find(id);
    if (it != m_trackedData.end()) {
        return it->second;
    }
    return DataEntry{};
=======
ZeroRetentionManager::DataEntry ZeroRetentionManager::getDataEntry(const std::string& id) const
{
    std::lock_guard<std::mutex> dataMutex(&m_dataMutex);
    return m_trackedData.value(id, DataEntry());
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

// ===== Metrics =====

ZeroRetentionManager::Metrics ZeroRetentionManager::getMetrics() const
{
<<<<<<< HEAD
    std::lock_guard<std::mutex> lock(m_metricsMutex);
=======
    std::lock_guard<std::mutex> locker(&m_metricsMutex);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return m_metrics;
}

void ZeroRetentionManager::resetMetrics()
{
<<<<<<< HEAD
    std::lock_guard<std::mutex> lock(m_metricsMutex);
    m_metrics = Metrics();
    logStructured("INFO", "Metrics reset", JsonObject{});
=======
    std::lock_guard<std::mutex> locker(&m_metricsMutex);
    m_metrics = Metrics();
    logStructured("INFO", "Metrics reset", void*{});
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

// ===== Auto cleanup =====

void ZeroRetentionManager::performAutoCleanup()
{
<<<<<<< HEAD
    logStructured("DEBUG", "Auto cleanup triggered", JsonObject{});
    cleanupExpiredData();
}

// ===== Callbacks (event notifications — replace Qt signals) =====

void ZeroRetentionManager::dataDeleted(const std::string& id, int64_t sizeBytes)
{
    fprintf(stderr, "[ZeroRetentionManager] Data deleted: id=%s size=%lld\n",
            id.c_str(), static_cast<long long>(sizeBytes));
}

void ZeroRetentionManager::dataExpired(const std::string& id)
{
    fprintf(stderr, "[ZeroRetentionManager] Data expired: id=%s\n", id.c_str());
}

void ZeroRetentionManager::sessionCleaned(const std::string& sessionId)
{
    fprintf(stderr, "[ZeroRetentionManager] Session cleaned: %s\n", sessionId.c_str());
}

void ZeroRetentionManager::cleanupCompleted(int itemsDeleted, int64_t bytesDeleted)
{
    fprintf(stderr,
            "[ZeroRetentionManager] Cleanup completed: items=%d bytes=%lld\n",
            itemsDeleted, static_cast<long long>(bytesDeleted));
}

void ZeroRetentionManager::errorOccurred(const std::string& error)
{
    fprintf(stderr, "[ZeroRetentionManager] Error: %s\n", error.c_str());
}

void ZeroRetentionManager::metricsUpdated(const Metrics& metrics)
{
    fprintf(stderr,
            "[ZeroRetentionManager] Metrics updated: tracked=%lld deleted=%lld errors=%lld\n",
            static_cast<long long>(metrics.dataEntriesTracked),
            static_cast<long long>(metrics.dataEntriesDeleted),
            static_cast<long long>(metrics.errorCount));
}

// ===== Private helpers =====

void ZeroRetentionManager::logStructured(const char* level,
                                         const std::string& message,
                                         const std::string& contextJson)
{
    fprintf(stderr, "[ZeroRetentionManager] [%s] %s context=%s\n", level, message.c_str(), contextJson.c_str());
}

void ZeroRetentionManager::logStructured(const char* level,
                                         const std::string& message,
                                         const JsonObject& context)
{
    logStructured(std::string(level), message, context);
}

void ZeroRetentionManager::logStructured(const std::string& level,
                                         const std::string& message,
                                         const std::string& contextJson)
{
    fprintf(stderr, "[ZeroRetentionManager] [%s] %s context=%s\n", level.c_str(), message.c_str(), contextJson.c_str());
}

void ZeroRetentionManager::logStructured(const std::string& level,
                                         const std::string& message,
                                         const JsonObject& context)
{
    JsonObject logEntry;
    logEntry["timestamp"] = timePointToISO8601(std::chrono::system_clock::now());
    logEntry["level"]     = level;
    logEntry["component"] = std::string("ZeroRetentionManager");
    logEntry["message"]   = message;
    logEntry["context"]   = JsonValue(context);

    std::string json = JsonDoc::toJson(logEntry);
    fprintf(stderr, "[ZeroRetentionManager] %s\n", json.c_str());
}

void ZeroRetentionManager::recordLatency(const std::string& operation,
                                         const std::chrono::milliseconds& duration)
{
    std::lock_guard<std::mutex> mLock(m_metricsMutex);

    if (operation == "cleanup" && m_metrics.dataEntriesDeleted > 0) {
        int64_t cleanupCount = m_metrics.dataEntriesDeleted;
        m_metrics.avgCleanupLatencyMs =
            (m_metrics.avgCleanupLatencyMs * static_cast<double>(cleanupCount - 1)
             + static_cast<double>(duration.count()))
            / static_cast<double>(cleanupCount);
=======
    logStructured("DEBUG", "Auto cleanup triggered", void*{});
    cleanupExpiredData();
}

void ZeroRetentionManager::logStructured(const std::string& level, const std::string& message, const void*& context)
{
    void* logEntry;
    logEntry["timestamp"] = std::chrono::system_clock::time_point::currentDateTime().toString(//ISODate);
    logEntry["level"] = level;
    logEntry["component"] = "ZeroRetentionManager";
    logEntry["message"] = message;
    logEntry["context"] = context;
    
    void* doc(logEntry);
}

void ZeroRetentionManager::recordLatency(const std::string& operation, const std::chrono::milliseconds& duration)
{
    std::lock_guard<std::mutex> locker(&m_metricsMutex);
    
    if (operation == "cleanup") {
        int cleanupCount = m_metrics.dataEntriesDeleted;
        m_metrics.avgCleanupLatencyMs = 
            (m_metrics.avgCleanupLatencyMs * (cleanupCount - 1) + duration.count()) / cleanupCount;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }

    Config config;
    {
<<<<<<< HEAD
        std::lock_guard<std::mutex> cfgLock(m_configMutex);
=======
        std::lock_guard<std::mutex> configLocker(&m_configMutex);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        config = m_config;
    }

    if (config.enableMetrics) {
        metricsUpdated(m_metrics);
    }
}

<<<<<<< HEAD
void ZeroRetentionManager::logAudit(const std::string& action, const JsonObject& details)
{
    Config config;
    {
        std::lock_guard<std::mutex> cfgLock(m_configMutex);
        config = m_config;
    }

    if (!config.enableAuditLog || config.auditLogPath.empty()) {
        return;
    }

    JsonObject auditEntry;
    auditEntry["timestamp"] = timePointToISO8601(std::chrono::system_clock::now());
    auditEntry["action"]    = action;
    auditEntry["details"]   = JsonValue(details);

    std::ofstream auditFile(config.auditLogPath, std::ios::out | std::ios::app);
    if (auditFile.is_open()) {
        auditFile << JsonDoc::toJson(auditEntry) << "\n";
        auditFile.close();

        std::lock_guard<std::mutex> mLock(m_metricsMutex);
        m_metrics.auditEntriesCreated++;
    } else {
        logStructured("ERROR", "Failed to write audit log",
                      JsonObject{{"path", config.auditLogPath}});
=======
void ZeroRetentionManager::logAudit(const std::string& action, const void*& details)
{
    Config config;
    {
        std::lock_guard<std::mutex> configLocker(&m_configMutex);
        config = m_config;
    }
    
    if (!config.enableAuditLog || config.auditLogPath.empty()) {
        return;
    }
    
    void* auditEntry;
    auditEntry["timestamp"] = std::chrono::system_clock::time_point::currentDateTime().toString(//ISODate);
    auditEntry["action"] = action;
    auditEntry["details"] = details;
    
    std::fstream auditFile(config.auditLogPath);
    if (auditFile.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        QTextStream out(&auditFile);
        void* doc(auditEntry);
        out << doc.toJson(void*::Compact) << "\n";
        auditFile.close();
        
        std::lock_guard<std::mutex> metricsLocker(&m_metricsMutex);
        m_metrics.auditEntriesCreated++;
    } else {
        logStructured("ERROR", "Failed to write audit log", void*{
            {"path", config.auditLogPath},
            {"error", auditFile.errorString()}
        });
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
}

bool ZeroRetentionManager::secureDelete(const std::string& path)
{
    Config config;
    {
<<<<<<< HEAD
        std::lock_guard<std::mutex> cfgLock(m_configMutex);
        config = m_config;
    }

    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        logStructured("WARN", "File does not exist for deletion",
                      JsonObject{{"path", path}});
=======
        std::lock_guard<std::mutex> configLocker(&m_configMutex);
        config = m_config;
    }
    
    if (!std::fstream::exists(path)) {
        logStructured("WARN", "File does not exist for deletion", void*{{"path", path}});
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        return false;
    }

    if (config.enableSecureWipe) {
<<<<<<< HEAD
        // Secure wipe: overwrite file with zeros before deletion
        auto fileSize = std::filesystem::file_size(path, ec);
        if (!ec && fileSize > 0) {
            std::ofstream file(path, std::ios::binary | std::ios::trunc);
            if (file.is_open()) {
                std::vector<char> zeroData(static_cast<size_t>(fileSize), '\0');
                file.write(zeroData.data(), static_cast<std::streamsize>(zeroData.size()));
                file.flush();
                file.close();

                logStructured("DEBUG", "Secure wipe completed", JsonObject{
                    {"path", path},
                    {"size", static_cast<int64_t>(fileSize)}
                });
            }
        }
    }

    bool removed = std::filesystem::remove(path, ec);

    if (!removed) {
        logStructured("ERROR", "Failed to delete file", JsonObject{{"path", path}});
=======
        // Secure wipe: overwrite file with random data before deletion
        std::fstream file(path);
        if (file.open(QIODevice::ReadWrite)) {
            int64_t size = file.size();
            std::vector<uint8_t> zeroData(size, '\0');
            file.write(zeroData);
            file.flush();
            file.close();
            
            logStructured("DEBUG", "Secure wipe completed", void*{
                {"path", path},
                {"size", size}
            });
        }
    }
    
    bool removed = std::fstream::remove(path);
    
    if (!removed) {
        logStructured("ERROR", "Failed to delete file", void*{{"path", path}});
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }

    return removed;
}

std::string ZeroRetentionManager::generateDataId()
{
    GUID guid;
    CoCreateGuid(&guid);
    char buf[64];
    snprintf(buf, sizeof(buf),
             "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             guid.Data1, guid.Data2, guid.Data3,
             guid.Data4[0], guid.Data4[1],
             guid.Data4[2], guid.Data4[3],
             guid.Data4[4], guid.Data4[5],
             guid.Data4[6], guid.Data4[7]);
    return std::string(buf);
}

bool ZeroRetentionManager::isExpired(const DataEntry& entry) const
{
<<<<<<< HEAD
    return std::chrono::system_clock::now() >= entry.expiresAt;
}

std::chrono::system_clock::time_point
ZeroRetentionManager::calculateExpiry(DataClass classification,
                                      int customTtlMinutes) const
{
    Config config;
    {
        std::lock_guard<std::mutex> cfgLock(m_configMutex);
        config = m_config;
    }

    auto now = std::chrono::system_clock::now();

=======
    return std::chrono::system_clock::time_point::currentDateTime() >= entry.expiresAt;
}

std::chrono::system_clock::time_point ZeroRetentionManager::calculateExpiry(DataClass classification, int customTtlMinutes) const
{
    Config config;
    {
        std::lock_guard<std::mutex> configLocker(&m_configMutex);
        config = m_config;
    }
    
    std::chrono::system_clock::time_point now = std::chrono::system_clock::time_point::currentDateTime();
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    if (customTtlMinutes >= 0) {
        return now + std::chrono::seconds(customTtlMinutes * 60);
    }

    switch (classification) {
        case Sensitive:
            return now + std::chrono::seconds(
                       static_cast<int64_t>(config.dataRetentionDays) * 24 * 60 * 60);
        case Session:
            return now + std::chrono::seconds(
                       static_cast<int64_t>(config.sessionTtlMinutes) * 60);
        case Cached:
            return now + std::chrono::seconds(
                       static_cast<int64_t>(config.sessionTtlMinutes) * 2 * 60);
        case Audit:
            return now + std::chrono::hours(
                       static_cast<int64_t>(config.auditRetentionDays) * 24);
        case Anonymous:
            return now + std::chrono::hours(365 * 24); // 1 year
        default:
            return now + std::chrono::seconds(
                       static_cast<int64_t>(config.sessionTtlMinutes) * 60);
    }
}



