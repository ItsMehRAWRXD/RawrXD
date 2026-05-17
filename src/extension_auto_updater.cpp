// ============================================================================
// extension_auto_updater.cpp — Auto-Update System Implementation
// ============================================================================
// Architecture: C++20 | Win32 | Background scheduler | No exceptions
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED
// ============================================================================

#include "extension_auto_updater.h"

#include <windows.h>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <thread>
#include <chrono>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace RawrXD {
namespace Extensions {

// ============================================================================
// Global Instance
// ============================================================================

static ExtensionAutoUpdater* g_autoUpdater = nullptr;

ExtensionAutoUpdater& GetAutoUpdater() {
    if (!g_autoUpdater) {
        g_autoUpdater = new ExtensionAutoUpdater();
    }
    return *g_autoUpdater;
}

// ============================================================================
// ExtensionAutoUpdater Implementation
// ============================================================================

ExtensionAutoUpdater::ExtensionAutoUpdater() {
}

ExtensionAutoUpdater::~ExtensionAutoUpdater() {
    StopAutoUpdateScheduler();
}

void ExtensionAutoUpdater::SetCheckInterval(uint32_t hours) {
    std::lock_guard<std::mutex> lock(m_lock);
    m_checkIntervalHours = hours;
}

uint32_t ExtensionAutoUpdater::GetCheckInterval() const {
    std::lock_guard<std::mutex> lock(m_lock);
    return m_checkIntervalHours;
}

void ExtensionAutoUpdater::SetUpdatePolicy(UpdatePolicy policy) {
    std::lock_guard<std::mutex> lock(m_lock);
    m_defaultPolicy = policy;
}

UpdatePolicy ExtensionAutoUpdater::GetUpdatePolicy() const {
    std::lock_guard<std::mutex> lock(m_lock);
    return m_defaultPolicy;
}

void ExtensionAutoUpdater::SetExtensionUpdatePolicy(
    const std::string& extensionId,
    UpdatePolicy policy
) {
    if (extensionId.empty()) return;

    std::lock_guard<std::mutex> lock(m_lock);
    m_perExtensionPolicy[extensionId] = policy;
}

UpdatePolicy ExtensionAutoUpdater::GetExtensionUpdatePolicy(
    const std::string& extensionId
) const {
    if (extensionId.empty()) return UpdatePolicy::Manual;

    std::lock_guard<std::mutex> lock(m_lock);

    auto it = m_perExtensionPolicy.find(extensionId);
    if (it != m_perExtensionPolicy.end()) {
        return it->second;
    }
    
    return m_defaultPolicy;
}

void ExtensionAutoUpdater::SetNotificationsEnabled(bool enabled) {
    std::lock_guard<std::mutex> lock(m_lock);
    m_notificationsEnabled = enabled;
}

bool ExtensionAutoUpdater::AreNotificationsEnabled() const {
    std::lock_guard<std::mutex> lock(m_lock);
    return m_notificationsEnabled;
}

UpdateCheckResult ExtensionAutoUpdater::CheckForUpdates() {
    // TODO: Fetch all installed extensions and check for updates
    // This would integrate with marketplace discovery
    
    UpdateCheckResult result;
    result.success = true;
    result.checkTimeMs = ::GetTickCount64();

    std::lock_guard<std::mutex> lock(m_lock);
    m_lastCheckTimeMs = result.checkTimeMs;

    return result;
}

UpdateCheckResult ExtensionAutoUpdater::CheckForUpdatesExclusive(
    const std::vector<std::string>& extensionIds
) {
    // TODO: Check specific extensions for updates
    UpdateCheckResult result;
    result.success = true;
    result.checkTimeMs = ::GetTickCount64();

    return result;
}

bool ExtensionAutoUpdater::InstallUpdate(const std::string& extensionId) {
    if (extensionId.empty()) {
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(m_lock);

        auto it = std::find_if(m_pendingUpdates.begin(), m_pendingUpdates.end(),
            [&extensionId](const ExtensionUpdateInfo& info) {
                return info.extensionId == extensionId;
            }
        );

        if (it == m_pendingUpdates.end()) {
            return false;  // No pending update for this extension
        }

        const auto updateInfo = *it;
        
        if (InstallUpdateInternal(extensionId, updateInfo)) {
            UpdateInstallRecord record;
            record.extensionId = extensionId;
            record.previousVersion = updateInfo.currentVersion;
            record.newVersion = updateInfo.newVersion;
            record.installTimeMs = ::GetTickCount64();
            record.success = true;

            m_installHistory.push_back(record);
            m_pendingUpdates.erase(it);

            NotifyUpdateInstalled(record);
            return true;
        }
    }

    return false;
}

bool ExtensionAutoUpdater::RollbackUpdate(const std::string& extensionId) {
    if (extensionId.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_lock);

    // Find last installation for this extension
    auto it = std::find_if(m_installHistory.rbegin(), m_installHistory.rend(),
        [&extensionId](const UpdateInstallRecord& record) {
            return record.extensionId == extensionId;
        }
    );

    if (it == m_installHistory.rend() || it->backupPath.empty()) {
        return false;
    }

    // TODO: Restore from backup
    return RestoreExtensionFromBackup(extensionId, it->backupPath);
}

bool ExtensionAutoUpdater::StartAutoUpdateScheduler() {
    {
        std::lock_guard<std::mutex> lock(m_lock);

        if (m_schedulerRunning) {
            return false;  // Already running
        }

        m_schedulerRunning = true;
    }

    m_schedulerThread = std::thread([this]() {
        this->RunSchedulerThread();
    });

    return true;
}

void ExtensionAutoUpdater::StopAutoUpdateScheduler() {
    m_schedulerRunning = false;

    if (m_schedulerThread.joinable()) {
        m_schedulerThread.join();
    }
}

std::vector<ExtensionUpdateInfo> ExtensionAutoUpdater::GetPendingUpdates() const {
    std::lock_guard<std::mutex> lock(m_lock);
    return m_pendingUpdates;
}

std::vector<UpdateInstallRecord> ExtensionAutoUpdater::GetUpdateHistory(
    const std::string& extensionId,
    int maxRecords
) const {
    std::lock_guard<std::mutex> lock(m_lock);

    std::vector<UpdateInstallRecord> result;

    for (auto it = m_installHistory.rbegin(); it != m_installHistory.rend(); ++it) {
        if (extensionId.empty() || it->extensionId == extensionId) {
            result.push_back(*it);
            if (static_cast<int>(result.size()) >= maxRecords) {
                break;
            }
        }
    }

    return result;
}

uint64_t ExtensionAutoUpdater::GetLastCheckTimeMs() const {
    std::lock_guard<std::mutex> lock(m_lock);
    return m_lastCheckTimeMs;
}

void ExtensionAutoUpdater::OnUpdateAvailable(
    std::function<void(const ExtensionUpdateInfo&)> callback
) {
    std::lock_guard<std::mutex> lock(m_lock);
    m_onUpdateAvailable = callback;
}

void ExtensionAutoUpdater::OnUpdateInstalled(
    std::function<void(const UpdateInstallRecord&)> callback
) {
    std::lock_guard<std::mutex> lock(m_lock);
    m_onUpdateInstalled = callback;
}

bool ExtensionAutoUpdater::LoadUpdateHistory(const std::string& storagePath) {
    if (storagePath.empty()) {
        return false;
    }

    try {
        std::ifstream file(storagePath);
        if (!file.is_open()) {
            return true;  // File doesn't exist yet
        }

        json data;
        file >> data;
        file.close();

        std::lock_guard<std::mutex> lock(m_lock);

        if (data.contains("history") && data["history"].is_array()) {
            for (const auto& item : data["history"]) {
                UpdateInstallRecord record;
                // TODO: Deserialize from JSON
                m_installHistory.push_back(record);
            }
        }

        return true;
    } catch (...) {
        return false;
    }
}

bool ExtensionAutoUpdater::SaveUpdateHistory(const std::string& storagePath) {
    if (storagePath.empty()) {
        return false;
    }

    try {
        json data;
        data["history"] = json::array();

        {
            std::lock_guard<std::mutex> lock(m_lock);

            for (const auto& record : m_installHistory) {
                json item;
                // TODO: Serialize to JSON
                data["history"].push_back(item);
            }
        }

        std::ofstream file(storagePath);
        if (!file.is_open()) {
            return false;
        }

        file << data.dump(2);
        file.close();

        return true;
    } catch (...) {
        return false;
    }
}

bool ExtensionAutoUpdater::BackupExtension(const std::string& extensionId) {
    return BackupExtensionInternal(extensionId);
}

void ExtensionAutoUpdater::RunSchedulerThread() {
    while (m_schedulerRunning) {
        uint32_t checkIntervalMs = GetCheckInterval() * 3600 * 1000;  // Convert hours to ms
        uint64_t now = ::GetTickCount64();

        if (now - m_lastCheckTimeMs >= checkIntervalMs) {
            PerformUpdateCheck();
            PerformAutoInstall();
        }

        // Sleep for a bit to avoid busy-waiting
        std::this_thread::sleep_for(std::chrono::seconds(60));
    }
}

bool ExtensionAutoUpdater::PerformUpdateCheck() {
    auto result = CheckForUpdates();
    return result.success;
}

bool ExtensionAutoUpdater::PerformAutoInstall() {
    std::lock_guard<std::mutex> lock(m_lock);

    for (const auto& update : m_pendingUpdates) {
        UpdatePolicy policy = GetExtensionUpdatePolicy(update.extensionId);

        bool shouldInstall = false;
        if (policy == UpdatePolicy::AutoInstall && !update.isBreakingChange) {
            shouldInstall = true;
        } else if (policy == UpdatePolicy::AutoInstallAll) {
            shouldInstall = true;
        }

        if (shouldInstall) {
            InstallUpdate(update.extensionId);
        }
    }

    return true;
}

bool ExtensionAutoUpdater::InstallUpdateInternal(
    const std::string& extensionId,
    const ExtensionUpdateInfo& updateInfo
) {
    // TODO: Download and install the update from updateInfo.downloadUrl
    // - Download VSIX file
    // - Backup current version
    // - Uninstall current version
    // - Install new version
    // - Verify installation
    // - Clean up backup if successful

    return false;
}

void ExtensionAutoUpdater::NotifyUpdateAvailable(const ExtensionUpdateInfo& updateInfo) {
    if (m_notificationsEnabled && m_onUpdateAvailable) {
        m_onUpdateAvailable(updateInfo);
    }
}

void ExtensionAutoUpdater::NotifyUpdateInstalled(const UpdateInstallRecord& record) {
    if (m_onUpdateInstalled) {
        m_onUpdateInstalled(record);
    }
}

bool ExtensionAutoUpdater::BackupExtensionInternal(const std::string& extensionId) {
    // TODO: Create backup of extension directory
    return false;
}

bool ExtensionAutoUpdater::RestoreExtensionFromBackup(
    const std::string& extensionId,
    const std::string& backupPath
) {
    // TODO: Restore extension from backup
    return false;
}

// ============================================================================
// Global Helpers
// ============================================================================

bool CheckExtensionUpdates(std::vector<ExtensionUpdateInfo>& outUpdates) {
    auto result = GetAutoUpdater().CheckForUpdates();
    if (result.success) {
        outUpdates = result.updatesAvailable;
        return true;
    }
    return false;
}

bool InstallExtensionUpdate(const std::string& extensionId) {
    return GetAutoUpdater().InstallUpdate(extensionId);
}

}  // namespace Extensions
}  // namespace RawrXD

// ============================================================================
// End of extension_auto_updater.cpp
// ============================================================================
