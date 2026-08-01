#pragma once
#include <string>
#include <functional>
#include <atomic>

namespace RawrXD::Ops {

class FieldUpdater {
public:
    enum class UpdateChannel { STABLE, BETA, NIGHTLY };

    struct UpdateInfo {
        std::string version;
        std::string release_date;
        std::string changelog;
        size_t package_size = 0;
        bool available = false;
    };

    FieldUpdater();
    ~FieldUpdater() = default;

    bool CheckForUpdate(UpdateChannel channel = UpdateChannel::STABLE);
    bool DownloadAndStage(const std::string& version);
    bool ApplyAndRestart();
    UpdateInfo GetLatestUpdate() const;
    bool IsUpdateAvailable() const { return update_available_; }

    using UpdateCallback = std::function<void(const std::string& stage, int progress)>;
    void SetUpdateCallback(UpdateCallback cb);

private:
    bool VerifySignature(const std::string& package_path);
    bool BackupCurrent();
    bool HealthCheck();

    std::atomic<bool> update_available_{false};
    std::atomic<bool> downloading_{false};
    UpdateInfo latest_update_;
    UpdateCallback callback_;
};

} // namespace RawrXD::Ops
