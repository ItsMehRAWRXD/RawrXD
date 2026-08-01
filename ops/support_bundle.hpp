#pragma once
#include <string>
#include <vector>
#include <filesystem>

namespace RawrXD::Ops {

class SupportBundle {
public:
    struct BundleManifest {
        std::string version;
        std::string created_at;
        std::vector<std::string> included_files;
        size_t total_size_bytes = 0;
    };

    SupportBundle();
    ~SupportBundle() = default;

    void Collect();
    void Encrypt(const std::string& public_key);
    void Export(const std::filesystem::path& out_path);
    BundleManifest GetManifest() const;

    static std::filesystem::path GetDefaultOutputPath();

private:
    void CollectRuntimeState();
    void CollectHardwareReport();
    void CollectCrashHistory();
    void CollectModelInventory();
    void CollectPluginList();
    void CollectLogs();
    void CollectValidationState();

    BundleManifest manifest_;
    std::filesystem::path temp_dir_;
    std::vector<std::filesystem::path> collected_files_;
};

} // namespace RawrXD::Ops
