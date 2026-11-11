// ============================================================================
// Deployment.hpp - Installer, Portable Mode, Docker, Windows Service, Headless
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace Sovereign {

struct InstallerConfig {
    std::string appName = "SovereignIDE";
    std::string version = "1.0.0";
    std::string publisher = "Sovereign";
    std::string installDir = "C:\\Program Files\\SovereignIDE";
    std::string dataDir = "%APPDATA%\\SovereignIDE";
    bool createDesktopShortcut = true;
    bool createStartMenuShortcut = true;
    bool addToPath = true;
    bool registerFileAssociations = true;
    std::vector<std::string> additionalFiles;
};

struct ServiceConfig {
    std::string serviceName = "SovereignIDE";
    std::string displayName = "Sovereign IDE Service";
    std::string description = "Sovereign IDE Background Service";
    std::string executablePath;
    std::vector<std::string> arguments;
    bool autoStart = true;
    bool runAsSystem = false;
    std::string userAccount;
};

class DeploymentManager {
public:
    DeploymentManager();
    ~DeploymentManager();

    // Installer
    bool BuildInstaller(const InstallerConfig& config, const std::string& outputPath);
    bool BuildPortable(const std::string& sourceDir, const std::string& outputPath);
    bool BuildDockerImage(const std::string& dockerfilePath, const std::string& tag);

    // Windows Service
    bool InstallService(const ServiceConfig& config);
    bool UninstallService(const std::string& serviceName);
    bool StartService(const std::string& serviceName);
    bool StopService(const std::string& serviceName);
    bool IsServiceRunning(const std::string& serviceName) const;

    // Headless mode
    bool StartHeadless(const std::string& configPath);
    bool StopHeadless();
    bool IsHeadlessRunning() const { return headlessRunning_; }

    // Portable mode
    bool IsPortableMode() const;
    std::string GetPortablePath() const;

    struct DeployStats { uint64_t installersBuilt; uint64_t servicesInstalled; uint64_t dockerImages; };
    DeployStats GetStats() const { return stats_; }

private:
    DeployStats stats_;
    bool headlessRunning_ = false;
    void* serviceHandle_ = nullptr;
    mutable std::mutex mutex_;
    
    bool CreateMSI(const InstallerConfig& config, const std::string& outputPath);
    bool CreateDirectoryStructure(const std::string& basePath);
    bool CopyFiles(const std::string& src, const std::string& dst, const std::vector<std::string>& files);
};

} // namespace Sovereign
