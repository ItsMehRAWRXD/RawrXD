#pragma once
#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <mutex>

class VsixInstaller {
public:
    struct InstallationInfo {
        std::string extensionId;
        std::string downloadUrl;
        std::string tempFilePath;
    };

    VsixInstaller();
    ~VsixInstaller();

    void installFromUrl(const std::string& url, const std::string& extensionId);
    void installFromFile(const std::string& filePath); // Logic merge for local install
    void installFromFile(const std::string& filePath, const std::string& extensionId);
    bool uninstallExtension(const std::string& extensionId);
    bool isExtensionInstalled(const std::string& extensionId);

    // Extracts a VSIX package into a destination directory.
    //
    // This is the runtime's own ZIP reader. It is public because the
    // JavaScript extension host extracts through it rather than through
    // an external tool.
    bool extractVsixPackage(const std::string& vsixPath, const std::string& destination);
    
    // Callbacks
    std::function<void(const std::string&)> installationStarted;
    std::function<void(const std::string&, int)> installationProgress;
    std::function<void(const std::string&, bool)> installationCompleted;
    std::function<void(const std::string&, const std::string&)> installationError;
    std::function<void(const std::string&, bool)> uninstallCompleted;

private:
    std::string getExtensionsDirectory();
    std::string getExtensionInstallPath(const std::string& extensionId);
    bool activateExtension(const std::string& extensionPath);
    bool deactivateExtension(const std::string& extensionId);
    void cleanupTempFiles();

    std::vector<InstallationInfo> m_activeInstallations;
    std::mutex m_mutex;
};
