// ============================================================================
// Deployment.cpp - Deployment Manager Implementation
// ============================================================================

#include "Deployment.hpp"
#include <fstream>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;
namespace Sovereign {

DeploymentManager::DeploymentManager() = default;
DeploymentManager::~DeploymentManager() {
    if (headlessRunning_) StopHeadless();
}

bool DeploymentManager::BuildInstaller(const InstallerConfig& config, const std::string& outputPath) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Create directory structure
    std::string tempDir = fs::temp_directory_path().string() + "\\sovereign_installer";
    CreateDirectoryStructure(tempDir);
    
    // Copy binaries
    CopyFiles(".", tempDir + "\\bin", config.additionalFiles);
    
    // Create installer script
    std::ofstream script(outputPath + "\\install.ps1");
    script << "# Sovereign IDE Installer\n";
    script << "$installDir = \"" << config.installDir << "\"\n";
    script << "Write-Host \"Installing " << config.appName << "...\"\n";
    script << "New-Item -ItemType Directory -Force -Path $installDir\n";
    script << "Copy-Item -Recurse -Force \"" << tempDir << "\\*\" $installDir\n";
    if (config.createDesktopShortcut) {
        script << "$ws = New-Object -ComObject WScript.Shell\n";
        script << "$s = $ws.CreateShortcut([Environment]::GetFolderPath('Desktop') + '\\" << config.appName << ".lnk')\n";
        script << "$s.TargetPath = \"$installDir\\bin\\SovereignIDE.exe\"\n";
        script << "$s.Save()\n";
    }
    if (config.addToPath) {
        script << "[Environment]::SetEnvironmentVariable('Path', [Environment]::GetEnvironmentVariable('Path', 'User') + ';$installDir\\bin', 'User')\n";
    }
    script.close();
    
    stats_.installersBuilt++;
    return true;
}

bool DeploymentManager::BuildPortable(const std::string& sourceDir, const std::string& outputPath) {
    fs::create_directories(outputPath);
    fs::create_directories(outputPath + "\\bin");
    fs::create_directories(outputPath + "\\data");
    fs::create_directories(outputPath + "\\models");
    fs::create_directories(outputPath + "\\extensions");
    
    // Create portable marker
    std::ofstream marker(outputPath + "\\PORTABLE");
    marker << "Sovereign IDE Portable Mode\n";
    marker.close();
    
    return true;
}

bool DeploymentManager::BuildDockerImage(const std::string& dockerfilePath, const std::string& tag) {
    std::ofstream df(dockerfilePath);
    df << "FROM mcr.microsoft.com/windows/servercore:ltsc2022\n";
    df << "LABEL name=\"Sovereign IDE\"\n";
    df << "WORKDIR /app\n";
    df << "COPY . /app\n";
    df << "EXPOSE 8080 8081\n";
    df << "ENTRYPOINT [\"SovereignIDE.exe\", \"--headless\"]\n";
    df.close();
    
    stats_.dockerImages++;
    return true;
}

bool DeploymentManager::InstallService(const ServiceConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return false;
    
    std::string cmdLine = config.executablePath;
    for (const auto& arg : config.arguments) cmdLine += " " + arg;
    
    SC_HANDLE service = CreateService(
        scm, config.serviceName.c_str(), config.displayName.c_str(),
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        config.autoStart ? SERVICE_AUTO_START : SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL, cmdLine.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr);
    
    if (service) {
        serviceHandle_ = service;
        CloseServiceHandle(service);
        stats_.servicesInstalled++;
    }
    
    CloseServiceHandle(scm);
    return service != nullptr;
}

bool DeploymentManager::UninstallService(const std::string& serviceName) {
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    
    SC_HANDLE service = OpenService(scm, serviceName.c_str(), SERVICE_ALL_ACCESS);
    if (!service) { CloseServiceHandle(scm); return false; }
    
    SERVICE_STATUS status;
    ControlService(service, SERVICE_CONTROL_STOP, &status);
    DeleteService(service);
    
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
}

bool DeploymentManager::StartService(const std::string& serviceName) {
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    
    SC_HANDLE service = OpenService(scm, serviceName.c_str(), SERVICE_START);
    if (!service) { CloseServiceHandle(scm); return false; }
    
    StartService(service, 0, nullptr);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
}

bool DeploymentManager::StopService(const std::string& serviceName) {
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    
    SC_HANDLE service = OpenService(scm, serviceName.c_str(), SERVICE_STOP);
    if (!service) { CloseServiceHandle(scm); return false; }
    
    SERVICE_STATUS status;
    ControlService(service, SERVICE_CONTROL_STOP, &status);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
}

bool DeploymentManager::StartHeadless(const std::string& configPath) {
    headlessRunning_ = true;
    return true;
}

bool DeploymentManager::StopHeadless() {
    headlessRunning_ = false;
    return true;
}

bool DeploymentManager::CreateDirectoryStructure(const std::string& basePath) {
    fs::create_directories(basePath + "\\bin");
    fs::create_directories(basePath + "\\data");
    fs::create_directories(basePath + "\\config");
    return true;
}

bool DeploymentManager::CopyFiles(const std::string& src, const std::string& dst, const std::vector<std::string>& files) {
    for (const auto& file : files) {
        try {
            fs::copy(src + "\\" + file, dst + "\\" + file, fs::copy_options::overwrite_existing);
        } catch (...) {}
    }
    return true;
}

} // namespace Sovereign
