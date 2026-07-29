// ============================================================================
// CrashReporting.hpp - Crash Reporting, Update Checker, SBOM, Vulnerability
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace Sovereign {

struct CrashReport {
    uint64_t id;
    uint64_t timestamp;
    std::string application;
    std::string version;
    std::string exception;
    std::string stackTrace;
    std::string moduleName;
    uint64_t moduleBase;
    std::string systemInfo;
    std::vector<std::string> loadedModules;
    bool isUploaded;
};

struct UpdateInfo {
    std::string currentVersion;
    std::string latestVersion;
    std::string downloadUrl;
    std::string releaseNotes;
    uint64_t releaseDate;
    bool isUpdateAvailable;
    bool isCritical;
};

struct SBOMEntry {
    std::string name;
    std::string version;
    std::string supplier;
    std::string license;
    std::string purl;
    bool hasVulnerability;
    std::vector<std::string> cves;
};

class CrashReporting {
public:
    CrashReporting();
    ~CrashReporting();

    bool Initialize(const std::string& crashDumpDir = "./crashdumps");
    void Shutdown();

    void CaptureCrash(const std::string& exception, const std::string& stackTrace);
    bool SaveCrashReport(const CrashReport& report);
    std::vector<CrashReport> GetCrashHistory() const;
    bool UploadCrashReport(uint64_t crashId);

    // Update checker
    UpdateInfo CheckForUpdates(const std::string& currentVersion);
    bool DownloadUpdate(const std::string& url, const std::string& outputPath);
    bool InstallUpdate(const std::string& updatePath);

    // SBOM
    std::vector<SBOMEntry> GenerateSBOM();
    bool ExportSBOM(const std::string& path);
    std::vector<std::string> CheckVulnerabilities(const std::vector<SBOMEntry>& sbom);

    struct CrashStats { uint64_t totalCrashes; uint64_t uploadedReports; uint64_t updatesInstalled; };
    CrashStats GetStats() const { return stats_; }

private:
    std::string crashDumpDir_;
    std::vector<CrashReport> crashHistory_;
    CrashStats stats_;
    mutable std::mutex mutex_;
};

} // namespace Sovereign
