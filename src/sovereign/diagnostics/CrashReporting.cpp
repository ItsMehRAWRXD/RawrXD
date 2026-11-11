// ============================================================================
// CrashReporting.cpp - Crash Reporting, Update Checker, SBOM Implementation
// ============================================================================

#include "CrashReporting.hpp"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <chrono>
#include <iostream>

namespace fs = std::filesystem;
namespace Sovereign {

CrashReporting::CrashReporting() = default;
CrashReporting::~CrashReporting() { Shutdown(); }

bool CrashReporting::Initialize(const std::string& crashDumpDir) {
    crashDumpDir_ = crashDumpDir;
    fs::create_directories(crashDumpDir_);
    return true;
}

void CrashReporting::Shutdown() { crashHistory_.clear(); }

void CrashReporting::CaptureCrash(const std::string& exception, const std::string& stackTrace) {
    CrashReport report;
    report.id = crashHistory_.size() + 1;
    report.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    report.application = "SovereignIDE";
    report.version = "1.0.0";
    report.exception = exception;
    report.stackTrace = stackTrace;
    report.isUploaded = false;
    
    crashHistory_.push_back(report);
    SaveCrashReport(report);
    stats_.totalCrashes++;
}

bool CrashReporting::SaveCrashReport(const CrashReport& report) {
    std::string path = crashDumpDir_ + "/crash_" + std::to_string(report.id) + ".dmp";
    std::ofstream file(path);
    if (!file) return false;
    
    file << "Crash Report #" << report.id << "\n";
    file << "Timestamp: " << report.timestamp << "\n";
    file << "Application: " << report.application << " v" << report.version << "\n";
    file << "Exception: " << report.exception << "\n";
    file << "Stack Trace:\n" << report.stackTrace << "\n";
    file << "System: " << report.systemInfo << "\n";
    return true;
}

UpdateInfo CrashReporting::CheckForUpdates(const std::string& currentVersion) {
    UpdateInfo info;
    info.currentVersion = currentVersion;
    info.latestVersion = currentVersion;
    info.isUpdateAvailable = false;
    info.isCritical = false;
    return info;
}

std::vector<SBOMEntry> CrashReporting::GenerateSBOM() {
    std::vector<SBOMEntry> sbom;
    
    SBOMEntry entry;
    entry.name = "SovereignIDE";
    entry.version = "1.0.0";
    entry.supplier = "Sovereign";
    entry.license = "Proprietary";
    entry.purl = "pkg:generic/sovereign-ide@1.0.0";
    entry.hasVulnerability = false;
    sbom.push_back(entry);
    
    return sbom;
}

bool CrashReporting::ExportSBOM(const std::string& path) {
    auto sbom = GenerateSBOM();
    std::ofstream file(path);
    if (!file) return false;
    
    file << "{\n  \"bomFormat\": \"CycloneDX\",\n  \"components\": [\n";
    for (size_t i = 0; i < sbom.size(); ++i) {
        file << "    {\"name\": \"" << sbom[i].name << "\", \"version\": \"" << sbom[i].version << "\"}";
        if (i < sbom.size() - 1) file << ",";
        file << "\n";
    }
    file << "  ]\n}\n";
    return true;
}

std::vector<std::string> CrashReporting::CheckVulnerabilities(const std::vector<SBOMEntry>& sbom) {
    std::vector<std::string> vulns;
    for (const auto& entry : sbom) {
        if (entry.hasVulnerability) {
            for (const auto& cve : entry.cves) {
                vulns.push_back(entry.name + ": " + cve);
            }
        }
    }
    return vulns;
}

} // namespace Sovereign
