#include "BackendConfig.hpp"
#include <shlobj.h>
#include <windows.h>
#include <fstream>
#include <sstream>

std::string BackendConfig::ResolveAppDataPath() {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path))) {
        std::string fullPath(path);
        fullPath += "\\RawrXD";
        CreateDirectoryA(fullPath.c_str(), NULL);
        return fullPath + "\\backend.json";
    }
    return "backend.json";
}

bool BackendConfig::SaveToDisk(const ConfigurationSession& session) {
    std::string targetFile = ResolveAppDataPath();
    std::ofstream out(targetFile, std::ios::trunc);
    if (!out.is_open()) return false;

    out << "{\n";
    out << "  \"activeBackend\": " << static_cast<int>(session.activeBackend) << ",\n";
    out << "  \"fallbackBackend\": " << static_cast<int>(session.fallbackBackend) << ",\n";
    out << "  \"timeoutMs\": " << session.timeoutMs << ",\n";
    out << "  \"allowScripts\": " << (session.allowScripts ? "true" : "false") << "\n";
    out << "}\n";
    out.close();
    return true;
}

ConfigurationSession BackendConfig::LoadFromDisk() {
    ConfigurationSession session;
    session.activeBackend = BackendType::BareMetal;
    session.fallbackBackend = BackendType::PowerShell;
    session.timeoutMs = 30000;
    session.allowScripts = false;

    std::string targetFile = ResolveAppDataPath();
    std::ifstream in(targetFile);
    if (!in.is_open()) return session;

    std::string line;
    while (std::getline(in, line)) {
        if (line.find("activeBackend") != std::string::npos) {
            size_t idx = line.find_last_of("0123456789");
            if (idx != std::string::npos) session.activeBackend = static_cast<BackendType>(line[idx] - '0');
        } else if (line.find("fallback") != std::string::npos) {
            size_t idx = line.find_last_of("0123456789");
            if (idx != std::string::npos) session.fallbackBackend = static_cast<BackendType>(line[idx] - '0');
        } else if (line.find("timeout") != std::string::npos) {
            size_t start = line.find_first_of("0123456789");
            size_t end = line.find_last_of("0123456789");
            if (start != std::string::npos && end != std::string::npos) {
                session.timeoutMs = std::stoi(line.substr(start, end - start + 1));
            }
        } else if (line.find("allowScripts") != std::string::npos) {
            session.allowScripts = (line.find("true") != std::string::npos);
        }
    }
    return session;
}
