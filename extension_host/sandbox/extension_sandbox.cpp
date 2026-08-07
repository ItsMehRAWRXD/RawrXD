// extension_sandbox.cpp — Extension Sandbox Implementation
#include "extension_sandbox.hpp"
#include <fstream>
#include <algorithm>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

namespace RawrXD {
namespace ExtensionHost {

ExtensionSandbox::ExtensionSandbox(const SandboxConfig& config)
    : m_config(config)
{
}

ExtensionSandbox::~ExtensionSandbox() {
    Shutdown();
}

bool ExtensionSandbox::Initialize() {
    m_initialized = true;
    return true;
}

void ExtensionSandbox::Shutdown() {
    m_initialized = false;
}

bool ExtensionSandbox::ValidatePath(const std::filesystem::path& path) const {
    if (!m_config.enableFilesystemRead && !m_config.enableFilesystemWrite) return false;

    // Check if path is within restricted root
    if (!m_config.restrictedRoot.empty()) {
        auto absPath = std::filesystem::absolute(path);
        auto absRoot = std::filesystem::absolute(m_config.restrictedRoot);
        auto rel = std::filesystem::relative(absPath, absRoot);
        if (rel.string().find("..") == 0) return false; // Outside sandbox
    }

    return true;
}

bool ExtensionSandbox::ReadFile(const std::filesystem::path& path, std::string& content) {
    if (!m_config.enableFilesystemRead) return false;
    if (!ValidatePath(path)) return false;

    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;

    content.assign((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    TrackOperation("read_file");
    return true;
}

bool ExtensionSandbox::WriteFile(const std::filesystem::path& path, const std::string& content) {
    if (!m_config.enableFilesystemWrite) return false;
    if (!ValidatePath(path)) return false;
    if (content.size() > static_cast<size_t>(m_config.maxFileSizeBytes)) {
        m_stats.exceededLimits = true;
        return false;
    }

    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) return false;

    file.write(content.data(), content.size());
    TrackOperation("write_file");
    return true;
}

bool ExtensionSandbox::DeleteFile(const std::filesystem::path& path) {
    if (!m_config.enableFilesystemWrite) return false;
    if (!ValidatePath(path)) return false;

    std::error_code ec;
    std::filesystem::remove(path, ec);
    TrackOperation("delete_file");
    return !ec;
}

bool ExtensionSandbox::ListDirectory(const std::filesystem::path& path, std::vector<std::filesystem::path>& files) {
    if (!m_config.enableFilesystemRead) return false;
    if (!ValidatePath(path)) return false;

    for (const auto& entry : std::filesystem::directory_iterator(path)) {
        files.push_back(entry.path());
    }
    TrackOperation("list_directory");
    return true;
}

bool ExtensionSandbox::HttpGet(const std::string& url, std::string& response) {
    if (!m_config.enableNetwork) return false;

    // Use WinHTTP for sandboxed HTTP requests
    HINTERNET hSession = WinHttpOpen(L"RawrXD-Extension/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nullptr, nullptr, 0);
    if (!hSession) return false;

    // Parse URL
    URL_COMPONENTS urlComp = { sizeof(URL_COMPONENTS) };
    urlComp.dwSchemeLength = -1;
    urlComp.dwHostNameLength = -1;
    urlComp.dwUrlPathLength = -1;
    urlComp.dwExtraInfoLength = -1;

    std::wstring wurl(url.begin(), url.end());
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &urlComp)) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::wstring host(urlComp.lpszHostName, urlComp.dwHostNameLength);
    std::wstring path(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), urlComp.nPort, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(),
        nullptr, nullptr, nullptr, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    if (WinHttpSendRequest(hRequest, nullptr, 0, nullptr, 0, 0, 0)) {
        WinHttpReceiveResponse(hRequest, nullptr);
        DWORD bytesRead = 0;
        char buffer[4096];
        while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
            response.append(buffer, bytesRead);
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    TrackOperation("http_get");
    return true;
}

bool ExtensionSandbox::HttpPost(const std::string& url, const std::string& body, std::string& response) {
    if (!m_config.enableNetwork) return false;
    // TODO: Implement HTTP POST
    TrackOperation("http_post");
    return false;
}

bool ExtensionSandbox::SpawnProcess(const std::string& command, const std::vector<std::string>& args, int& exitCode) {
    if (!m_config.enableProcessSpawn) return false;

    // TODO: Create sandboxed process with restricted token
    TrackOperation("spawn_process");
    return false;
}

bool ExtensionSandbox::CheckPermission(const std::string& operation) const {
    if (operation == "filesystem.read") return m_config.enableFilesystemRead;
    if (operation == "filesystem.write") return m_config.enableFilesystemWrite;
    if (operation == "network") return m_config.enableNetwork;
    if (operation == "terminal") return m_config.enableTerminal;
    if (operation == "clipboard") return m_config.enableClipboard;
    if (operation == "debugger") return m_config.enableDebugger;
    return false;
}

void ExtensionSandbox::TrackOperation(const std::string& operation) {
    if (operation.find("read") != std::string::npos) m_stats.fileOperations++;
    if (operation.find("http") != std::string::npos) m_stats.networkRequests++;
    if (operation.find("spawn") != std::string::npos) m_stats.processSpawns++;
}

} // namespace ExtensionHost
} // namespace RawrXD
