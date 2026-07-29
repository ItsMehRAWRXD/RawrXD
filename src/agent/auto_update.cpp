/**
 * @file auto_update.cpp
 * @brief Self-updater using WinHTTP (Qt-free)
 *
 * Checks a JSON manifest for new versions, downloads, verifies SHA-256,
 * and launches the replacement binary.
 */
#include "auto_update.hpp"
<<<<<<< HEAD
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <winhttp.h>
#  include <wincrypt.h>
#  pragma comment(lib, "winhttp.lib")
#  pragma comment(lib, "crypt32.lib")
#  pragma comment(lib, "advapi32.lib")
#endif

#include <nlohmann/json.hpp>
namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

std::string getUpdateURL() {
    const char* env = std::getenv("RAWRXD_UPDATE_URL");
    return (env && env[0]) ? env
        : "https://rawrxd.blob.core.windows.net/updates/update_manifest.json";
}

std::string getAppVersion() {
    const char* env = std::getenv("RAWRXD_VERSION");
    if (env && env[0]) return env;
#ifdef RAWRXD_VERSION_STRING
    return RAWRXD_VERSION_STRING;
#else
    return "0.0.0";
#endif
=======
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <chrono>
#include <iomanip>
#include "release_agent.hpp" // Utilizing existing WinHTTP helpers if possible, or reimplementing simple ones

#pragma comment(lib, "winhttp.lib")

namespace fs = std::filesystem;
using json = nlohmann::json;

// Helper function to perform GET request using WinHTTP
// Note: This is a simplified version. For production, error handling should be more robust.
static std::vector<uint8_t> httpGet(const std::string& url, int& statusCode) {
    std::vector<uint8_t> responseData;
    statusCode = 0;

    URL_COMPONENTS urlComponents;
    ZeroMemory(&urlComponents, sizeof(urlComponents));
    urlComponents.dwStructSize = sizeof(urlComponents);
    
    wchar_t hostName[256];
    wchar_t urlPath[1024];
    
    urlComponents.lpszHostName = hostName;
    urlComponents.dwHostNameLength = 256;
    urlComponents.lpszUrlPath = urlPath;
    urlComponents.dwUrlPathLength = 1024;
    
    std::wstring wUrl(url.begin(), url.end());
    
    if (!WinHttpCrackUrl(wUrl.c_str(), (DWORD)wUrl.length(), 0, &urlComponents)) {
        return {};
    }

    HINTERNET hSession = WinHttpOpen(L"RawrXD-AutoUpdate/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return {};

    HINTERNET hConnect = WinHttpConnect(hSession, hostName, urlComponents.nPort, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return {};
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 
        (urlComponents.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return {};
    }

    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        if (WinHttpReceiveResponse(hRequest, NULL)) {
            DWORD dwStatusCode = 0;
            DWORD dwSize = sizeof(dwStatusCode);
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, 
                WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);
            statusCode = static_cast<int>(dwStatusCode);
            
            DWORD dwAvailable = 0;
            while (WinHttpQueryDataAvailable(hRequest, &dwAvailable) && dwAvailable > 0) {
                std::vector<uint8_t> chunk(dwAvailable);
                DWORD dwRead = 0;
                if (WinHttpReadData(hRequest, chunk.data(), dwAvailable, &dwRead)) {
                    responseData.insert(responseData.end(), chunk.begin(), chunk.begin() + dwRead);
                }
            }
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return responseData;
}

// Helper to get environment variable
static std::string getEnv(const std::string& name) {
    char* val = nullptr;
    size_t len = 0;
    _dupenv_s(&val, &len, name.c_str());
    if (val && len > 0) {
        std::string s(val);
        free(val);
        return s;
    }
    return "";
}

static std::string getUpdateURL() {
    std::string envUrl = getEnv("RAWRXD_UPDATE_URL");
    return envUrl.empty() 
        ? "https://rawrxd.blob.core.windows.net/updates/update_manifest.json"
        : envUrl;
}

static void logUpdateEvent(const std::string& event, const std::string& detail = "", int64_t latencyMs = -1) {
    
    if (!detail.empty()) {
        
    }
    if (latencyMs >= 0) {
        
    }
    
}

// Compute SHA256 of data using BCrypt
static std::string computeSHA256(const std::vector<uint8_t>& data) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHash = 0;
    DWORD cbData = 0;
    
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) {
        return "";
    }
    
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
    
    std::vector<BYTE> hash(cbHash);
    
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) == 0) {
        BCryptHashData(hHash, (PBYTE)data.data(), (ULONG)data.size(), 0);
        BCryptFinishHash(hHash, hash.data(), cbHash, 0);
        BCryptDestroyHash(hHash);
    }
    
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    std::stringstream ss;
    for (size_t i = 0; i < std::min(size_t(32), hash.size()); ++i) { // SHA256 is 32 bytes
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    
    return ss.str();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

std::string getAppDataDir() {
#ifdef _WIN32
    const char* ad = std::getenv("LOCALAPPDATA");
    return ad ? (std::string(ad) + "\\RawrXD") : ".";
#else
    const char* h = std::getenv("HOME");
    return h ? (std::string(h) + "/.local/share/RawrXD") : ".";
#endif
}

#ifdef _WIN32
std::string sha256Hex(const std::vector<uint8_t>& data) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return {};
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return {};
    }

    CryptHashData(hHash, data.data(), static_cast<DWORD>(data.size()), 0);

    DWORD hashLen = 32;
    uint8_t hash[32]{};
    CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);

    static const char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (DWORD i = 0; i < hashLen; ++i) {
        result += hex[hash[i] >> 4];
        result += hex[hash[i] & 0xF];
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
}

std::vector<uint8_t> httpGet(const std::wstring& host, const std::wstring& path, bool tls) {
    std::vector<uint8_t> body;
    HINTERNET hSession = WinHttpOpen(L"RawrXD/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return body;

    INTERNET_PORT port = tls ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    HINTERNET hConn = WinHttpConnect(hSession, host.c_str(), port, 0);
    if (!hConn) { WinHttpCloseHandle(hSession); return body; }

    DWORD flags = tls ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", path.c_str(), nullptr,
                                        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession); return body; }

    if (!WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hReq, nullptr)) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession);
        return body;
    }

    // Check HTTP status code
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    if (!WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX)) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession);
        return body;
    }

    if (statusCode != 200) {
        fprintf(stderr, "[ERROR] [AutoUpdate] HTTP %lu (expected 200)\n", statusCode);
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession);
        return body;
    }

    DWORD avail = 0;
    while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
        size_t pos = body.size();
        body.resize(pos + avail);
        DWORD bytesRead = 0;
        WinHttpReadData(hReq, body.data() + pos, avail, &bytesRead);
        body.resize(pos + bytesRead);
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSession);
    return body;
}
#endif

} // namespace

bool AutoUpdate::checkAndInstall() {
<<<<<<< HEAD
#ifdef _WIN32
    const char* disable = std::getenv("RAWRXD_DISABLE_AUTOUPDATE");
    if (disable && std::string(disable) == "1") {
        fprintf(stderr, "[INFO] [AutoUpdate] SKIPPED – disabled via env\n");
        return true;
    }

    std::string updateUrl = getUpdateURL();
    fprintf(stderr, "[INFO] [AutoUpdate] CHECK_START | URL: %s\n", updateUrl.c_str());

    // Parse URL
    bool tls = updateUrl.rfind("https", 0) == 0;
    size_t hs = updateUrl.find("://");
    if (hs == std::string::npos) return false;
    hs += 3;
    size_t ps = updateUrl.find('/', hs);
    if (ps == std::string::npos) ps = updateUrl.size();
    std::wstring host(updateUrl.begin() + hs, updateUrl.begin() + ps);
    std::wstring path(updateUrl.begin() + ps, updateUrl.end());

    auto manifestBytes = httpGet(host, path, tls);
    if (manifestBytes.empty()) {
        fprintf(stderr, "[WARN] [AutoUpdate] CHECK_FAILED – empty response\n");
        return false;
    }

    json manifest;
    try {
        manifest = json::parse(manifestBytes.begin(), manifestBytes.end());
    } catch (const json::exception& e) {
        fprintf(stderr, "[WARN] [AutoUpdate] CHECK_FAILED – bad JSON: %s\n", e.what());
        return false;
    }

    std::string remoteVer = manifest.value("version", "");
    std::string remoteURL = manifest.value("url", "");
    std::string remoteSHA = manifest.value("sha256", "");
    std::string localVer  = getAppVersion();

    fprintf(stderr, "[INFO] [AutoUpdate] Local: %s, Remote: %s\n",
            localVer.c_str(), remoteVer.c_str());

=======
    auto start = std::chrono::high_resolution_clock::now();
    
    // Feature toggle check via config file or env? Using simple env for now as settings replacement
    // or checking a config json if exists.
    // For now assuming enabled unless disabled by env
    if (getEnv("RAWRXD_AUTO_UPDATE_DISABLED") == "1") {
        logUpdateEvent("SKIPPED", "Auto-update disabled in environment");
        return true;
    }
    
    std::string updateUrl = getUpdateURL();
    
    logUpdateEvent("CHECK_START", "URL: " + updateUrl);
    
    int statusCode = 0;
    std::vector<uint8_t> data = httpGet(updateUrl, statusCode);
    
    auto end = std::chrono::high_resolution_clock::now();
    auto latency = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    if (statusCode != 200 || data.empty()) {
        logUpdateEvent("CHECK_FAILED", "Status: " + std::to_string(statusCode), latency);
        return false;
    }

    json root;
    try {
        root = json::parse(data);
    } catch (...) {
        logUpdateEvent("CHECK_FAILED", "Invalid JSON", latency);
        return false;
    }
    
    std::string remoteVer = root.value("version", "");
    std::string remoteURL = root.value("url", "");
    std::string remoteSHA = root.value("sha256", "");
    
    // Get local version - no QCoreApplication... assume hardcoded or from macro
    // Using a placeholder or macro if available.
    // In agent_main.cpp (if I read it) it might have version.
    std::string localVer = "1.0.0"; // Fallback
#ifdef RAWRXD_VERSION
    localVer = RAWRXD_VERSION;
#endif
    
    logUpdateEvent("VERSION_CHECK", "Local: " + localVer + ", Remote: " + remoteVer, latency);
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    if (remoteVer == localVer) {
        fprintf(stderr, "[INFO] [AutoUpdate] UP_TO_DATE\n");
        return true;
    }
<<<<<<< HEAD

    // Download
    std::string localPath = getAppDataDir() + "\\updates\\RawrXD-Shell-" + remoteVer + ".exe";
    fs::create_directories(fs::path(localPath).parent_path());

    size_t dhs = remoteURL.find("://");
    if (dhs == std::string::npos) return false;
    dhs += 3;
    size_t dps = remoteURL.find('/', dhs);
    if (dps == std::string::npos) dps = remoteURL.size();
    bool dTLS = remoteURL.rfind("https", 0) == 0;
    std::wstring dHost(remoteURL.begin() + dhs, remoteURL.begin() + dps);
    std::wstring dPath(remoteURL.begin() + dps, remoteURL.end());

    fprintf(stderr, "[INFO] [AutoUpdate] DOWNLOAD_START | Version: %s\n", remoteVer.c_str());
    auto dlBytes = httpGet(dHost, dPath, dTLS);
    if (dlBytes.empty()) {
        fprintf(stderr, "[WARN] [AutoUpdate] DOWNLOAD_FAILED\n");
        return false;
    }

    // Integrity
    if (!remoteSHA.empty()) {
        std::string sha = sha256Hex(dlBytes);
        if (sha != remoteSHA) {
            fprintf(stderr, "[WARN] [AutoUpdate] INTEGRITY_FAILED | Expected: %s Got: %s\n",
                    remoteSHA.c_str(), sha.c_str());
            return false;
        }
    }

    // Write
    {
        std::ofstream f(localPath, std::ios::binary | std::ios::trunc);
        if (!f.is_open()) {
            fprintf(stderr, "[WARN] [AutoUpdate] WRITE_FAILED | Path: %s\n", localPath.c_str());
            return false;
        }
        f.write(reinterpret_cast<const char*>(dlBytes.data()),
                static_cast<std::streamsize>(dlBytes.size()));
    }

    fprintf(stderr, "[INFO] [AutoUpdate] DOWNLOAD_COMPLETE | %zu bytes\n", dlBytes.size());

    // Launch replacement
    std::string launchCmd = "cmd.exe /C timeout /t 3 && \"" + localPath + "\"";
    STARTUPINFOA si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    CreateProcessA(nullptr, launchCmd.data(), nullptr, nullptr,
                   FALSE, CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    ExitProcess(0);
#else
    fprintf(stderr, "[INFO] [AutoUpdate] Not supported on this platform\n");
    return false;
#endif
=======
    
    // Determine path
    std::string localPath;
    char* appData = nullptr;
    size_t len = 0;
    _dupenv_s(&appData, &len, "APPDATA");
    if (appData && len > 0) {
        localPath = std::string(appData) + "\\RawrXD\\updates\\RawrXD-QtShell-" + remoteVer + ".exe";
        free(appData);
    } else {
        localPath = "updates/RawrXD-Shell-" + remoteVer + ".exe";
    }
    
    fs::create_directories(fs::path(localPath).parent_path());
    
    start = std::chrono::high_resolution_clock::now();
    logUpdateEvent("DOWNLOAD_START", "Version: " + remoteVer + ", URL: " + remoteURL);
    
    data = httpGet(remoteURL, statusCode);
    
    end = std::chrono::high_resolution_clock::now();
    latency = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    if (statusCode != 200 || data.empty()) {
        logUpdateEvent("DOWNLOAD_FAILED", "Status: " + std::to_string(statusCode), latency);
        return false;
    }
    
    // Check integrity
    std::string sha256 = computeSHA256(data);
    if (sha256 != remoteSHA) {
        logUpdateEvent("INTEGRITY_FAILED", "Expected: " + remoteSHA + ", Got: " + sha256, latency);
        return false;
    }
    
    logUpdateEvent("INTEGRITY_OK", "SHA256: " + sha256);
    
    // Write file
    std::ofstream f(localPath, std::ios::binary);
    if (!f) {
        logUpdateEvent("WRITE_FAILED", "Path: " + localPath);
        return false;
    }
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
    f.close();
    
    logUpdateEvent("DOWNLOAD_COMPLETE", "Path: " + localPath + ", Size: " + std::to_string(data.size()) + " bytes", latency);
    
    // Restart logic
    logUpdateEvent("RESTART_SCHEDULED", "New version: " + remoteVer + ", Delay: 3s");
    
    std::string cmd = "timeout /t 3 && \"" + localPath + "\"";
    
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    
    char* cmdLine = _strdup(("cmd.exe /C " + cmd).c_str());
    if (CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        free(cmdLine);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        // Use ExitProcess called from caller or handled gracefully
        exit(0);
    }
    free(cmdLine);
    
    return true;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}
