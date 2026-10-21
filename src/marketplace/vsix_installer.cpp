#include "marketplace/vsix_installer.h"
#include "core/zip_reader.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <cstdlib>
#include <windows.h>
#include <winhttp.h>
#include <shlobj.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

namespace fs = std::filesystem;

// Helper: Convert wstring
static std::string WideToAnsi(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

// Helper for HTTP GET to file
static bool DownloadFile(const std::string& url, const std::string& destPath, std::function<void(int)> progressCallback) {
    // Parse URL
    std::wstring wUrl(url.begin(), url.end());
    URL_COMPONENTS urlComp;
    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwSchemeLength    = (DWORD)-1;
    urlComp.dwHostNameLength  = (DWORD)-1;
    urlComp.dwUrlPathLength   = (DWORD)-1;
    urlComp.dwExtraInfoLength = (DWORD)-1;

    if (!WinHttpCrackUrl(wUrl.c_str(), (DWORD)wUrl.length(), 0, &urlComp)) {
        return false;
    }

    std::wstring host(urlComp.lpszHostName, urlComp.dwHostNameLength);
    std::wstring path(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
    if (urlComp.dwExtraInfoLength > 0) {
        path += std::wstring(urlComp.lpszExtraInfo, urlComp.dwExtraInfoLength);
    }

    HINTERNET hSession = WinHttpOpen(L"RawrXD/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), urlComp.nPort, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 
        (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false;
    }

    // Get Content Length
    DWORD dwContentLen = 0, dwLen = sizeof(dwContentLen);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER, 
                        WINHTTP_HEADER_NAME_BY_INDEX, &dwContentLen, &dwLen, WINHTTP_NO_HEADER_INDEX);

    std::ofstream outFile(destPath, std::ios::binary);
    if (!outFile) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false;
    }

    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    DWORD totalDownloaded = 0;

    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
        if (dwSize == 0) break;

        std::vector<char> buffer(dwSize);
        if (WinHttpReadData(hRequest, &buffer[0], dwSize, &dwDownloaded)) {
            outFile.write(buffer.data(), dwDownloaded);
            totalDownloaded += dwDownloaded;
            if (dwContentLen > 0 && progressCallback) {
                progressCallback((int)((totalDownloaded * 100) / dwContentLen));
            }
        }
    } while (dwSize > 0);

    outFile.close();
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return true;
}

VsixInstaller::VsixInstaller() {}

VsixInstaller::~VsixInstaller() {
    cleanupTempFiles();
}

void VsixInstaller::installFromUrl(const std::string& url, const std::string& extensionId) {
    if (installationStarted) installationStarted(extensionId);

    std::thread([this, url, extensionId]() {
        // Temp file
        TCHAR tempPath[MAX_PATH];
        GetTempPath(MAX_PATH, tempPath);
        std::string tempFile = std::string(tempPath) + extensionId + ".vsix";
        
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            InstallationInfo info = { extensionId, url, tempFile };
            m_activeInstallations.push_back(info);
        }

        // Download
        bool success = DownloadFile(url, tempFile, [this, extensionId](int progress) {
            if (installationProgress) installationProgress(extensionId, progress);
        });

        if (!success) {
            if (installationError) installationError(extensionId, "Download failed");
            return;
        }

        // Install from file logic
        installFromFile(tempFile, extensionId);
        
        // Cleanup handled by cleanupTempFiles or subsequent logic
    }).detach();
}

void VsixInstaller::installFromFile(const std::string& filePath) {
    // try to infer extension ID from filename or manifest
    std::string filename = fs::path(filePath).stem().string();
    installFromFile(filePath, filename); 
}

void VsixInstaller::installFromFile(const std::string& filePath, const std::string& extensionId) {
    std::string extensionsDir = getExtensionsDirectory();
    std::string installPath = getExtensionInstallPath(extensionId);
    
    // Ensure dir exists
    fs::create_directories(installPath);
    
    // Extract
    if (extractVsixPackage(filePath, installPath)) {
        if (activateExtension(extensionId)) {
            if (installationCompleted) installationCompleted(extensionId, true);
        } else {
             if (installationError) installationError(extensionId, "Activation failed");
        }
    } else {
        if (installationError) installationError(extensionId, "Extraction failed (Archive invalid?)");
    }
}

bool VsixInstaller::extractVsixPackage(const std::string& vsixPath, const std::string& destination) {
    // A VSIX is a ZIP, and the runtime carries its own reader for that
    // format. Shelling out to PowerShell or tar made the extension runtime
    // depend on external tools that are not present on every machine and
    // that cannot be relied on in a headless context.
    std::error_code ec;
    if (!fs::exists(vsixPath, ec)) return false;

    std::ifstream in(vsixPath, std::ios::binary);
    if (!in) return false;
    std::string archive((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (archive.empty()) return false;

    RawrXD::ZipReader reader;
    if (!reader.open(reinterpret_cast<const uint8_t*>(archive.data()), archive.size())) {
        return false;
    }

    int written = reader.extractAll(destination);
    if (written <= 0) return false;

    // A VSIX holds its manifest under extension/, but a bare package may
    // put package.json at the root, so both layouts are accepted.
    if (fs::exists(destination + "/extension.vsixmanifest") ||
        fs::exists(destination + "/package.json") ||
        fs::exists(destination + "/extension/package.json")) {
        return true;
    }
    return written > 0;
}

bool VsixInstaller::activateExtension(const std::string& extensionPath) {
    // Logic: Register in some registry or JSON file.
    // For now, we assume filesystem presence is enough for loaders.
    return true;
}

bool VsixInstaller::deactivateExtension(const std::string& extensionId) {
    return true;
}

bool VsixInstaller::uninstallExtension(const std::string& extensionId) {
    std::string path = getExtensionInstallPath(extensionId);
    if (!fs::exists(path)) {
        if (uninstallCompleted) uninstallCompleted(extensionId, false);
        return false;
    }
    
    std::error_code ec;
    fs::remove_all(path, ec);
    
    bool success = !ec;
    if (uninstallCompleted) uninstallCompleted(extensionId, success);
    return success;
}

bool VsixInstaller::isExtensionInstalled(const std::string& extensionId) {
    std::string path = getExtensionInstallPath(extensionId);
    return fs::exists(path);
}

std::string VsixInstaller::getExtensionsDirectory() {
    // Real AppData path
    PWSTR path = NULL;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &path))) {
        std::wstring wpath(path);
        CoTaskMemFree(path);
        
        std::string appData = WideToAnsi(wpath);
        std::string extDir = appData + "\\RawrXD\\extensions";
        fs::create_directories(extDir);
        return extDir;
    }
    return "C:\\RawrXD\\extensions"; // Fallback
}

std::string VsixInstaller::getExtensionInstallPath(const std::string& extensionId) {
    return getExtensionsDirectory() + "\\" + extensionId;
}

void VsixInstaller::cleanupTempFiles() {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& info : m_activeInstallations) {
        if (fs::exists(info.tempFilePath)) {
            std::error_code ec;
            fs::remove(info.tempFilePath, ec);
        }
    }
    m_activeInstallations.clear();
}
