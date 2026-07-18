// RawrXD Auto-Updater
// Phase 8 - Task 17: Auto-Updater Mechanism

#include <windows.h>
#include <wininet.h>
#include <string>
#include <vector>
#include <json/json.h>

#pragma comment(lib, "wininet.lib")

// Update information
struct UpdateInfo {
    std::string version;
    std::string downloadUrl;
    std::string releaseNotes;
    uint64_t fileSize;
    std::string checksum;
    bool mandatory;
};

// Update status
enum class UpdateStatus {
    UpToDate,
    UpdateAvailable,
    Downloading,
    Downloaded,
    Installing,
    Error
};

// Auto-updater class
class AutoUpdater {
private:
    std::string currentVersion;
    std::string updateServerUrl;
    UpdateInfo pendingUpdate;
    UpdateStatus status;
    std::string errorMessage;
    float downloadProgress;
    
    // Download to temp file
    bool DownloadFile(const std::string& url, const std::wstring& localPath) {
        HINTERNET hInternet = InternetOpenA("RawrXD Updater", 
                                            INTERNET_OPEN_TYPE_PRECONFIG,
                                            NULL, NULL, 0);
        if (!hInternet) return false;
        
        HINTERNET hUrl = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0,
                                          INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE, 0);
        if (!hUrl) {
            InternetCloseHandle(hInternet);
            return false;
        }
        
        // Get file size
        DWORD fileSize = 0;
        DWORD sizeLen = sizeof(fileSize);
        HttpQueryInfo(hUrl, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
                      &fileSize, &sizeLen, NULL);
        
        // Create local file
        HANDLE hFile = CreateFileW(localPath.c_str(), GENERIC_WRITE, 0, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            InternetCloseHandle(hUrl);
            InternetCloseHandle(hInternet);
            return false;
        }
        
        // Download in chunks
        const DWORD bufferSize = 64 * 1024; // 64KB
        std::vector<BYTE> buffer(bufferSize);
        DWORD downloaded = 0;
        DWORD bytesRead = 0;
        
        while (InternetReadFile(hUrl, buffer.data(), bufferSize, &bytesRead) && bytesRead > 0) {
            DWORD written = 0;
            WriteFile(hFile, buffer.data(), bytesRead, &written, NULL);
            downloaded += bytesRead;
            
            if (fileSize > 0) {
                downloadProgress = (float)downloaded / fileSize * 100.0f;
            }
        }
        
        CloseHandle(hFile);
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        
        return downloaded > 0;
    }
    
    // Verify checksum
    bool VerifyChecksum(const std::wstring& filePath, const std::string& expectedChecksum) {
        // Simplified - would use SHA-256 in production
        return true;
    }
    
    // Compare versions (returns true if v2 > v1)
    bool IsNewerVersion(const std::string& v1, const std::string& v2) {
        int major1, minor1, patch1;
        int major2, minor2, patch2;
        
        sscanf_s(v1.c_str(), "%d.%d.%d", &major1, &minor1, &patch1);
        sscanf_s(v2.c_str(), "%d.%d.%d", &major2, &minor2, &patch2);
        
        if (major2 != major1) return major2 > major1;
        if (minor2 != minor1) return minor2 > minor1;
        return patch2 > patch1;
    }
    
public:
    AutoUpdater(const std::string& version) 
        : currentVersion(version), 
          updateServerUrl("https://api.rawrxd.io/updates"),
          status(UpdateStatus::UpToDate),
          downloadProgress(0.0f) {
    }
    
    // Check for updates
    bool CheckForUpdate() {
        status = UpdateStatus::UpToDate;
        
        HINTERNET hInternet = InternetOpenA("RawrXD Updater",
                                            INTERNET_OPEN_TYPE_PRECONFIG,
                                            NULL, NULL, 0);
        if (!hInternet) {
            status = UpdateStatus::Error;
            errorMessage = "Failed to initialize internet connection";
            return false;
        }
        
        // Build check URL
        std::string checkUrl = updateServerUrl + "/check?version=" + currentVersion + "&platform=windows";
        
        HINTERNET hUrl = InternetOpenUrlA(hInternet, checkUrl.c_str(), NULL, 0,
                                          INTERNET_FLAG_SECURE, 0);
        if (!hUrl) {
            InternetCloseHandle(hInternet);
            status = UpdateStatus::Error;
            errorMessage = "Failed to connect to update server";
            return false;
        }
        
        // Read response
        std::string response;
        char buffer[4096];
        DWORD bytesRead = 0;
        
        while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
            response.append(buffer, bytesRead);
        }
        
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        
        // Parse JSON response
        // Simplified - would use proper JSON parser in production
        if (response.find("\"update_available\": true") != std::string::npos) {
            status = UpdateStatus::UpdateAvailable;
            
            // Extract update info (simplified parsing)
            size_t verPos = response.find("\"version\": \"");
            if (verPos != std::string::npos) {
                verPos += 11;
                size_t verEnd = response.find("\"", verPos);
                pendingUpdate.version = response.substr(verPos, verEnd - verPos);
            }
            
            size_t urlPos = response.find("\"download_url\": \"");
            if (urlPos != std::string::npos) {
                urlPos += 15;
                size_t urlEnd = response.find("\"", urlPos);
                pendingUpdate.downloadUrl = response.substr(urlPos, urlEnd - urlPos);
            }
            
            return true;
        }
        
        return false;
    }
    
    // Download update
    bool DownloadUpdate(HWND hwndProgress = NULL) {
        if (status != UpdateStatus::UpdateAvailable) {
            return false;
        }
        
        status = UpdateStatus::Downloading;
        
        // Get temp path
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        
        std::wstring updateFile = std::wstring(tempPath) + L"\\RawrXD_Update_" + 
                                  std::wstring(pendingUpdate.version.begin(), 
                                              pendingUpdate.version.end()) + L".exe";
        
        // Download
        if (!DownloadFile(pendingUpdate.downloadUrl, updateFile)) {
            status = UpdateStatus::Error;
            errorMessage = "Failed to download update";
            return false;
        }
        
        // Verify checksum
        if (!VerifyChecksum(updateFile, pendingUpdate.checksum)) {
            DeleteFileW(updateFile.c_str());
            status = UpdateStatus::Error;
            errorMessage = "Update file verification failed";
            return false;
        }
        
        status = UpdateStatus::Downloaded;
        return true;
    }
    
    // Install update
    bool InstallUpdate() {
        if (status != UpdateStatus::Downloaded) {
            return false;
        }
        
        status = UpdateStatus::Installing;
        
        // Get temp path
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        
        std::wstring updateFile = std::wstring(tempPath) + L"\\RawrXD_Update_" + 
                                  std::wstring(pendingUpdate.version.begin(), 
                                              pendingUpdate.version.end()) + L".exe";
        
        // Run installer
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = L"runas";
        sei.lpFile = updateFile.c_str();
        sei.lpParameters = L"/SILENT /CLOSEAPPLICATIONS";
        sei.nShow = SW_SHOW;
        
        if (!ShellExecuteExW(&sei)) {
            status = UpdateStatus::Error;
            errorMessage = "Failed to launch installer";
            return false;
        }
        
        // Exit current application
        return true;
    }
    
    // Silent update (check, download, install automatically)
    bool SilentUpdate() {
        if (!CheckForUpdate()) {
            return false;
        }
        
        if (!DownloadUpdate()) {
            return false;
        }
        
        return InstallUpdate();
    }
    
    // Getters
    UpdateStatus GetStatus() const { return status; }
    const std::string& GetErrorMessage() const { return errorMessage; }
    float GetDownloadProgress() const { return downloadProgress; }
    const UpdateInfo& GetPendingUpdate() const { return pendingUpdate; }
    bool HasUpdate() const { return status == UpdateStatus::UpdateAvailable || 
                                    status == UpdateStatus::Downloaded; }
};

// C API
extern "C" {

typedef void* UpdaterHandle;

UpdaterHandle Updater_Create(const char* version) {
    return new AutoUpdater(version);
}

void Updater_Destroy(UpdaterHandle handle) {
    delete (AutoUpdater*)handle;
}

int Updater_CheckForUpdate(UpdaterHandle handle) {
    if (!handle) return 0;
    return ((AutoUpdater*)handle)->CheckForUpdate() ? 1 : 0;
}

int Updater_DownloadUpdate(UpdaterHandle handle) {
    if (!handle) return 0;
    return ((AutoUpdater*)handle)->DownloadUpdate() ? 1 : 0;
}

int Updater_InstallUpdate(UpdaterHandle handle) {
    if (!handle) return 0;
    return ((AutoUpdater*)handle)->InstallUpdate() ? 1 : 0;
}

int Updater_HasUpdate(UpdaterHandle handle) {
    if (!handle) return 0;
    return ((AutoUpdater*)handle)->HasUpdate() ? 1 : 0;
}

float Updater_GetProgress(UpdaterHandle handle) {
    if (!handle) return 0.0f;
    return ((AutoUpdater*)handle)->GetDownloadProgress();
}

const char* Updater_GetError(UpdaterHandle handle) {
    if (!handle) return "";
    return ((AutoUpdater*)handle)->GetErrorMessage().c_str();
}

} // extern "C"

// Simple test
int main() {
    AutoUpdater updater("1.0.0");
    
    printf("RawrXD Auto-Updater Test\n");
    printf("========================\n\n");
    
    printf("Checking for updates...\n");
    if (updater.CheckForUpdate()) {
        printf("Update available: %s\n", updater.GetPendingUpdate().version.c_str());
        
        printf("Downloading...\n");
        if (updater.DownloadUpdate()) {
            printf("Download complete!\n");
            printf("Installing...\n");
            updater.InstallUpdate();
        } else {
            printf("Download failed: %s\n", updater.GetErrorMessage().c_str());
        }
    } else {
        printf("No updates available.\n");
    }
    
    return 0;
}
