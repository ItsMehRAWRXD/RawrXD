#include "vscode_marketplace.hpp"
#include <string>
#include <vector>
#include <windows.h>
#include <winhttp.h>
#include <fstream>
#include <algorithm>

#pragma comment(lib, "winhttp.lib")

namespace VSCodeMarketplace {

namespace {

static std::wstring utf8ToWide(const std::string& s) {
    if (s.empty()) {
        return std::wstring();
    }
    int wlen = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (wlen <= 0) {
        return std::wstring();
    }
    std::wstring out;
    out.resize(static_cast<size_t>(wlen - 1));
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), wlen);
    return out;
}

static bool readAllResponse(HINTERNET hRequest, std::string& out) {
    out.clear();
    DWORD dwSize = 0;
    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            return false;
        }
        if (dwSize == 0) {
            break;
        }
        std::vector<char> buffer(static_cast<size_t>(dwSize));
        DWORD dwDownloaded = 0;
        if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) {
            return false;
        }
        out.append(buffer.data(), buffer.data() + dwDownloaded);
    } while (dwSize > 0);
    return true;
}

static bool getStatusCode(HINTERNET hRequest, DWORD& codeOut) {
    codeOut = 0;
    DWORD size = sizeof(codeOut);
    return WinHttpQueryHeaders(
        hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &codeOut,
        &size,
        WINHTTP_NO_HEADER_INDEX) == TRUE;
}

static std::string extractJsonString(const std::string& json, const char* key) {
    const std::string needle = std::string("\"") + key + "\"";
    size_t keyPos = json.find(needle);
    if (keyPos == std::string::npos) return std::string();
    size_t colon = json.find(':', keyPos + needle.size());
    if (colon == std::string::npos) return std::string();
    size_t firstQuote = json.find('"', colon + 1);
    if (firstQuote == std::string::npos) return std::string();
    size_t secondQuote = json.find('"', firstQuote + 1);
    if (secondQuote == std::string::npos) return std::string();
    return json.substr(firstQuote + 1, secondQuote - firstQuote - 1);
}

} // namespace

struct MarketplaceEntry {
    std::string name;
    std::string publisher;
    std::string version;
    std::string description;
    std::string downloadUrl;
    int installCount;
    float rating;
};

bool Query(const std::string& searchTerm, int page, int pageSize, 
           std::vector<MarketplaceEntry>& results) {
    results.clear();
    
    HINTERNET hSession = WinHttpOpen(L"RawrXD-IDE/1.0", 
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return false;
    
    // Microsoft Marketplace API endpoint
    HINTERNET hConnect = WinHttpConnect(hSession, 
        L"marketplace.visualstudio.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    std::wstring path = L"/_apis/public/gallery/extensionquery";
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(), 
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 
        WINHTTP_FLAG_SECURE);
    
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    // Simplified query - real implementation would build proper JSON
    std::string body = "{\"filters\":[{\"criteria\":[{\"filterType\":8,\"value\":\"" + 
                       searchTerm + "\"}],\"pageNumber\":" + std::to_string(page) + 
                       ",\"pageSize\":" + std::to_string(pageSize) + "}]}";
    
    std::wstring headers = L"Content-Type: application/json\r\nAccept: application/json;api-version=3.0-preview.1";
    BOOL bResults = WinHttpSendRequest(hRequest, headers.c_str(), -1, 
        (LPVOID)body.c_str(), (DWORD)body.length(), (DWORD)body.length(), 0);
    if (!bResults || !WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD statusCode = 0;
    if (!getStatusCode(hRequest, statusCode) || statusCode < 200 || statusCode >= 300) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::string responseBody;
    if (!readAllResponse(hRequest, responseBody) || responseBody.empty()) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // Minimal fail-closed extraction without fabricating placeholder entries.
    MarketplaceEntry entry;
    entry.name = extractJsonString(responseBody, "extensionName");
    entry.publisher = extractJsonString(responseBody, "publisherName");
    entry.version = extractJsonString(responseBody, "version");
    entry.description = extractJsonString(responseBody, "shortDescription");
    entry.downloadUrl.clear();
    entry.installCount = 0;
    entry.rating = 0.0f;

    if (!entry.name.empty() && !entry.publisher.empty()) {
        results.push_back(entry);
    }
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return !results.empty();
}

bool DownloadVsix(const std::string& publisher, const std::string& extName, 
                  const std::string& version, const std::string& destPath) {
    std::wstring wPublisher = utf8ToWide(publisher);
    std::wstring wExtName = utf8ToWide(extName);
    std::wstring wVersion = utf8ToWide(version);
    if (wPublisher.empty() || wExtName.empty() || wVersion.empty()) {
        return false;
    }
    
    HINTERNET hSession = WinHttpOpen(L"RawrXD-IDE/1.0", 
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return false;
        
    HINTERNET hConnect = WinHttpConnect(hSession, L"marketplace.visualstudio.com", 
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    std::wstring path = L"/_apis/public/gallery/publishers/" + wPublisher + 
                        L"/vsextensions/" + wExtName + L"/" + wVersion + 
                        L"/vspackage";
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(),
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD statusCode = 0;
    if (!getStatusCode(hRequest, statusCode) || statusCode < 200 || statusCode >= 300) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    std::ofstream outFile(destPath, std::ios::binary);
    if (!outFile) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    bool wroteAny = false;
    DWORD dwSize = 0;
    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            break;
        }
        if (dwSize == 0) break;
        
        std::vector<BYTE> buffer(dwSize);
        DWORD dwDownloaded = 0;
        if (!WinHttpReadData(hRequest, (LPVOID)buffer.data(), dwSize, &dwDownloaded)) {
            break;
        }
        outFile.write((char*)buffer.data(), dwDownloaded);
        wroteAny = wroteAny || (dwDownloaded > 0);
    } while (dwSize > 0);
    
    outFile.close();
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return wroteAny;
}

} // namespace VSCodeMarketplace
