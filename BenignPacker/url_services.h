#pragma once

#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <cstdint>

#ifdef _WIN32
#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")
#else
#include <cstdlib>
#endif

class URLServices {
private:
    // Download file from URL (Windows implementation)
#ifdef _WIN32
    bool downloadFileWindows(const std::string& url, std::vector<uint8_t>& data) {
        HINTERNET hInternet = InternetOpenA("VS2022 PE Packer/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (!hInternet) return false;

        HINTERNET hUrl = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
        if (!hUrl) {
            InternetCloseHandle(hInternet);
            return false;
        }

        DWORD bytesRead = 0;
        BYTE buffer[4096];
        data.clear();

        while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
            data.insert(data.end(), buffer, buffer + bytesRead);
        }

        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        return !data.empty();
    }
#else
    // Linux implementation using wget or curl
    bool downloadFileLinux(const std::string& url, std::vector<uint8_t>& data) {
        std::string tempFile = "/tmp/url_download_" + std::to_string(getpid()) + ".tmp";
        std::string cmd = "wget -q -O \"" + tempFile + "\" \"" + url + "\" 2>/dev/null || curl -s -o \"" + tempFile + "\" \"" + url + "\"";
        
        int result = system(cmd.c_str());
        if (result != 0) return false;

        std::ifstream file(tempFile, std::ios::binary);
        if (!file) {
            unlink(tempFile.c_str());
            return false;
        }

        data = std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        unlink(tempFile.c_str());
        
        return !data.empty();
    }
#endif

public:
    // Main download function
    bool downloadFile(const std::string& url, std::vector<uint8_t>& data) {
#ifdef _WIN32
        return downloadFileWindows(url, data);
#else
        return downloadFileLinux(url, data);
#endif
    }

    // Download and save to file
    bool downloadToFile(const std::string& url, const std::string& outputPath) {
        std::vector<uint8_t> data;
        if (!downloadFile(url, data)) {
            return false;
        }

        std::ofstream outFile(outputPath, std::ios::binary);
        if (!outFile) {
            return false;
        }

        outFile.write(reinterpret_cast<const char*>(data.data()), data.size());
        outFile.close();
        return true;
    }

    // Get filename from URL
    std::string getFilenameFromURL(const std::string& url) {
        size_t lastSlash = url.find_last_of('/');
        if (lastSlash != std::string::npos && lastSlash < url.length() - 1) {
            std::string filename = url.substr(lastSlash + 1);
            
            // Remove query parameters if present
            size_t queryPos = filename.find('?');
            if (queryPos != std::string::npos) {
                filename = filename.substr(0, queryPos);
            }
            
            // If no extension, add .bin
            if (filename.find('.') == std::string::npos) {
                filename += ".bin";
            }
            
            return filename;
        }
        return "download.bin";
    }

    // Check if URL is valid
    bool isValidURL(const std::string& url) {
        return (url.substr(0, 7) == "http://" || url.substr(0, 8) == "https://");
    }

    // Upload file to URL
    bool uploadFile(const std::string& url, const std::vector<uint8_t>& data, 
                    const std::string& filename = "upload.bin") {
#ifdef _WIN32
        return uploadFileWindows(url, data, filename);
#else
        return uploadFileLinux(url, data, filename);
#endif
    }

private:
#ifdef _WIN32
    // Windows upload implementation
    bool uploadFileWindows(const std::string& url, const std::vector<uint8_t>& data,
                          const std::string& filename) {
        HINTERNET hInternet = InternetOpenA("VS2022 Encryptor/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (!hInternet) return false;

        // Parse URL to get host and path
        URL_COMPONENTSA urlComp = {0};
        urlComp.dwStructSize = sizeof(urlComp);
        char hostName[256] = {0};
        char urlPath[1024] = {0};
        urlComp.lpszHostName = hostName;
        urlComp.dwHostNameLength = sizeof(hostName);
        urlComp.lpszUrlPath = urlPath;
        urlComp.dwUrlPathLength = sizeof(urlPath);
        
        if (!InternetCrackUrlA(url.c_str(), 0, 0, &urlComp)) {
            InternetCloseHandle(hInternet);
            return false;
        }

        // Connect to server
        HINTERNET hConnect = InternetConnectA(hInternet, hostName, 
            urlComp.nPort ? urlComp.nPort : (urlComp.nScheme == INTERNET_SCHEME_HTTPS ? 443 : 80),
            NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        if (!hConnect) {
            InternetCloseHandle(hInternet);
            return false;
        }

        // Create multipart/form-data boundary
        std::string boundary = "----BoundaryString" + std::to_string(GetTickCount());
        
        // Build request body
        std::stringstream body;
        body << "--" << boundary << "\r\n";
        body << "Content-Disposition: form-data; name=\"file\"; filename=\"" << filename << "\"\r\n";
        body << "Content-Type: application/octet-stream\r\n\r\n";
        std::string prefix = body.str();
        
        std::string suffix = "\r\n--" + boundary + "--\r\n";
        
        // Calculate total size
        DWORD totalSize = prefix.length() + data.size() + suffix.length();

        // Create request
        DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? INTERNET_FLAG_SECURE : 0;
        HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", urlPath, NULL, NULL, NULL, flags, 0);
        if (!hRequest) {
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return false;
        }

        // Add headers
        std::string contentType = "Content-Type: multipart/form-data; boundary=" + boundary;
        HttpAddRequestHeadersA(hRequest, contentType.c_str(), -1, HTTP_ADDREQ_FLAG_ADD);

        // Send request
        INTERNET_BUFFERSA bufferIn = {0};
        bufferIn.dwStructSize = sizeof(INTERNET_BUFFERSA);
        bufferIn.dwBufferTotal = totalSize;

        if (!HttpSendRequestExA(hRequest, &bufferIn, NULL, 0, 0)) {
            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return false;
        }

        // Write data
        DWORD bytesWritten;
        InternetWriteFile(hRequest, prefix.c_str(), prefix.length(), &bytesWritten);
        InternetWriteFile(hRequest, data.data(), data.size(), &bytesWritten);
        InternetWriteFile(hRequest, suffix.c_str(), suffix.length(), &bytesWritten);

        // End request
        if (!HttpEndRequestA(hRequest, NULL, 0, 0)) {
            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return false;
        }

        // Check response
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                      &statusCode, &statusSize, NULL);

        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);

        return (statusCode >= 200 && statusCode < 300);
    }
#else
    // Linux upload implementation using curl
    bool uploadFileLinux(const std::string& url, const std::vector<uint8_t>& data,
                        const std::string& filename) {
        // Save data to temporary file
        std::string tempFile = "/tmp/upload_" + std::to_string(getpid()) + ".tmp";
        std::ofstream outFile(tempFile, std::ios::binary);
        if (!outFile) return false;
        
        outFile.write(reinterpret_cast<const char*>(data.data()), data.size());
        outFile.close();

        // Use curl to upload
        std::string cmd = "curl -s -o /dev/null -w \"%{http_code}\" -F \"file=@" + tempFile + 
                         ";filename=" + filename + "\" \"" + url + "\"";
        
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) {
            unlink(tempFile.c_str());
            return false;
        }

        char buffer[128];
        std::string result = "";
        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            result += buffer;
        }
        
        int exitCode = pclose(pipe);
        unlink(tempFile.c_str());

        // Check if status code is 2xx
        try {
            int statusCode = std::stoi(result);
            return (statusCode >= 200 && statusCode < 300);
        } catch (...) {
            return false;
        }
    }
#endif

public:
    // Upload file from disk
    bool uploadFileFromDisk(const std::string& url, const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return false;

        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), 
                                 std::istreambuf_iterator<char>());
        file.close();

        std::string filename = filePath.substr(filePath.find_last_of("/\\") + 1);
        return uploadFile(url, data, filename);
    }

    // Popular file hosting services support
    struct FileHostingService {
        std::string name;
        std::string uploadEndpoint;
        size_t maxFileSize;
    };

    std::vector<FileHostingService> getFileHostingServices() {
        return {
            {"AnonFiles", "https://api.anonfiles.com/upload", 20 * 1024 * 1024}, // 20MB
            {"File.io", "https://file.io", 100 * 1024 * 1024}, // 100MB
            {"Transfer.sh", "https://transfer.sh", 10 * 1024 * 1024 * 1024LL}, // 10GB
            {"GoFile", "https://store1.gofile.io/uploadFile", 5 * 1024 * 1024 * 1024LL}, // 5GB
            {"WeTransfer", "https://wetransfer.com/api/v4/transfers", 2 * 1024 * 1024 * 1024LL} // 2GB
        };
    }
};