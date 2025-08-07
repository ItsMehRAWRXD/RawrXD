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
};