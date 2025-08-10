#include <windows.h>
#include <wininet.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>

#pragma comment(lib, "wininet.lib")

// ===============================================================================
// GITHUB INTEGRATION TESTER
// ===============================================================================

class GitHubTester {
private:
    std::string user_agent = "FUD-System-Tester/1.0";
    
public:
    // Test GitHub API to fetch .c files
    bool testGitHubAPI(const std::string& username, const std::string& repo) {
        std::cout << "Testing GitHub API for: " << username << "/" << repo << std::endl;
        
        std::string api_url = "https://api.github.com/repos/" + username + "/" + repo + "/contents";
        
        std::vector<std::string> c_files = fetchGitHubContents(api_url);
        
        if (c_files.empty()) {
            std::cout << "❌ No .c files found or API failed" << std::endl;
            return false;
        }
        
        std::cout << "✅ Found " << c_files.size() << " .c files:" << std::endl;
        for (const auto& file : c_files) {
            std::cout << "   - " << file << std::endl;
        }
        
        // Test downloading and compiling the first .c file
        if (!c_files.empty()) {
            return testCompileFile(username, repo, c_files[0]);
        }
        
        return true;
    }
    
    // Fetch contents from GitHub API
    std::vector<std::string> fetchGitHubContents(const std::string& url) {
        std::vector<std::string> c_files;
        
        HINTERNET hInternet = InternetOpenA(user_agent.c_str(), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (!hInternet) {
            std::cout << "Failed to initialize WinINet" << std::endl;
            return c_files;
        }
        
        HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
        if (!hConnect) {
            std::cout << "Failed to connect to GitHub API" << std::endl;
            InternetCloseHandle(hInternet);
            return c_files;
        }
        
        std::string response;
        char buffer[1024];
        DWORD bytesRead;
        
        while (InternetReadFile(hConnect, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            response += buffer;
        }
        
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        
        // Parse JSON response (simplified)
        if (response.find("\"name\"") != std::string::npos) {
            // Extract .c files from response
            size_t pos = 0;
            while ((pos = response.find("\"name\":\"", pos)) != std::string::npos) {
                pos += 8;
                size_t end = response.find("\"", pos);
                if (end != std::string::npos) {
                    std::string filename = response.substr(pos, end - pos);
                    if (filename.length() > 2 && filename.substr(filename.length() - 2) == ".c") {
                        c_files.push_back(filename);
                    }
                }
            }
        }
        
        return c_files;
    }
    
    // Test downloading and compiling a specific .c file
    bool testCompileFile(const std::string& username, const std::string& repo, const std::string& filename) {
        std::cout << "\nTesting compilation of: " << filename << std::endl;
        
        std::string raw_url = "https://raw.githubusercontent.com/" + username + "/" + repo + "/main/" + filename;
        std::string local_path = "test_" + filename;
        
        if (!downloadFile(raw_url, local_path)) {
            std::cout << "❌ Failed to download " << filename << std::endl;
            return false;
        }
        
        std::cout << "✅ Downloaded " << filename << " successfully" << std::endl;
        
        // Test compilation with MinGW
        if (testMinGWCompilation(local_path)) {
            std::cout << "✅ MinGW compilation successful" << std::endl;
        } else {
            std::cout << "❌ MinGW compilation failed" << std::endl;
        }
        
        // Test compilation with MSVC
        if (testMSVCCompilation(local_path)) {
            std::cout << "✅ MSVC compilation successful" << std::endl;
        } else {
            std::cout << "❌ MSVC compilation failed" << std::endl;
        }
        
        // Clean up
        DeleteFileA(local_path.c_str());
        
        return true;
    }
    
    // Download file from URL
    bool downloadFile(const std::string& url, const std::string& local_path) {
        HINTERNET hInternet = InternetOpenA(user_agent.c_str(), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (!hInternet) return false;
        
        HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
        if (!hConnect) {
            InternetCloseHandle(hInternet);
            return false;
        }
        
        std::ofstream file(local_path, std::ios::binary);
        if (!file.is_open()) {
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return false;
        }
        
        char buffer[1024];
        DWORD bytesRead;
        bool success = false;
        
        while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
            file.write(buffer, bytesRead);
            success = true;
        }
        
        file.close();
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        
        return success;
    }
    
    // Test MinGW compilation
    bool testMinGWCompilation(const std::string& file_path) {
        std::string command = "i686-w64-mingw32-gcc -o test_mingw.exe " + file_path + " -lkernel32 -luser32 -lshell32 -ladvapi32 -static";
        
        STARTUPINFOA si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        
        if (CreateProcessA(NULL, const_cast<char*>(command.c_str()), NULL, NULL, FALSE, 
                          CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 10000); // Wait up to 10 seconds
            
            DWORD exitCode;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            
            DeleteFileA("test_mingw.exe");
            return exitCode == 0;
        }
        
        return false;
    }
    
    // Test MSVC compilation
    bool testMSVCCompilation(const std::string& file_path) {
        std::string command = "cl /Fe:test_msvc.exe " + file_path + " kernel32.lib user32.lib shell32.lib advapi32.lib";
        
        STARTUPINFOA si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        
        if (CreateProcessA(NULL, const_cast<char*>(command.c_str()), NULL, NULL, FALSE, 
                          CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 10000); // Wait up to 10 seconds
            
            DWORD exitCode;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            
            DeleteFileA("test_msvc.exe");
            return exitCode == 0;
        }
        
        return false;
    }
    
    // Test specific GitHub repositories
    void testKnownRepos() {
        std::vector<std::pair<std::string, std::string>> repos = {
            {"your-username", "your-repo"},  // Replace with actual username/repo
            {"microsoft", "vcpkg"},
            {"torvalds", "linux"},
            {"openssl", "openssl"}
        };
        
        for (const auto& repo : repos) {
            std::cout << "\n===============================================================================" << std::endl;
            std::cout << "Testing: " << repo.first << "/" << repo.second << std::endl;
            std::cout << "===============================================================================" << std::endl;
            
            testGitHubAPI(repo.first, repo.second);
            
            Sleep(1000); // Rate limiting
        }
    }
};

int main() {
    std::cout << "===============================================================================" << std::endl;
    std::cout << "GITHUB INTEGRATION TESTER" << std::endl;
    std::cout << "===============================================================================" << std::endl;
    
    GitHubTester tester;
    
    // Test with your GitHub username and repo
    std::string username, repo;
    
    std::cout << "Enter your GitHub username: ";
    std::getline(std::cin, username);
    
    std::cout << "Enter your repository name: ";
    std::getline(std::cin, repo);
    
    if (!username.empty() && !repo.empty()) {
        tester.testGitHubAPI(username, repo);
    } else {
        std::cout << "Testing known repositories..." << std::endl;
        tester.testKnownRepos();
    }
    
    std::cout << "\n===============================================================================" << std::endl;
    std::cout << "TEST COMPLETE" << std::endl;
    std::cout << "===============================================================================" << std::endl;
    
    return 0;
}