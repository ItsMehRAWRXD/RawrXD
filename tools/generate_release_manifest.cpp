#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <filesystem>
#include <json/json.h>
#include <vector>
#include <algorithm>

namespace fs = std::filesystem;

// Function to get current timestamp
std::string getCurrentTimestamp() {
    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

// Function to get git commit hash
std::string getGitCommitHash() {
    std::string result;
    std::array<char, 128> buffer;
    std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen("git rev-parse HEAD", "r"), _pclose);
    if (!pipe) {
        return "unknown";
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    // Remove newline
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }
    return result.empty() ? "unknown" : result;
}

// Function to get git branch
std::string getGitBranch() {
    std::string result;
    std::array<char, 128> buffer;
    std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen("git rev-parse --abbrev-ref HEAD", "r"), _pclose);
    if (!pipe) {
        return "unknown";
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    // Remove newline
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }
    return result.empty() ? "unknown" : result;
}

// Function to calculate file hash (SHA-256)
std::string calculateFileHash(const std::string& filePath) {
    // In a real implementation, we would use a cryptographic library like OpenSSL or Crypto++
    // For this example, we'll return a placeholder
    return "placeholder_hash_" + std::to_string(std::hash<std::string>{}(filePath));
}

// Function to get compiler information
std::string getCompilerInfo() {
#if defined(_MSC_VER)
    return "MSVC " + std::to_string(_MSC_VER);
#elif defined(__GNUC__)
    return "GCC " + std::to_string(__GNUC__) + "." + std::to_string(__GNUC_MINOR__);
#elif defined(__clang__)
    return "Clang " + std::to_string(__clang_major__) + "." + std::to_string(__clang_minor__);
#else
    return "Unknown Compiler";
#endif
}

// Function to get build configuration
std::string getBuildConfig() {
#ifdef _DEBUG
    return "Debug";
#else
    return "Release";
#endif
}

// Function to get target architecture
std::string getTargetArchitecture() {
#if defined(_M_X64) || defined(__x86_64__)
    return "x86_64";
#elif defined(_M_X86) || defined(__i386__)
    return "x86";
#elif defined(_M_ARM64) || defined(__aarch64__)
    return "arm64";
#else
    return "unknown";
#endif
}

// Function to collect binary files
std::vector<std::string> getBinaryFiles(const std::string& directory) {
    std::vector<std::string> files;
    try {
        for (const auto& entry : fs::recursive_directory_iterator(directory)) {
            if (entry.is_regular_file()) {
                std::string ext = entry.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                if (ext == ".exe" || ext == ".dll" || ext == ".so" || ext == ".dylib") {
                    files.push_back(entry.path().string());
                }
            }
        }
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Error scanning directory: " << e.what() << std::endl;
    }
    return files;
}

// Function to collect model files
std::vector<std::string> getModelFiles(const std::string& directory) {
    std::vector<std::string> files;
    try {
        for (const auto& entry : fs::recursive_directory_iterator(directory)) {
            if (entry.is_regular_file()) {
                std::string ext = entry.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                if (ext == ".gguf" || ext == ".ggml" || ext == ".bin") {
                    files.push_back(entry.path().string());
                }
            }
        }
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Error scanning directory: " << e.what() << std::endl;
    }
    return files;
}

int main() {
    Json::Value manifest;
    
    // Basic build information
    manifest["version"] = "15.0.0";
    manifest["build_timestamp"] = getCurrentTimestamp();
    manifest["git_commit"] = getGitCommitHash();
    manifest["git_branch"] = getGitBranch();
    manifest["compiler"] = getCompilerInfo();
    manifest["build_configuration"] = getBuildConfig();
    manifest["target_architecture"] = getTargetArchitecture();
    
    // File hashes
    Json::Value binaryHashes(Json::objectValue);
    Json::Value modelHashes(Json::objectValue);
    
    // Get binary files from bin directory
    auto binaryFiles = getBinaryFiles("bin");
    for (const auto& file : binaryFiles) {
        std::string filename = fs::path(file).filename().string();
        binaryHashes[filename] = calculateFileHash(file);
    }
    
    // Get binary files from runtime directory
    auto runtimeFiles = getBinaryFiles("runtime");
    for (const auto& file : runtimeFiles) {
        std::string filename = fs::path(file).filename().string();
        binaryHashes[filename] = calculateFileHash(file);
    }
    
    // Get model files
    auto modelFiles = getModelFiles("models");
    for (const auto& file : modelFiles) {
        std::string filename = fs::path(file).filename().string();
        modelHashes[filename] = calculateFileHash(file);
    }
    
    manifest["binary_hashes"] = binaryHashes;
    manifest["model_hashes"] = modelHashes;
    
    // Write manifest to file
    std::ofstream outFile("evidence/rc0.2/release_manifest.json");
    if (!outFile.is_open()) {
        std::cerr << "Failed to open output file!" << std::endl;
        return 1;
    }
    
    Json::StreamWriterBuilder writer;
    writer["indentation"] = "  ";
    std::string output = Json::writeString(writer, manifest);
    outFile << output;
    outFile.close();
    
    std::cout << "Release manifest generated successfully at evidence/rc0.2/release_manifest.json" << std::endl;
    return 0;
}