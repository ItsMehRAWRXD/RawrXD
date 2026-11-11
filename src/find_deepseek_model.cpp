// ============================================================================
// find_deepseek_model.cpp - Locates DeepSeek-V3.1 671B model file
// ============================================================================

#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <cstdint>

namespace fs = std::filesystem;

// GGUF magic number
static constexpr uint32_t GGUF_MAGIC = 0x46554747; // "GGUF"

bool isGGUFFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    
    uint32_t magic = 0;
    file.read(reinterpret_cast<char*>(&magic), 4);
    return magic == GGUF_MAGIC;
}

void scanDirectory(const fs::path& dir, std::vector<std::string>& foundModels, int maxDepth = 3, int currentDepth = 0) {
    if (currentDepth > maxDepth) return;
    
    try {
        for (const auto& entry : fs::directory_iterator(dir, fs::directory_options::skip_permission_denied)) {
            if (entry.is_regular_file()) {
                auto ext = entry.path().extension().string();
                auto name = entry.path().filename().string();
                
                // Check for GGUF files
                if (ext == ".gguf" || name.find(".gguf") != std::string::npos) {
                    auto sizeGB = entry.file_size() / (1024.0 * 1024.0 * 1024.0);
                    std::cout << "  Found: " << entry.path().string() 
                              << " (" << sizeGB << " GB)" << std::endl;
                    
                    if (isGGUFFile(entry.path().string())) {
                        std::cout << "    -> Valid GGUF file!" << std::endl;
                        foundModels.push_back(entry.path().string());
                    }
                }
                
                // Check for Ollama blob files (large files with sha256 prefix)
                if (name.find("sha256-") == 0 && entry.file_size() > 1ULL * 1024 * 1024 * 1024) {
                    auto sizeGB = entry.file_size() / (1024.0 * 1024.0 * 1024.0);
                    std::cout << "  Found blob: " << entry.path().string() 
                              << " (" << sizeGB << " GB)" << std::endl;
                    
                    if (isGGUFFile(entry.path().string())) {
                        std::cout << "    -> Valid GGUF file!" << std::endl;
                        foundModels.push_back(entry.path().string());
                    }
                }
            } else if (entry.is_directory() && currentDepth < maxDepth) {
                scanDirectory(entry.path(), foundModels, maxDepth, currentDepth + 1);
            }
        }
    } catch (const std::exception& e) {
        // Skip directories we can't access
    }
}

int main(int argc, char* argv[]) {
    std::cout << "============================================================" << std::endl;
    std::cout << "  DeepSeek-V3.1 671B Model Locator" << std::endl;
    std::cout << "============================================================" << std::endl;
    std::cout << std::endl;
    
    std::vector<std::string> searchPaths;
    
    if (argc > 1) {
        // Use provided paths
        for (int i = 1; i < argc; i++) {
            searchPaths.push_back(argv[i]);
        }
    } else {
        // Default search paths
        searchPaths = {
            "D:\\",
            "F:\\",
            "G:\\",
            "D:\\rawrxd",
            "F:\\OllamaModels",
            "D:\\models",
            "F:\\models"
        };
    }
    
    std::vector<std::string> foundModels;
    
    for (const auto& path : searchPaths) {
        if (!fs::exists(path)) {
            std::cout << "[SKIP] Path does not exist: " << path << std::endl;
            continue;
        }
        
        std::cout << "[SCANNING] " << path << std::endl;
        
        if (fs::is_regular_file(path)) {
            // Single file check
            if (isGGUFFile(path)) {
                std::cout << "  -> Valid GGUF file!" << std::endl;
                foundModels.push_back(path);
            }
        } else if (fs::is_directory(path)) {
            scanDirectory(path, foundModels);
        }
        
        std::cout << std::endl;
    }
    
    std::cout << "============================================================" << std::endl;
    std::cout << "  Results" << std::endl;
    std::cout << "============================================================" << std::endl;
    
    if (foundModels.empty()) {
        std::cout << "No GGUF model files found." << std::endl;
        std::cout << std::endl;
        std::cout << "Please provide the path to your DeepSeek-V3.1 model file:" << std::endl;
        std::cout << "  find_deepseek_model.exe <path_to_model>" << std::endl;
        return 1;
    }
    
    std::cout << "Found " << foundModels.size() << " GGUF model(s):" << std::endl;
    std::cout << std::endl;
    
    for (size_t i = 0; i < foundModels.size(); i++) {
        std::cout << "  [" << (i + 1) << "] " << foundModels[i] << std::endl;
    }
    
    std::cout << std::endl;
    std::cout << "To test with PrometheusMoE:" << std::endl;
    std::cout << "  test_deepseek_v3_1_moe.exe \"" << foundModels[0] << "\"" << std::endl;
    
    return 0;
}
