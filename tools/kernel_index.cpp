// ============================================================================
// Kernel Index Generator
// Walks source tree, finds KERNEL_COMPLETE tags, generates markdown inventory
// ============================================================================

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <regex>
#include <algorithm>
#include <chrono>

namespace fs = std::filesystem;

// ============================================================================
// Kernel Info Structure
// ============================================================================
struct KernelInfo {
    std::string name;
    std::string file;
    int line;
    std::string type;      // MASM, C++, Vulkan
    std::string language;
    std::string category;  // Gemm, Attention, etc
};

// ============================================================================
// Category Detection
// ============================================================================
std::string DetectCategory(const std::string& kernelName, const std::string& filePath) {
    std::string upperName = kernelName;
    std::string upperFile = filePath;
    std::transform(upperName.begin(), upperName.end(), upperName.begin(), ::toupper);
    std::transform(upperFile.begin(), upperFile.end(), upperFile.begin(), ::toupper);
    
    // Check kernel name patterns
    if (upperName.find("GEMM") != std::string::npos || 
        upperName.find("MATMUL") != std::string::npos) return "GEMM";
    if (upperName.find("ATTENTION") != std::string::npos ||
        upperName.find("ATTN") != std::string::npos) return "Attention";
    if (upperName.find("RMSNORM") != std::string::npos ||
        upperName.find("NORM") != std::string::npos) return "RMSNorm";
    if (upperName.find("SOFTMAX") != std::string::npos) return "Softmax";
    if (upperName.find("DMA") != std::string::npos ||
        upperName.find("SDMA") != std::string::npos) return "DMA";
    if (upperName.find("NF4") != std::string::npos ||
        upperName.find("QUANT") != std::string::npos ||
        upperName.find("Q4") != std::string::npos ||
        upperName.find("Q8") != std::string::npos) return "Quantization";
    if (upperName.find("MEDUSA") != std::string::npos ||
        upperName.find("SPECULATIVE") != std::string::npos) return "Speculative";
    if (upperName.find("FLASH") != std::string::npos) return "FlashAttention";
    if (upperName.find("KV") != std::string::npos ||
        upperName.find("KV_CACHE") != std::string::npos) return "KVCache";
    if (upperName.find("SILU") != std::string::npos ||
        upperName.find("ACTIVATION") != std::string::npos) return "Activation";
    if (upperName.find("ROPE") != std::string::npos) return "RoPE";
    if (upperName.find("TRANSFORMER") != std::string::npos) return "Transformer";
    if (upperName.find("INFERENCE") != std::string::npos) return "Inference";
    
    // Check file path patterns
    if (upperFile.find("AVX2") != std::string::npos) return "AVX2";
    if (upperFile.find("AVX512") != std::string::npos ||
        upperFile.find("AVX-512") != std::string::npos) return "AVX-512";
    if (upperFile.find("RDNA3") != std::string::npos) return "RDNA3";
    if (upperFile.find("GPU") != std::string::npos) return "GPU";
    if (upperFile.find("MASM") != std::string::npos) return "MASM";
    
    return "Other";
}

// ============================================================================
// File Extension to Type Mapping
// ============================================================================
std::string GetFileType(const std::string& extension) {
    if (extension == ".asm") return "MASM";
    if (extension == ".cpp" || extension == ".hpp" || extension == ".h") return "C++";
    if (extension == ".spv" || extension == ".comp" || extension == ".glsl") return "Vulkan";
    return "Unknown";
}

std::string GetLanguage(const std::string& extension) {
    if (extension == ".asm") return "MASM64";
    if (extension == ".cpp" || extension == ".hpp" || extension == ".h") return "C++17";
    if (extension == ".spv") return "SPIR-V";
    if (extension == ".comp" || extension == ".glsl") return "GLSL";
    return "Unknown";
}

// ============================================================================
// Scan File for KERNEL_COMPLETE Tags
// ============================================================================
std::vector<KernelInfo> ScanFile(const fs::path& filePath, const fs::path& rootPath) {
    std::vector<KernelInfo> kernels;
    
    std::ifstream file(filePath);
    if (!file.is_open()) return kernels;
    
    std::string line;
    int lineNum = 0;
    std::regex kernelPattern(R"((?:\/\/|;|#)\s*KERNEL_COMPLETE:\s*(\S+))");
    
    while (std::getline(file, line)) {
        lineNum++;
        std::smatch match;
        if (std::regex_search(line, match, kernelPattern)) {
            KernelInfo info;
            info.name = match[1];
            info.file = fs::relative(filePath, rootPath).string();
            info.line = lineNum;
            info.type = GetFileType(filePath.extension().string());
            info.language = GetLanguage(filePath.extension().string());
            info.category = DetectCategory(info.name, info.file);
            kernels.push_back(info);
        }
    }
    
    return kernels;
}

// ============================================================================
// Generate Markdown Inventory
// ============================================================================
void GenerateInventory(const std::vector<KernelInfo>& kernels, const std::string& outputPath) {
    std::ofstream md(outputPath);
    if (!md.is_open()) {
        std::cerr << "Failed to create output file: " << outputPath << std::endl;
        return;
    }
    
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    
    // Header
    md << "# RawrXD Kernel Inventory\n\n";
    md << "**Generated:** " << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S") << "\n";
    md << "**Total Kernels:** " << kernels.size() << "\n\n";
    
    // Summary table
    md << "## Summary\n\n";
    md << "| Category | Count |\n";
    md << "|----------|-------|\n";
    
    std::map<std::string, int> categoryCounts;
    std::map<std::string, int> typeCounts;
    for (const auto& k : kernels) {
        categoryCounts[k.category]++;
        typeCounts[k.type]++;
    }
    
    for (const auto& [cat, count] : categoryCounts) {
        md << "| " << cat << " | " << count << " |\n";
    }
    md << "\n";
    
    // By Type
    md << "## By Type\n\n";
    md << "| Type | Count |\n";
    md << "|------|-------|\n";
    for (const auto& [type, count] : typeCounts) {
        md << "| " << type << " | " << count << " |\n";
    }
    md << "\n";
    
    // All Kernels
    md << "## Complete Kernel List\n\n";
    md << "| Kernel | File | Line | Type | Category |\n";
    md << "|--------|------|------|------|----------|\n";
    
    auto sortedKernels = kernels;
    std::sort(sortedKernels.begin(), sortedKernels.end(), 
              [](const KernelInfo& a, const KernelInfo& b) {
                  return a.category < b.category || (a.category == b.category && a.name < b.name);
              });
    
    for (const auto& k : sortedKernels) {
        md << "| `" << k.name << "` | `" << k.file << "` | " << k.line 
           << " | " << k.type << " | " << k.category << " |\n";
    }
    md << "\n";
    
    // By Category Detail
    md << "## By Category\n\n";
    std::string currentCategory;
    for (const auto& k : sortedKernels) {
        if (k.category != currentCategory) {
            currentCategory = k.category;
            md << "### " << currentCategory << "\n\n";
        }
        md << "- **" << k.name << "** (`" << k.file << ":" << k.line << "`) - " << k.language << "\n";
    }
    md << "\n";
    
    // Tagging guide
    md << "## Tagging Convention\n\n";
    md << "To mark a kernel as complete, add this comment:\n\n";
    md << "**C++:**\n";
    md << "```cpp\n";
    md << "// KERNEL_COMPLETE: Kernel_Name_Here\n";
    md << "void Kernel_Name_Here(...) { }\n";
    md << "```\n\n";
    md << "**MASM:**\n";
    md << "```asm\n";
    md << "; KERNEL_COMPLETE: Kernel_Name_Here\n";
    md << "Kernel_Name_Here PROC\n";
    md << "    ...\n";
    md << "Kernel_Name_Here ENDP\n";
    md << "```\n\n";
    
    md << "---\n";
    md << "*Auto-generated by kernel_index tool*\n";
    
    std::cout << "Inventory written to: " << outputPath << std::endl;
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char* argv[]) {
    std::string rootPath = (argc > 1) ? argv[1] : ".";
    std::string outputPath = (argc > 2) ? argv[2] : "KERNEL_INVENTORY.md";
    
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD Kernel Index Generator" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Root: " << fs::absolute(rootPath) << std::endl;
    std::cout << "Output: " << outputPath << std::endl;
    std::cout << std::endl;
    
    std::vector<KernelInfo> allKernels;
    int filesScanned = 0;
    
    // Supported extensions
    std::vector<std::string> extensions = {".cpp", ".hpp", ".h", ".asm", ".comp", ".glsl"};
    
    try {
        for (const auto& entry : fs::recursive_directory_iterator(rootPath)) {
            if (!entry.is_regular_file()) continue;
            
            std::string ext = entry.path().extension().string();
            if (std::find(extensions.begin(), extensions.end(), ext) == extensions.end()) continue;
            
            // Skip history directories
            std::string pathStr = entry.path().string();
            if (pathStr.find("history\\all_versions") != std::string::npos) continue;
            if (pathStr.find(".git") != std::string::npos) continue;
            if (pathStr.find("build") != std::string::npos) continue;
            
            filesScanned++;
            auto kernels = ScanFile(entry.path(), rootPath);
            allKernels.insert(allKernels.end(), kernels.begin(), kernels.end());
        }
    } catch (const std::exception& e) {
        std::cerr << "Warning: " << e.what() << std::endl;
    }
    
    std::cout << "Scanned " << filesScanned << " files" << std::endl;
    std::cout << "Found " << allKernels.size() << " completed kernels" << std::endl;
    std::cout << std::endl;
    
    if (!allKernels.empty()) {
        GenerateInventory(allKernels, outputPath);
    } else {
        std::cout << "No kernels found. Add KERNEL_COMPLETE tags to your source files." << std::endl;
    }
    
    return 0;
}
