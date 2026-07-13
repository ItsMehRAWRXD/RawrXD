/**
 * @file diagnose_simple.cpp
 * @brief Simple memory diagnostic - standalone version
 */

#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>

// Minimal GGUF structures
static constexpr uint32_t GGUF_MAGIC = 0x46554747;

struct TensorInfo {
    std::string name;
    std::vector<uint64_t> shape;
    uint32_t type;
    uint64_t offset;
    
    uint64_t GetNumElements() const {
        uint64_t n = 1;
        for (auto d : shape) n *= d;
        return n;
    }
};

std::string FormatBytes(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = static_cast<double>(bytes);
    while (size >= 1024.0 && unit < 4) {
        size /= 1024.0;
        unit++;
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "%.2f %s", size, units[unit]);
    return std::string(buf);
}

std::string GetTypeName(uint32_t type) {
    switch (type) {
        case 0: return "F32";
        case 1: return "F16";
        case 2: return "Q4_0";
        case 3: return "Q4_1";
        case 6: return "Q5_0";
        case 7: return "Q5_1";
        case 8: return "Q8_0";
        case 9: return "Q8_1";
        case 10: return "Q2_K";
        case 11: return "Q3_K";
        case 12: return "Q4_K";
        case 13: return "Q5_K";
        case 14: return "Q6_K";
        case 15: return "Q8_K";
        default: return "UNKNOWN";
    }
}

bool IsQuantized(uint32_t type) {
    return type >= 2;
}

int main(int argc, char* argv[]) {
    std::cout << "========================================\n";
    std::cout << "RawrXD Memory Diagnostic (Simple)\n";
    std::cout << "========================================\n\n";
    
    std::string model_path = (argc > 1) ? argv[1] : "d:\\rawrxd\\src\\codestral22b.gguf";
    std::cout << "Model: " << model_path << "\n\n";
    
    std::ifstream file(model_path, std::ios::binary);
    if (!file) {
        std::cerr << "ERROR: Cannot open model file\n";
        return 1;
    }
    
    // Read header
    uint32_t magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    if (magic != GGUF_MAGIC) {
        std::cerr << "ERROR: Not a valid GGUF file (magic mismatch)\n";
        return 1;
    }
    
    uint32_t version;
    file.read(reinterpret_cast<char*>(&version), sizeof(version));
    std::cout << "GGUF Version: " << version << "\n";
    
    uint64_t tensor_count, metadata_count;
    file.read(reinterpret_cast<char*>(&tensor_count), sizeof(tensor_count));
    file.read(reinterpret_cast<char*>(&metadata_count), sizeof(metadata_count));
    
    std::cout << "Tensors: " << tensor_count << "\n";
    std::cout << "Metadata entries: " << metadata_count << "\n\n";
    
    // Skip metadata for now
    // ... (would parse metadata here)
    
    // Read tensor info
    std::vector<TensorInfo> tensors;
    for (uint64_t i = 0; i < tensor_count; i++) {
        TensorInfo info;
        
        // Read name
        uint64_t name_len;
        file.read(reinterpret_cast<char*>(&name_len), sizeof(name_len));
        std::vector<char> name_buf(name_len + 1);
        file.read(name_buf.data(), name_len);
        name_buf[name_len] = '\0';
        info.name = name_buf.data();
        
        // Read dimensions
        uint32_t n_dims;
        file.read(reinterpret_cast<char*>(&n_dims), sizeof(n_dims));
        for (uint32_t d = 0; d < n_dims; d++) {
            uint64_t dim;
            file.read(reinterpret_cast<char*>(&dim), sizeof(dim));
            info.shape.push_back(dim);
        }
        
        // Read type
        file.read(reinterpret_cast<char*>(&info.type), sizeof(info.type));
        
        // Read offset
        file.read(reinterpret_cast<char*>(&info.offset), sizeof(info.offset));
        
        tensors.push_back(info);
    }
    
    // Calculate memory usage
    uint64_t file_size = 0;
    file.seekg(0, std::ios::end);
    file_size = file.tellg();
    file.close();
    
    uint64_t quantized_total = 0;
    uint64_t fp32_total = 0;
    uint64_t fp16_total = 0;
    
    for (const auto& t : tensors) {
        uint64_t num_elements = t.GetNumElements();
        fp32_total += num_elements * 4;
        fp16_total += num_elements * 2;
        
        // Approximate quantized size (simplified)
        if (IsQuantized(t.type)) {
            quantized_total += num_elements / 2;  // Rough estimate
        } else if (t.type == 0) {
            quantized_total += num_elements * 4;
        } else if (t.type == 1) {
            quantized_total += num_elements * 2;
        }
    }
    
    // Get system memory
    uint64_t system_memory = 128ULL * 1024 * 1024 * 1024;  // Assume 128GB for now
    
    std::cout << "========================================\n";
    std::cout << "MEMORY ANALYSIS\n";
    std::cout << "========================================\n\n";
    
    std::cout << "File size: " << FormatBytes(file_size) << "\n\n";
    
    std::cout << "CURRENT (FP32 materialization):\n";
    std::cout << "  Memory: " << FormatBytes(fp32_total) << "\n";
    std::cout << "  % of RAM: " << std::fixed << std::setprecision(1) 
              << (100.0 * fp32_total / system_memory) << "%\n";
    std::cout << "  Status: " << (fp32_total > system_memory * 0.8 ? "WILL FAIL" : "OK") << "\n\n";
    
    std::cout << "WITH FP16:\n";
    std::cout << "  Memory: " << FormatBytes(fp16_total) << "\n";
    std::cout << "  % of RAM: " << (100.0 * fp16_total / system_memory) << "%\n";
    std::cout << "  Status: " << (fp16_total > system_memory * 0.8 ? "WILL FAIL" : "OK") << "\n\n";
    
    std::cout << "QUANTIZED (in-place):\n";
    std::cout << "  Memory: " << FormatBytes(quantized_total) << "\n";
    std::cout << "  % of RAM: " << (100.0 * quantized_total / system_memory) << "%\n";
    std::cout << "  Status: OPTIMAL\n\n";
    
    // Show largest tensors
    std::cout << "TOP 10 LARGEST TENSORS:\n";
    std::cout << std::string(80, '-') << "\n";
    std::cout << std::left << std::setw(35) << "Name" 
              << std::setw(12) << "Shape" 
              << std::setw(10) << "Type"
              << std::setw(15) << "FP32 Size" << "\n";
    std::cout << std::string(80, '-') << "\n";
    
    // Sort by FP32 size
    std::vector<TensorInfo> sorted = tensors;
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) {
        return a.GetNumElements() > b.GetNumElements();
    });
    
    for (size_t i = 0; i < std::min(size_t(10), sorted.size()); i++) {
        const auto& t = sorted[i];
        uint64_t fp32 = t.GetNumElements() * 4;
        
        std::string shape_str;
        for (size_t j = 0; j < t.shape.size(); j++) {
            if (j > 0) shape_str += "x";
            shape_str += std::to_string(t.shape[j]);
        }
        
        std::cout << std::left << std::setw(35) << t.name.substr(0, 34)
                  << std::setw(12) << shape_str
                  << std::setw(10) << GetTypeName(t.type)
                  << std::setw(15) << FormatBytes(fp32) << "\n";
    }
    
    std::cout << "\n========================================\n";
    std::cout << "ROOT CAUSE:\n";
    std::cout << "========================================\n";
    std::cout << "The transformer_layer.cpp creates FP32 copies of all weights.\n";
    std::cout << "For a 22B model, this requires ~" << FormatBytes(fp32_total) << " of RAM.\n";
    std::cout << "\nFIX: Keep weights quantized and dequantize on-the-fly in MatMul.\n";
    std::cout << "========================================\n";
    
    return (fp32_total > system_memory * 0.8) ? 1 : 0;
}
