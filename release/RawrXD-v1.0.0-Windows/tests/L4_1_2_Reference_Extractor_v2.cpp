// L4_1_2_Reference_Extractor_v2.cpp
// Simplified version - directly seeks to tensor data

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <cstdint>
#include <cmath>

// Q4_0 block structure
struct Q4_0_Block {
    uint16_t scale;     // FP16 scale
    uint8_t quants[16]; // 32 nibbles packed
};

// Simple FP16 to FP32 conversion
float fp16_to_fp32(uint16_t fp16) {
    uint32_t sign = (fp16 >> 15) & 0x1;
    uint32_t exp = (fp16 >> 10) & 0x1F;
    uint32_t mant = fp16 & 0x3FF;
    
    if (exp == 0) {
        if (mant == 0) return sign ? -0.0f : 0.0f;
        float val = mant / 1024.0f;
        return sign ? -val * 0.00006103515625f : val * 0.00006103515625f;
    }
    if (exp == 0x1F) {
        if (mant == 0) {
            float inf;
            uint32_t inf_bits = 0x7F800000;
            memcpy(&inf, &inf_bits, sizeof(inf));
            return sign ? -inf : inf;
        }
        float nan;
        uint32_t nan_bits = 0x7FC00000;
        memcpy(&nan, &nan_bits, sizeof(nan));
        return nan;
    }
    
    uint32_t fp32 = (sign << 31) | ((exp + 112) << 23) | (mant << 13);
    float result;
    memcpy(&result, &fp32, sizeof(result));
    return result;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <gguf_file> <token_id>" << std::endl;
        return 1;
    }
    
    const char* gguf_path = argv[1];
    int token_id = std::atoi(argv[2]);
    
    std::ifstream file(gguf_path, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open: " << gguf_path << std::endl;
        return 1;
    }
    
    // Read header
    uint32_t magic, version;
    uint64_t n_tensors, n_metadata;
    file.read(reinterpret_cast<char*>(&magic), 4);
    file.read(reinterpret_cast<char*>(&version), 4);
    file.read(reinterpret_cast<char*>(&n_tensors), 8);
    file.read(reinterpret_cast<char*>(&n_metadata), 8);
    
    if (magic != 0x46554747) {
        std::cerr << "Invalid GGUF magic" << std::endl;
        return 1;
    }
    
    std::cout << "GGUF Version: " << version << std::endl;
    std::cout << "Tensors: " << n_tensors << ", Metadata: " << n_metadata << std::endl;
    
    // Skip metadata
    for (uint64_t i = 0; i < n_metadata; i++) {
        // Read key length and skip key
        uint64_t key_len;
        file.read(reinterpret_cast<char*>(&key_len), 8);
        file.seekg(key_len, std::ios::cur);
        
        // Read type and skip value
        uint32_t type;
        file.read(reinterpret_cast<char*>(&type), 4);
        
        switch (type) {
            case 0: case 1: file.seekg(1, std::ios::cur); break;
            case 2: case 3: file.seekg(2, std::ios::cur); break;
            case 4: case 5: case 6: file.seekg(4, std::ios::cur); break;
            case 7: case 8: case 9: file.seekg(8, std::ios::cur); break;
            case 10: file.seekg(1, std::ios::cur); break;
            case 11: {
                uint64_t len;
                file.read(reinterpret_cast<char*>(&len), 8);
                file.seekg(len, std::ios::cur);
                break;
            }
            case 12: {
                uint32_t arr_type;
                uint64_t arr_len;
                file.read(reinterpret_cast<char*>(&arr_type), 4);
                file.read(reinterpret_cast<char*>(&arr_len), 8);
                for (uint64_t j = 0; j < arr_len; j++) {
                    // Simplified: just skip based on type
                    switch (arr_type) {
                        case 0: case 1: file.seekg(1, std::ios::cur); break;
                        case 2: case 3: file.seekg(2, std::ios::cur); break;
                        case 4: case 5: case 6: file.seekg(4, std::ios::cur); break;
                        case 7: case 8: case 9: file.seekg(8, std::ios::cur); break;
                        case 10: file.seekg(1, std::ios::cur); break;
                        case 11: {
                            uint64_t len;
                            file.read(reinterpret_cast<char*>(&len), 8);
                            file.seekg(len, std::ios::cur);
                            break;
                        }
                        default: file.seekg(4, std::ios::cur); break;
                    }
                }
                break;
            }
            default: file.seekg(4, std::ios::cur); break;
        }
    }
    
    // Read tensor info
    uint64_t tensor_offset = 0;
    uint32_t tensor_type = 0;
    uint64_t n_dims = 0;
    std::vector<uint64_t> dims;
    bool found = false;
    
    for (uint64_t i = 0; i < n_tensors; i++) {
        // Read name
        uint64_t name_len;
        file.read(reinterpret_cast<char*>(&name_len), 8);
        std::string name(name_len, '\0');
        file.read(&name[0], name_len);
        
        // Read dimensions
        file.read(reinterpret_cast<char*>(&n_dims), 4);
        dims.resize(n_dims);
        for (uint32_t d = 0; d < n_dims; d++) {
            file.read(reinterpret_cast<char*>(&dims[d]), 8);
        }
        
        // Read type and offset
        file.read(reinterpret_cast<char*>(&tensor_type), 4);
        file.read(reinterpret_cast<char*>(&tensor_offset), 8);
        
        if (name == "token_embd.weight") {
            found = true;
            std::cout << "\nFound token_embd.weight:" << std::endl;
            std::cout << "  Dims: ";
            for (auto d : dims) std::cout << d << " ";
            std::cout << std::endl;
            std::cout << "  Type: " << tensor_type << std::endl;
            std::cout << "  Offset: " << tensor_offset << std::endl;
            break;
        }
    }
    
    if (!found) {
        std::cerr << "token_embd.weight not found" << std::endl;
        return 1;
    }
    
    // Calculate tensor data start (align to 32 bytes)
    uint64_t current_pos = file.tellg();
    uint64_t tensor_data_start = (current_pos + 31) & ~31;
    
    // For Q4_0: each block is 18 bytes (2 bytes scale + 16 bytes quants for 32 values)
    uint64_t embedding_dim = dims[0];
    uint64_t n_blocks = embedding_dim / 32;
    uint64_t row_size = n_blocks * 18;  // 18 bytes per block
    
    std::cout << "\nExtraction parameters:" << std::endl;
    std::cout << "  Token ID: " << token_id << std::endl;
    std::cout << "  Embedding dim: " << embedding_dim << std::endl;
    std::cout << "  Blocks per row: " << n_blocks << std::endl;
    std::cout << "  Row size: " << row_size << " bytes" << std::endl;
    
    // Seek to token row
    uint64_t row_offset = tensor_data_start + tensor_offset + (token_id * row_size);
    file.seekg(row_offset);
    
    // Read and dequantize
    std::vector<float> embedding(embedding_dim);
    
    for (uint64_t b = 0; b < n_blocks; b++) {
        Q4_0_Block block;
        file.read(reinterpret_cast<char*>(&block), sizeof(block));
        
        float scale = fp16_to_fp32(block.scale);
        
        for (int i = 0; i < 16; i++) {
            uint8_t byte = block.quants[i];
            int low = (byte & 0x0F) - 8;
            int high = ((byte >> 4) & 0x0F) - 8;
            
            embedding[b * 32 + i] = low * scale;
            embedding[b * 32 + i + 16] = high * scale;
        }
    }
    
    // Save to binary file
    std::string out_path = "llamacpp_token_" + std::to_string(token_id) + ".bin";
    std::ofstream out(out_path, std::ios::binary);
    out.write(reinterpret_cast<char*>(embedding.data()), embedding.size() * sizeof(float));
    out.close();
    
    std::cout << "\nReference embedding saved to: " << out_path << std::endl;
    std::cout << "  Size: " << embedding.size() * sizeof(float) << " bytes" << std::endl;
    
    // Print statistics
    float min_val = embedding[0], max_val = embedding[0], sum = 0;
    for (float v : embedding) {
        min_val = std::min(min_val, v);
        max_val = std::max(max_val, v);
        sum += v;
    }
    std::cout << "  Min: " << min_val << std::endl;
    std::cout << "  Max: " << max_val << std::endl;
    std::cout << "  Mean: " << (sum / embedding.size()) << std::endl;
    
    return 0;
}
