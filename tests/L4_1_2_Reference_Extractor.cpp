// L4_1_2_Reference_Extractor.cpp
// Extracts token embedding from GGUF using llama.cpp as reference
// Output: llamacpp_token_42.bin (4096 FP32 values)

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <limits>

// Minimal GGUF structures (same as L4_1_1)
#pragma pack(push, 1)
struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t n_tensors;
    uint64_t n_metadata;
};

struct GGUFMetadata {
    std::string key;
    uint32_t type;
    std::vector<uint8_t> value;
};

struct GGUFTensorInfo {
    std::string name;
    uint32_t n_dims;
    std::vector<uint64_t> dims;
    uint32_t type;
    uint64_t offset;
};
#pragma pack(pop)

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
        // Subnormal
        float val = mant / 1024.0f;
        return sign ? -val * 0.00006103515625f : val * 0.00006103515625f;
    }
    if (exp == 0x1F) {
        if (mant == 0) return sign ? -INFINITY : INFINITY;
        return NAN;
    }
    
    uint32_t fp32 = (sign << 31) | ((exp + 112) << 23) | (mant << 13);
    float result;
    memcpy(&result, &fp32, sizeof(result));
    return result;
}

// Dequantize Q4_0 block (reference implementation matching llama.cpp)
void dequantize_q4_0_block(const Q4_0_Block* block, float* output, int n) {
    float scale = fp16_to_fp32(block->scale);
    
    for (int i = 0; i < 16 && i < n/2; i++) {
        uint8_t byte = block->quants[i];
        int low_nibble = (byte & 0x0F) - 8;
        int high_nibble = ((byte >> 4) & 0x0F) - 8;
        
        output[i] = low_nibble * scale;
        if (i + 16 < n) {
            output[i + 16] = high_nibble * scale;
        }
    }
}

// Read string from file
std::string read_string(std::ifstream& file) {
    uint64_t len;
    file.read(reinterpret_cast<char*>(&len), sizeof(len));
    std::string str(len, '\0');
    file.read(&str[0], len);
    return str;
}

// Skip metadata value based on type (we don't need to store it)
void skip_metadata_value(std::ifstream& file, uint32_t type) {
    switch (type) {
        case 0: case 1: file.seekg(1, std::ios::cur); break;  // uint8/int8
        case 2: case 3: file.seekg(2, std::ios::cur); break;  // uint16/int16
        case 4: case 5: case 6: file.seekg(4, std::ios::cur); break;  // uint32/int32/float32
        case 7: case 8: case 9: file.seekg(8, std::ios::cur); break;  // uint64/int64/float64
        case 10: file.seekg(1, std::ios::cur); break;  // bool
        case 11: { // string
            uint64_t len;
            file.read(reinterpret_cast<char*>(&len), sizeof(len));
            file.seekg(len, std::ios::cur);
            break;
        }
        case 12: { // array
            uint32_t arr_type;
            uint64_t arr_len;
            file.read(reinterpret_cast<char*>(&arr_type), sizeof(arr_type));
            file.read(reinterpret_cast<char*>(&arr_len), sizeof(arr_len));
            for (uint64_t i = 0; i < arr_len; i++) {
                skip_metadata_value(file, arr_type);
            }
            break;
        }
    }
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
    GGUFHeader header;
    file.read(reinterpret_cast<char*>(&header), sizeof(header));
    
    if (header.magic != 0x46554747) { // "GGUF" in little-endian
        std::cerr << "Invalid GGUF magic" << std::endl;
        return 1;
    }
    
    std::cout << "GGUF Version: " << header.version << std::endl;
    std::cout << "Tensors: " << header.n_tensors << std::endl;
    std::cout << "Metadata: " << header.n_metadata << std::endl;
    
    // Skip metadata
    for (uint64_t i = 0; i < header.n_metadata; i++) {
        auto key = read_string(file);
        uint32_t type;
        file.read(reinterpret_cast<char*>(&type), sizeof(type));
        skip_metadata_value(file, type);
    }
    
    // Read tensor info
    GGUFTensorInfo token_embd;
    bool found = false;
    
    for (uint64_t i = 0; i < header.n_tensors; i++) {
        GGUFTensorInfo info;
        info.name = read_string(file);
        file.read(reinterpret_cast<char*>(&info.n_dims), sizeof(info.n_dims));
        
        info.dims.resize(info.n_dims);
        for (uint32_t d = 0; d < info.n_dims; d++) {
            file.read(reinterpret_cast<char*>(&info.dims[d]), sizeof(info.dims[d]));
        }
        
        file.read(reinterpret_cast<char*>(&info.type), sizeof(info.type));
        file.read(reinterpret_cast<char*>(&info.offset), sizeof(info.offset));
        
        if (info.name == "token_embd.weight") {
            token_embd = info;
            found = true;
            std::cout << "\nFound token_embd.weight:" << std::endl;
            std::cout << "  Dims: ";
            for (auto d : info.dims) std::cout << d << " ";
            std::cout << std::endl;
            std::cout << "  Type: " << info.type << " (Q4_0 = 2)" << std::endl;
            std::cout << "  Offset: 0x" << std::hex << info.offset << std::dec << std::endl;
        }
    }
    
    if (!found) {
        std::cerr << "token_embd.weight not found" << std::endl;
        return 1;
    }
    
    // Calculate tensor data start (after header + metadata + tensor info)
    uint64_t tensor_data_start = file.tellg();
    // Align to 32 bytes
    tensor_data_start = (tensor_data_start + 31) & ~31;
    
    // Calculate row size for Q4_0
    // Each block is 18 bytes (2 bytes FP16 scale + 16 bytes for 32 nibbles)
    // For embedding_dim elements, we need embedding_dim/32 blocks
    uint64_t embedding_dim = token_embd.dims[0];
    uint64_t n_blocks_per_row = embedding_dim / 32;
    uint64_t row_size = n_blocks_per_row * sizeof(Q4_0_Block);
    
    std::cout << "\nExtraction parameters:" << std::endl;
    std::cout << "  Token ID: " << token_id << std::endl;
    std::cout << "  Embedding dim: " << embedding_dim << std::endl;
    std::cout << "  Blocks per row: " << n_blocks_per_row << std::endl;
    std::cout << "  Row size: " << row_size << " bytes" << std::endl;
    
    // Seek to token row
    uint64_t row_offset = tensor_data_start + token_embd.offset + (token_id * row_size);
    file.seekg(row_offset);
    
    // Read and dequantize
    std::vector<float> embedding(embedding_dim);
    
    for (uint64_t b = 0; b < n_blocks_per_row; b++) {
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
