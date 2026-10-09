#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <filesystem>

struct TensorInfo {
    std::string name;
    uint32_t n_dims;
    uint64_t ne[4];
    uint32_t type;
    uint64_t offset;
};

int main() {
    std::string gguf_path = "F:\\rawrxd\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf";
    std::ifstream f(gguf_path, std::ios::binary);
    if (!f) {
        std::cerr << "Failed to open GGUF\n";
        return 1;
    }
    
    // Read header
    uint32_t magic, version;
    uint64_t tensor_count, metadata_kv_count;
    f.read(reinterpret_cast<char*>(&magic), 4);
    f.read(reinterpret_cast<char*>(&version), 4);
    f.read(reinterpret_cast<char*>(&tensor_count), 8);
    f.read(reinterpret_cast<char*>(&metadata_kv_count), 8);
    
    // Skip metadata
    for (uint64_t i = 0; i < metadata_kv_count; ++i) {
        uint64_t key_len;
        f.read(reinterpret_cast<char*>(&key_len), 8);
        f.seekg(key_len, std::ios::cur);
        
        uint32_t value_type;
        f.read(reinterpret_cast<char*>(&value_type), 4);
        
        if (value_type == 8) { // string
            uint64_t str_len;
            f.read(reinterpret_cast<char*>(&str_len), 8);
            f.seekg(str_len, std::ios::cur);
        } else if (value_type == 9) { // array
            uint32_t elem_type;
            uint64_t arr_len;
            f.read(reinterpret_cast<char*>(&elem_type), 4);
            f.read(reinterpret_cast<char*>(&arr_len), 8);
            size_t elem_size = 1;
            if (elem_type == 4) elem_size = 4;
            else if (elem_type == 5) elem_size = 8;
            else if (elem_type == 6) elem_size = 4;
            else if (elem_type == 7) elem_size = 1;
            else if (elem_type == 8) { // strings
                for (uint64_t j = 0; j < arr_len; ++j) {
                    uint64_t str_len;
                    f.read(reinterpret_cast<char*>(&str_len), 8);
                    f.seekg(str_len, std::ios::cur);
                }
                continue;
            }
            f.seekg(arr_len * elem_size, std::ios::cur);
        } else {
            size_t size = 0;
            if (value_type == 4) size = 4;
            else if (value_type == 5) size = 8;
            else if (value_type == 6) size = 4;
            else if (value_type == 7) size = 1;
            f.seekg(size, std::ios::cur);
        }
    }
    
    // Read tensor infos
    std::vector<TensorInfo> tensors;
    tensors.reserve(tensor_count);
    
    for (uint64_t i = 0; i < tensor_count; ++i) {
        TensorInfo t;
        uint64_t name_len;
        f.read(reinterpret_cast<char*>(&name_len), 8);
        t.name.resize(name_len);
        f.read(&t.name[0], name_len);
        f.read(reinterpret_cast<char*>(&t.n_dims), 4);
        for (uint32_t d = 0; d < t.n_dims; ++d) {
            f.read(reinterpret_cast<char*>(&t.ne[d]), 8);
        }
        f.read(reinterpret_cast<char*>(&t.type), 4);
        f.read(reinterpret_cast<char*>(&t.offset), 8);
        tensors.push_back(t);
    }
    
    std::cout << "Found " << tensors.size() << " tensors\n";
    
    // Find token_embd.weight
    TensorInfo* embd_tensor = nullptr;
    for (auto &t : tensors) {
        if (t.name.find("embd") != std::string::npos || t.name.find("embed") != std::string::npos) {
            if (embd_tensor == nullptr || t.name.length() < embd_tensor->name.length()) {
                embd_tensor = &t;
            }
        }
    }
    
    if (!embd_tensor) {
        std::cerr << "No embedding tensor found\n";
        return 1;
    }
    
    std::cout << "\nEmbedding tensor:\n";
    std::cout << "  Name: " << embd_tensor->name << "\n";
    std::cout << "  n_dims: " << embd_tensor->n_dims << "\n";
    for (uint32_t d = 0; d < embd_tensor->n_dims; ++d) {
        std::cout << "  ne[" << d << "]: " << embd_tensor->ne[d] << "\n";
    }
    std::cout << "  type: " << embd_tensor->type << "\n";
    std::cout << "  offset: " << embd_tensor->offset << "\n";
    
    // Read a small sample of the embedding data for token 1
    f.seekg(embd_tensor->offset, std::ios::beg);
    std::vector<uint8_t> sample(256);
    f.read(reinterpret_cast<char*>(sample.data()), 256);
    size_t read = f.gcount();
    
    std::cout << "  First 256 bytes at offset: ";
    for (size_t i = 0; i < std::min<size_t>(32, read); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)sample[i] << " ";
    }
    std::cout << std::dec << "\n";
    
    return 0;
}