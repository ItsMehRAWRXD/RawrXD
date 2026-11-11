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
    if (!f) { std::cerr << "FAIL: open\n"; return 1; }
    
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
        if (!f) { std::cerr << "FAIL: key_len " << i << "\n"; return 1; }
        f.seekg(key_len, std::ios::cur);
        
        uint32_t value_type;
        f.read(reinterpret_cast<char*>(&value_type), 4);
        if (!f) { std::cerr << "FAIL: value_type read " << i << "\n"; return 1; }
        
        if (value_type == 8) { // string
            uint64_t str_len;
            f.read(reinterpret_cast<char*>(&str_len), 8);
            if (!f) { std::cerr << "FAIL: str_len " << i << "\n"; return 1; }
            f.seekg(str_len, std::ios::cur);
        } else if (value_type == 9) { // array
            uint32_t elem_type;
            uint64_t arr_len;
            f.read(reinterpret_cast<char*>(&elem_type), 4);
            f.read(reinterpret_cast<char*>(&arr_len), 8);
            if (!f) { std::cerr << "FAIL: array header " << i << "\n"; return 1; }
            
            if (elem_type == 8) { // array of strings - use fast skip
                // Each string has uint64_t length + string data
                // We need to read each length, but can skip the string data
                for (uint64_t j = 0; j < arr_len; ++j) {
                    uint64_t str_len;
                    f.read(reinterpret_cast<char*>(&str_len), 8);
                    if (!f) { std::cerr << "FAIL: array string len " << i << "." << j << "\n"; return 1; }
                    f.seekg(str_len, std::ios::cur);
                }
            } else {
                size_t elem_size = 1;
                if (elem_type == 4) elem_size = 4;
                else if (elem_type == 5) elem_size = 8;
                else if (elem_type == 6) elem_size = 4;
                else if (elem_type == 7) elem_size = 1;
                else if (elem_type == 10) elem_size = 8;
                else if (elem_type == 11) elem_size = 8;
                else if (elem_type == 12) elem_size = 8;
                else { std::cerr << "FAIL: unknown elem_type " << elem_type << " at " << i << "\n"; return 1; }
                f.seekg(arr_len * elem_size, std::ios::cur);
            }
        } else {
            size_t size = 0;
            if (value_type == 4) size = 4;
            else if (value_type == 5) size = 8;
            else if (value_type == 6) size = 4;
            else if (value_type == 7) size = 1;
            else if (value_type == 10) size = 8;
            else if (value_type == 11) size = 8;
            else if (value_type == 12) size = 8;
            else { std::cerr << "FAIL: unknown value_type " << value_type << " at " << i << "\n"; return 1; }
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
        if (!f) { std::cerr << "FAIL: name_len " << i << "\n"; return 1; }
        t.name.resize(name_len);
        f.read(&t.name[0], name_len);
        if (!f) { std::cerr << "FAIL: name " << i << "\n"; return 1; }
        f.read(reinterpret_cast<char*>(&t.n_dims), 4);
        for (uint32_t d = 0; d < t.n_dims; ++d) { f.read(reinterpret_cast<char*>(&t.ne[d]), 8); }
        f.read(reinterpret_cast<char*>(&t.type), 4);
        f.read(reinterpret_cast<char*>(&t.offset), 8);
        tensors.push_back(t);
    }
    
    // Print only embedding-related tensors
    for (auto &t : tensors) {
        if (t.name.find("embd") != std::string::npos || t.name.find("embed") != std::string::npos || t.name.find("tok_emb") != std::string::npos) {
            std::cout << t.name << " | dims=" << t.n_dims << " | ne0=" << t.ne[0] << " ne1=" << t.ne[1] << " | type=" << t.type << " | offset=" << t.offset << "\n";
        }
    }
    
    return 0;
}