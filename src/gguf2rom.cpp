#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <string_view>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <filesystem>

namespace Deep2Engine::Emulator {

    #pragma pack(push, 1)
    struct alignas(64) RomHeader {
        uint8_t  magic[8];
        uint32_t engine_version;
        uint32_t architecture_id;
        uint64_t total_rom_size;
        uint32_t num_layers;
        uint32_t num_experts;
        uint32_t top_k_experts;
        uint32_t hidden_dimension;
        uint32_t kv_heads;
        uint64_t metadata_offset;
        uint32_t metadata_count;
        uint8_t  reserved[16];
    };

    struct TensorDescriptor {
        char     tensor_name[64];
        uint64_t absolute_offset;
        uint64_t tensor_bytes;
        uint32_t dimensions[4];
        uint16_t quantization_type;
        uint8_t  target_device_id;
        uint8_t  reserved[5];
    };
    #pragma pack(pop)

    // GGUF parsing helpers
    std::string ReadGGUFStr(std::ifstream& f) {
        uint64_t len = 0;
        if (!f.read(reinterpret_cast<char*>(&len), sizeof(len))) {
            return "";
        }
        if (len == 0 || len > 1024) return "";  // Safety threshold for tensor names
        std::vector<char> buf(len);
        if (!f.read(buf.data(), len)) {
            return "";
        }
        return std::string(buf.data(), len);
    }

    void SkipGGUFValue(uint32_t type, std::ifstream& f) {
        if (type <= 7) {
            uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 1};
            f.seekg(sz[type & 7], std::ios::cur);
        } else if (type == 8) {
            ReadGGUFStr(f);
        } else if (type == 9) {
            uint32_t arrayType = 0;
            uint64_t arrayLen = 0;
            f.read(reinterpret_cast<char*>(&arrayType), sizeof(arrayType));
            f.read(reinterpret_cast<char*>(&arrayLen), sizeof(arrayLen));
            if (arrayType == 8) {
                for (uint64_t i = 0; i < arrayLen; ++i) ReadGGUFStr(f);
            } else if (arrayType == 9) {
                for (uint64_t i = 0; i < arrayLen; ++i) SkipGGUFValue(arrayType, f);
            } else {
                uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 8};
                f.seekg(arrayLen * sz[arrayType & 7], std::ios::cur);
            }
        } else {
            uint32_t sub = 0;
            uint64_t len = 0;
            f.read(reinterpret_cast<char*>(&sub), sizeof(sub));
            f.read(reinterpret_cast<char*>(&len), sizeof(len));
            if (sub == 9) {
                for (uint64_t i = 0; i < len; ++i) ReadGGUFStr(f);
            } else {
                uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 8};
                f.seekg(len * sz[sub & 7], std::ios::cur);
            }
        }
    }

    uint16_t MapGGUFTypeToROM(uint32_t gguf_type) {
        switch (gguf_type) {
            case 8: return 2;   // Q2_K
            case 9: return 3;   // Q3_K
            case 10: return 4;  // Q4_K
            case 11: return 5;  // Q5_K
            case 12: return 6;  // Q6_K
            case 13: return 7;  // Q8_K
            case 0: return 1;   // F32
            case 1: return 0;   // F16
            case 6: return 8;   // Q8_0
            default: return 0xFFFF;
        }
    }

    uint32_t MapArchToID(const std::string& arch) {
        if (arch.find("deepseek") != std::string::npos) return 1;
        if (arch.find("kimi") != std::string::npos) return 2;
        if (arch.find("phi3") != std::string::npos) return 3;
        if (arch.find("qwen") != std::string::npos) return 4;
        if (arch.find("gemma") != std::string::npos) return 5;
        if (arch.find("llama") != std::string::npos) return 6;
        return 3;
    }

    uint64_t Align64(uint64_t offset) {
        return (offset + 63) & ~63ull;
    }

} // namespace Deep2Engine::Emulator

int wmain(int argc, wchar_t* argv[]) {
    using namespace Deep2Engine::Emulator;
    using namespace std::filesystem;

    std::wcout << L"=== GGUF to ROM Converter START ===\n";
    std::wcout.flush();
    
    if (argc < 3) {
        std::wcerr << L"Usage: gguf2rom.exe <input.gguf> <output.rom> [architecture]\n";
        std::wcerr << L"Architecture options: phi3, deepseek, kimi, qwen, gemma, llama\n";
        return 1;
    }

std::wcout << L"Args parsed\n";
    std::wcout.flush();

    std::wstring input_path = argv[1];
    std::wstring output_path = argv[2];
    std::string arch = "phi3";
    if (argc >= 4) {
        std::wstring warch = argv[3];
        arch.assign(warch.begin(), warch.end());
    }

    std::wcout << L"Paths set\n";
    std::wcout.flush();

    std::wcout << L"=== GGUF to ROM Converter ===\n";
    std::wcout << L"Input:  " << input_path << L"\n";
    std::wcout << L"Output: " << output_path << L"\n";
    std::wcout << L"Arch:   " << arch.c_str() << L"\n\n";
    std::wcout.flush();

    std::wcout << L"Opening input file...\n";
    std::wcout.flush();
    
    std::ifstream input(input_path, std::ios::binary);
    if (!input.is_open()) {
        std::wcerr << L"Failed to open input file: " << input_path << L"\n";
        return 1;
    }
    
    std::wcout << L"Input file opened\n";
    std::wcout.flush();

    std::wcout << L"Input file opened\n";
    std::wcout.flush();
    
    std::wcout << L"Reading header...\n";
    std::wcout.flush();
    
    uint32_t magic, version;
    input.read(reinterpret_cast<char*>(&magic), 4);
    input.read(reinterpret_cast<char*>(&version), 4);
    
    std::wcout << L"Header read: magic=0x" << std::hex << magic << std::dec << L", version=" << version << L"\n";
    std::wcout.flush();
    
    if (magic != 0x46554747) {
        std::cerr << "Invalid GGUF magic: 0x" << std::hex << magic << "\n";
        return 1;
    }

    uint64_t tensor_count, kv_count;
    input.read(reinterpret_cast<char*>(&tensor_count), 8);
    input.read(reinterpret_cast<char*>(&kv_count), 8);

    std::wcout << L"GGUF: " << tensor_count << L" tensors, " << kv_count << L" metadata KVs\n";
    std::wcout.flush();

    std::string detected_arch;
    uint32_t num_layers = 0;
    uint32_t hidden_dim = 0;
    uint32_t kv_heads = 0;

    for (uint64_t i = 0; i < kv_count; ++i) {
        std::string key = ReadGGUFStr(input);
        uint32_t type = 0;
        input.read(reinterpret_cast<char*>(&type), sizeof(type));
        
        if (key == "general.architecture") {
            detected_arch = ReadGGUFStr(input);
        } else if (key == "general.architecture.block_count" || key == "phi3.block_count" || key == "llama.block_count") {
            uint32_t val = 0;
            input.read(reinterpret_cast<char*>(&val), sizeof(val));
            num_layers = val;
        } else if (key == "general.architecture.embedding_length" || key == "phi3.embedding_length" || key == "llama.embedding_length") {
            uint32_t val = 0;
            input.read(reinterpret_cast<char*>(&val), sizeof(val));
            hidden_dim = val;
        } else if (key == "general.architecture.attention.head_count" || key == "phi3.attention.head_count" || key == "llama.attention.head_count") {
            uint32_t val = 0;
            input.read(reinterpret_cast<char*>(&val), sizeof(val));
            kv_heads = val;
        } else if (key == "general.architecture.attention.head_count_kv" || key == "phi3.attention.head_count_kv") {
            uint32_t val = 0;
            input.read(reinterpret_cast<char*>(&val), sizeof(val));
            kv_heads = val;
        } else {
            SkipGGUFValue(type, input);
        }
    }

    if (detected_arch.empty()) detected_arch = arch;
    if (num_layers == 0) num_layers = 32;
    if (hidden_dim == 0) hidden_dim = 3072;
    if (kv_heads == 0) kv_heads = 32;

    std::wcout << L"Detected: " << detected_arch.c_str() << L", Layers: " << num_layers 
               << L", Hidden: " << hidden_dim << L", KV Heads: " << kv_heads << L"\n";
    std::wcout.flush();

    // GGUF spec: tensor info begins IMMEDIATELY after metadata (no alignment).
    // Only tensor DATA is aligned to 64-byte boundary.
    uint64_t pos_after_kvs = input.tellg();
    uint64_t tensor_info_start = pos_after_kvs;  // No alignment for tensor info per GGUF spec
    input.seekg(static_cast<std::streamoff>(tensor_info_start), std::ios::beg);
    std::wcout << L"Tensor info starts at offset: " << tensor_info_start << L"\n";
    std::wcout.flush();

    struct TensorInfo {
        std::string name;
        uint32_t n_dims;
        std::vector<uint64_t> dims;
        uint32_t type;
        uint64_t offset;
    };
    
    std::vector<TensorInfo> tensors;
    tensors.reserve(tensor_count);

    std::wcout << L"[INFO] Commencing structural extraction of " << tensor_count << L" tensor descriptors...\n";
    std::wcout.flush();

    for (uint64_t i = 0; i < tensor_count; ++i) {
        TensorInfo ti;
        
        // 1. Read string name
        ti.name = ReadGGUFStr(input);
        if (ti.name.empty()) {
            std::cerr << "[ERROR] Tensor index " << i << " failed name parsing or hit EOF/corrupt size.\n";
            return 1;
        }
        
        // 2. Read number of dimensions (Strictly uint32_t per spec)
        if (!input.read(reinterpret_cast<char*>(&ti.n_dims), 4)) {
            std::cerr << "[ERROR] Tensor '" << ti.name << "' hit unexpected stream truncation at n_dims.\n";
            return 1;
        }
        
        // 3. Read variable dimension parameters (Strictly arrays of uint64_t)
        ti.dims.resize(ti.n_dims);
        if (ti.n_dims > 0) {
            if (!input.read(reinterpret_cast<char*>(ti.dims.data()), ti.n_dims * sizeof(uint64_t))) {
                std::cerr << "[ERROR] Tensor '" << ti.name << "' hit stream corruption inside dimensions array.\n";
                return 1;
            }
        }
        
        // 4. Read tensor underlying type flag (Strictly uint32_t per spec)
        if (!input.read(reinterpret_cast<char*>(&ti.type), 4)) {
            std::cerr << "[ERROR] Tensor '" << ti.name << "' hit unexpected stream truncation at type field.\n";
            return 1;
        }
        
        // 5. Read relative data payload offset (Strictly uint64_t)
        if (!input.read(reinterpret_cast<char*>(&ti.offset), 8)) {
            std::cerr << "[ERROR] Tensor '" << ti.name << "' hit stream failure tracking weight offset location.\n";
            return 1;
        }
        
        // Catch the pattern signature early before writing trash layouts
        if (ti.offset == 0x6565656565656566ULL || ti.offset == 0x6666666666666666ULL) {
            std::cerr << "[CRITICAL ALIGNMENT BREAK] Tensor offset reading out-of-phase!\n";
            std::cerr << "                           Tensor Name: " << ti.name << "\n";
            std::cerr << "                           Stream Pos:  " << input.tellg() << "\n";
            return 1;
        }
        
        tensors.push_back(std::move(ti));
    }
    std::wcout.flush();

    uint64_t current_pos = input.tellg();
    uint64_t aligned_data_start = Align64(current_pos);
    input.seekg(aligned_data_start);

    input.seekg(0, std::ios::end);
    uint64_t file_size = static_cast<uint64_t>(input.tellg());
    input.seekg(aligned_data_start);

    // Build ROM header
    RomHeader header{};
    std::memcpy(header.magic, "RAWRXD2\0", 8);
    header.engine_version = 2;
    header.architecture_id = MapArchToID(detected_arch);
    header.num_layers = num_layers;
    header.num_experts = 0;
    header.top_k_experts = 0;
    header.hidden_dimension = hidden_dim;
    header.kv_heads = kv_heads;
    header.metadata_count = static_cast<uint32_t>(tensors.size());
    header.metadata_offset = sizeof(RomHeader);

    uint64_t tensor_table_size = static_cast<uint64_t>(tensors.size()) * sizeof(TensorDescriptor);
    uint64_t tensor_data_start = Align64(sizeof(RomHeader) + tensor_count * sizeof(TensorDescriptor));
    header.total_rom_size = tensor_count * sizeof(TensorDescriptor);  // placeholder
    header.metadata_offset = sizeof(RomHeader);

    std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
    if (!output.is_open()) {
        std::wcerr << L"Failed to create output file: " << output_path << L"\n";
        return 1;
    }

    // Write header (placeholder)
    output.write(reinterpret_cast<char*>(&header), sizeof(RomHeader));

    // Write tensor descriptors with placeholder sizes
    std::vector<std::streampos> descriptor_positions(tensors.size());
    for (size_t i = 0; i < tensors.size(); ++i) {
        std::streampos pos = output.tellp();
        
        TensorDescriptor desc{};
        size_t name_len = std::min<size_t>(tensors[i].name.size(), 63);
        std::memcpy(desc.tensor_name, tensors[i].name.c_str(), std::min<size_t>(name_len, 63));
        desc.tensor_name[std::min<size_t>(name_len, 63)] = '\0';
        
        desc.quantization_type = MapGGUFTypeToROM(tensors[i].type);
        desc.target_device_id = 0;
        
        for (int d = 0; d < 4; ++d) {
            desc.dimensions[d] = (d < static_cast<int>(tensors[i].dims.size())) ? 
                static_cast<uint32_t>(tensors[i].dims[d]) : 0;
        }
        
        desc.tensor_bytes = 0;  // Will update after copy
        desc.absolute_offset = 0;  // Will update after copy
        
        output.write(reinterpret_cast<char*>(&desc), sizeof(TensorDescriptor));
    }

    // Pad to tensor data start
    if (output.tellp() < static_cast<std::streampos>(tensor_data_start)) {
        std::vector<char> pad(tensor_data_start - output.tellp(), 0);
        output.write(pad.data(), pad.size());
    }

    // Copy tensor data from GGUF to ROM
    std::wcout << L"Copying tensor data...\n";
    std::vector<uint64_t> actual_sizes(tensors.size());
    
    for (size_t i = 0; i < tensors.size(); ++i) {
        // Calculate tensor size
        uint64_t elements = 1;
        for (auto d : tensors[i].dims) elements *= d;
        
        uint64_t bytes_to_read = 0;
        switch (tensors[i].type) {
            case 0: bytes_to_read = elements * 4; break;
            case 1: bytes_to_read = elements * 2; break;
            case 2: bytes_to_read = elements / 2 + 32; break;
            case 3: bytes_to_read = elements / 2 + 32; break;
            case 4: bytes_to_read = elements * 5 / 8 + 32; break;
            case 5: bytes_to_read = elements * 5 / 8 + 32; break;
            case 6: bytes_to_read = elements + 32; break;
            case 7: bytes_to_read = elements + 32; break;
            case 8: bytes_to_read = elements / 4 + 16; break;
            case 9: bytes_to_read = elements * 3 / 8 + 16; break;
            case 10: bytes_to_read = elements / 2 + 16; break;
            case 11: bytes_to_read = elements * 5 / 8 + 16; break;
            case 12: bytes_to_read = elements * 6 / 8 + 16; break;
            case 13: bytes_to_read = elements + 16; break;
            default: bytes_to_read = elements * 2; break;
        }
        bytes_to_read = Align64(bytes_to_read);
        
        // GGUF tensor offsets are relative to the start of tensor data section
        input.seekg(static_cast<std::streamoff>(aligned_data_start + tensors[i].offset), std::ios::beg);
        std::vector<char> buffer(bytes_to_read);
        std::streamsize bytes_read = input.read(buffer.data(), static_cast<std::streamsize>(bytes_to_read)).gcount();
        std::wcout << L"  Tensor " << (i+1) << L": off=" << tensors[i].offset << L" read " << bytes_read << L" bytes, wrote ";
        output.write(buffer.data(), static_cast<std::streamsize>(bytes_read));
        std::wcout << bytes_read << L" bytes\r";
        std::wcout.flush();
        
        if ((i + 1) % 32 == 0 || i + 1 == tensors.size()) {
            std::wcout << L"  Copied " << (i + 1) << L"/" << tensors.size() << L" tensors\r";
            std::wcout.flush();
        }
    }
    std::wcout << L"\n";

    output.close();
    input.close();

    // Verify output
    std::ifstream verify(output_path, std::ios::binary);
    verify.seekg(0, std::ios::end);
    uint64_t verify_size = verify.tellg();
    
    std::wcout << L"\n=== CONVERSION COMPLETE ===\n";
    std::wcout << L"Output ROM: " << output_path << L"\n";
    std::wcout << L"ROM size:   " << verify_size << L" bytes (" << (verify_size / 1024 / 1024) << L" MB)\n";
    std::wcout << L"Tensors:    " << tensors.size() << L"\n";

    std::ifstream check(output_path, std::ios::binary);
    RomHeader check_header{};
    check.read(reinterpret_cast<char*>(&check_header), sizeof(RomHeader));
    
    if (std::memcmp(check_header.magic, "RAWRXD2\0", 8) == 0) {
        std::wcout << L"\n✓ ROM signature verified: RAWRXD2\n";
    } else {
        std::wcerr << L"\n✗ ROM signature INVALID!\n";
        return 1;
    }

    std::wcout << L"✓ Conversion successful!\n";
    return 0;
}