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
    struct alignas(64) RomHeaderMultiShard {
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
        uint32_t total_shards;
        uint8_t  reserved[12];
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

    // GGUF Type System (per GGUF spec)
    enum GGUFValueType : uint32_t {
        GGUF_TYPE_UINT8   = 0,
        GGUF_TYPE_INT8    = 1,
        GGUF_TYPE_UINT16  = 2,
        GGUF_TYPE_INT16   = 3,
        GGUF_TYPE_UINT32  = 4,
        GGUF_TYPE_INT32   = 5,
        GGUF_TYPE_FLOAT32 = 6,
        GGUF_TYPE_BOOL    = 7,
        GGUF_TYPE_STRING  = 8,
        GGUF_TYPE_ARRAY   = 9,
        GGUF_TYPE_UINT64  = 10,
        GGUF_TYPE_INT64   = 11,
        GGUF_TYPE_FLOAT64 = 12,
    };

    // GGML quantization types (per GGML/GGUF spec)
    // https://github.com/ggerganov/ggml/blob/master/src/ggml.h
    enum GGMLType : uint32_t {
        GGML_TYPE_F32     = 0,
        GGML_TYPE_F16     = 1,
        GGML_TYPE_Q4_0    = 2,
        GGML_TYPE_Q4_1    = 4,
        GGML_TYPE_Q5_0    = 6,
        GGML_TYPE_Q5_1    = 8,
        GGML_TYPE_Q8_0    = 8,
        GGML_TYPE_Q8_1    = 9,
        GGML_TYPE_Q2_K    = 10,
        GGML_TYPE_Q3_K    = 11,
        GGML_TYPE_Q4_K    = 12,
        GGML_TYPE_Q5_K    = 13,
        GGML_TYPE_Q6_K    = 14,
        GGML_TYPE_Q8_K    = 15,
    };

    // GGML block layout for exact tensor size calculation (per GGML spec)
    struct GGMLLayout {
        uint32_t elements_per_block;
        uint32_t bytes_per_block;
    };

    GGMLLayout GetGGMLLayout(uint32_t gguf_type) {
        switch (gguf_type) {
            case 0:  return {1,   4};   // F32
            case 1:  return {1,   2};   // F16
            case 2:  return {32,  18};  // Q4_0
            case 4:  return {32,  20};  // Q4_1
            case 6:  return {32,  22};  // Q5_0
            case 8:  return {32,  34};  // Q8_0
            case 10: return {256, 84};  // Q2_K
            case 11: return {256, 110}; // Q3_K
            case 12: return {256, 144}; // Q4_K
            case 13: return {256, 176}; // Q5_K
            case 14: return {256, 210}; // Q6_K
            case 15: return {256, 292}; // Q8_K
            default: 
                throw std::runtime_error("Unsupported GGML tensor type: " + std::to_string(gguf_type));
        }
    }

    uint64_t CalculateTensorBytes(uint32_t gguf_type, uint64_t elements) {
        GGMLLayout layout = GetGGMLLayout(gguf_type);
        if (layout.elements_per_block == 0) return 0;
        uint64_t blocks = (elements + layout.elements_per_block - 1) / layout.elements_per_block;
        return blocks * layout.bytes_per_block;
    }

// GGUF type to ROM quantization type mapping (GGUF type code -> TensorType enum)
    uint16_t MapGGUFTypeToROM(uint32_t gguf_type) {
        // GGUF type codes per GGUF spec:
        // 0=F32, 1=F16, 2=Q4_0, 3=Q4_1, 4=Q5_0, 5=Q5_1, 6=Q8_0, 7=Q8_1,
        // 8=Q2_K, 9=Q3_K, 10=Q4_K, 11=Q5_K, 12=Q6_K, 13=Q8_K, 14=IQ2_XX, etc.
        // Map to TensorType enum values (from TensorView.hpp)
        switch (gguf_type) {
            case 0:  return 0;    // F32 -> TensorType::F32 (0)
            case 1:  return 1;    // F16 -> TensorType::F16 (1)
            case 2:  return 2;    // Q4_0 -> TensorType::Q4_0 (2)
            case 3:  return 3;    // Q4_1 -> TensorType::Q4_1 (3)
            case 4:  return 6;    // Q5_0 -> TensorType::Q5_0 (6) [not in enum yet]
            case 5:  return 7;    // Q5_1 -> TensorType::Q5_1 (7) [not in enum yet]
            case 6:  return 8;    // Q8_0 -> TensorType::Q8_0 (8)
            case 7:  return 9;    // Q8_1 -> TensorType::Q8_1 (9)
            case 8:  return 10;   // Q2_K -> TensorType::Q2_K (10)
            case 9:  return 11;   // Q3_K -> TensorType::Q3_K_S (11) [base type]
            case 10: return 14;   // Q4_K -> TensorType::Q4_K_S (14) [base type]
            case 11: return 16;   // Q5_K -> TensorType::Q5_K_S (16) [base type]
            case 12: return 18;   // Q6_K -> TensorType::Q6_K (18)
            case 13: return 8;    // Q8_K -> TensorType::Q8_0 (8) [approximate]
            case 14: return 10;   // IQ2_XX -> TensorType::Q2_K (10) [approximate]
            case 15: return 10;   // IQ3_XX -> TensorType::Q2_K (10) [approximate]
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

    uint64_t AlignUp(uint64_t offset, uint64_t alignment) {
        if (alignment == 0 || (alignment & (alignment - 1)) != 0) return offset;
        return (offset + alignment - 1) & ~(alignment - 1);
    }

    uint64_t Align64(uint64_t offset) {
        return (offset + 63) & ~63ull;
    }

    // GGUF parsing helpers
    std::string ReadGGUFStr(std::ifstream& f) {
        uint64_t len = 0;
        if (!f.read(reinterpret_cast<char*>(&len), sizeof(len))) {
            return "";
        }
        if (len == 0 || len > 1024 * 1024) return ""; // 1MB max for safety
        std::vector<char> buf(len);
        f.read(buf.data(), len);
        return std::string(buf.data(), len);
    }

    void SkipGGUFValue(uint32_t type, std::ifstream& f) {
        if (type <= 7) {
            static constexpr uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 1};
            f.seekg(sz[type & 7], std::ios::cur);
        } else if (type == 8) { // string
            ReadGGUFStr(f);
        } else if (type == 9) { // array
            uint32_t arrayType = 0;
            uint64_t arrayLen = 0;
            f.read(reinterpret_cast<char*>(&arrayType), sizeof(arrayType));
            f.read(reinterpret_cast<char*>(&arrayLen), sizeof(arrayLen));
            if (arrayType == 8) { // string array
                for (uint64_t i = 0; i < arrayLen; ++i) ReadGGUFStr(f);
            } else if (arrayType == 9) { // nested array
                for (uint64_t i = 0; i < arrayLen; ++i) SkipGGUFValue(arrayType, f);
            } else {
                static constexpr uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 8};
                f.seekg(arrayLen * sz[arrayType & 7], std::ios::cur);
            }
        } else if (type == 10) { // UINT64
            f.seekg(8, std::ios::cur);
        } else if (type == 11) { // INT64
            f.seekg(8, std::ios::cur);
        } else if (type == 12) { // FLOAT64
            f.seekg(8, std::ios::cur);
} else {
            // Unknown type - skip conservatively
            f.seekg(8, std::ios::cur);
        }
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

    std::wstring input_path = argv[1];
    std::wstring output_path = argv[2];
    std::string arch = "phi3";
    if (argc >= 4) {
        std::wstring warch = argv[3];
        arch.assign(warch.begin(), warch.end());
    }

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
    uint32_t gguf_alignment = 32; // Default GGUF alignment per spec

    for (uint64_t i = 0; i < kv_count; ++i) {
        std::string key = ReadGGUFStr(input);
        uint32_t type = 0;
        input.read(reinterpret_cast<char*>(&type), sizeof(type));
        
        if (key == "general.architecture") {
            detected_arch = ReadGGUFStr(input);
        } else if (key == "general.alignment") {
            uint32_t val = 0;
            input.read(reinterpret_cast<char*>(&val), sizeof(val));
            gguf_alignment = val;
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

    // GGUF spec: tensor info begins IMMEDIATELY after metadata (no alignment).
    // Only tensor DATA is aligned to the GGUF alignment (default 32 bytes).
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

    std::wcout << L"\nFinished reading tensor info, count: " << tensors.size() << L"\n";
    std::wcout.flush();

    uint64_t current_pos = input.tellg();
    uint64_t aligned_data_start = AlignUp(current_pos, gguf_alignment); // GGUF alignment (default 32)
    input.seekg(aligned_data_start);

    input.seekg(0, std::ios::end);
    uint64_t file_size = static_cast<uint64_t>(input.tellg());
    input.seekg(aligned_data_start);

// Build ROM header
    RomHeaderMultiShard header{};
    std::memcpy(header.magic, "GGUF\0\0\0\0", 8);
    header.engine_version = 2;
    header.architecture_id = MapArchToID(detected_arch);
    header.num_layers = num_layers;
    header.num_experts = 0;
    header.top_k_experts = 0;
    header.hidden_dimension = hidden_dim;
    header.kv_heads = kv_heads;
    header.metadata_offset = sizeof(RomHeaderMultiShard);
    header.metadata_count = static_cast<uint32_t>(tensors.size());
    header.total_shards = 1;
    header.total_rom_size = 0;  // placeholder

    std::fstream output(output_path, std::ios::in | std::ios::out | std::ios::binary | std::ios::trunc);
    if (!output.is_open() || !output.good()) {
        std::wcerr << L"[ERROR] Failed to create output file: " << output_path << L"\n";
        return 1;
    }

    // Write header (placeholder)
    output.write(reinterpret_cast<char*>(&header), sizeof(RomHeaderMultiShard));

    uint64_t tensor_data_start = Align64(sizeof(RomHeaderMultiShard) + tensor_count * sizeof(TensorDescriptor));

    // Write tensor descriptors with placeholder sizes
    std::vector<std::streampos> descriptor_positions(tensors.size());
    for (size_t i = 0; i < tensors.size(); ++i) {
        std::streampos pos = output.tellp();
        descriptor_positions[i] = pos;
        
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
std::wcout << L"  Wrote " << tensors.size() << L" tensor descriptors\n" << std::flush;
    
    // Track total file size
    uint64_t file_size = 0;
    
    // Pad to tensor data start
    if (output.tellp() < static_cast<std::streampos>(tensor_data_start)) {
        std::vector<char> pad(tensor_data_start - output.tellp(), 0);
        output.write(pad.data(), pad.size());
        if (!output.good()) {
            std::wcerr << L"[ERROR] Failed to write padding\n";
            return 1;
        }
    }
    
    std::wcout << L"  Padded to tensor data start: " << output.tellp() << L" bytes\n" << std::flush;
    
    // Copy tensor data from GGUF to ROM
    std::wcout << L"Copying tensor data...\n";
    
    // Track actual tensor data offset in ROM
    uint64_t rom_tensor_data_start = output.tellp();
std::wcout << L"  Tensor data starts at ROM offset: " << rom_tensor_data_start << L" bytes\n";
    std::wcout.flush();
    
    for (size_t i = 0; i < tensors.size(); ++i) {
        // Calculate tensor size
        uint64_t elements = 1;
        for (auto d : tensors[i].dims) elements *= d;
        
        uint64_t bytes_to_read = CalculateTensorBytes(tensors[i].type, elements);
        
        // GGUF tensor offsets are relative to the start of tensor data section
        input.seekg(static_cast<std::streamoff>(aligned_data_start + tensors[i].offset), std::ios::beg);
        if (!input.good()) {
            std::wcerr << L"[ERROR] Failed to seek to tensor " << i << L" data at offset " << tensors[i].offset << L"\n";
            return 1;
        }
        
        std::wcout << L"  Tensor " << (i+1) << L": seek OK, pos=" << input.tellg() << L"\n";
        std::wcout.flush();
        
        std::vector<char> buffer(bytes_to_read);
        std::streamsize bytes_read = input.read(buffer.data(), static_cast<std::streamsize>(bytes_to_read)).gcount();
        
        std::wcout << L"  Tensor " << (i+1) << L": read " << bytes_read << L" bytes (expected " << bytes_to_read << L")\n";
        std::wcout.flush();
        
        if (bytes_read == 0) {
            std::wcerr << L"[WARNING] Read 0 bytes for tensor " << std::wstring(tensors[i].name.begin(), tensors[i].name.end()) << L"\n";
        }
        
        // Write to ROM
        output.write(buffer.data(), static_cast<std::streamsize>(bytes_read));
        if (!output.good()) {
            std::wcerr << L"[ERROR] Failed to write tensor " << i << L" (" << std::wstring(tensors[i].name.begin(), tensors[i].name.end()) << L")\n";
            return 1;
        }
        
        // Update file size
        file_size += bytes_read;
        
        std::wcout << L"  Tensor " << (i+1) << L": off=" << tensors[i].offset << L" read " << bytes_read << L" bytes, wrote ";
        std::wcout << bytes_read << L" bytes\r";
        std::wcout.flush();
        
        // Update descriptor with actual values
        if (i < descriptor_positions.size()) {
            std::streampos cur = output.tellp();
            output.seekp(descriptor_positions[i]);
            
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
            
            desc.tensor_bytes = static_cast<uint64_t>(bytes_read);
            desc.absolute_offset = static_cast<uint64_t>(static_cast<std::streamoff>(output.tellp()) - static_cast<std::streamoff>(rom_tensor_data_start));
            
            output.write(reinterpret_cast<char*>(&desc), sizeof(TensorDescriptor));
            if (!output.good()) {
                std::wcerr << L"[ERROR] Failed to update descriptor " << i << L"\n";
                return 1;
            }
            
            output.seekp(output.tellp()); // Continue from current position
        }
        
        std::wcout << L"  Tensor " << (i+1) << L": off=" << tensors[i].offset << L" read " << bytes_read << L" bytes, wrote ";
        std::wcout << bytes_read << L" bytes\r";
        std::wcout.flush();
        
        if ((i + 1) % 32 == 0 || i + 1 == tensors.size()) {
            std::wcout << L"  Copied " << (i + 1) << L"/" << tensors.size() << L" tensors\r";
            std::wcout.flush();
        }
    }

}

    output.flush();
    output.close();
    
    // Reopen to update header without truncation
    std::fstream output2(output_path, std::ios::in | std::ios::out | std::ios::binary);
    if (!output2.is_open() || !output2.good()) {
        std::wcerr << L"[ERROR] Failed to reopen output file for header update: " << output_path << L"\n";
        return 1;
    }
    
    output2.seekp(0);
    uint64_t final_size = static_cast<uint64_t>(std::filesystem::file_size(output_path));
    header.total_rom_size = final_size;
    output2.write(reinterpret_cast<char*>(&header), sizeof(RomHeaderMultiShard));
    if (!output2.good()) {
        std::wcerr << L"[ERROR] Failed to update header\n";
        return 1;
    }
    output2.close();
    
    std::wcout << L"\n=== CONVERSION COMPLETE ===\n";
    std::wcout << L"Output ROM: " << output_path << L"\n";
    std::wcout << L"ROM size:   " << final_size << L" bytes (" << (final_size / 1024 / 1024) << L" MB)\n";
    std::wcout << L"Tensors:    " << tensors.size() << L"\n";
    std::wcout.flush();
    
    return 0;
}