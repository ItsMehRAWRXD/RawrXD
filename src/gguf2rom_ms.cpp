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
#include <unordered_map>

#include "Win32RomEmulator.hpp"

namespace Deep2Engine::Emulator {

    // GGUF parsing helpers
    std::string ReadGGUFStr(std::ifstream& f) {
        uint64_t len = 0;
        f.read(reinterpret_cast<char*>(&len), sizeof(len));
        if (!f || len > 4096) return "";
        std::vector<char> buf(len);
        f.read(buf.data(), len);
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
        } else if (type == 10 || type == 11 || type == 12) {
            // UINT64 / INT64 / FLOAT64: simple 8-byte value
            f.seekg(8, std::ios::cur);
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

    uint64_t CalcTensorBytes(uint32_t type, const std::vector<uint64_t>& dims) {
        uint64_t elements = 1;
        for (auto d : dims) elements *= d;
        uint64_t bytes = 0;
        switch (type) {
            case 0: bytes = elements * 4; break;  // F32
            case 1: bytes = elements * 2; break;  // F16
            case 2: bytes = elements / 2 + 32; break;  // Q4_0
            case 3: bytes = elements / 2 + 32; break;  // Q4_1
            case 6: bytes = elements + 32; break;  // Q8_0
            case 8: bytes = elements / 4 + 16; break;  // Q2_K
            case 9: bytes = elements * 3 / 8 + 16; break;  // Q3_K
            case 10: bytes = elements / 2 + 16; break;  // Q4_K
            case 11: bytes = elements * 5 / 8 + 16; break;  // Q5_K
            case 12: bytes = elements * 6 / 8 + 16; break;  // Q6_K
            case 13: bytes = elements + 16; break;  // Q8_K
            default: bytes = elements * 2; break;
        }
        return Align64(bytes);
    }

} // namespace Deep2Engine::Emulator

int wmain(int argc, wchar_t* argv[]) {
    using namespace Deep2Engine::Emulator;
    using namespace Deep2Rom;
    using namespace std::filesystem;

    std::wcout << L"=== Multi-Shard GGUF to ROM Converter ===\n";
    std::wcout.flush();

    if (argc < 4) {
        std::wcerr << L"Usage: gguf2rom_ms.exe <output.rom> <shard_base_pattern> <shard_count> [architecture]\n";
        std::wcerr << L"Example: gguf2rom_ms.exe model.rom G:\\models\\DeepSeek-R1 11 deepseek\n";
        std::wcerr << L"This will open model.gguf.00 through model.gguf.10\n";
        return 1;
    }

    std::wstring output_path = argv[1];
    std::wstring base_pattern = argv[2];   // e.g. "G:\\models\\DeepSeek-R1" -> opens .gguf.00, .gguf.01...
    uint32_t shard_count = static_cast<uint32_t>(_wtoi(argv[3]));
    std::string arch = "deepseek";
    if (argc >= 5) {
        std::wstring warch = argv[4];
        arch.assign(warch.begin(), warch.end());
    }

    if (shard_count == 0) {
        std::wcerr << L"Error: shard_count must be > 0\n";
        return 1;
    }

    std::wcout << L"Output: " << output_path << L"\n";
    std::wcout << L"Base pattern: " << base_pattern << L"\n";
    std::wcout << L"Shard count: " << shard_count << L"\n";
    std::wcout << L"Arch: " << arch.c_str() << L"\n\n";
    std::wcout.flush();

    // ------------------------------------------------------------------
    // Pass 1: Open each shard, read header + KV metadata + tensor directory
    // ------------------------------------------------------------------
    struct ShardContext {
        std::wstring path;
        std::ifstream file;
        uint64_t tensor_count = 0;
        uint64_t kv_count = 0;
        uint64_t data_offset = 0;
        uint64_t data_size = 0;
        std::string detected_arch;
        uint32_t num_layers = 0;
        uint32_t hidden_dim = 0;
        uint32_t kv_heads = 0;
        bool valid = false;
    };

    std::vector<ShardContext> shards;
    shards.reserve(shard_count);

    for (uint32_t s = 0; s < shard_count; ++s) {
        wchar_t shard_path[MAX_PATH];
        swprintf_s(shard_path, L"%s.gguf.%02d", base_pattern.c_str(), s);

        ShardContext ctx;
        ctx.path = shard_path;
        ctx.file.open(shard_path, std::ios::binary);
        if (!ctx.file.is_open()) {
            std::wcerr << L"[-] Failed to open shard: " << shard_path << L"\n";
            return 1;
        }

        uint32_t magic = 0, version = 0;
        ctx.file.read(reinterpret_cast<char*>(&magic), 4);
        ctx.file.read(reinterpret_cast<char*>(&version), 4);
        if (magic != 0x46554747u) {
            std::wcerr << L"[-] Shard " << s << " bad magic 0x" << std::hex << magic << L"\n";
            return 1;
        }

        ctx.file.read(reinterpret_cast<char*>(&ctx.tensor_count), 8);
        ctx.file.read(reinterpret_cast<char*>(&ctx.kv_count), 8);

        // Parse KV metadata for architecture info
        for (uint64_t i = 0; i < ctx.kv_count; ++i) {
            std::string key = ReadGGUFStr(ctx.file);
            uint32_t type = 0;
            ctx.file.read(reinterpret_cast<char*>(&type), sizeof(type));

            if (key == "general.architecture") {
                ctx.detected_arch = ReadGGUFStr(ctx.file);
            } else if (key == "llama.block_count" || key == "phi3.block_count" ||
                       key == "deepseek.block_count" || key == "general.block_count") {
                uint32_t val = 0;
                ctx.file.read(reinterpret_cast<char*>(&val), sizeof(val));
                ctx.num_layers = val;
            } else if (key == "llama.embedding_length" || key == "phi3.embedding_length" ||
                       key == "deepseek.embedding_length" || key == "general.embedding_length") {
                uint32_t val = 0;
                ctx.file.read(reinterpret_cast<char*>(&val), sizeof(val));
                ctx.hidden_dim = val;
            } else if (key == "llama.attention.head_count" || key == "phi3.attention.head_count" ||
                       key == "deepseek.attention.head_count" || key == "general.attention.head_count") {
                uint32_t val = 0;
                ctx.file.read(reinterpret_cast<char*>(&val), sizeof(val));
                ctx.kv_heads = val;
            } else {
                SkipGGUFValue(type, ctx.file);
            }
        }

        if (ctx.detected_arch.empty()) ctx.detected_arch = arch;
        if (ctx.num_layers == 0) ctx.num_layers = 32;
        if (ctx.hidden_dim == 0) ctx.hidden_dim = 3072;
        if (ctx.kv_heads == 0) ctx.kv_heads = 32;

        // Align to 64 bytes: payload starts here
        uint64_t pos = static_cast<uint64_t>(ctx.file.tellg());
        ctx.data_offset = Align64(pos);
        ctx.file.seekg(0, std::ios::end);
        uint64_t end = static_cast<uint64_t>(ctx.file.tellg());
        ctx.data_size = (end > ctx.data_offset) ? (end - ctx.data_offset) : 0;
        ctx.file.seekg(ctx.data_offset, std::ios::beg);
        ctx.valid = true;

        shards.push_back(std::move(ctx));

        std::wcout << L"[+] Shard " << s << ": " << ctx.tensor_count << L" tensors, "
                   << L"kv=" << ctx.kv_count << L", data_off=" << ctx.data_offset
                   << L", data_size=" << ctx.data_size << L"\n";
        std::wcout.flush();
    }

    // ------------------------------------------------------------------
    // Pass 2: Read tensor directory from each shard, build global manifest
    // ------------------------------------------------------------------
    struct GlobalTensor {
        std::string name;
        uint32_t shard_id;
        uint64_t absolute_offset;  // offset within shard data section
        uint64_t tensor_bytes;
        uint32_t type;
        uint32_t dimensions[4] = {0, 0, 0, 0};
        uint8_t target_device_id = 0;
    };

    std::vector<GlobalTensor> global_tensors;
    uint64_t cumulative_bytes = 0;

    for (uint32_t s = 0; s < shard_count; ++s) {
        auto& ctx = shards[s];
        ctx.file.seekg(ctx.data_offset, std::ios::beg); // re-read tensor directory

        // Tensor directory follows KV directory; we already advanced past it in Pass 1,
        // but we need to re-read from the tensor info start. Re-compute:
        // The file position after KV parsing is the tensor directory start.
        // We saved nothing, so re-seek to data_offset then back up is not possible.
        // Instead, we re-open and re-parse quickly: skip to tensor dir.
        // Simplest: re-read from data_offset backward is not supported, so re-open.
        ctx.file.close();
        ctx.file.open(ctx.path, std::ios::binary);
        if (!ctx.file.is_open()) {
            std::wcerr << L"[-] Failed to reopen shard " << s << L"\n";
            return 1;
        }
        // Skip header
        ctx.file.seekg(8, std::ios::beg);
        uint64_t tc, kvc;
        ctx.file.read(reinterpret_cast<char*>(&tc), 8);
        ctx.file.read(reinterpret_cast<char*>(&kvc), 8);
        // Skip KV directory
        for (uint64_t i = 0; i < kvc; ++i) {
            std::string key = ReadGGUFStr(ctx.file);
            uint32_t type = 0;
            ctx.file.read(reinterpret_cast<char*>(&type), sizeof(type));
            SkipGGUFValue(type, ctx.file);
        }
        // Now at tensor directory
        for (uint64_t t = 0; t < tc; ++t) {
            GlobalTensor gt;
            gt.name = ReadGGUFStr(ctx.file);
            uint32_t n_dims = 0;
            ctx.file.read(reinterpret_cast<char*>(&n_dims), 4);
            if (n_dims > 4) n_dims = 4;
            if (n_dims > 0) ctx.file.read(reinterpret_cast<char*>(gt.dimensions), n_dims * 4);
            ctx.file.read(reinterpret_cast<char*>(&gt.type), sizeof(gt.type));
            ctx.file.read(reinterpret_cast<char*>(&gt.absolute_offset), 8);
            gt.shard_id = s;

            uint64_t bytes = CalcTensorBytes(gt.type,
                std::vector<uint64_t>(gt.dimensions, gt.dimensions + n_dims));
            gt.tensor_bytes = bytes;
            cumulative_bytes += bytes;

            global_tensors.push_back(std::move(gt));
        }

        std::wcout << L"[+] Indexed Shard [" << s << "]: Tensors Found = " << tc << L"\n";
        std::wcout.flush();
    }

    // ------------------------------------------------------------------
    // Pass 3: Write compact serialized ROM manifest to disk
    // ------------------------------------------------------------------
    std::ofstream out_rom(output_path, std::ios::binary | std::ios::trunc);
    if (!out_rom.is_open()) {
        std::wcerr << L"[-] Failed to create output: " << output_path << L"\n";
        return 1;
    }

    RomHeaderMultiShard header{};
    std::memcpy(header.magic, "RAWRXD2\0", 8);
    header.engine_version = 100;
    header.architecture_id = MapArchToID(shards.empty() ? arch : shards[0].detected_arch);
    header.total_shards = shard_count;
    header.total_rom_size = cumulative_bytes;
    header.num_layers = shards.empty() ? 32 : shards[0].num_layers;
    header.num_experts = 0;
    header.top_k_experts = 0;
    header.hidden_dimension = shards.empty() ? 3072 : shards[0].hidden_dim;
    header.kv_heads = shards.empty() ? 32 : shards[0].kv_heads;
    header.metadata_offset = sizeof(RomHeaderMultiShard);
    header.metadata_count = static_cast<uint32_t>(global_tensors.size());

    out_rom.write(reinterpret_cast<const char*>(&header), sizeof(RomHeaderMultiShard));

    // Write tensor descriptors
    for (const auto& gt : global_tensors) {
        TensorDescriptorMultiShard desc{};
        size_t name_len = std::min<size_t>(gt.name.size(), 63);
        std::memcpy(desc.tensor_name, gt.name.c_str(), name_len);
        desc.tensor_name[name_len] = '\0';
        desc.shard_id = gt.shard_id;
        desc.absolute_offset = gt.absolute_offset;
        desc.tensor_bytes = gt.tensor_bytes;
        for (int d = 0; d < 4; ++d) desc.dimensions[d] = gt.dimensions[d];
        desc.quantization_type = static_cast<uint16_t>(MapGGUFTypeToROM(gt.type));
        desc.target_device_id = gt.target_device_id;
        out_rom.write(reinterpret_cast<const char*>(&desc), sizeof(TensorDescriptorMultiShard));
    }

    out_rom.close();

    std::wcout << L"\n[✓] Multi-Shard Mapping Generated.\n";
    std::wcout << L"    Output: " << output_path << L"\n";
    std::wcout << L"    Total tensors: " << global_tensors.size() << L"\n";
    std::wcout << L"    Total shards: " << shard_count << L"\n";
    std::wcout << L"    Cumulative bytes: " << cumulative_bytes << L"\n";
    std::wcout << L"    Manifest size: " << (sizeof(RomHeaderMultiShard) + global_tensors.size() * sizeof(TensorDescriptorMultiShard)) << L" bytes\n";
    std::wcout.flush();

    return 0;
}
