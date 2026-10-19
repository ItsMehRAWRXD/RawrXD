#include <windows.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <cstdio>
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

    // ------------------------------------------------------------------
    // Memory-buffer GGUF parser (avoids FILE* positioning issues)
    // ------------------------------------------------------------------
    struct GgufBuffer {
        std::vector<uint8_t> data;
        size_t pos = 0;

        GgufBuffer() = default;
        explicit GgufBuffer(const std::wstring& path) {
            FILE* f = _wfopen(path.c_str(), L"rb");
            if (!f) return;
            if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return; }
            long long sz = _ftelli64(f);
            if (sz <= 0) { fclose(f); return; }
            fseek(f, 0, SEEK_SET);
            data.resize(static_cast<size_t>(sz));
            if (fread(data.data(), 1, data.size(), f) != data.size()) {
                data.clear();
            }
            fclose(f);
        }

        bool valid() const { return !data.empty(); }

        template<typename T>
        bool read(T& out) {
            if (pos + sizeof(T) > data.size()) return false;
            memcpy(&out, data.data() + pos, sizeof(T));
            pos += sizeof(T);
            return true;
        }

        bool read_bytes(void* dst, size_t n) {
            if (pos + n > data.size()) return false;
            memcpy(dst, data.data() + pos, n);
            pos += n;
            return true;
        }

        std::string read_str() {
            uint64_t len = 0;
            if (!read(len)) return "";
            if (len > data.size() - pos) return "";
            std::string s(reinterpret_cast<const char*>(data.data() + pos), len);
            pos += len;
            return s;
        }

        void skip(size_t n) { pos += n; }
    };

    void SkipGGUFValue(uint32_t type, GgufBuffer& buf) {
        if (type <= 7) {
            uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 1};
            buf.skip(sz[type & 7]);
        } else if (type == 8) {
            (void)buf.read_str();
        } else if (type == 9) {
            uint32_t arrayType = 0;
            uint64_t arrayLen = 0;
            buf.read(arrayType);
            buf.read(arrayLen);
            if (arrayType == 8) {
                for (uint64_t i = 0; i < arrayLen; ++i) buf.read_str();
            } else if (arrayType == 9) {
                for (uint64_t i = 0; i < arrayLen; ++i) SkipGGUFValue(arrayType, buf);
            } else {
                uint64_t elem_size = 0;
                if (arrayType <= 7) {
                    uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 1};
                    elem_size = sz[arrayType];
                } else if (arrayType == 10 || arrayType == 11 || arrayType == 12) {
                    elem_size = 8;
                } else {
                    elem_size = 4;
                }
                buf.skip(static_cast<size_t>(arrayLen * elem_size));
            }
        } else if (type == 10 || type == 11 || type == 12) {
            buf.skip(8);
        } else {
            uint32_t sub = 0;
            uint64_t len = 0;
            buf.read(sub);
            buf.read(len);
            if (sub == 9) {
                for (uint64_t i = 0; i < len; ++i) buf.read_str();
            } else {
                uint64_t elem_size = 0;
                if (sub <= 7) {
                    uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 1};
                    elem_size = sz[sub];
                } else if (sub == 10 || sub == 11 || sub == 12) {
                    elem_size = 8;
                } else {
                    elem_size = 4;
                }
                buf.skip(static_cast<size_t>(len * elem_size));
            }
        }
    }

    uint16_t MapGGUFTypeToROM(uint32_t gguf_type) {
        // Store GGUF type codes directly in the ROM manifest.
        // CalcTensorBytes interprets them using the GGML type-code table below.
        return static_cast<uint16_t>(gguf_type);
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
        if (alignment == 0) return offset;
        return (offset + alignment - 1) & ~(alignment - 1);
    }

    // Exact GGML block-based tensor byte sizes per GGML type code.
    // Source: ggml.h GGML_TYPE_* enum and block layout definitions.
    uint64_t CalcTensorBytes(uint32_t type, const std::vector<uint64_t>& dims) {
        uint64_t elements = 1;
        for (auto d : dims) elements *= d;

        switch (type) {
            case 0:  return AlignUp(elements * 4, 64);                          // F32
            case 1:  return AlignUp(elements * 2, 64);                          // F16
            case 2:  { uint64_t b = (elements + 31) / 32; return AlignUp(b * 18, 64); }  // Q4_0
            case 3:  { uint64_t b = (elements + 31) / 32; return AlignUp(b * 20, 64); }  // Q4_1
            case 6:  { uint64_t b = (elements + 31) / 32; return AlignUp(b * 22, 64); }   // Q5_0
            case 7:  { uint64_t b = (elements + 31) / 32; return AlignUp(b * 24, 64); }   // Q5_1
            case 8:  { uint64_t b = (elements + 31) / 32; return AlignUp(b * 34, 64); }   // Q8_0
            case 9:  { uint64_t b = (elements + 31) / 32; return AlignUp(b * 36, 64); }   // Q8_1
            case 10: { uint64_t b = (elements + 255) / 256; return AlignUp(b * 84, 64); }  // Q2_K
            case 11: { uint64_t b = (elements + 255) / 256; return AlignUp(b * 110, 64); } // Q3_K
            case 12: { uint64_t b = (elements + 255) / 256; return AlignUp(b * 144, 64); } // Q4_K
            case 13: { uint64_t b = (elements + 255) / 256; return AlignUp(b * 176, 64); } // Q5_K
            case 14: { uint64_t b = (elements + 255) / 256; return AlignUp(b * 210, 64); } // Q6_K
            case 15: { uint64_t b = (elements + 255) / 256; return AlignUp(b * 292, 64); } // Q8_K
            default: return AlignUp(elements * 2, 64);
        }
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
    std::wstring base_pattern = argv[2];
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
    // Pass 1: Load each shard into memory, parse header + KV metadata,
    //         read tensor directory, compute data_offset from dir_end.
    // ------------------------------------------------------------------
    struct ShardContext {
        std::wstring path;
        GgufBuffer buf;
        uint64_t tensor_count = 0;
        uint64_t kv_count = 0;
        uint64_t data_offset = 0;   // Start of tensor DATA section (aligned)
        uint64_t tensor_dir_offset = 0; // Start of tensor DIRECTORY (right after KV metadata)
        uint64_t data_size = 0;
        uint32_t alignment = 32;    // GGUF general.alignment, default 32
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
        ctx.buf = GgufBuffer(shard_path);
        if (!ctx.buf.valid()) {
            std::wcerr << L"[-] Failed to open shard: " << shard_path << L"\n";
            return 1;
        }

        uint32_t magic = 0, version = 0;
        if (!ctx.buf.read(magic)) { std::wcerr << L"[-] Failed reading magic\n"; return 1; }
        if (!ctx.buf.read(version)) { std::wcerr << L"[-] Failed reading version\n"; return 1; }
        if (magic != 0x46554747u) {
            std::wcerr << L"[-] Shard " << s << " bad magic 0x" << std::hex << magic << L"\n";
            return 1;
        }

        if (!ctx.buf.read(ctx.tensor_count)) { std::wcerr << L"[-] Failed reading tensor_count\n"; return 1; }
        if (!ctx.buf.read(ctx.kv_count)) { std::wcerr << L"[-] Failed reading kv_count\n"; return 1; }

        // Parse KV metadata for architecture info + alignment
        for (uint64_t i = 0; i < ctx.kv_count; ++i) {
            std::string key = ctx.buf.read_str();
            uint32_t type = 0;
            if (!ctx.buf.read(type)) { std::wcerr << L"[-] Failed reading KV type\n"; return 1; }

            if (key == "general.architecture") {
                ctx.detected_arch = ctx.buf.read_str();
            } else if (key == "general.alignment") {
                uint32_t val = 0;
                if (!ctx.buf.read(val)) { std::wcerr << L"[-] Failed reading alignment\n"; return 1; }
                ctx.alignment = val;
            } else if (key == "llama.block_count" || key == "phi3.block_count" ||
                       key == "deepseek.block_count" || key == "general.block_count") {
                uint32_t val = 0;
                if (!ctx.buf.read(val)) { std::wcerr << L"[-] Failed reading KV value\n"; return 1; }
                ctx.num_layers = val;
            } else if (key == "llama.embedding_length" || key == "phi3.embedding_length" ||
                       key == "deepseek.embedding_length" || key == "general.embedding_length") {
                uint32_t val = 0;
                if (!ctx.buf.read(val)) { std::wcerr << L"[-] Failed reading KV value\n"; return 1; }
                ctx.hidden_dim = val;
            } else if (key == "llama.attention.head_count" || key == "phi3.attention.head_count" ||
                       key == "deepseek.attention.head_count" || key == "general.attention.head_count") {
                uint32_t val = 0;
                if (!ctx.buf.read(val)) { std::wcerr << L"[-] Failed reading KV value\n"; return 1; }
                ctx.kv_heads = val;
            } else {
                SkipGGUFValue(type, ctx.buf);
            }
        }

        if (ctx.detected_arch.empty()) ctx.detected_arch = arch;
        if (ctx.num_layers == 0) ctx.num_layers = 32;
        if (ctx.hidden_dim == 0) ctx.hidden_dim = 3072;
        if (ctx.kv_heads == 0) ctx.kv_heads = 32;

        // Tensor directory starts immediately after KV metadata.
        ctx.tensor_dir_offset = ctx.buf.pos;

        // Read tensor directory entries to find where it ends, then data_offset
        // = Align(alignment, dir_end). We store raw GGUF offsets first, then
        // fix up absolute_offsets once data_offset is known.
        struct RawTensor {
            std::string name;
            uint32_t dimensions[4] = {0, 0, 0, 0};
            uint32_t n_dims = 0;
            uint32_t type = 0;
            uint64_t gguf_offset = 0;   // offset relative to data section start
        };
        std::vector<RawTensor> raw_tensors;
        raw_tensors.reserve(ctx.tensor_count);

        for (uint64_t t = 0; t < ctx.tensor_count; ++t) {
            RawTensor rt;
            rt.name = ctx.buf.read_str();
            uint32_t n_dims = 0;
            if (!ctx.buf.read(n_dims)) { std::wcerr << L"[-] Failed reading n_dims\n"; return 1; }
            rt.n_dims = (n_dims > 4) ? 4 : n_dims;
            for (uint32_t d = 0; d < rt.n_dims; ++d) {
                uint64_t val = 0;
                if (!ctx.buf.read(val)) { std::wcerr << L"[-] Failed reading dim\n"; return 1; }
                rt.dimensions[d] = static_cast<uint32_t>(val);
            }
            if (!ctx.buf.read(rt.type)) { std::wcerr << L"[-] Failed reading type\n"; return 1; }
            if (!ctx.buf.read(rt.gguf_offset)) { std::wcerr << L"[-] Failed reading offset\n"; return 1; }
            raw_tensors.push_back(std::move(rt));
        }

        // Tensor DATA starts after the directory, aligned to gguf alignment.
        ctx.data_offset = AlignUp(ctx.buf.pos, ctx.alignment);
        ctx.data_size = static_cast<uint64_t>(ctx.buf.data.size()) - ctx.data_offset;
        ctx.valid = true;

        shards.push_back(std::move(ctx));

        std::wcout << L"[+] Shard " << s << ": " << ctx.tensor_count << L" tensors, "
                   << L"kv=" << ctx.kv_count << L", align=" << ctx.alignment
                   << L", dir_end=0x" << std::hex << ctx.buf.pos << std::dec
                   << L", data_off=0x" << std::hex << ctx.data_offset << std::dec
                   << L", data_size=" << ctx.data_size << L"\n";
        std::wcout.flush();

        // Store raw tensors for Pass 2 (need shard context)
        // We'll re-read in Pass 2 since raw_tensors is local here.
        // Instead, store a reference to raw data via shard index.
        // Simplest: re-parse in Pass 2 using stored tensor_dir_offset.
    }

    // ------------------------------------------------------------------
    // Pass 2: Build global manifest using corrected data_offset per shard
    // ------------------------------------------------------------------
    struct GlobalTensor {
        std::string name;
        uint32_t shard_id;
        uint64_t absolute_offset;
        uint64_t tensor_bytes;
        uint32_t type;
        uint32_t dimensions[4] = {0, 0, 0, 0};
        uint8_t target_device_id = 0;
    };

    std::vector<GlobalTensor> global_tensors;
    uint64_t cumulative_bytes = 0;

    for (uint32_t s = 0; s < shard_count; ++s) {
        auto& ctx = shards[s];
        // Reset buffer position to tensor directory start
        ctx.buf.pos = ctx.tensor_dir_offset;

        for (uint64_t t = 0; t < ctx.tensor_count; ++t) {
            GlobalTensor gt;
            gt.name = ctx.buf.read_str();
            uint32_t n_dims = 0;
            if (!ctx.buf.read(n_dims)) { std::wcerr << L"[-] Failed reading n_dims\n"; return 1; }
            if (s == 0 && t < 10) {
                std::wcout << L"    [T" << t << L"] '" << gt.name.c_str() << L"' n_dims=" << n_dims << L"\n";
            }
            if (n_dims > 4) n_dims = 4;
            if (n_dims > 0) {
                for (uint32_t d = 0; d < n_dims; ++d) {
                    uint64_t val = 0;
                    if (!ctx.buf.read(val)) { std::wcerr << L"[-] Failed reading dim\n"; return 1; }
                    gt.dimensions[d] = static_cast<uint32_t>(val);
                }
            }
            if (!ctx.buf.read(gt.type)) { std::wcerr << L"[-] Failed reading type\n"; return 1; }
            // GGUF tensor offsets are relative to data section start.
            uint64_t gguf_offset = 0;
            if (!ctx.buf.read(gguf_offset)) { std::wcerr << L"[-] Failed reading offset\n"; return 1; }
            gt.absolute_offset = ctx.data_offset + gguf_offset;
            gt.shard_id = s;

            uint64_t bytes = CalcTensorBytes(gt.type,
                std::vector<uint64_t>(gt.dimensions, gt.dimensions + n_dims));
            gt.tensor_bytes = bytes;
            cumulative_bytes += bytes;

            if (s == 0 && t < 10) {
                std::wcout << L"    [T" << t << L"] '" << gt.name.c_str() << L"' n_dims=" << n_dims
                           << L" type=" << gt.type << L" dims=("
                           << gt.dimensions[0] << L"," << gt.dimensions[1] << L"," << gt.dimensions[2] << L"," << gt.dimensions[3] << L")"
                           << L" gguf_off=0x" << std::hex << gguf_offset << std::dec
                           << L" abs_off=0x" << std::hex << gt.absolute_offset << std::dec
                           << L" bytes=" << bytes << L"\n";
            }

            global_tensors.push_back(std::move(gt));
        }

        std::wcout << L"[+] Indexed Shard [" << s << "]: Tensors Found = " << ctx.tensor_count << L"\n";
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
