// gguf_extract_bench.cpp -- extract real tensor payloads from a GGUF file and
// benchmark tensor-aware lossless compression on them.
// Build: g++ -std=c++17 -O2 -DRAWRXD_HAVE_ZLIB=1 -I. -I include -I src tools/gguf_extract_bench.cpp -o gguf_bench
// Usage: gguf_bench <model.gguf> [max_tensors=N]
#include "src/deep2/TensorAwareLossless.hpp"
#include "src/deep2/TensorWeightStorage.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace rawrxd::weights;

// GGUF type sizes (bytes per element) for the types we handle as raw bytes.
static int gguf_type_bytes(uint32_t t) {
    // 0=F32,1=F16,2=Q4_0,3=Q4_1,6=Q5_0,7=Q5_1,8=Q8_0,9=Q8_1,
    // 10=Q2_K,11=Q3_K,12=Q4_K,13=Q5_K,14=Q6_K,15=Q8_K,16=IQ2_XXS,...
    // For non-quantized we know exact sizes; for quantized blocks the "type
    // size" is a block, not a scalar -- we treat the whole tensor bytes as the
    // unit and let the codec decide (element_bytes=1 is safest for packed).
    switch (t) {
        case 0: return 4;  // F32
        case 1: return 2;  // F16
        default: return 0; // quantized: handled as raw bytes (element_bytes=1)
    }
}

struct TensorInfo {
    std::string name;
    uint32_t n_dims = 0;
    uint64_t dims[4] = {0, 0, 0, 0};
    uint32_t type = 0;
    uint64_t offset = 0;
};

static bool read_str(std::ifstream& f, std::string& s) {
    uint64_t len = 0;
    if (!f.read(reinterpret_cast<char*>(&len), sizeof(len))) return false;
    if (len > (1u << 20)) return false;
    s.resize(static_cast<size_t>(len));
    return f.read(s.data(), static_cast<std::streamsize>(len)).good();
}

static bool read_u32(std::ifstream& f, uint32_t& v) {
    return f.read(reinterpret_cast<char*>(&v), sizeof(v)).good();
}
static bool read_u64(std::ifstream& f, uint64_t& v) {
    return f.read(reinterpret_cast<char*>(&v), sizeof(v)).good();
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: gguf_bench <model.gguf> [max_tensors=N]\n";
        return 2;
    }
    const std::string path = argv[1];
    size_t max_tensors = 8;
    if (argc > 2) {
        std::string a = argv[2];
        if (a.rfind("max_tensors=", 0) == 0) max_tensors = std::stoul(a.substr(12));
    }
    std::ifstream f(path, std::ios::binary);
    if (!f) { std::cerr << "cannot open " << path << "\n"; return 1; }

    char magic[4];
    uint32_t version = 0;
    uint64_t n_tensors = 0, n_kv = 0;
    if (!f.read(magic, 4) || std::memcmp(magic, "GGUF", 4) != 0) {
        std::cerr << "not a GGUF file\n"; return 1;
    }
    if (!read_u32(f, version) || !read_u64(f, n_tensors) || !read_u64(f, n_kv)) {
        std::cerr << "truncated header\n"; return 1;
    }
    std::cerr << "GGUF v" << version << " tensors=" << n_tensors << " kv=" << n_kv << "\n";

    // Skip metadata KV pairs. Value types: 0=UINT8,1=INT8,2=UINT16,3=INT16,
    // 4=UINT32,5=INT32,6=FLOAT32,7=BOOL,8=STRING,9=ARRAY,10=UINT64,11=INT64,12=FLOAT64
    auto skip_value = [&](uint32_t vt) -> bool {
        auto skip_bytes = [&](uint64_t n) -> bool {
            if (n > (1ull << 32)) return false;
            return f.seekg(static_cast<std::streamoff>(n), std::ios::cur).good();
        };
        switch (vt) {
            case 0: case 1: case 7: return skip_bytes(1);
            case 2: case 3: return skip_bytes(2);
            case 4: case 5: case 6: return skip_bytes(4);
            case 10: case 11: case 12: return skip_bytes(8);
            case 8: { std::string s; return read_str(f, s); }
            case 9: {
                uint32_t at = 0; uint64_t alen = 0;
                if (!read_u32(f, at) || !read_u64(f, alen)) return false;
                // array of at; need element size to skip
                uint64_t esz = 0;
                switch (at) {
                    case 0: case 1: case 7: esz = 1; break;
                    case 2: case 3: esz = 2; break;
                    case 4: case 5: case 6: esz = 4; break;
                    case 10: case 11: case 12: esz = 8; break;
                    case 8: esz = 0; break; // string array: skip per-element
                    default: return false;
                }
                if (at == 8) {
                    for (uint64_t i = 0; i < alen; ++i) {
                        std::string s; if (!read_str(f, s)) return false;
                    }
                    return true;
                }
                if (alen > (1ull << 32)) return false;
                return skip_bytes(alen * esz);
            }
            default: return false;
        }
    };

    for (uint64_t i = 0; i < n_kv; ++i) {
        std::string key; uint32_t vt = 0;
        if (!read_str(f, key) || !read_u32(f, vt) || !skip_value(vt)) {
            std::cerr << "truncated metadata at kv " << i << "\n"; return 1;
        }
    }

    struct TInfo { std::string name; uint64_t dims[4]; uint32_t n_dims; uint32_t type; uint64_t offset; };
    std::vector<TInfo> infos(n_tensors);
    for (uint64_t i = 0; i < n_tensors; ++i) {
        auto& ti = infos[i];
        if (!read_str(f, ti.name) || !read_u32(f, ti.n_dims) || ti.n_dims > 4) {
            std::cerr << "bad tensor info " << i << "\n"; return 1;
        }
        uint64_t total = 1;
        for (uint32_t d = 0; d < ti.n_dims; ++d) {
            if (!read_u64(f, ti.dims[d])) { std::cerr << "bad dims\n"; return 1; }
            total *= ti.dims[d];
        }
        uint32_t tt = 0;
        if (!read_u32(f, tt) || !read_u64(f, ti.offset)) { std::cerr << "bad type/offset\n"; return 1; }
        ti.type = tt;
    }

    // Alignment: GGUF default alignment is 32; the data section starts at the
    // current position rounded up to alignment. We use 32 (standard).
    const uint64_t ALIGN = 32;
    uint64_t data_start = static_cast<uint64_t>(f.tellg());
    data_start = (data_start + ALIGN - 1) & ~(ALIGN - 1);
    f.seekg(static_cast<std::streamoff>(data_start), std::ios::beg);

    std::cerr << "data_start=" << data_start << "\n";
    size_t done = 0;
    double total_raw = 0, total_comp = 0;
    for (uint64_t i = 0; i < n_tensors && done < max_tensors; ++i) {
        auto& ti = infos[i];
        uint64_t n_elem = 1;
        for (uint32_t d = 0; d < ti.n_dims; ++d) n_elem *= ti.dims[d];
        // bytes: F32=4, F16=2, quantized = we approximate by reading the tensor
        // block count. For a real benchmark we just read the raw tensor span as
        // the next tensor's offset delta, but simpler: compute bytes from type.
        uint64_t bytes = 0;
        int eb = gguf_type_bytes(ti.type);
        if (eb > 0) bytes = n_elem * static_cast<uint64_t>(eb);
        else {
            // Quantized: block types have a block size in elements. Use known
            // block element counts to compute byte size.
            // Q4_0:32, Q4_1:32, Q5_0:32, Q5_1:32, Q8_0:32, Q8_1:32,
            // Q2_K:256, Q3_K:256, Q4_K:256, Q5_K:256, Q6_K:256, Q8_K:256
            uint32_t block_elems = 0, block_bytes = 0;
            switch (ti.type) {
                case 2: block_elems=32; block_bytes=18; break; // Q4_0
                case 3: block_elems=32; block_bytes=20; break; // Q4_1
                case 6: block_elems=32; block_bytes=22; break; // Q5_0
                case 7: block_elems=32; block_bytes=24; break; // Q5_1
                case 8: block_elems=32; block_bytes=34; break; // Q8_0
                case 9: block_elems=32; block_bytes=36; break; // Q8_1
                case 10: block_elems=256; block_bytes=84; break; // Q2_K
                case 11: block_elems=256; block_bytes=110; break; // Q3_K
                case 12: block_elems=256; block_bytes=144; break; // Q4_K
                case 13: block_elems=256; block_bytes=176; break; // Q5_K
                case 14: block_elems=256; block_bytes=210; break; // Q6_K
                case 15: block_elems=256; block_bytes=292; break; // Q8_K
                default: block_elems=0; block_bytes=0; break;
            }
            if (block_elems > 0) bytes = (n_elem / block_elems) * block_bytes;
            else { std::cerr << "skip " << ti.name << " type=" << ti.type << " (unknown)\n"; continue; }
        }
        if (bytes == 0 || bytes > (1ull << 30)) { std::cerr << "skip " << ti.name << " bytes=" << bytes << "\n"; continue; }

        std::vector<uint8_t> buf(static_cast<size_t>(bytes));
        f.seekg(static_cast<std::streamoff>(ti.offset), std::ios::beg);
        // ti.offset is relative to data_start
        f.seekg(static_cast<std::streamoff>(data_start + ti.offset), std::ios::beg);
        if (!f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(bytes))) {
            std::cerr << "read fail " << ti.name << "\n"; continue;
        }

        uint8_t eb_used = (eb > 0) ? static_cast<uint8_t>(eb) : 1;
        auto t = encode(buf.data(), buf.size(), eb_used, 65536);
        auto wire = serialize(t);
        double ratio = wire.size() / static_cast<double>(buf.size());
        total_raw += buf.size();
        total_comp += wire.size();
        std::cout << "tensor=" << ti.name << " type=" << ti.type << " bytes=" << buf.size()
                  << " compressed=" << wire.size() << " ratio=" << ratio << "\n";
        ++done;
    }
    std::cout << "SUMMARY tensors=" << done << " raw=" << total_raw << " compressed=" << total_comp
              << " overall_ratio=" << (total_raw ? total_comp / total_raw : 0) << "\n";
    return 0;
}