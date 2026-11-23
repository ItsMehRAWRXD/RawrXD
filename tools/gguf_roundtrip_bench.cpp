// gguf_roundtrip_bench.cpp -- extract real GGUF tensors, tensor-aware compress,
// decompress, and VERIFY byte-exact roundtrip. Reports compression ratios and
// per-codec selection. No synthetic data: real model weights only.
// Build: g++ -std=c++17 -O2 -DRAWRXD_HAVE_ZLIB=1 -I. -I include -I src tools/gguf_roundtrip_bench.cpp -o gguf_rt
// Usage: gguf_rt <model.gguf> [max_tensors=N] [block_bytes=65536]
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

static bool read_str(std::ifstream& f, std::string& s) {
    uint64_t len = 0;
    if (!f.read(reinterpret_cast<char*>(&len), sizeof(len))) return false;
    if (len > (1u << 20)) return false;
    s.resize(static_cast<size_t>(len));
    return f.read(s.data(), static_cast<std::streamsize>(len)).good();
}
static bool read_u32(std::ifstream& f, uint32_t& v) { return f.read(reinterpret_cast<char*>(&v), sizeof(v)).good(); }
static bool read_u64(std::ifstream& f, uint64_t& v) { return f.read(reinterpret_cast<char*>(&v), sizeof(v)).good(); }

static uint64_t type_bytes(uint32_t t, uint64_t n_elem) {
    switch (t) {
        case 0: return n_elem * 4;  // F32
        case 1: return n_elem * 2;  // F16
        case 2: return (n_elem / 32) * 18;  // Q4_0
        case 3: return (n_elem / 32) * 20;  // Q4_1
        case 6: return (n_elem / 32) * 22;  // Q5_0
        case 7: return (n_elem / 32) * 24;  // Q5_1
        case 8: return (n_elem / 32) * 34;  // Q8_0
        case 9: return (n_elem / 32) * 36;  // Q8_1
        case 10: return (n_elem / 256) * 84;  // Q2_K
        case 11: return (n_elem / 256) * 110; // Q3_K
        case 12: return (n_elem / 256) * 144; // Q4_K
        case 13: return (n_elem / 256) * 176; // Q5_K
        case 14: return (n_elem / 256) * 210; // Q6_K
        case 15: return (n_elem / 256) * 292; // Q8_K
        default: return 0;
    }
}

int main(int argc, char** argv) {
    if (argc < 2) { std::cerr << "usage: gguf_rt <model.gguf> [max_tensors=N] [block_bytes=65536]\n"; return 2; }
    const std::string path = argv[1];
    size_t max_tensors = 12;
    uint32_t block = 65536;
    size_t skipped = 0;
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a.rfind("max_tensors=", 0) == 0) max_tensors = std::stoul(a.substr(12));
        else if (a.rfind("block=", 0) == 0) {
            const auto requested = std::stoull(a.substr(6));
            if (requested == 0 || requested > UINT32_MAX) {
                std::cerr << "invalid block size\n"; return 2;
            }
            block = static_cast<uint32_t>(requested);
        }
    }
    std::ifstream f(path, std::ios::binary);
    if (!f) { std::cerr << "cannot open " << path << "\n"; return 1; }
    char magic[4]; uint32_t version = 0; uint64_t n_tensors = 0, n_kv = 0;
    if (!f.read(magic, 4) || std::memcmp(magic, "GGUF", 4) != 0 || !read_u32(f, version) || !read_u64(f, n_tensors) || !read_u64(f, n_kv)) {
        std::cerr << "not a GGUF file\n"; return 1;
    }
    auto skip_value = [&](uint32_t vt) -> bool {
        auto skip = [&](uint64_t n) { return n <= (1ull << 32) && f.seekg(static_cast<std::streamoff>(n), std::ios::cur).good(); };
        switch (vt) {
            case 0: case 1: case 7: return skip(1);
            case 2: case 3: return skip(2);
            case 4: case 5: case 6: return skip(4);
            case 10: case 11: case 12: return skip(8);
            case 8: { std::string s; return read_str(f, s); }
            case 9: { uint32_t at = 0; uint64_t alen = 0; if (!read_u32(f, at) || !read_u64(f, alen)) return false;
                if (at == 8) { for (uint64_t i = 0; i < alen; ++i) { std::string s; if (!read_str(f, s)) return false; } return true; }
                uint64_t esz = 0; switch (at) { case 0: case 1: case 7: esz=1; break; case 2: case 3: esz=2; break; case 4: case 5: case 6: esz=4; break; case 10: case 11: case 12: esz=8; break; default: return false; }
                return skip(alen * esz); }
            default: return false;
        }
    };
    for (uint64_t i = 0; i < n_kv; ++i) { std::string k; uint32_t vt = 0; if (!read_str(f, k) || !read_u32(f, vt) || !skip_value(vt)) { std::cerr << "truncated kv\n"; return 1; } }

    struct TInfo { std::string name; uint64_t dims[4]; uint32_t n_dims; uint32_t type; uint64_t offset; };
    std::vector<TInfo> infos(n_tensors);
    for (uint64_t i = 0; i < n_tensors; ++i) {
        auto& ti = infos[i];
        if (!read_str(f, ti.name) || !read_u32(f, ti.n_dims) || ti.n_dims > 4) { std::cerr << "bad info\n"; return 1; }
        for (uint32_t d = 0; d < ti.n_dims; ++d) if (!read_u64(f, ti.dims[d])) { std::cerr << "bad dims\n"; return 1; }
        if (!read_u32(f, ti.type) || !read_u64(f, ti.offset)) { std::cerr << "bad type\n"; return 1; }
    }
    const uint64_t ALIGN = 32;
    uint64_t data_start = static_cast<uint64_t>(f.tellg());
    data_start = (data_start + ALIGN - 1) & ~(ALIGN - 1);

    size_t done = 0, ok = 0, fail = 0;
    uint64_t total_raw = 0, total_comp = 0;
    uint32_t codec_counts[4] = {0, 0, 0, 0}; // Raw, Zlib, ByteShuffle, DeltaShuffle
    for (uint64_t i = 0; i < n_tensors && done < max_tensors; ++i) {
        auto& ti = infos[i];
        uint64_t n_elem = 1;
        for (uint32_t d = 0; d < ti.n_dims; ++d) n_elem *= ti.dims[d];
        uint64_t bytes = type_bytes(ti.type, n_elem);
        if (bytes == 0 || bytes > (1ull << 31)) {
            ++skipped;
            std::cerr << "SKIP " << ti.name << " unsupported type or size\n";
            continue;
        }
        std::vector<uint8_t> buf(static_cast<size_t>(bytes));
        f.seekg(static_cast<std::streamoff>(data_start + ti.offset), std::ios::beg);
        if (!f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(bytes))) {
            ++skipped;
            std::cerr << "SKIP " << ti.name << " unreadable tensor bytes\n";
            f.clear();
            continue;
        }
        uint8_t eb = (ti.type == 0) ? 4 : (ti.type == 1 ? 2 : 1);
        auto t = encode(buf.data(), buf.size(), eb, block);
        auto wire = serialize(t);
        auto restored = deserialize(wire);
        auto decoded = decode_range(restored, 0, buf.size());
        bool match = (decoded == buf);
        if (match) ++ok; else ++fail;
        total_raw += buf.size(); total_comp += wire.size();
        for (const auto& b : t.blocks) codec_counts[static_cast<int>(b.codec)]++;
        double ratio = wire.size() / static_cast<double>(buf.size());
        std::cout << (match ? "OK " : "FAIL ") << ti.name << " type=" << ti.type << " bytes=" << buf.size()
                  << " comp=" << wire.size() << " ratio=" << ratio << "\n";
        ++done;
    }
    std::cout << "SUMMARY tensors=" << done << " roundtrip_ok=" << ok << " fail=" << fail
              << " raw=" << total_raw << " comp=" << total_comp
              << " overall_ratio=" << (total_raw ? static_cast<double>(total_comp) / static_cast<double>(total_raw) : 0.0)
              << " skipped=" << skipped
              << " codecs[Raw=" << codec_counts[0] << " Zlib=" << codec_counts[1]
              << " Shuffle=" << codec_counts[2] << " DeltaShuffle=" << codec_counts[3] << "]\n";
    // A clean exit must represent at least one checked tensor; skipped tensors
    // remain visible so incomplete model coverage cannot be mistaken for certification.
    return (fail == 0 && ok > 0 && skipped == 0) ? 0 : 1;
}