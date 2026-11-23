// isolated_memory_proof.cpp -- measure peak memory in ISOLATED processes:
// one process loads raw tensors only, another loads compressed tensors only.
// This avoids the high-water-mark contamination of a single-process test.
// Build: g++ -std=c++17 -O2 -DRAWRXD_HAVE_ZLIB=1 -I. -I include -I src tools/isolated_memory_proof.cpp -o isolated
// Usage: isolated <model.gguf> <mode: raw|compressed> [max_tensors=N]
#include "src/deep2/TensorAwareLossless.hpp"
#include "src/deep2/TensorWeightStorage.hpp"
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace rawrxd::weights;

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
static uint64_t PeakWorkingSetBytes() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return static_cast<uint64_t>(pmc.PeakWorkingSetSize); // bytes, not KB
    }
    return 0;
}
#else
static uint64_t PeakWorkingSetBytes() { return 0; }
#endif

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
        case 0: return n_elem * 4;  case 1: return n_elem * 2;
        case 2: return (n_elem / 32) * 18;  case 3: return (n_elem / 32) * 20;
        case 6: return (n_elem / 32) * 22;  case 7: return (n_elem / 32) * 24;
        case 8: return (n_elem / 32) * 34;  case 9: return (n_elem / 32) * 36;
        case 10: return (n_elem / 256) * 84;  case 11: return (n_elem / 256) * 110;
        case 12: return (n_elem / 256) * 144; case 13: return (n_elem / 256) * 176;
        case 14: return (n_elem / 256) * 210; case 15: return (n_elem / 256) * 292;
        default: return 0;
    }
}

int main(int argc, char** argv) {
    if (argc < 3) { std::cerr << "usage: isolated <model.gguf> <raw|compressed> [max_tensors=N]\n"; return 2; }
    const std::string path = argv[1];
    const std::string mode = argv[2];
    if (mode != "raw" && mode != "compressed") { std::cerr << "mode must be raw or compressed\n"; return 2; }
    size_t max_tensors = 16;
    if (argc > 3) { std::string a = argv[3]; if (a.rfind("max_tensors=", 0) == 0) max_tensors = std::stoul(a.substr(12)); }

    std::ifstream f(path, std::ios::binary);
    if (!f) { std::cerr << "FAIL: cannot open " << path << "\n"; return 1; }
    char magic[4]; uint32_t version = 0; uint64_t n_tensors = 0, n_kv = 0;
    if (!f.read(magic, 4) || std::memcmp(magic, "GGUF", 4) != 0 || !read_u32(f, version) || !read_u64(f, n_tensors) || !read_u64(f, n_kv)) {
        std::cerr << "FAIL: not a GGUF file\n"; return 1;
    }
    auto skip_value = [&](uint32_t vt) -> bool {
        auto skip = [&](uint64_t n) { return n <= (1ull << 32) && f.seekg(static_cast<std::streamoff>(n), std::ios::cur).good(); };
        switch (vt) {
            case 0: case 1: case 7: return skip(1); case 2: case 3: return skip(2);
            case 4: case 5: case 6: return skip(4); case 10: case 11: case 12: return skip(8);
            case 8: { std::string s; return read_str(f, s); }
            case 9: { uint32_t at = 0; uint64_t alen = 0; if (!read_u32(f, at) || !read_u64(f, alen)) return false;
                if (at == 8) { for (uint64_t i = 0; i < alen; ++i) { std::string s; if (!read_str(f, s)) return false; } return true; }
                uint64_t esz = 0; switch (at) { case 0: case 1: case 7: esz=1; break; case 2: case 3: esz=2; break; case 4: case 5: case 6: esz=4; break; case 10: case 11: case 12: esz=8; break; default: return false; }
                return skip(alen * esz); }
            default: return false;
        }
    };
    for (uint64_t i = 0; i < n_kv; ++i) { std::string k; uint32_t vt = 0; if (!read_str(f, k) || !read_u32(f, vt) || !skip_value(vt)) { std::cerr << "FAIL: truncated kv\n"; return 1; } }

    struct TInfo { std::string name; uint64_t dims[4]; uint32_t n_dims; uint32_t type; uint64_t offset; };
    std::vector<TInfo> infos(n_tensors);
    for (uint64_t i = 0; i < n_tensors; ++i) {
        auto& ti = infos[i];
        if (!read_str(f, ti.name) || !read_u32(f, ti.n_dims) || ti.n_dims > 4) { std::cerr << "FAIL: bad info\n"; return 1; }
        for (uint32_t d = 0; d < ti.n_dims; ++d) if (!read_u64(f, ti.dims[d])) { std::cerr << "FAIL: bad dims\n"; return 1; }
        if (!read_u32(f, ti.type) || !read_u64(f, ti.offset)) { std::cerr << "FAIL: bad type\n"; return 1; }
    }
    const uint64_t ALIGN = 32;
    uint64_t data_start = static_cast<uint64_t>(f.tellg());
    data_start = (data_start + ALIGN - 1) & ~(ALIGN - 1);

    uint64_t total_bytes = 0;
    size_t count = 0;
    if (mode == "raw") {
        // RAW ONLY: load tensors into memory, keep them, measure peak
        std::vector<std::vector<uint8_t>> raw_tensors;
        for (uint64_t i = 0; i < n_tensors && count < max_tensors; ++i) {
            auto& ti = infos[i];
            uint64_t n_elem = 1;
            for (uint32_t d = 0; d < ti.n_dims; ++d) n_elem *= ti.dims[d];
            uint64_t bytes = type_bytes(ti.type, n_elem);
            if (bytes == 0 || bytes > (1ull << 31)) continue;
            std::vector<uint8_t> buf(static_cast<size_t>(bytes));
            f.seekg(static_cast<std::streamoff>(data_start + ti.offset), std::ios::beg);
            if (!f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(bytes))) continue;
            raw_tensors.push_back(std::move(buf));
            total_bytes += raw_tensors.back().size();
            ++count;
        }
        // Force peak: touch all data
        volatile uint8_t sink = 0;
        for (auto& t : raw_tensors) for (auto b : t) sink ^= b;
        uint64_t peak = PeakWorkingSetBytes();
        std::cout << "RESULT mode=raw tensors=" << count << " bytes=" << total_bytes << " peak_ws_bytes=" << peak << "\n";
    } else {
        // COMPRESSED ONLY: compress each tensor, keep compressed form, measure peak
        std::vector<std::vector<uint8_t>> wire_blobs;
        for (uint64_t i = 0; i < n_tensors && count < max_tensors; ++i) {
            auto& ti = infos[i];
            uint64_t n_elem = 1;
            for (uint32_t d = 0; d < ti.n_dims; ++d) n_elem *= ti.dims[d];
            uint64_t bytes = type_bytes(ti.type, n_elem);
            if (bytes == 0 || bytes > (1ull << 31)) continue;
            std::vector<uint8_t> buf(static_cast<size_t>(bytes));
            f.seekg(static_cast<std::streamoff>(data_start + ti.offset), std::ios::beg);
            if (!f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(bytes))) continue;
            uint8_t eb = (ti.type == 0) ? 4 : (ti.type == 1 ? 2 : 1);
            auto t = encode(buf.data(), buf.size(), eb, 65536);
            auto wire = serialize(t);
            wire_blobs.push_back(std::move(wire));
            total_bytes += wire_blobs.back().size();
            ++count;
            // buf goes out of scope here -- raw is freed, only compressed remains
        }
        // Force peak: touch all compressed data
        volatile uint8_t sink = 0;
        for (auto& w : wire_blobs) for (auto b : w) sink ^= b;
        uint64_t peak = PeakWorkingSetBytes();
        std::cout << "RESULT mode=compressed tensors=" << count << " bytes=" << total_bytes << " peak_ws_bytes=" << peak << "\n";
    }
    return 0;
}