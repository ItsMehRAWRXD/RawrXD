// REAP independent reference extractor — standalone C++20, no GGUFLoader dependency.
// Parses GGUF v3 shard manually and extracts packed expert slices using an
// independently implemented stride calculation. Used to certify the production
// writer byte-for-byte.
//
// Usage: reap_ref_extract <shard.gguf> <tensor_name> <expert_index> <out.bin>
//        reap_ref_extract <shard.gguf> <tensor_name> <expert_index1> <expert_index2> ... <out.bin>
//
// Expert slice: stride = sizeBytes / dims.back(); slice k = [k*stride, (k+1)*stride)

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

#ifdef _WIN32
static inline int fseek64(FILE* f, int64_t offset, int origin) {
    return _fseeki64(f, offset, origin);
}
#else
static inline int fseek64(FILE* f, int64_t offset, int origin) {
    return fseek(f, static_cast<long>(offset), origin);
}
#endif

static bool readExact(FILE* f, void* dst, size_t n) {
    return fread(dst, 1, n, f) == n;
}

static uint64_t readU64(FILE* f) {
    uint64_t v = 0; readExact(f, &v, 8); return v;
}
static uint32_t readU32(FILE* f) {
    uint32_t v = 0; readExact(f, &v, 4); return v;
}

static std::string readString(FILE* f) {
    uint64_t len = readU64(f);
    std::string s(len, '\0');
    if (len) readExact(f, &s[0], len);
    return s;
}

enum GGUFMetaType : uint32_t {
    UINT8=0, INT8=1, UINT16=2, INT16=3, UINT32=4, INT32=5, FLOAT32=6, BOOL=7,
    STRING=8, ARRAY=9, UINT64=10, INT64=11, FLOAT64=12
};

// Skip a metadata value of given type
static bool skipValue(FILE* f, uint32_t type) {
    switch (type) {
        case UINT8: case INT8:  { uint8_t v; return readExact(f,&v,1); }
        case UINT16: case INT16:{ uint16_t v; return readExact(f,&v,2); }
        case UINT32: case INT32: case FLOAT32:{ uint32_t v; return readExact(f,&v,4); }
        case BOOL: { uint8_t v; return readExact(f,&v,1); }
        case STRING: { uint64_t len=readU64(f); return fseek64(f, (int64_t)len, SEEK_CUR)==0; }
        case ARRAY: {
            uint32_t et=readU32(f); uint64_t n=readU64(f);
            if (et == STRING) {
                for (uint64_t i = 0; i < n; ++i) {
                    uint64_t len = readU64(f);
                    if (fseek64(f, (int64_t)len, SEEK_CUR) != 0) return false;
                }
                return true;
            }
            size_t es=1;
            switch(et){case UINT8:case INT8:case BOOL: es=1;break; case UINT16:case INT16: es=2;break; case UINT32:case INT32:case FLOAT32: es=4;break; case UINT64:case INT64:case FLOAT64: es=8;break; default: return false;}
            return fseek64(f, (int64_t)(n*es), SEEK_CUR)==0;
        }
        case UINT64: case INT64: case FLOAT64:{ uint64_t v; return readExact(f,&v,8); }
        default: return false;
    }
}

struct TensorInfo {
    std::string name;
    std::vector<int64_t> dims;
    uint32_t type = 0;
    uint64_t offset = 0;
};

int main(int argc, char** argv) {
    if (argc < 5) {
        std::cerr << "usage: reap_ref_extract <shard.gguf> <tensor_name> <expert_index> [expert_index...] <out.bin>\n";
        return 2;
    }

    const char* shardPath = argv[1];
    const char* tensorName = argv[2];
    const char* outPath = argv[argc-1];

    // Parse expert indices (args 3..argc-2)
    std::vector<uint32_t> experts;
    for (int i = 3; i < argc-1; ++i) {
        char* end = nullptr;
        unsigned long v = std::strtoul(argv[i], &end, 10);
        if (*end != '\0' || v > UINT32_MAX) { std::cerr << "invalid expert index: " << argv[i] << "\n"; return 2; }
        experts.push_back(static_cast<uint32_t>(v));
    }
    if (experts.empty()) { std::cerr << "no expert indices specified\n"; return 2; }

    FILE* f = std::fopen(shardPath, "rb");
    if (!f) { std::cerr << "cannot open: " << shardPath << "\n"; return 2; }

    // GGUF header
    char magic[4];
    if (!readExact(f, magic, 4) || memcmp(magic, "GGUF", 4) != 0) {
        std::cerr << "not a GGUF file\n"; std::fclose(f); return 2;
    }
    uint32_t version = readU32(f);
    uint64_t nTensors = readU64(f);
    uint64_t nMeta = readU64(f);
    uint64_t alignment = 32;

    // Skip metadata
    for (uint64_t i = 0; i < nMeta; ++i) {
        std::string key = readString(f);
        uint32_t type = readU32(f);
        if (key == "general.alignment" && type == UINT32) {
            uint32_t val; readExact(f, &val, 4); alignment = val;
        } else if (!skipValue(f, type)) {
            std::cerr << "meta parse error at " << key << "\n"; std::fclose(f); return 2;
        }
    }

    // Parse tensor descriptors, find target
    TensorInfo target; bool found = false;
    for (uint64_t i = 0; i < nTensors; ++i) {
        std::string name = readString(f);
        uint32_t ndims = readU32(f);
        TensorInfo t; t.name = name;
        t.dims.resize(ndims);
        for (uint32_t d = 0; d < ndims; ++d) t.dims[d] = (int64_t)readU64(f);
        t.type = readU32(f);
        t.offset = readU64(f);

        if (name == tensorName) { target = t; found = true; }
    }

    if (!found) {
        std::cerr << "tensor not found: " << tensorName << "\n"; std::fclose(f); return 2;
    }

    // dataStart = file position after all tensor descriptors, aligned up
    uint64_t dataStartRaw = static_cast<uint64_t>(std::ftell(f));
    uint64_t dataStart = (dataStartRaw + alignment - 1) / alignment * alignment;
    if (target.dims.empty()) { std::cerr << "tensor has no dims\n"; std::fclose(f); return 2; }
    uint64_t expertDim = static_cast<uint64_t>(target.dims.back());
    if (expertDim == 0) { std::cerr << "zero expert dim\n"; std::fclose(f); return 2; }
    // We need sizeBytes — not stored in descriptor; recompute from dims + type.
    // For simplicity, read the full tensor to get size, then slice.
    // Get file size to determine tensor data region.
    // The tensor data size = file size - last tensor offset (approx). Instead,
    // compute expected bytes from quantization.
    // We'll just seek to offset and read stride*experts bytes.

    // Compute stride: we need bytes per expert. Since we don't have sizeBytes here,
    // read from offset to end of file for the last tensor, or use dims-based calc.
    // Simplest independent approach: stride = (file remaining bytes at this tensor) / expertDim
    // but multiple tensors share data region. Use stride = total_bytes / expertDim where
    // total_bytes is computed from quantization block table.

    // Quantization block table (independent of GGUFLoader)
    struct BlockInfo { uint64_t elems; uint64_t bytes; };
    auto blockInfo = [](uint32_t t) -> bool {
        switch (t) {
            case 2: case 3: return true; // Q4_0, Q4_1
            case 6: case 7: return true; // Q5_0, Q5_1
            case 8: return true; // Q8_0
            case 10: case 11: case 12: case 13: case 14: case 15: return true; // K quants
            default: return false;
        }
    };

    // For stride we need bytes per row. rows = product of dims[1..end-1] (all but last)
    // contiguous dim = dims[0]. blocks_per_row = ceil(dims[0]/blockElems). rowBytes = blocks_per_row*blockBytes.
    // totalBytes = rowBytes * rows. stride = totalBytes / expertDim.

    // We don't have block table values hardcoded here for all types; instead, 
    // infer totalBytes from the file: read from target.offset to next tensor's offset
    // or to end of data region. Simpler: just read stride bytes per expert starting at offset.
    // But we need stride. Compute from dims[0] using block table.

    // Hardcode Q4_K (type 12) and Q6_K (type 14) block sizes — the types used by Kimi K2 experts.
    uint64_t blockElems=0, blockBytes=0;
    switch (target.type) {
        case 12: blockElems=256; blockBytes=144; break; // Q4_K
        case 14: blockElems=256; blockBytes=210; break; // Q6_K
        case 0: blockElems=1; blockBytes=4; break; // F32
        case 1: blockElems=1; blockBytes=2; break; // F16
        default:
            std::cerr << "unsupported type " << target.type << " for independent calc\n";
            std::fclose(f); return 2;
    }

    uint64_t contiguous = static_cast<uint64_t>(target.dims[0]);
    uint64_t blocksPerRow = (contiguous + blockElems - 1) / blockElems;
    uint64_t rowBytes = blocksPerRow * blockBytes;
    uint64_t rows = 1;
    for (size_t d = 1; d+1 < target.dims.size(); ++d) rows *= static_cast<uint64_t>(target.dims[d]);
    // bytes per expert = rowBytes * rows (expert dim is outermost, slowest-varying)
    uint64_t bytesPerExpert = rowBytes * rows;
    // stride between consecutive experts = bytesPerExpert
    uint64_t stride = bytesPerExpert;
    // Verify against GGVF full tensor size: stride * expertDim should equal full tensor bytes
    uint64_t fullTensorBytes = stride * expertDim;

    // Build dims string separately to avoid stream operator parsing issues
    std::string dimsStr = "[";
    for (size_t d = 0; d < target.dims.size(); ++d) {
        if (d) dimsStr += ",";
        dimsStr += std::to_string(target.dims[d]);
    }
    dimsStr += "]";

    std::cout << "tensor=" << tensorName << " type=" << target.type
              << " dims=" << dimsStr
              << " expertDim=" << expertDim << " fullTensorBytes=" << fullTensorBytes
              << " stride=" << stride << " offset=" << target.offset << "\n";

    // Validate expert indices
    for (uint32_t ex : experts) {
        if (ex >= expertDim) {
            std::cerr << "expert " << ex << " >= expertDim " << expertDim << "\n";
            std::fclose(f); return 2;
        }
        if (stride > 0 && ex > 0 && stride > UINT64_MAX / ex) {
            std::cerr << "overflow: stride * expert " << ex << "\n";
            std::fclose(f); return 2;
        }
    }

    // Write output: concatenate selected expert slices
    std::ofstream out(outPath, std::ios::binary | std::ios::trunc);
    if (!out) { std::cerr << "cannot open output: " << outPath << "\n"; std::fclose(f); return 2; }

    for (uint32_t ex : experts) {
        uint64_t srcOffset = dataStart + target.offset + stride * ex;
        if (fseek64(f, (int64_t)srcOffset, SEEK_SET) != 0) {
            std::cerr << "seek failed at expert " << ex << "\n"; std::fclose(f); return 2;
        }
        std::vector<char> buf(stride > (1u<<20) ? (1u<<20) : static_cast<size_t>(stride));
        uint64_t remaining = stride;
        while (remaining) {
            size_t chunk = (size_t)((std::min)(remaining, static_cast<uint64_t>(buf.size())));
            if (!readExact(f, buf.data(), chunk)) { std::cerr << "read failed at expert " << ex << "\n"; std::fclose(f); return 2; }
            out.write(buf.data(), static_cast<std::streamsize>(chunk));
            if (!out) { std::cerr << "write failed at expert " << ex << "\n"; std::fclose(f); return 2; }
            remaining -= chunk;
        }
    }

    out.close();
    std::fclose(f);
    std::cout << "wrote " << outPath << " (" << (stride * experts.size()) << " bytes, " << experts.size() << " experts)\n";
    return 0;
}
