#include <algorithm>
#include <cctype>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <limits>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

constexpr uint32_t kGgufMagic = 0x46554747u; // "GGUF"

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

struct KVEntry {
    std::string key;
    uint32_t type = 0;
    std::vector<uint8_t> rawValue;
};

struct TensorInfo {
    std::string name;
    uint32_t nDims = 0;
    std::vector<uint64_t> dims;
    uint32_t ggmlType = 0;
    uint64_t offset = 0;
    uint64_t byteSize = 0;
};

struct GGUFFile {
    uint32_t version = 0;
    uint64_t alignment = 32;
    uint64_t dataStart = 0;
    uint64_t fileSize = 0;
    std::vector<KVEntry> kv;
    std::vector<TensorInfo> tensors;
};

bool readExact(std::ifstream& in, void* dst, size_t bytes) {
    in.read(static_cast<char*>(dst), static_cast<std::streamsize>(bytes));
    return in.good();
}

bool writeExact(std::ofstream& out, const void* src, size_t bytes) {
    out.write(static_cast<const char*>(src), static_cast<std::streamsize>(bytes));
    return out.good();
}

template <typename T>
bool readScalar(std::ifstream& in, T& value) {
    static_assert(std::is_trivially_copyable<T>::value, "scalar must be trivially copyable");
    return readExact(in, &value, sizeof(T));
}

template <typename T>
bool writeScalar(std::ofstream& out, const T& value) {
    static_assert(std::is_trivially_copyable<T>::value, "scalar must be trivially copyable");
    return writeExact(out, &value, sizeof(T));
}

uint64_t alignUp(uint64_t x, uint64_t a) {
    if (a == 0) {
        return x;
    }
    const uint64_t r = x % a;
    return r == 0 ? x : (x + (a - r));
}

bool readGGUFString(std::ifstream& in, uint32_t version, std::string& out) {
    uint64_t len = 0;
    if (version == 1) {
        uint32_t len32 = 0;
        if (!readScalar(in, len32)) {
            return false;
        }
        len = len32;
    } else {
        if (!readScalar(in, len)) {
            return false;
        }
    }
    if (len > static_cast<uint64_t>(std::numeric_limits<int32_t>::max())) {
        return false;
    }
    out.assign(static_cast<size_t>(len), '\0');
    if (len == 0) {
        return true;
    }
    return readExact(in, out.data(), static_cast<size_t>(len));
}

bool writeGGUFString(std::ofstream& out, uint32_t version, const std::string& value) {
    if (version == 1) {
        const uint32_t len32 = static_cast<uint32_t>(value.size());
        if (!writeScalar(out, len32)) {
            return false;
        }
    } else {
        const uint64_t len64 = static_cast<uint64_t>(value.size());
        if (!writeScalar(out, len64)) {
            return false;
        }
    }
    if (value.empty()) {
        return true;
    }
    return writeExact(out, value.data(), value.size());
}

bool skipValue(std::ifstream& in, uint32_t version, uint32_t type);

bool skipArray(std::ifstream& in, uint32_t version) {
    uint32_t elemType = 0;
    if (!readScalar(in, elemType)) {
        return false;
    }

    uint64_t count = 0;
    if (version == 1) {
        uint32_t c32 = 0;
        if (!readScalar(in, c32)) {
            return false;
        }
        count = c32;
    } else {
        if (!readScalar(in, count)) {
            return false;
        }
    }

    for (uint64_t i = 0; i < count; ++i) {
        if (!skipValue(in, version, elemType)) {
            return false;
        }
    }
    return true;
}

bool skipValue(std::ifstream& in, uint32_t version, uint32_t type) {
    switch (type) {
        case GGUF_TYPE_UINT8:
        case GGUF_TYPE_INT8:
        case GGUF_TYPE_BOOL: {
            uint8_t v = 0;
            return readScalar(in, v);
        }
        case GGUF_TYPE_UINT16:
        case GGUF_TYPE_INT16: {
            uint16_t v = 0;
            return readScalar(in, v);
        }
        case GGUF_TYPE_UINT32:
        case GGUF_TYPE_INT32:
        case GGUF_TYPE_FLOAT32: {
            uint32_t v = 0;
            return readScalar(in, v);
        }
        case GGUF_TYPE_UINT64:
        case GGUF_TYPE_INT64:
        case GGUF_TYPE_FLOAT64: {
            uint64_t v = 0;
            return readScalar(in, v);
        }
        case GGUF_TYPE_STRING: {
            std::string s;
            return readGGUFString(in, version, s);
        }
        case GGUF_TYPE_ARRAY:
            return skipArray(in, version);
        default:
            return false;
    }
}

bool parseGGUF(const std::string& path, GGUFFile& out, std::string& error) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        error = "failed to open input GGUF";
        return false;
    }

    in.seekg(0, std::ios::end);
    const std::streamoff endPos = in.tellg();
    in.seekg(0, std::ios::beg);
    if (endPos <= 0) {
        error = "input file is empty";
        return false;
    }
    out.fileSize = static_cast<uint64_t>(endPos);

    uint32_t magic = 0;
    if (!readScalar(in, magic) || magic != kGgufMagic) {
        error = "invalid GGUF magic";
        return false;
    }

    if (!readScalar(in, out.version)) {
        error = "failed to read GGUF version";
        return false;
    }
    std::printf("[GGUF_Truncator] GGUF version: %u\n", out.version);
    if (out.version < 1 || out.version > 4) {
        error = "unsupported GGUF version";
        return false;
    }

    uint64_t nTensors = 0;
    uint64_t nKV = 0;
    if (out.version == 1) {
        uint32_t t32 = 0;
        uint32_t kv32 = 0;
        if (!readScalar(in, t32) || !readScalar(in, kv32)) {
            error = "failed to read GGUF header counts";
            return false;
        }
        nTensors = t32;
        nKV = kv32;
    } else {
        if (!readScalar(in, nTensors) || !readScalar(in, nKV)) {
            error = "failed to read GGUF header counts";
            return false;
        }
    }
    std::printf("[GGUF_Truncator] nTensors=%llu, nKV=%llu\n", nTensors, nKV);

    out.kv.clear();
    out.kv.reserve(static_cast<size_t>(nKV));

    for (uint64_t i = 0; i < nKV; ++i) {
        KVEntry entry;
        if (!readGGUFString(in, out.version, entry.key)) {
            error = "failed to read GGUF KV key";
            return false;
        }
        if (!readScalar(in, entry.type)) {
            error = "failed to read GGUF KV type";
            return false;
        }

        const std::streamoff valueBegin = in.tellg();
        if (valueBegin < 0) {
            error = "failed to capture KV begin offset";
            return false;
        }
        if (!skipValue(in, out.version, entry.type)) {
            error = "failed to skip GGUF KV value";
            return false;
        }
        const std::streamoff valueEnd = in.tellg();
        if (valueEnd < valueBegin) {
            error = "invalid KV range";
            return false;
        }
        const size_t valueBytes = static_cast<size_t>(valueEnd - valueBegin);
        entry.rawValue.resize(valueBytes);

        in.seekg(valueBegin);
        if (!readExact(in, entry.rawValue.data(), valueBytes)) {
            error = "failed to read KV raw value";
            return false;
        }
        in.seekg(valueEnd);

        if (entry.key == "general.alignment" && entry.type == GGUF_TYPE_UINT32 && entry.rawValue.size() >= 4) {
            uint32_t a = 0;
            std::memcpy(&a, entry.rawValue.data(), sizeof(uint32_t));
            if (a != 0) {
                out.alignment = a;
            }
        }
        out.kv.push_back(std::move(entry));
    }

    out.tensors.clear();
    out.tensors.reserve(static_cast<size_t>(nTensors));
    for (uint64_t i = 0; i < nTensors; ++i) {
        TensorInfo ti;
        if (!readGGUFString(in, out.version, ti.name)) {
            error = "failed to read tensor name";
            return false;
        }
        if (!readScalar(in, ti.nDims)) {
            error = "failed to read tensor n_dims";
            return false;
        }
        ti.dims.resize(ti.nDims);
        for (uint32_t d = 0; d < ti.nDims; ++d) {
            if (!readScalar(in, ti.dims[d])) {
                error = "failed to read tensor dim";
                return false;
            }
        }
        if (!readScalar(in, ti.ggmlType) || !readScalar(in, ti.offset)) {
            error = "failed to read tensor type/offset";
            return false;
        }
        out.tensors.push_back(std::move(ti));
    }

    const uint64_t afterInfos = static_cast<uint64_t>(in.tellg());
    out.dataStart = alignUp(afterInfos, out.alignment);
    if (out.dataStart > out.fileSize) {
        error = "tensor data start beyond file size";
        return false;
    }

    std::vector<size_t> order(out.tensors.size());
    for (size_t i = 0; i < order.size(); ++i) {
        order[i] = i;
    }
    std::sort(order.begin(), order.end(), [&](size_t a, size_t b) {
        return out.tensors[a].offset < out.tensors[b].offset;
    });

    for (size_t i = 0; i < order.size(); ++i) {
        std::printf("[GGUF_Truncator] Tensor[%zu] name=%s, offset=%llu\n", i, out.tensors[order[i]].name.c_str(), out.tensors[order[i]].offset);
    }

    const uint64_t dataBytes = out.fileSize - out.dataStart;
    std::printf("[GGUF_Truncator] dataStart=%llu, fileSize=%llu, dataBytes=%llu\n", out.dataStart, out.fileSize, dataBytes);
    for (size_t i = 0; i < order.size(); ++i) {
        const size_t idx = order[i];
        const uint64_t begin = out.tensors[idx].offset;
        const uint64_t end = (i + 1 < order.size()) ? out.tensors[order[i + 1]].offset : dataBytes;
        if (end < begin || end > dataBytes) {
            std::printf("[GGUF_Truncator] TENSOR ERROR: name=%s, begin=%llu, end=%llu, dataBytes=%llu\n", out.tensors[idx].name.c_str(), begin, end, dataBytes);
            error = "invalid tensor offset layout";
            return false;
        }
        out.tensors[idx].byteSize = end - begin;
    }

    return true;
}

bool parseBlockIndex(const std::string& name, int& outIdx) {
    if (name.rfind("blk.", 0) != 0) {
        return false;
    }
    size_t i = 4;
    if (i >= name.size() || !std::isdigit(static_cast<unsigned char>(name[i]))) {
        return false;
    }
    int value = 0;
    while (i < name.size() && std::isdigit(static_cast<unsigned char>(name[i]))) {
        value = value * 10 + (name[i] - '0');
        ++i;
    }
    outIdx = value;
    return true;
}

bool shouldKeepTensor(const std::string& name, int targetLayers) {
    int blk = -1;
    if (!parseBlockIndex(name, blk)) {
        return true;
    }
    return blk < targetLayers;
}

std::vector<uint8_t> encodeLayerValue(const KVEntry& kv, int targetLayers) {
    std::vector<uint8_t> out = kv.rawValue;
    if (kv.type == GGUF_TYPE_UINT32 || kv.type == GGUF_TYPE_INT32) {
        if (out.size() >= 4) {
            uint32_t v = static_cast<uint32_t>(targetLayers);
            std::memcpy(out.data(), &v, sizeof(uint32_t));
        }
    } else if (kv.type == GGUF_TYPE_UINT64 || kv.type == GGUF_TYPE_INT64) {
        if (out.size() >= 8) {
            uint64_t v = static_cast<uint64_t>(targetLayers);
            std::memcpy(out.data(), &v, sizeof(uint64_t));
        }
    }
    return out;
}

bool isBlockCountKey(const std::string& key) {
    if (key == "general.block_count" || key == "n_layer") {
        return true;
    }
    const std::string suffix = ".block_count";
    return key.size() >= suffix.size() && key.compare(key.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool truncateGGUF(const std::string& inputPath, const std::string& outputPath, int targetLayers, std::string& error) {
    GGUFFile src;
    if (!parseGGUF(inputPath, src, error)) {
        return false;
    }

    std::vector<size_t> keptTensorIdx;
    keptTensorIdx.reserve(src.tensors.size());
    for (size_t i = 0; i < src.tensors.size(); ++i) {
        if (shouldKeepTensor(src.tensors[i].name, targetLayers)) {
            keptTensorIdx.push_back(i);
        }
    }
    if (keptTensorIdx.empty()) {
        error = "no tensors remain after truncation";
        return false;
    }

    std::ofstream out(outputPath, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        error = "failed to open output path";
        return false;
    }

    if (!writeScalar(out, kGgufMagic) || !writeScalar(out, src.version)) {
        error = "failed to write GGUF header";
        return false;
    }

    const uint64_t newNTensors = static_cast<uint64_t>(keptTensorIdx.size());
    const uint64_t newNKV = static_cast<uint64_t>(src.kv.size());
    if (src.version == 1) {
        const uint32_t t32 = static_cast<uint32_t>(newNTensors);
        const uint32_t kv32 = static_cast<uint32_t>(newNKV);
        if (!writeScalar(out, t32) || !writeScalar(out, kv32)) {
            error = "failed to write v1 GGUF counts";
            return false;
        }
    } else {
        if (!writeScalar(out, newNTensors) || !writeScalar(out, newNKV)) {
            error = "failed to write GGUF counts";
            return false;
        }
    }

    size_t patchedBlockCountKeys = 0;
    for (const KVEntry& kv : src.kv) {
        if (!writeGGUFString(out, src.version, kv.key) || !writeScalar(out, kv.type)) {
            error = "failed to write KV key/type";
            return false;
        }

        const bool isBlockCount = isBlockCountKey(kv.key);
        if (isBlockCount) {
            ++patchedBlockCountKeys;
        }
        const std::vector<uint8_t> valueBytes = isBlockCount ? encodeLayerValue(kv, targetLayers) : kv.rawValue;
        if (!valueBytes.empty() && !writeExact(out, valueBytes.data(), valueBytes.size())) {
            error = "failed to write KV value";
            return false;
        }
    }

    if (patchedBlockCountKeys == 0) {
        error = "no block_count metadata key was patched";
        return false;
    }

    std::unordered_map<size_t, uint64_t> newOffsets;
    uint64_t cursor = 0;
    for (size_t idx : keptTensorIdx) {
        cursor = alignUp(cursor, src.alignment);
        newOffsets[idx] = cursor;
        cursor += src.tensors[idx].byteSize;
    }

    for (size_t idx : keptTensorIdx) {
        const TensorInfo& t = src.tensors[idx];
        if (!writeGGUFString(out, src.version, t.name) || !writeScalar(out, t.nDims)) {
            error = "failed to write tensor header";
            return false;
        }
        for (uint64_t dim : t.dims) {
            if (!writeScalar(out, dim)) {
                error = "failed to write tensor dims";
                return false;
            }
        }
        if (!writeScalar(out, t.ggmlType) || !writeScalar(out, newOffsets[idx])) {
            error = "failed to write tensor type/offset";
            return false;
        }
    }

    const uint64_t dataStartOut = alignUp(static_cast<uint64_t>(out.tellp()), src.alignment);
    const uint64_t dataStartPad = dataStartOut - static_cast<uint64_t>(out.tellp());
    if (dataStartPad > 0) {
        std::vector<uint8_t> pad(static_cast<size_t>(dataStartPad), 0);
        if (!writeExact(out, pad.data(), pad.size())) {
            error = "failed to write data alignment padding";
            return false;
        }
    }

    std::ifstream in(inputPath, std::ios::binary);
    if (!in.is_open()) {
        error = "failed to reopen input for tensor copy";
        return false;
    }

    std::vector<uint8_t> copyBuf;
    for (size_t idx : keptTensorIdx) {
        const TensorInfo& t = src.tensors[idx];
        const uint64_t outOffset = newOffsets[idx];
        const uint64_t desiredOutPos = dataStartOut + outOffset;
        const uint64_t currentOutPos = static_cast<uint64_t>(out.tellp());
        if (desiredOutPos > currentOutPos) {
            std::vector<uint8_t> pad(static_cast<size_t>(desiredOutPos - currentOutPos), 0);
            if (!writeExact(out, pad.data(), pad.size())) {
                error = "failed to write tensor alignment padding";
                return false;
            }
        }

        const uint64_t srcPos = src.dataStart + t.offset;
        in.seekg(static_cast<std::streamoff>(srcPos), std::ios::beg);
        if (!in.good()) {
            error = "failed to seek input tensor data";
            return false;
        }
        copyBuf.resize(static_cast<size_t>(t.byteSize));
        if (t.byteSize > 0 && !readExact(in, copyBuf.data(), copyBuf.size())) {
            error = "failed to read input tensor bytes";
            return false;
        }
        if (t.byteSize > 0 && !writeExact(out, copyBuf.data(), copyBuf.size())) {
            error = "failed to write output tensor bytes";
            return false;
        }
    }

    out.flush();
    if (!out.good()) {
        error = "failed to flush output GGUF";
        return false;
    }

    std::printf("[GGUF_Truncator] done\n");
    std::printf("[GGUF_Truncator] input=%s\n", inputPath.c_str());
    std::printf("[GGUF_Truncator] output=%s\n", outputPath.c_str());
    std::printf("[GGUF_Truncator] target_layers=%d\n", targetLayers);
    std::printf("[GGUF_Truncator] tensors_kept=%zu/%zu\n", keptTensorIdx.size(), src.tensors.size());
    std::printf("[GGUF_Truncator] block_count_keys_patched=%zu\n", patchedBlockCountKeys);
    return true;
}

void printUsage() {
    std::printf("RawrXD-GGUF-Truncator\n");
    std::printf("  --input <path.gguf>   Source GGUF\n");
    std::printf("  --output <path.gguf>  Truncated GGUF\n");
    std::printf("  --layers <n>          Keep blk.0..blk.(n-1)\n");
}

} // namespace

int main(int argc, char** argv) {
    std::string input;
    std::string output;
    int layers = -1;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--input" && i + 1 < argc) {
            input = argv[++i];
        } else if (arg == "--output" && i + 1 < argc) {
            output = argv[++i];
        } else if (arg == "--layers" && i + 1 < argc) {
            layers = std::atoi(argv[++i]);
        } else if (arg == "--help" || arg == "-h") {
            printUsage();
            return 0;
        }
    }

    if (input.empty() || output.empty() || layers <= 0) {
        printUsage();
        return 2;
    }

    std::string error;
    if (!truncateGGUF(input, output, layers, error)) {
        std::fprintf(stderr, "[GGUF_Truncator] ERROR: %s\n", error.c_str());
        return 1;
    }
    return 0;
}
