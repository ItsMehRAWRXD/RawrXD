#include "rawrxd/config/ModelDiscovery.h"

#include <filesystem>
#include <fstream>
#include <unordered_map>

namespace fs = std::filesystem;

namespace rawrxd::config {
namespace {

uint32_t readU32(const std::string& data, size_t& offset, bool& ok) {
    if (offset + 4 > data.size()) { ok = false; return 0; }
    uint32_t v;
    std::memcpy(&v, data.data() + offset, 4);
    offset += 4;
    return v;
}

uint64_t readU64(const std::string& data, size_t& offset, bool& ok) {
    if (offset + 8 > data.size()) { ok = false; return 0; }
    uint64_t v;
    std::memcpy(&v, data.data() + offset, 8);
    offset += 8;
    return v;
}

std::string readString(const std::string& data, size_t& offset, bool& ok) {
    uint64_t len = readU64(data, offset, ok);
    if (!ok || len > data.size() - offset) { ok = false; return {}; }
    std::string s = data.substr(offset, static_cast<size_t>(len));
    offset += static_cast<size_t>(len);
    return s;
}

std::string quantFromTensorName(const std::string& name) {
    static const char* candidates[] = {"Q8_K", "Q6_K", "Q5_K", "Q4_K", "Q3_K", "Q2_K", "Q5_0", "Q4_0", "Q8_0", "F16", "F32"};
    for (const char* c : candidates) {
        if (name.find(c) != std::string::npos) return c;
    }
    return "unknown";
}

} // namespace

ModelInfo inspectModel(const std::string& path) {
    ModelInfo info;
    info.path = path;
    info.fileName = fs::path(path).filename().string();
    std::error_code ec;
    info.sizeBytes = static_cast<uint64_t>(fs::file_size(path, ec));
    if (ec) { info.error = "cannot stat file"; return info; }

    std::ifstream in(path, std::ios::binary);
    if (!in) { info.error = "cannot open file"; return info; }
    std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (data.size() < 24 || data.compare(0, 4, "GGUF") != 0) {
        info.error = "not a GGUF file";
        return info;
    }

    size_t offset = 4;
    bool ok = true;
    uint32_t version = readU32(data, offset, ok);
    (void)version;
    uint64_t tensorCount = readU64(data, offset, ok);
    uint64_t kvCount = readU64(data, offset, ok);
    info.tensorCount = tensorCount;

    for (uint64_t i = 0; i < kvCount && ok; ++i) {
        std::string key = readString(data, offset, ok);
        if (!ok) break;
        uint32_t type = readU32(data, offset, ok);
        if (!ok) break;
        auto skipValue = [&]() {
            switch (type) {
                case 0: case 1: case 7: offset += 1; break; // uint8/int8/bool
                case 2: case 3: offset += 2; break; // uint16/int16
                case 4: case 5: case 6: offset += 4; break; // uint32/int32/float32
                case 8: { std::string s = readString(data, offset, ok); if (key == "general.architecture") info.architecture = s; break; }
                case 9: { uint32_t n = readU32(data, offset, ok); offset += static_cast<size_t>(n) * 4; break; }
                case 10: offset += 8; break; // uint64
                case 11: offset += 8; break; // int64
                case 12: offset += 8; break; // float64
                default: ok = false; break;
            }
        };
        if (type == 8) {
            std::string s = readString(data, offset, ok);
            if (key == "general.architecture") info.architecture = s;
            if (key == "general.name" && info.architecture.empty()) info.architecture = s;
        } else if (type == 4 || type == 5) {
            uint32_t v = readU32(data, offset, ok);
            if (key.find("context_length") != std::string::npos) info.contextLength = v;
        } else if (type == 6) {
            uint32_t raw = readU32(data, offset, ok);
            float f;
            std::memcpy(&f, &raw, 4);
            if (key.find("context_length") != std::string::npos) info.contextLength = static_cast<uint32_t>(f);
        } else if (type == 10 || type == 11) {
            uint64_t v = readU64(data, offset, ok);
            if (key.find("context_length") != std::string::npos) info.contextLength = static_cast<uint32_t>(v);
        } else {
            skipValue();
        }
        if (!ok) break;
        if (offset > data.size()) { ok = false; break; }
    }

    // Quantization is encoded in tensor names; scan the raw tensor-info area.
    if (offset + tensorCount * 8 <= data.size()) {
        for (uint64_t i = 0; i < tensorCount; ++i) {
            size_t namePos = offset;
            std::string name = readString(data, namePos, ok);
            if (!ok || name.empty()) break;
            info.quantization = quantFromTensorName(name);
            if (info.quantization != "unknown") break;
            offset = namePos;
            if (offset + 8 > data.size()) break;
            offset += 8; // n_dims + dims placeholder
        }
    }

    info.valid = !info.architecture.empty() && info.sizeBytes > 0;
    if (!info.valid && info.error.empty()) info.error = "missing architecture metadata";
    return info;
}

std::vector<ModelInfo> discoverModels(const std::string& directory) {
    std::vector<ModelInfo> models;
    std::error_code ec;
    if (!fs::is_directory(directory, ec)) return models;
    for (const auto& entry : fs::directory_iterator(directory, ec)) {
        if (!entry.is_regular_file(ec)) continue;
        const fs::path& p = entry.path();
        if (p.extension() != ".gguf") continue;
        models.push_back(inspectModel(p.string()));
    }
    return models;
}

} // namespace rawrxd::config