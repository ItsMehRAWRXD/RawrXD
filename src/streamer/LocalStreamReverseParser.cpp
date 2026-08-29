#include "LocalStreamReverseParser.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace rawrxd::streamer {
namespace {

constexpr uint32_t kGgufMagic = 0x46554747u;
constexpr uint32_t kGgufVersionMin = 1;
constexpr uint32_t kGgufVersionMax = 3;
constexpr uint32_t kTypeUint8 = 0;
constexpr uint32_t kTypeInt8 = 1;
constexpr uint32_t kTypeUint16 = 2;
constexpr uint32_t kTypeInt16 = 3;
constexpr uint32_t kTypeUint32 = 4;
constexpr uint32_t kTypeInt32 = 5;
constexpr uint32_t kTypeFloat32 = 6;
constexpr uint32_t kTypeBool = 7;
constexpr uint32_t kTypeString = 8;
constexpr uint32_t kTypeArray = 9;
constexpr uint32_t kTypeUint64 = 10;
constexpr uint32_t kTypeInt64 = 11;
constexpr uint32_t kTypeFloat64 = 12;
constexpr size_t kScanChunk = 1024 * 1024;
constexpr uint64_t kMaxString = 16ull * 1024ull * 1024ull;
constexpr uint64_t kMaxArray = 16ull * 1024ull * 1024ull;
constexpr uint64_t kMaxTensors = 1ull << 20;
constexpr uint64_t kMaxKv = 1ull << 20;
constexpr uint32_t kMaxDims = 8;

std::string toLower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

void addMissing(ReverseParseReport& report, const char* id, const std::string& detail)
{
    report.missing.push_back(MissingItem{id, detail});
}

void addPresent(ReverseParseReport& report, const std::string& item)
{
    report.present.push_back(item);
}

bool parseU64(const std::string& text, uint64_t& out)
{
    if (text.empty())
        return false;
    errno = 0;
    char* end = nullptr;
    const unsigned long long value = std::strtoull(text.c_str(), &end, 10);
    if (errno != 0 || end == text.c_str() || (end && *end != '\0'))
        return false;
    out = static_cast<uint64_t>(value);
    return true;
}

class StreamCursor {
public:
    bool open(const std::string& path)
    {
        in_.open(path, std::ios::binary);
        if (!in_)
            return false;
        in_.seekg(0, std::ios::end);
        size_ = static_cast<uint64_t>(in_.tellg());
        in_.seekg(0, std::ios::beg);
        return true;
    }

    uint64_t size() const { return size_; }

    bool seek(uint64_t offset)
    {
        if (offset > size_)
            return false;
        in_.clear();
        in_.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
        return static_cast<bool>(in_);
    }

    uint64_t tell()
    {
        const std::streamoff pos = in_.tellg();
        if (pos < 0)
            return size_;
        return static_cast<uint64_t>(pos);
    }

    bool remaining(uint64_t n) { return tell() + n <= size_; }

    bool readExact(void* dst, size_t n)
    {
        if (!remaining(n))
            return false;
        in_.read(static_cast<char*>(dst), static_cast<std::streamsize>(n));
        return static_cast<size_t>(in_.gcount()) == n;
    }

    template <typename T>
    bool readPod(T& value)
    {
        return readExact(&value, sizeof(T));
    }

    bool readString(std::string& out)
    {
        uint64_t len = 0;
        if (!readPod(len) || len > kMaxString || !remaining(len))
            return false;
        out.assign(static_cast<size_t>(len), '\0');
        if (len == 0)
            return true;
        return readExact(out.data(), static_cast<size_t>(len));
    }

    bool skip(uint64_t n)
    {
        if (!remaining(n))
            return false;
        return seek(tell() + n);
    }

    bool findMagic(uint64_t& offset)
    {
        if (size_ < 4)
            return false;
        if (!seek(0))
            return false;

        std::vector<char> buffer(kScanChunk + 3);
        uint64_t position = 0;
        while (position + 4 <= size_) {
            const uint64_t want = std::min<uint64_t>(kScanChunk, size_ - position);
            if (!readExact(buffer.data(), static_cast<size_t>(want)))
                return false;
            const size_t bytes = static_cast<size_t>(want);
            for (size_t i = 0; i + 4 <= bytes; ++i) {
                uint32_t candidate = 0;
                std::memcpy(&candidate, buffer.data() + i, 4);
                if (candidate == kGgufMagic) {
                    offset = position + static_cast<uint64_t>(i);
                    return true;
                }
            }
            if (want < kScanChunk)
                break;
            if (bytes >= 3) {
                position += want - 3;
                if (!seek(position))
                    return false;
            } else {
                break;
            }
        }
        return false;
    }

private:
    std::ifstream in_;
    uint64_t size_ = 0;
};

bool skipValue(StreamCursor& cur, uint32_t type);

bool skipArray(StreamCursor& cur)
{
    uint32_t elemType = 0;
    uint64_t count = 0;
    if (!cur.readPod(elemType) || !cur.readPod(count) || count > kMaxArray)
        return false;
    for (uint64_t i = 0; i < count; ++i) {
        if (!skipValue(cur, elemType))
            return false;
    }
    return true;
}

bool skipValue(StreamCursor& cur, uint32_t type)
{
    switch (type) {
        case kTypeUint8:
        case kTypeInt8:
        case kTypeBool:
            return cur.skip(1);
        case kTypeUint16:
        case kTypeInt16:
            return cur.skip(2);
        case kTypeUint32:
        case kTypeInt32:
        case kTypeFloat32:
            return cur.skip(4);
        case kTypeUint64:
        case kTypeInt64:
        case kTypeFloat64:
            return cur.skip(8);
        case kTypeString: {
            std::string tmp;
            return cur.readString(tmp);
        }
        case kTypeArray:
            return skipArray(cur);
        default:
            return false;
    }
}

bool readScalarAsString(StreamCursor& cur, uint32_t type, std::string& out)
{
    switch (type) {
        case kTypeUint8: {
            uint8_t v = 0;
            if (!cur.readPod(v))
                return false;
            out = std::to_string(v);
            return true;
        }
        case kTypeInt8: {
            int8_t v = 0;
            if (!cur.readPod(v))
                return false;
            out = std::to_string(v);
            return true;
        }
        case kTypeUint16: {
            uint16_t v = 0;
            if (!cur.readPod(v))
                return false;
            out = std::to_string(v);
            return true;
        }
        case kTypeInt16: {
            int16_t v = 0;
            if (!cur.readPod(v))
                return false;
            out = std::to_string(v);
            return true;
        }
        case kTypeUint32: {
            uint32_t v = 0;
            if (!cur.readPod(v))
                return false;
            out = std::to_string(v);
            return true;
        }
        case kTypeInt32: {
            int32_t v = 0;
            if (!cur.readPod(v))
                return false;
            out = std::to_string(v);
            return true;
        }
        case kTypeFloat32: {
            float v = 0;
            if (!cur.readPod(v))
                return false;
            out = std::to_string(v);
            return true;
        }
        case kTypeBool: {
            uint8_t v = 0;
            if (!cur.readPod(v))
                return false;
            out = v ? "true" : "false";
            return true;
        }
        case kTypeString:
            return cur.readString(out);
        case kTypeUint64: {
            uint64_t v = 0;
            if (!cur.readPod(v))
                return false;
            out = std::to_string(v);
            return true;
        }
        case kTypeInt64: {
            int64_t v = 0;
            if (!cur.readPod(v))
                return false;
            out = std::to_string(v);
            return true;
        }
        case kTypeFloat64: {
            double v = 0;
            if (!cur.readPod(v))
                return false;
            out = std::to_string(v);
            return true;
        }
        case kTypeArray: {
            uint32_t elemType = 0;
            uint64_t count = 0;
            if (!cur.readPod(elemType) || !cur.readPod(count))
                return false;
            out = std::to_string(count);
            for (uint64_t i = 0; i < count; ++i) {
                if (!skipValue(cur, elemType))
                    return false;
            }
            return true;
        }
        default:
            return false;
    }
}

bool parseGgufPayload(StreamCursor& cur, uint64_t offset, ReverseParseReport& report)
{
    if (!cur.seek(offset)) {
        addMissing(report, "payload.seek", "cannot seek to GGUF payload offset " + std::to_string(offset));
        return false;
    }

    uint32_t magic = 0;
    uint32_t version = 0;
    uint64_t tensorCount = 0;
    uint64_t kvCount = 0;
    if (!cur.readPod(magic) || magic != kGgufMagic) {
        addMissing(report, "gguf.magic", "GGUF magic not readable at payload offset");
        return false;
    }
    if (!cur.readPod(version)) {
        addMissing(report, "gguf.version", "version field truncated");
        return false;
    }
    if (!cur.readPod(tensorCount) || !cur.readPod(kvCount)) {
        addMissing(report, "gguf.header", "tensor_count / metadata_kv_count truncated");
        return false;
    }
    if (tensorCount > kMaxTensors || kvCount > kMaxKv) {
        addMissing(report, "gguf.header.bounds", "tensor or KV count exceeds parser limits");
        return false;
    }

    report.ggufVersion = version;
    report.tensorCount = tensorCount;
    report.metadataCount = kvCount;
    addPresent(report, "gguf.magic");
    addPresent(report, "gguf.header");

    if (version < kGgufVersionMin || version > kGgufVersionMax)
        addMissing(report, "gguf.version.supported", "version " + std::to_string(version) + " is outside 1..3");

    for (uint64_t i = 0; i < kvCount; ++i) {
        std::string key;
        uint32_t type = 0;
        if (!cur.readString(key) || !cur.readPod(type)) {
            addMissing(report, "gguf.metadata", "KV pair " + std::to_string(i) + " truncated");
            return false;
        }
        std::string value;
        if (!readScalarAsString(cur, type, value)) {
            addMissing(report, "gguf.metadata.value", "failed to read value for key '" + key + "'");
            return false;
        }
        if (key == "general.architecture")
            report.architecture = value;
        else if (key == "general.name")
            report.modelName = value;
        else if (key == "tokenizer.ggml.model")
            report.tokenizerModel = value;
        else if (key == "tokenizer.ggml.tokens" || key.find(".vocab_size") != std::string::npos) {
            uint64_t parsed = 0;
            if (parseU64(value, parsed) && (key == "tokenizer.ggml.tokens" || report.vocabSize == 0))
                report.vocabSize = parsed;
        } else if (key.find(".block_count") != std::string::npos) {
            uint64_t parsed = 0;
            if (parseU64(value, parsed))
                report.layerCount = parsed;
        }
    }
    addPresent(report, "gguf.metadata (" + std::to_string(kvCount) + " keys)");

    for (uint64_t i = 0; i < tensorCount; ++i) {
        std::string name;
        uint32_t nDims = 0;
        uint32_t ggmlType = 0;
        uint64_t dataOff = 0;
        if (!cur.readString(name) || !cur.readPod(nDims)) {
            addMissing(report, "gguf.tensor", "tensor info " + std::to_string(i) + " truncated");
            return false;
        }
        if (nDims > kMaxDims) {
            addMissing(report, "gguf.tensor.dims", "tensor '" + name + "' has invalid n_dims");
            return false;
        }
        if (!cur.skip(static_cast<uint64_t>(nDims) * sizeof(uint64_t)) || !cur.readPod(ggmlType) ||
            !cur.readPod(dataOff)) {
            addMissing(report, "gguf.tensor", "tensor '" + name + "' shape/type/offset truncated");
            return false;
        }
        ++report.tensorsNamed;
        const std::string lower = toLower(name);
        if (lower.find("token_embd") != std::string::npos || lower.find("tok_embeddings") != std::string::npos ||
            lower.find("embed") != std::string::npos)
            report.hasEmbedTensor = true;
        if (lower.find("output") != std::string::npos || lower.find("lm_head") != std::string::npos)
            report.hasOutputTensor = true;
        if (lower.find("blk.0") != std::string::npos || lower.find("layers.0") != std::string::npos)
            report.hasFirstBlock = true;
        if (report.layerCount == 0) {
            const auto blk = lower.find("blk.");
            if (blk != std::string::npos) {
                uint64_t index = 0;
                const std::string rest = lower.substr(blk + 4);
                const auto dot = rest.find_first_not_of("0123456789");
                if (parseU64(dot == std::string::npos ? rest : rest.substr(0, dot), index))
                    report.layerCount = std::max(report.layerCount, index + 1);
            }
        }
    }
    addPresent(report, "gguf.tensor_index (" + std::to_string(report.tensorsNamed) + " names)");
    report.payloadParsed = true;
    return true;
}

void classifyModelGaps(ReverseParseReport& report)
{
    if (!report.payloadParsed)
        return;
    if (report.architecture.empty())
        addMissing(report, "meta.architecture", "general.architecture");
    else
        addPresent(report, "architecture=" + report.architecture);
    if (report.tokenizerModel.empty())
        addMissing(report, "meta.tokenizer", "tokenizer.ggml.model");
    if (report.vocabSize == 0)
        addMissing(report, "meta.vocab", "tokenizer / vocab size");
    else
        addPresent(report, "vocab_size=" + std::to_string(report.vocabSize));
    if (report.tensorCount == 0)
        addMissing(report, "tensors.table", "tensor_count is 0 (weights table missing)");
    if (report.tensorCount > 0 && !report.hasEmbedTensor)
        addMissing(report, "tensors.embed", "embedding tensor (token_embd / tok_embeddings)");
    if (report.tensorCount > 0 && !report.hasOutputTensor)
        addMissing(report, "tensors.output", "output / lm_head tensor");
    if (report.tensorCount > 2 && !report.hasFirstBlock)
        addMissing(report, "tensors.blk0", "first transformer block (blk.0 / layers.0)");
    if (report.layerCount == 0 && report.tensorCount > 2)
        addMissing(report, "meta.layers", "block_count / layer count");
}

void parseExtensionSidecars(const std::string& path, ReverseParseReport& report)
{
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::path p(path);
    const bool isDir = fs::is_directory(p, ec);
    fs::path dir = isDir ? p : p.parent_path();
    const std::string lower = toLower(path);
    if (lower.size() >= 5 && lower.compare(lower.size() - 5, 5, ".vsix") == 0)
        addMissing(report, "extension.unpacked", "unpacked VSIX (extract before activate)");

    const fs::path manifest = dir / "package.json";
    const fs::path js = dir / "extension.js";
    const fs::path jsOut = dir / "out" / "extension.js";
    if (!fs::exists(manifest, ec))
        addMissing(report, "extension.manifest", "package.json");
    else
        addPresent(report, "package.json");
    if (!fs::exists(js, ec) && !fs::exists(jsOut, ec))
        addMissing(report, "extension.entry", "extension.js or out/extension.js");
    else
        addPresent(report, "extension.js");
}

}  // namespace

ArtifactKind artifactKindFromName(const std::string& name)
{
    const std::string lower = toLower(name);
    if (lower == "model")
        return ArtifactKind::Model;
    if (lower == "agent")
        return ArtifactKind::Agent;
    if (lower == "extension")
        return ArtifactKind::Extension;
    return ArtifactKind::File;
}

ReverseParseReport parseLocalArtifact(const std::string& kindName, const std::string& path)
{
    ReverseParseReport report;
    parseLocalArtifact(artifactKindFromName(kindName), path, report);
    return report;
}

const char* artifactKindName(ArtifactKind kind)
{
    switch (kind) {
        case ArtifactKind::Model:
            return "model";
        case ArtifactKind::Agent:
            return "agent";
        case ArtifactKind::Extension:
            return "extension";
        case ArtifactKind::File:
            return "file";
    }
    return "unknown";
}

const char* reverseParseErrorName(ReverseParseError error)
{
    switch (error) {
        case ReverseParseError::Ok:
            return "ok";
        case ReverseParseError::EmptyPath:
            return "empty_path";
        case ReverseParseError::NotFound:
            return "not_found";
        case ReverseParseError::Unreadable:
            return "unreadable";
        case ReverseParseError::Truncated:
            return "truncated";
        case ReverseParseError::InvalidFormat:
            return "invalid_format";
    }
    return "unknown";
}

bool parseLocalArtifact(ArtifactKind kind, const std::string& path, ReverseParseReport& report)
{
    report = ReverseParseReport{};
    report.kind = kind;
    report.path = path;

    if (path.empty()) {
        report.error = ReverseParseError::EmptyPath;
        addMissing(report, "path", "empty path");
        return false;
    }

    namespace fs = std::filesystem;
    std::error_code ec;
    if (!fs::exists(path, ec)) {
        report.error = ReverseParseError::NotFound;
        addMissing(report, "file", std::string("not on disk: ") + path);
        return false;
    }
    addPresent(report, "file.exists");

    if (kind == ArtifactKind::Extension) {
        parseExtensionSidecars(path, report);
        report.error = report.missing.empty() ? ReverseParseError::Ok : ReverseParseError::NotFound;
        return report.missing.empty();
    }

    if (!fs::is_regular_file(path, ec)) {
        report.error = ReverseParseError::Unreadable;
        addMissing(report, "file.regular", "path is not a regular file");
        return false;
    }

    StreamCursor cur;
    if (!cur.open(path)) {
        report.error = ReverseParseError::Unreadable;
        addMissing(report, "file.open", "open failed");
        return false;
    }
    report.fileSize = cur.size();
    if (report.fileSize == 0) {
        report.error = ReverseParseError::Truncated;
        addMissing(report, "file.content", "size is 0");
        return false;
    }
    addPresent(report, "file.size=" + std::to_string(report.fileSize));

    if (kind == ArtifactKind::File && path.find(".gguf") == std::string::npos &&
        path.find(".GGUF") == std::string::npos && path.find("sha256") == std::string::npos) {
        report.error = ReverseParseError::Ok;
        return true;
    }

    uint64_t offset = 0;
    if (!cur.findMagic(offset)) {
        report.error = ReverseParseError::InvalidFormat;
        addMissing(report, "gguf.magic", "no GGUF magic in file (not a GGUF and no embedded blob payload)");
        return false;
    }
    report.ggufOffset = offset;
    report.magicAtZero = (offset == 0);
    if (offset == 0)
        addPresent(report, "gguf.magic@0");
    else
        addPresent(report, "gguf.magic@blob_offset=" + std::to_string(offset));

    if (!parseGgufPayload(cur, offset, report)) {
        report.error = ReverseParseError::Truncated;
        return false;
    }

    classifyModelGaps(report);
    if (kind == ArtifactKind::Agent && report.tensorCount == 0)
        addMissing(report, "agent.weights", "agent has no tensor table to bind");

    report.error = ReverseParseError::Ok;
    return true;
}

std::string formatReverseParseReport(const ReverseParseReport& report)
{
    std::ostringstream oss;
    oss << "[ReverseParser] kind=" << artifactKindName(report.kind)
        << " error=" << reverseParseErrorName(report.error)
        << " path=" << (report.path.empty() ? "<none>" : report.path) << "\n";
    oss << "  size=" << report.fileSize << " gguf_offset=" << report.ggufOffset
        << " version=" << report.ggufVersion << " tensors=" << report.tensorCount
        << " kv=" << report.metadataCount << " parsed=" << (report.payloadParsed ? "1" : "0") << "\n";
    if (!report.architecture.empty())
        oss << "  architecture=" << report.architecture << "\n";
    if (!report.modelName.empty())
        oss << "  name=" << report.modelName << "\n";
    if (!report.present.empty()) {
        oss << "  Present:\n";
        for (const auto& item : report.present)
            oss << "    + " << item << "\n";
    }
    if (report.missing.empty()) {
        oss << "  Missing: (none)\n";
    } else {
        oss << "  Missing / incomplete:\n";
        for (const auto& item : report.missing)
            oss << "    - " << item.id << ": " << item.detail << "\n";
    }
    return oss.str();
}

}  // namespace rawrxd::streamer
