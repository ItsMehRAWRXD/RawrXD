// ============================================================================
// ModelInventory.cpp — RAWRXD_DEEP2_STREAMER_DISCOVERY_001
// ============================================================================
#include "streamer/ModelInventory.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <sstream>

namespace fs = std::filesystem;

namespace rawrxd {
namespace streamer {
namespace {

std::string Lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string BaseName(const std::string& p) {
    const std::size_t a = p.find_last_of("/\\");
    return a == std::string::npos ? p : p.substr(a + 1);
}

std::string DirName(const std::string& p) {
    const std::size_t a = p.find_last_of("/\\");
    return a == std::string::npos ? std::string() : p.substr(0, a);
}

std::string Extension(const std::string& p) {
    const std::string b = BaseName(p);
    const std::size_t d = b.find_last_of('.');
    return d == std::string::npos ? std::string() : Lower(b.substr(d));
}

// "name-00001-of-00013.gguf" -> name, 1, 13. Returns false when the name is not
// a shard member. Deliberately independent of the extension, so a blob with no
// extension is still recognised as a member of a set.
bool ParseShardSuffix(const std::string& filename, std::string& base, int& index,
                      int& expected) {
    const std::size_t dot = filename.find_last_of('.');
    std::string stem = dot == std::string::npos ? filename : filename.substr(0, dot);
    // "-00001-of-00013"
    const std::size_t of = stem.rfind("-of-");
    if (of == std::string::npos || of + 4 > stem.size()) return false;
    const std::string expPart = stem.substr(of + 4);
    if (expPart.size() != 5) return false;
    for (const char c : expPart) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    }
    if (of < 6) return false;
    const std::string idxPart = stem.substr(of - 5, 5);
    for (const char c : idxPart) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    }
    base = stem.substr(0, of - 6);
    index = std::stoi(idxPart);
    expected = std::stoi(expPart);
    return index >= 1 && expected >= 1 && index <= expected;
}

// --- minimal GGUF header reader -------------------------------------------
// The format is: "GGUF", u32 version, u64 tensor_count, u64 kv_count,
// then kv_count pairs of (u64 key_len, key bytes, u32 value_type, value).
// Reading only what the census needs keeps this independent of whatever JSON or
// GGUF library a given target happens to link.

struct Reader {
    std::ifstream f;
    std::vector<char> buf;
    // Decoded keys, in order, and the byte offset of each. When a header fails to
    // parse, "truncated_key" alone says nothing; the last few keys and the offset
    // say exactly where the reader and the file disagreed, which is the only
    // information that makes the failure diagnosable.
    std::vector<std::pair<std::uint64_t, std::string>> trace;

    void Note(const std::string& key) {
        trace.emplace_back(static_cast<std::uint64_t>(f.tellg()), key);
    }
    std::string Tail(int n) const {
        std::string s;
        for (std::size_t i = (trace.size() > static_cast<std::size_t>(n)
                                  ? trace.size() - static_cast<std::size_t>(n)
                                  : 0);
             i < trace.size(); ++i) {
            if (!s.empty()) s += " | ";
            s += "@" + std::to_string(trace[i].first) + ":" + trace[i].second;
        }
        return s;
    }

    bool Read(void* dst, std::size_t n) {
        f.read(static_cast<char*>(dst), static_cast<std::streamsize>(n));
        return f.gcount() == static_cast<std::streamsize>(n);
    }
    bool U32(std::uint32_t& v) { return Read(&v, sizeof v); }
    bool U64(std::uint64_t& v) { return Read(&v, sizeof v); }
    bool Str(std::string& s) {
        std::uint64_t n = 0;
        if (!U64(n)) return false;
        if (n > (1u << 20)) return false;  // a key longer than 1 MiB is not a key
        buf.resize(static_cast<std::size_t>(n) + 1);
        if (!Read(buf.data(), static_cast<std::size_t>(n))) return false;
        s.assign(buf.data(), static_cast<std::size_t>(n));
        return true;
    }
    // Skips a value of the given type, recursing through arrays and strings.
    bool SkipValue(std::uint32_t type, int depth = 0) {
        if (depth > 8) return false;
        switch (type) {
            case 0: case 1: { std::uint8_t v; return Read(&v, 1); }
            case 2: case 3: { std::uint16_t v; return Read(&v, 2); }
            case 4: case 5: { std::uint32_t v; return Read(&v, 4); }
            // BOOL is ONE BYTE. Reading it as u32 consumed three bytes that
            // belong to the next key, which desynchronised the parse from the
            // first boolean onward. Measured consequence: a 5 GB gemma-4 model
            // and a 1 GB clip projector both reported "header: truncated_key",
            // i.e. the census declared two healthy models CORRUPT because its
            // own reader disagreed with the file format.
            case 7: { std::uint8_t v; return Read(&v, 1); }
            case 6:  { float v; return Read(&v, 4); }
            case 10: case 11: { std::uint64_t v; return Read(&v, 8); }
            case 12: { double v; return Read(&v, 8); }
            case 8: { std::string s; return Str(s); }
            case 9: {
                // GGUF array: u32 element_type, u64 count, then the elements.
                //
                // The COUNT IS 64-BIT. Reading it as u32 desynchronises the
                // header parse by four bytes at the first array, and every
                // subsequent key then decodes as a garbage length -- which is
                // exactly what was measured on gemma-4-E4B-it: the architecture
                // read correctly and the very next key reported "truncated_key".
                // A diagnostic that mis-parses the thing it is describing will
                // call a 5 GB model corrupt.
                std::uint32_t elemType = 0;
                std::uint64_t count = 0;
                if (!U32(elemType) || !U64(count)) return false;
                if (count > (1ull << 24)) return false;
                for (std::uint64_t i = 0; i < count; ++i) {
                    if (!SkipValue(elemType, depth + 1)) return false;
                }
                return true;
            }
            default: return false;
        }
    }
    // After the KV block, tensor descriptors: (name, u32 n_dims, dims[],
    // u32 ggml_type, u64 offset).
    //
    // The OFFSET MUST BE CONSUMED. Omitting it leaves the reader eight bytes
    // short after the first descriptor, so the second read desynchronises and a
    // histogram over "all" tensors silently contained exactly one entry --
    // measured as "types_distinct=1 dominant_count=1 of 201".
    bool ReadTensorDescriptor(std::string& name, std::uint32_t& type) {
        if (!Str(name)) return false;
        std::uint32_t nDims = 0;
        if (!U32(nDims) || nDims > 8) return false;
        for (std::uint32_t i = 0; i < nDims; ++i) {
            std::uint64_t d = 0;
            if (!U64(d)) return false;
        }
        if (!U32(type)) return false;
        std::uint64_t offset = 0;
        return U64(offset);
    }
};

} // namespace

const char* GgufTypeName(std::uint32_t t) {
    switch (t) {
        case 0:  return "F32";
        case 1:  return "F16";
        case 2:  return "Q4_0";
        case 3:  return "Q4_1";
        case 6:  return "Q5_0";
        case 7:  return "Q5_1";
        case 8:  return "Q8_0";
        case 9:  return "Q8_1";
        case 10: return "Q2_K";
        case 11: return "Q3_K";
        case 12: return "Q4_K";
        case 13: return "Q5_K";
        case 14: return "Q6_K";
        case 15: return "Q8_K";
        case 16: return "IQ2_XXS";
        case 17: return "IQ2_XS";
        case 18: return "IQ3_XXS";
        case 19: return "IQ1_S";
        case 20: return "IQ4_NL";
        case 30: return "BF16";
        default: return "UNKNOWN";
    }
}

bool ModelInventory::HasGgufMagic(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    unsigned char m[4] = {0, 0, 0, 0};
    f.read(reinterpret_cast<char*>(m), 4);
    if (f.gcount() != 4) return false;
    return m[0] == 0x47 && m[1] == 0x47 && m[2] == 0x55 && m[3] == 0x46;  // "GGUF"
}

bool ModelInventory::ReadHeader(const std::string& path, GgufHeader& out) {
    out = GgufHeader{};
    Reader r;
    r.f.open(path, std::ios::binary);
    if (!r.f) { out.error = "cannot_open"; return false; }

    char magic[4] = {0, 0, 0, 0};
    if (!r.Read(magic, 4)) { out.error = "truncated_magic"; return false; }
    if (std::memcmp(magic, "GGUF", 4) != 0) { out.error = "bad_magic"; return false; }

    if (!r.U32(out.version)) { out.error = "truncated_version"; return false; }
    if (!r.U64(out.tensorCount)) { out.error = "truncated_tensor_count"; return false; }
    if (!r.U64(out.kvCount)) { out.error = "truncated_kv_count"; return false; }
    if (out.version == 0 || out.version > 3) {
        // Still parsed, but recorded: an unexpected version is information, and
        // refusing it here would hide models the loader may well handle.
        out.error = "unexpected_version";
    }

    for (std::uint64_t i = 0; i < out.kvCount; ++i) {
        std::string key;
        if (!r.Str(key)) {
            out.error = "truncated_key at kv " + std::to_string(i) + " after [" +
                        r.Tail(4) + "]";
            return false;
        }
        std::uint32_t type = 0;
        if (!r.U32(type)) {
            out.error = "truncated_value_type at kv " + std::to_string(i) + " key=" + key;
            return false;
        }
        r.Note(key);

        if (type == 8) {
            std::string value;
            if (!r.Str(value)) { out.error = "truncated_string_value"; return false; }
            if (key == "general.architecture") out.architecture = value;
            else if (key == "general.name") out.name = value;
        } else if (type == 4) {
            std::uint32_t v = 0;
            if (!r.Read(&v, 4)) { out.error = "truncated_u32_value"; return false; }
            if (key == "general.file_type") {
                out.fileType = v;
                out.fileTypePresent = true;
            }
        } else if (!r.SkipValue(type)) {
            out.error = "unsupported_value_type_" + std::to_string(type) +
                        " at kv " + std::to_string(i) + " key=" + key +
                        " after [" + r.Tail(4) + "]";
            return false;
        }
    }

    // Tensor descriptors follow the KV block. Read them ALL and count ggml types.
    //
    // The first version took the FIRST tensor's type and printed it as "quant".
    // Measured on tinyllama-1.1b it reported Q6_K while Deep2's own admission log
    // reported Q4_K: the first descriptor is not representative, so the receipt
    // carried a confident quantisation claim that was simply wrong. A dominant
    // type over the whole tensor list is cheap here -- the descriptors are all in
    // the header -- and is an actual measurement.
    if (out.tensorCount > 0) {
        std::map<std::uint32_t, std::uint64_t> typeHist;
        std::uint64_t read = 0;
        for (std::uint64_t i = 0; i < out.tensorCount; ++i) {
            std::string name;
            std::uint32_t type = 0;
            if (!r.ReadTensorDescriptor(name, type)) {
                out.error += (out.error.empty() ? "" : ";") +
                             std::string("tensor_descriptor_unreadable_at_") +
                             std::to_string(i);
                break;
            }
            if (i == 0) {
                out.firstTensorName = name;
                out.firstTensorType = type;
            }
            typeHist[type]++;
            ++read;
        }
        // The count of tensors actually READ, not the count the header claims.
        // Reporting tensorCount here would turn a partial read into a claim of
        // full coverage.
        out.tensorsRead = read;
        out.distinctTensorTypes = static_cast<std::uint32_t>(typeHist.size());
        if (!typeHist.empty()) {
            std::uint64_t bestCount = 0;
            for (const auto& kv : typeHist) {
                if (kv.second > bestCount) {
                    bestCount = kv.second;
                    out.dominantTensorType = kv.first;
                }
            }
            out.dominantTensorCount = bestCount;
            out.quantName = GgufTypeName(out.dominantTensorType);
            out.quantNameIsDominant = read == out.tensorCount;
        }
    }

    out.valid = true;
    return true;
}

ArtifactClass ModelInventory::ClassifyByName(const std::string& filename) {
    const std::string b = Lower(BaseName(filename));
    // A projector is not an inference model. Testing it as one produces either a
    // bogus load failure or, worse, a pass that means nothing.
    if (b.find("mmproj") != std::string::npos) return ArtifactClass::Projector;
    if (b.find("clip") != std::string::npos) return ArtifactClass::Projector;
    return ArtifactClass::InferenceModel;
}

bool LogicalModel::shardsCompleteImpl() const {
    // EVERY index 1..N must be present. Comparing the COUNT against N is not
    // sufficient: a set holding members {1,2,4} of an expected 3 has count 3 and
    // would pass a count check while member 3 is absent -- and the loader would
    // then be handed a model with a hole in it.
    if (shards.empty()) return false;
    if (expectedShards <= 1) return static_cast<int>(shards.size()) >= 1;
    std::vector<char> present(static_cast<std::size_t>(expectedShards) + 1, 0);
    for (const ShardInfo& s : shards) {
        if (s.index >= 1 && s.index <= expectedShards) present[s.index] = 1;
    }
    for (int i = 1; i <= expectedShards; ++i) {
        if (!present[i]) return false;
    }
    return true;
}

std::vector<int> LogicalModel::missingShardIndices() const {
    std::vector<int> missing;
    if (expectedShards <= 1) return missing;
    std::vector<char> present(static_cast<std::size_t>(expectedShards) + 1, 0);
    for (const ShardInfo& s : shards) {
        if (s.index >= 1 && s.index <= expectedShards) present[s.index] = 1;
    }
    for (int i = 1; i <= expectedShards; ++i) {
        if (!present[i]) missing.push_back(i);
    }
    return missing;
}

std::string LogicalModel::entryShardPath() const {
    if (shards.empty()) return std::string();
    // Shard 1 is the entry point. Picking the last shard, or an arbitrary one,
    // hands the loader a fragment that is not a model.
    for (const ShardInfo& s : shards) {
        if (s.index == 1) return s.path;
    }
    return shards.front().path;
}

void ModelInventory::FinaliseGroup(LogicalModel& m) {
    // Deduplicate by shard index, FIRST WINS.
    //
    // This previously collected `const ShardInfo*` into a std::map<int, ...>,
    // then called m.shards.clear(), then dereferenced those pointers to rebuild
    // the vector. Every element had already been destroyed at that point: a
    // use-after-free. std::uint64_t bytes survived by luck because the memory was
    // not immediately reused; the std::string path did not, so every sharded
    // model came out of the census with an EMPTY entry_shard and was reported
    // MODEL_CORRUPT.
    //
    // That is the most dangerous shape a bug can take here: a 578 GB, 13-of-13
    // complete model was reported as corrupt, and the real cause was heap
    // corruption inside the instrument that was supposed to be describing it.
    // The inventory confidently invented a finding about Kimi K2.
    std::vector<ShardInfo> unique;
    unique.reserve(m.shards.size());
    std::set<int> seenIndex;
    for (const ShardInfo& s : m.shards) {
        if (seenIndex.insert(s.index).second) unique.push_back(s);
    }
    std::sort(unique.begin(), unique.end(),
              [](const ShardInfo& a, const ShardInfo& b) { return a.index < b.index; });
    m.shards.swap(unique);

    m.presentShards = static_cast<int>(m.shards.size());
    m.totalBytes = 0;
    for (const ShardInfo& s : m.shards) m.totalBytes += s.bytes;
    census_.totalBytes += m.totalBytes;

    // Every shard must carry a usable path. A shard without one cannot be
    // opened, so a set of them is not a model anyone can test.
    bool pathsUsable = true;
    for (const ShardInfo& s : m.shards) {
        if (s.path.empty()) pathsUsable = false;
    }
    if (m.presentShards > 0 && !pathsUsable) {
        m.artifact = ArtifactClass::CorruptGguf;
        census_.corruptHeaders++;
        census_.logicalModels++;
        return;
    }

    const bool projector = ClassifyByName(m.logicalName) == ArtifactClass::Projector;

    if (m.expectedShards > 1 && !m.shardsCompleteImpl()) {
        // Missing members. NOT a load failure and NOT a test failure: it is an
        // inventory state, and no amount of trying will produce the absent bytes.
        const std::vector<int> missing = m.missingShardIndices();
        std::string detail = "shards " + std::to_string(m.presentShards) + "/" +
                             std::to_string(m.expectedShards) + " present";
        if (!missing.empty()) {
            detail += "; missing member(s) ";
            for (std::size_t i = 0; i < missing.size() && i < 24; ++i) {
                if (i) detail += ",";
                detail += std::to_string(missing[i]);
            }
        }
        m.artifact = ArtifactClass::IncompleteShardSet;
        m.shardDetail = detail;
    } else if (projector) {
        m.artifact = ArtifactClass::Projector;
        census_.projectors++;
    } else if (m.expectedShards > 1) {
        m.artifact = ArtifactClass::ShardedInferenceModel;
        census_.shardedComplete++;
    } else {
        m.artifact = ArtifactClass::InferenceModel;
        census_.singleFile++;
    }

    // Header of the entry shard, never of an arbitrary member.
    const std::string entry = m.entryShardPath();
    if (!entry.empty() && !ReadHeader(entry, m.header) && m.artifact != ArtifactClass::IncompleteShardSet) {
        m.artifact = ArtifactClass::CorruptGguf;
        census_.corruptHeaders++;
    }

    if (m.artifact == ArtifactClass::IncompleteShardSet) census_.shardedIncomplete++;
    census_.logicalModels++;
}

Census ModelInventory::ScanRoot(const std::string& root) {
    census_ = Census{};
    std::error_code ec;
    if (!fs::exists(root, ec)) return census_;

    // directory -> logical base name -> model
    std::map<std::string, std::map<std::string, LogicalModel>> groups;

    fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec);
    if (ec) return census_;
    for (const fs::directory_entry& e : it) {
        if (ec) break;
        if (!e.is_regular_file(ec)) continue;
        census_.filesScanned++;

        const std::string path = e.path().string();
        const std::string filename = BaseName(path);
        const std::string dir = DirName(path);

        std::uint64_t bytes = 0;
        try { bytes = e.file_size(ec); } catch (...) { bytes = 0; }

        // RAWRXD_STREAMER_NO_FILESIZE_GATE_001
        // Magic is the authority on whether a file is a model, not its length.
        // The 1 KiB heuristic used to run BEFORE this magic check, so a small but
        // structurally valid GGUF was declared ManifestNoPayload and skipped
        // without ever being identified. Cloud manifests and redirect stubs are
        // still classified as payload-less -- they have no GGUF magic -- but a
        // file that declares itself a GGUF is now counted as one and handed to
        // Deep2, which is the only thing entitled to say it cannot be loaded.
        // Nothing here decides loadability from file size.
        constexpr std::uint64_t kMinPlausiblePayload = 1024;
        const bool isGguf = HasGgufMagic(path);

        if (!isGguf && bytes < kMinPlausiblePayload) {
            LogicalModel stub;
            stub.logicalName = filename;
            stub.directory = dir;
            stub.artifact = ArtifactClass::ManifestNoPayload;
            stub.totalBytes = bytes;
            stub.shardDetail = "no GGUF magic and " + std::to_string(bytes) +
                               " B; treated as manifest/redirect stub, not weights";
            census_.manifestsNoPayload++;
            census_.logicalModels++;
            models_.push_back(std::move(stub));
            census_.nonGgufSkipped++;
            continue;
        }

        if (!isGguf) {
            census_.nonGgufSkipped++;
            continue;
        }
        census_.ggufByMagic++;

        std::string base;
        int index = 1, expected = 1;
        if (ParseShardSuffix(filename, base, index, expected)) {
            LogicalModel& m = groups[dir][base];
            if (m.logicalName.empty()) {
                m.logicalName = base;
                m.directory = dir;
                m.expectedShards = expected;
            }
            // A later member carrying a larger N wins: a stray subset on disk
            // must not lower the denominator for the real set.
            m.expectedShards = std::max(m.expectedShards, expected);
            ShardInfo si;
            si.path = path;
            si.bytes = bytes;
            si.index = index;
            m.shards.push_back(si);
        } else {
            std::string key = "SINGLE:" + filename;
            LogicalModel& m = groups[dir][key];
            if (m.logicalName.empty()) {
                m.logicalName = filename;
                m.directory = dir;
                m.expectedShards = 1;
            }
            ShardInfo si;
            si.path = path;
            si.bytes = bytes;
            si.index = 1;
            m.shards.push_back(si);
        }
    }

    for (auto& dirEntry : groups) {
        for (auto& nameEntry : dirEntry.second) {
            LogicalModel m = nameEntry.second;
            FinaliseGroup(m);
            models_.push_back(std::move(m));
        }
    }

    std::sort(models_.begin(), models_.end(),
              [](const LogicalModel& a, const LogicalModel& b) {
                  return a.totalBytes > b.totalBytes;
              });
    return census_;
}

Census ModelInventory::ScanOllamaManifests(const std::string& manifestsDir,
                                           const std::string& blobsDir) {
    std::error_code ec;
    if (!fs::exists(manifestsDir, ec)) return census_;

    std::uint64_t missing = 0;
    fs::recursive_directory_iterator it(manifestsDir, fs::directory_options::skip_permission_denied, ec);
    if (ec) return census_;
    for (const fs::directory_entry& e : it) {
        if (ec) break;
        if (!e.is_regular_file(ec)) continue;

        std::ifstream f(e.path().string());
        if (!f) continue;
        std::stringstream ss;
        ss << f.rdbuf();
        const std::string text = ss.str();
        if (text.find("\"model\"") == std::string::npos) continue;

        // Pull every sha256 blob id the manifest references and check the store.
        bool allPresent = true;
        bool sawBlob = false;
        std::size_t at = 0;
        while ((at = text.find("sha256:", at)) != std::string::npos) {
            at += 7;
            if (at + 64 > text.size()) break;
            const std::string digest = text.substr(at, 64);
            sawBlob = true;
            const std::string blobPath = blobsDir + "/sha256-" + digest;
            std::error_code ec2;
            if (!fs::exists(blobPath, ec2)) allPresent = false;
        }

        // A manifest with no local payload is an inventory state, never a test
        // failure and never a model. Reporting it as one would turn "cloud" into
        // "Deep2 cannot load this", which is a different and false claim.
        if (sawBlob && !allPresent) {
            missing++;
            LogicalModel m;
            m.logicalName = BaseName(e.path().string());
            m.directory = DirName(e.path().string());
            m.artifact = ArtifactClass::ManifestNoPayload;
            models_.push_back(std::move(m));
        }
    }
    census_.manifestsNoPayload += missing;
    return census_;
}

void ModelInventory::Clear() {
    models_.clear();
    census_ = Census{};
}

namespace {
const char* ClassName(ArtifactClass c) {
    switch (c) {
        case ArtifactClass::InferenceModel:        return "INFERENCE_MODEL";
        case ArtifactClass::ShardedInferenceModel: return "SHARDED_INFERENCE_MODEL";
        case ArtifactClass::IncompleteShardSet:    return "INCOMPLETE_SHARD_SET";
        case ArtifactClass::Projector:             return "PROJECTOR";
        case ArtifactClass::NotGguf:               return "NOT_GGUF";
        case ArtifactClass::CorruptGguf:           return "CORRUPT_GGUF";
        case ArtifactClass::ManifestNoPayload:     return "MANIFEST_NO_PAYLOAD";
    }
    return "UNKNOWN";
}

std::string Escape(const std::string& s) {
    std::string o;
    for (const char c : s) {
        if (c == '"' || c == '\\') { o += '\\'; o += c; }
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else o += c;
    }
    return o;
}
} // namespace

std::string ModelInventory::WriteJson(const std::string& path) const {
    std::error_code ec;
    const fs::path parent = fs::path(path).parent_path();
    if (!parent.empty()) fs::create_directories(parent, ec);

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return std::string();
    f << "{\n";
    f << "  \"census\": {\n"
      << "    \"files_scanned\": " << census_.filesScanned << ",\n"
      << "    \"gguf_by_magic\": " << census_.ggufByMagic << ",\n"
      << "    \"non_gguf_skipped\": " << census_.nonGgufSkipped << ",\n"
      << "    \"logical_models\": " << census_.logicalModels << ",\n"
      << "    \"single_file\": " << census_.singleFile << ",\n"
      << "    \"sharded_complete\": " << census_.shardedComplete << ",\n"
      << "    \"sharded_incomplete\": " << census_.shardedIncomplete << ",\n"
      << "    \"projectors\": " << census_.projectors << ",\n"
      << "    \"manifests_no_payload\": " << census_.manifestsNoPayload << ",\n"
      << "    \"corrupt_headers\": " << census_.corruptHeaders << ",\n"
      << "    \"total_bytes\": " << census_.totalBytes << "\n"
      << "  },\n";
    f << "  \"models\": [\n";
    for (std::size_t i = 0; i < models_.size(); ++i) {
        const LogicalModel& m = models_[i];
        f << "    {\"logical_name\": \"" << Escape(m.logicalName) << "\","
          << " \"directory\": \"" << Escape(m.directory) << "\","
          << " \"artifact\": \"" << ClassName(m.artifact) << "\","
          << " \"present_shards\": " << m.presentShards << ","
          << " \"expected_shards\": " << m.expectedShards << ","
          << " \"total_bytes\": " << m.totalBytes << ","
          << " \"entry_shard\": \"" << Escape(m.entryShardPath()) << "\","
          << " \"gguf_version\": " << m.header.version << ","
          << " \"arch\": \"" << Escape(m.header.architecture) << "\","
          << " \"name\": \"" << Escape(m.header.name) << "\","
          << " \"tensor_count\": " << m.header.tensorCount << ","
          << " \"quant\": \"" << Escape(m.header.quantName) << "\","
          << " \"header_valid\": " << (m.header.valid ? "true" : "false") << ","
          << " \"header_error\": \"" << Escape(m.header.error) << "\"}";
        if (i + 1 < models_.size()) f << ",";
        f << "\n";
    }
    f << "  ]\n}\n";
    f.close();
    if (!f) return std::string();
    return path;
}

std::string ModelInventory::WriteReceipt(const std::string& path,
                                         const std::string& engineNote) const {
    std::error_code ec;
    const fs::path parent = fs::path(path).parent_path();
    if (!parent.empty()) fs::create_directories(parent, ec);

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return std::string();
    f << "=== RAWRXD_DEEP2_STREAMER_DISCOVERY_001 ===\n";
    f << "DISCOVERY_BY=GGUF_MAGIC_47_47_55_46\n";
    f << "ADMISSION_POLICY=NONE_BY_SIZE\n";
    f << "FILES_SCANNED=" << census_.filesScanned << "\n";
    f << "GGUF_BY_MAGIC=" << census_.ggufByMagic << "\n";
    f << "NON_GGUF_SKIPPED=" << census_.nonGgufSkipped << "\n";
    f << "LOGICAL_MODELS=" << census_.logicalModels << "\n";
    f << "SINGLE_FILE=" << census_.singleFile << "\n";
    f << "SHARDED_COMPLETE=" << census_.shardedComplete << "\n";
    f << "SHARDED_INCOMPLETE=" << census_.shardedIncomplete << "\n";
    f << "PROJECTORS=" << census_.projectors << "\n";
    f << "MANIFESTS_NO_PAYLOAD=" << census_.manifestsNoPayload << "\n";
    f << "CORRUPT_HEADERS=" << census_.corruptHeaders << "\n";
    f << "TOTAL_BYTES=" << census_.totalBytes << "\n";
    f << "ENGINE_NOTE=" << engineNote << "\n";
    f << "NOTE=Discovery is an INVENTORY. It admits nothing on size and decides\n"
         "     nothing about capability. Every capable-looking artifact is handed\n"
         "     to Deep2 and the verdict is whatever Deep2 does.\n";
    f << "=== RECEIPT_END ===\n";
    f.close();
    if (!f) return std::string();
    return path;
}

} // namespace streamer
} // namespace rawrxd