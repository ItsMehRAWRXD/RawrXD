#include "reap/ReapPhysicalReduceExport.hpp"

#include "deep2/GGUFLoader.hpp"
#include "deep2/ReapMoETransformer.hpp"
#include "deep2/deep2_sha256.hpp"

#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace RawrXD::Reap {
namespace {

namespace fs = std::filesystem;

bool pathIsUnderOrEqual(const fs::path& candidate, const fs::path& root) {
    std::error_code ec;
    const fs::path c = fs::weakly_canonical(candidate, ec);
    if (ec) return true;
    const fs::path r = fs::weakly_canonical(root, ec);
    if (ec) return true;
    auto cIt = c.begin(), rIt = r.begin();
    for (; rIt != r.end(); ++cIt, ++rIt) {
        if (cIt == c.end() || *cIt != *rIt) return false;
    }
    return true;
}

bool listShards(const fs::path& first, std::vector<fs::path>& out,
                std::string& error) {
    out.clear();
    std::error_code ec;
    if (!fs::is_regular_file(first, ec)) {
        error = "PHYSICAL_FIRST_SHARD_MISSING";
        return false;
    }
    const std::string name = first.filename().string();
    const auto marker = name.find("-00001-of-");
    if (marker == std::string::npos) {
        out.push_back(first);
        return true;
    }
    const std::string prefix = name.substr(0, marker);
    for (auto& ent : fs::directory_iterator(first.parent_path(), ec)) {
        if (ec || !ent.is_regular_file(ec)) continue;
        const std::string fn = ent.path().filename().string();
        if (fn.rfind(prefix, 0) == 0 && ent.path().extension() == ".gguf")
            out.push_back(ent.path());
    }
    std::sort(out.begin(), out.end());
    if (out.empty()) {
        error = "PHYSICAL_NO_SHARDS_FOUND";
        return false;
    }
    return true;
}

bool collectMoeLayers(const fs::path& first, std::set<uint32_t>& layers,
                      std::string& error) {
    std::vector<fs::path> shards;
    if (!listShards(first, shards, error)) return false;
    Deep2::GGUFLoadOptions options{};
    options.mmap = false;
    options.loadTensors = false;
    options.verbose = false;
    for (const auto& shard : shards) {
        Deep2::GGUFLoadResult result =
            Deep2::GGUFLoader::Load(shard.string().c_str(), options);
        if (!result.success) {
            error = std::string("EXPORT_INVENTORY_FAILED:") +
                    shard.filename().string() + ":" + result.error;
            return false;
        }
        for (const auto& tensor : result.tensors) {
            if (tensor.name.find("ffn_gate_exps") == std::string::npos)
                continue;
            if (tensor.name.rfind("blk.", 0) != 0) continue;
            const size_t end = tensor.name.find('.', 4);
            if (end == std::string::npos) continue;
            try {
                layers.insert(static_cast<uint32_t>(
                    std::stoul(tensor.name.substr(4, end - 4))));
            } catch (...) {
            }
        }
    }
    if (layers.empty()) {
        error = "EXPORT_NO_MOE_LAYERS";
        return false;
    }
    return true;
}

std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        if (c == '\\' || c == '"') {
            out.push_back('\\');
            out.push_back(static_cast<char>(c));
        } else if (c < 0x20) {
            out.push_back('?');
        } else {
            out.push_back(static_cast<char>(c));
        }
    }
    return out;
}

bool writeUniformManifest(const fs::path& path, const std::string& model,
                          uint32_t retained,
                          const std::set<uint32_t>& layers,
                          std::string& error) {
    std::ostringstream o;
    o << "{\"schema\":\"RAWRXD_REAP_EXPERT_SELECTION_001\","
      << "\"status\":\"STREAM_PHYSICAL_UNCERTIFIED\","
      << "\"experimental_uncertified_export\":true,"
      << "\"rewrite_authorized\":false,"
      << "\"reference_parity_pass\":false,"
      << "\"stream_physical_export\":true,"
      << "\"model\":\"" << jsonEscape(model) << "\","
      << "\"active_experts\":" << retained << ","
      << "\"PROMOTE\":0,\"CERTIFIED\":0,"
      << "\"layers\":[";
    bool firstLayer = true;
    for (uint32_t layer : layers) {
        if (!firstLayer) o << ',';
        firstLayer = false;
        o << "{\"layer\":" << layer << ",\"selected\":[";
        for (uint32_t e = 0; e < retained; ++e) {
            if (e) o << ',';
            o << "{\"expert\":" << e << "}";
        }
        o << "]}";
    }
    o << "]}\n";
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        error = "EXPORT_MANIFEST_OPEN_FAILED";
        return false;
    }
    out << o.str();
    if (!out.good()) {
        error = "EXPORT_MANIFEST_WRITE_FAILED";
        return false;
    }
    return true;
}

} // namespace

bool TryExportReducedSidecar(const std::string& sourceFirstShard,
                             const std::string& outputDir,
                             uint32_t retainedExperts,
                             uint64_t targetBytes,
                             PhysicalExportResult& out) {
    out = {};
    out.status = "NOT_RUN";
    if (sourceFirstShard.empty()) {
        out.reason = "MISSING_INPUT:SOURCE_FIRST_SHARD";
        return false;
    }
    if (outputDir.empty()) {
        out.reason = "MISSING_INPUT:RAWR_REAP_EXPORT_DIR";
        return false;
    }
    if (!retainedExperts) {
        out.reason = "EXPORT_RETAINED_ZERO";
        return false;
    }

    const fs::path sourcePath(sourceFirstShard);
    const fs::path outPath(outputDir);
    if (pathIsUnderOrEqual(outPath, sourcePath.parent_path())) {
        out.status = "BLOCKED";
        out.reason = "EXPORT_DIR_MUST_NOT_BE_SOURCE_DIR";
        return false;
    }

    const char* exp = std::getenv("RAWR_REAP_EXPORT_EXPERIMENTAL");
    if (!exp || exp[0] != '1') {
        out.status = "BLOCKED";
        out.reason =
            "EXPORT_REQUIRES_RAWR_REAP_EXPORT_EXPERIMENTAL=1_OR_CERTIFIED_MANIFEST;"
            "STREAM_PATH_SOURCE_IMMUTABLE=1";
        return false;
    }

    std::string manifestPath;
    const char* manifestEnv = std::getenv("RAWR_REAP_SELECTION_MANIFEST");
    if (manifestEnv && manifestEnv[0]) {
        manifestPath = manifestEnv;
    } else {
        const fs::path autoManifest =
            fs::path(outputDir).string() +
            ".selection_stream_physical_uncertified.json";
        std::set<uint32_t> layers;
        std::string invErr;
        if (!collectMoeLayers(sourcePath, layers, invErr)) {
            out.status = "BLOCKED";
            out.reason = invErr;
            return false;
        }
        if (!writeUniformManifest(autoManifest, sourceFirstShard,
                                  retainedExperts, layers, invErr)) {
            out.status = "BLOCKED";
            out.reason = invErr;
            return false;
        }
        manifestPath = autoManifest.string();
    }

    Deep2::ReapMoETransformRequest req{};
    req.sourceFirstShard = sourceFirstShard;
    req.outputDirectory = outputDir;
    req.selectionManifest = manifestPath;
    req.activeExperts = retainedExperts;
    (void)targetBytes;
    req.targetSizeBytes = 0;
    req.replaceExisting = false;

    /* transformMoEGGUF remaps ffn_gate_inp as ggml expert columns (ne=[H,E]
     * col e = [e*H*4,(e+1)*H*4)) in sorted M_l order with bodies+bias. */
    const Deep2::ReapMoETransformResult published =
        Deep2::transformMoEGGUF(req);
    if (!published.success) {
        out.status = "FAIL";
        out.reason = published.error.empty() ? "transformMoEGGUF_FAILED"
                                             : published.error;
        std::fprintf(stderr, "REAP_PHYSICAL_EXPORT fail reason=%s PROMOTE=0\n",
                     out.reason.c_str());
        return false;
    }

    out.status = "EXPORTED";
    out.reason = "transformMoEGGUF_SIDECAR_SOURCE_IMMUTABLE";
    out.outputFirstShard = published.outputFirstShard;
    out.outputBytes = published.outputBytes;
    std::array<uint8_t, 32> digest{};
    if (deep2::sha256_file(published.outputFirstShard, digest, nullptr))
        out.sha256 = deep2::hex32(digest);
    return true;
}

} // namespace RawrXD::Reap
