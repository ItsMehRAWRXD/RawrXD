#include "deep2/GGUFLoader.hpp"
#include "deep2/ReapMoETransformer.hpp"
#include "reap_cli_contract.hpp"
#include "reap_expert_layout.hpp"
#include "reap_inventory.hpp"
#include "deep2/deep2_sha256.hpp"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <sstream>
#include <string>
#include <set>
#include <unordered_map>
#include <vector>

namespace fs = std::filesystem;
using json = nlohmann::json;

static void usage() {
    std::cerr << "rawr-reap inspect <first-shard.gguf>\n"
                 "rawr-reap plan <first-shard.gguf> --size <B|MB|GB|TB>\n"
                 "rawr-reap topology <first-shard.gguf> [--output <topology.json>]\n"
                 "rawr-reap capabilities <model-file-or-directory>\n"
                 "rawr-reap verify <first-shard.gguf> [--receipt <receipt.json>] [--structural-only]\n"
                 "rawr-reap reap <first-shard.gguf> --target-size|--size <B|MB|GB|TB> "
                 "--active-experts <N> --expert-budget <B|MB|GB|TB> "
                 "--quality-floor <0..1> [--calibration <receipt.json>] "
                 "[--selection-output <selection.json>] [--output-model <dir>] "
                 "[--authorize-rewrite] [--output <plan.json>]\n";
}

static std::string json_quote(const std::string& s);

struct ShardVerification {
    std::string path;
    uint64_t bytes = 0;
    std::string sha256;
    bool ggufMagic = false;
    bool readable = false;
};

static bool readU32LE(const std::string& path, uint32_t& value) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    unsigned char b[4]{};
    in.read(reinterpret_cast<char*>(b), sizeof(b));
    if (in.gcount() != static_cast<std::streamsize>(sizeof(b))) return false;
    value = static_cast<uint32_t>(b[0]) |
            (static_cast<uint32_t>(b[1]) << 8) |
            (static_cast<uint32_t>(b[2]) << 16) |
            (static_cast<uint32_t>(b[3]) << 24);
    return true;
}

static bool enumerateShards(const std::string& firstPath,
                            std::vector<fs::path>& shards,
                            std::string& error) {
    const fs::path first(firstPath);
    std::error_code ec;
    if (!fs::is_regular_file(first, ec)) {
        error = "FIRST_SHARD_NOT_REGULAR";
        return false;
    }
    const std::string filename = first.filename().string();
    const size_t marker = filename.find("-00001-of-");
    if (marker == std::string::npos) {
        shards.push_back(first);
        return true;
    }
    const std::string prefix = filename.substr(0, marker);
    const size_t numberStart = marker + 1;
    const size_t numberEnd = filename.find("-of-", numberStart);
    if (numberEnd == std::string::npos) {
        error = "INVALID_SHARD_NAME";
        return false;
    }
    const size_t suffixStart = numberEnd + 4;
    const size_t extStart = filename.rfind(".gguf");
    if (extStart == std::string::npos || extStart <= suffixStart) {
        error = "INVALID_SHARD_NAME";
        return false;
    }
    uint64_t shardCount = 0;
    try {
        shardCount = std::stoull(filename.substr(suffixStart, extStart - suffixStart));
    } catch (...) {
        error = "INVALID_SHARD_COUNT";
        return false;
    }
    if (shardCount == 0 || shardCount > 4096) {
        error = "INVALID_SHARD_COUNT";
        return false;
    }
    shards.reserve(static_cast<size_t>(shardCount));
    for (uint64_t i = 1; i <= shardCount; ++i) {
        std::ostringstream name;
        name << prefix << '-' << std::setw(5) << std::setfill('0') << i
             << "-of-" << std::setw(5) << std::setfill('0') << shardCount << ".gguf";
        fs::path candidate = first.parent_path() / name.str();
        if (!fs::is_regular_file(candidate, ec)) {
            error = "MISSING_SHARD:" + candidate.string();
            return false;
        }
        shards.push_back(std::move(candidate));
    }
    return true;
}

static int verifyModelShards(const std::string& firstPath,
                             const std::string& receiptPath,
                             bool structuralOnly) {
    Deep2::GGUFLoader loader;
    if (!loader.load(firstPath)) {
        std::cerr << "GGUF_LOAD_FAILED: " << loader.error() << "\n";
        return 1;
    }
    std::vector<fs::path> shards;
    std::string error;
    if (!enumerateShards(firstPath, shards, error)) {
        std::cerr << "SHARD_ENUMERATION_FAILED: " << error << "\n";
        return 4;
    }
    std::vector<ShardVerification> records;
    records.reserve(shards.size());
    uint64_t totalBytes = 0;
    bool allValid = true;
    for (const auto& shard : shards) {
        ShardVerification record;
        record.path = shard.string();
        std::error_code ec;
        record.bytes = fs::file_size(shard, ec);
        uint32_t magic = 0;
        record.readable = !ec && record.bytes >= 8 && readU32LE(record.path, magic);
        record.ggufMagic = record.readable && magic == 0x46554747u; // "GGUF"
        if (!structuralOnly) {
            std::array<uint8_t, 32> digest{};
            if (record.readable && deep2::sha256_file(record.path, digest, nullptr)) {
                record.sha256 = deep2::hex32(digest);
            } else {
                record.readable = false;
            }
        }
        allValid = allValid && record.readable && record.ggufMagic &&
                   (structuralOnly || !record.sha256.empty());
        totalBytes += record.bytes;
        records.push_back(std::move(record));
    }
    const bool loaderCountMatches = loader.shardCount() == records.size();
    allValid = allValid && loaderCountMatches && !records.empty();

    std::ostringstream out;
    out << "{\"schema\":\"reap.model_shard_verification_001\","
        << "\"model_first_shard\":" << json_quote(firstPath) << ','
        << "\"shards\":" << records.size() << ','
        << "\"loader_shards\":" << loader.shardCount() << ','
        << "\"loader_tensors\":" << loader.tensorCount() << ','
        << "\"total_bytes\":" << totalBytes << ','
        << "\"hash_scope\":\"" << (structuralOnly ? "none_structural_only" : "all_shards_sha256") << "\","
        << "\"all_shards_present\":" << (allValid ? "true" : "false") << ','
        << "\"originals_unchanged\":true,\"records\":[";
    for (size_t i = 0; i < records.size(); ++i) {
        if (i) out << ',';
        const auto& r = records[i];
        out << "{\"index\":" << (i + 1)
            << ",\"path\":" << json_quote(r.path)
            << ",\"bytes\":" << r.bytes
            << ",\"gguf_magic\":" << (r.ggufMagic ? "true" : "false")
            << ",\"readable\":" << (r.readable ? "true" : "false")
            << ",\"sha256\":" << json_quote(r.sha256) << '}';
    }
    out << "]}\n";
    const std::string result = out.str();
    std::cout << result;
    if (!receiptPath.empty()) {
        const fs::path target(receiptPath);
        const fs::path temp = target.string() + ".tmp";
        std::ofstream file(temp, std::ios::binary | std::ios::trunc);
        if (!file || !(file << result) || !file.good()) return 5;
        file.close();
        std::error_code ec;
        fs::rename(temp, target, ec);
        if (ec) {
            fs::remove(temp, ec);
            return 5;
        }
    }
    return allValid ? 0 : 4;
}

static std::string json_quote(const std::string& s) {
    std::string o = "\"";
    for (unsigned char c : s) { if (c == '\\' || c == '\"') o += '\\'; if (c < 0x20) o += '?'; else o += (char)c; }
    return o + "\"";
}

static int capabilities(const std::string& input) {
    fs::path p(input); std::error_code ec;
    fs::path candidate = p;
    if (fs::is_directory(p, ec)) {
        for (auto& e : fs::directory_iterator(p, ec)) {
            if (!ec && e.is_regular_file() && e.path().extension() == ".gguf") { candidate = e.path(); break; }
        }
    }
    const bool recognized = candidate.extension() == ".gguf";
    if (!recognized) {
        std::cout << "{\"source\":" << json_quote(input)
                  << ",\"format\":\"unknown\",\"inspectable\":false,\"calibratable\":false,\"transformable\":false,\"reason\":\"unsupported_format_or_missing_metadata\"}\n";
        return 4;
    }
    Deep2::GGUFLoader l;
    if (!l.load(candidate.string())) {
        std::cout << "{\"source\":" << json_quote(input)
                  << ",\"format\":\"gguf\",\"inspectable\":false,\"calibratable\":false,\"transformable\":false,\"reason\":"
                  << json_quote(l.error()) << "}\n";
        return 4;
    }
    const bool tokenizer = !l.getMetaString("tokenizer.ggml.model", "").empty() ||
                           !l.getMetaString("tokenizer.ggml.pre", "").empty();
    std::string architecture = l.getMetaString("general.architecture", "");
    std::transform(architecture.begin(), architecture.end(), architecture.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    // The replay backend currently has a certified native stream path only
    // for the Kimi/DeepSeek MLA families.  Inventory remains valid for every
    // GGUF, but a tokenizer alone is not enough to advertise calibratability.
    const bool replayArchitecture = architecture.find("kimi") != std::string::npos ||
                                    architecture.find("deepseek") != std::string::npos;
    const bool calibratable = tokenizer && replayArchitecture;
    std::string reason;
    if (!tokenizer) reason = "tokenizer_metadata_missing";
    else if (!replayArchitecture) reason = "architecture_runtime_not_supported:" + architecture;
    else reason = "transform_writer_and_parity_gate_required";
    std::cout << "{\"source\":" << json_quote(input) << ",\"format\":\"gguf\",\"inspectable\":true"
              << ",\"architecture\":" << json_quote(architecture)
              << ",\"calibratable\":" << (calibratable ? "true" : "false")
              << ",\"transformable\":false,\"shards\":" << l.shardCount()
              << ",\"tensors\":" << l.tensorCount()
              << ",\"reason\":" << json_quote(reason) << "}\n";
    return calibratable ? 0 : 4;
}

static bool bytes(const std::string& s, uint64_t& out) {
    size_t n = 0; while (n < s.size() && (std::isdigit((unsigned char)s[n]) || s[n] == '.')) ++n;
    if (!n || n == s.size()) return false;
    double v = std::strtod(s.substr(0, n).c_str(), nullptr);
    std::string u = s.substr(n); std::transform(u.begin(), u.end(), u.begin(), ::toupper);
    uint64_t m = 1;
    if (u == "B") m = 1; else if (u == "MB" || u == "MIB") m = 1ull<<20;
    else if (u == "GB" || u == "GIB") m = 1ull<<30; else if (u == "TB" || u == "TIB") m = 1ull<<40;
    else return false;
    if (!(v > 0) || v * (long double)m > UINT64_MAX) return false;
    out = (uint64_t)(v * m); return out != 0;
}

struct ReapInventory {
    uint64_t totalBytes = 0;
    uint64_t expertBytes = 0;
    uint64_t expertTensors = 0;
    uint64_t logicalExperts = 0;
    uint64_t maxExpertsPerLayer = 0;
    uint64_t layerCount = 0;
    std::set<uint32_t> moeLayers;
};

static bool supportsPairUpDownExperts(const std::string& architecture) {
    // Nemotron-H MoE stores a router plus packed expert up/down projections.
    // It has no per-expert gate projection; treating that absence as a
    // malformed DeepSeek triplet would reject a structurally valid model.
    return architecture == "nemotron_h_moe";
}

static bool collectReapInventory(const std::string& path,
                                 Deep2::GGUFLoader& loader,
                                 ReapInventory& out,
                                 std::string& error) {
    if (!loader.load(path)) {
        error = loader.error();
        return false;
    }
    const char* archKeys[] = {"deepseek2.block_count", "deepseek.block_count", "llama.block_count"};
    for (const char* key : archKeys) {
        const int64_t count = loader.getMetaInt(key, 0);
        if (count > 0) { out.layerCount = static_cast<uint64_t>(count); break; }
    }
    for (const auto& name : loader.listTensors()) {
        const auto* tensor = loader.getTensor(name);
        if (!tensor) continue;
        const bool expert = name.find(".experts.") != std::string::npos ||
                            name.find(".expert.") != std::string::npos ||
                            name.find(".ffn_gate_exps.") != std::string::npos ||
                            name.find(".ffn_up_exps.") != std::string::npos ||
                            name.find(".ffn_down_exps.") != std::string::npos ||
                            name.find("experts.") == 0;
        if (expert) {
            out.expertBytes += tensor->sizeBytes;
            ++out.expertTensors;
        }
    }
    for (uint32_t layer = 0; layer < 256; ++layer) {
        const std::string prefix = "blk." + std::to_string(layer) + ".";
        const auto* gate = loader.getTensor(prefix + "ffn_gate_exps.weight");
        const auto* up = loader.getTensor(prefix + "ffn_up_exps.weight");
        const auto* down = loader.getTensor(prefix + "ffn_down_exps.weight");
        if (!gate && !up && !down) continue;
        const std::string architecture = loader.getMetaString("general.architecture", "");
        const auto decision = RawrXD::Reap::ClassifyExpertProjections(
            gate != nullptr, up != nullptr, down != nullptr,
            gate && !gate->shape.empty(), up && !up->shape.empty(), down && !down->shape.empty(),
            gate && !gate->shape.empty() ? gate->shape.back() : 0,
            up && !up->shape.empty() ? up->shape.back() : 0,
            down && !down->shape.empty() ? down->shape.back() : 0);
        const bool pairLayout = decision.kind == RawrXD::Reap::ExpertLayoutKind::PairUpDown &&
                                supportsPairUpDownExperts(architecture);
        if (pairLayout) {
            if (!up || !down || up->shape.empty() || down->shape.empty() ||
                up->shape.back() != down->shape.back()) {
                error = "invalid Nemotron-H expert up/down pair at layer " + std::to_string(layer);
                return false;
            }
        } else if (decision.kind != RawrXD::Reap::ExpertLayoutKind::DeepseekTriplet) {
            error = RawrXD::Reap::LayoutRejection(decision, layer, architecture);
            return false;
        }
        out.layerCount = (std::max)(out.layerCount, static_cast<uint64_t>(layer + 1));
        if ((!pairLayout && (!gate || !up || !down || gate->shape.empty() || up->shape.empty() ||
            down->shape.empty() || gate->shape.back() != up->shape.back() ||
            gate->shape.back() != down->shape.back()))) {
            error = "invalid expert projection triplet at layer " + std::to_string(layer);
            return false;
        }
        out.moeLayers.insert(layer);
        const uint64_t count = static_cast<uint64_t>((pairLayout ? up : gate)->shape.back());
        if (count == 0 || (pairLayout ? 0 : gate->sizeBytes) % count || up->sizeBytes % count ||
            down->sizeBytes % count) {
            error = "expert projection slices are not divisible at layer " + std::to_string(layer);
            return false;
        }
        out.logicalExperts += count;
        out.maxExpertsPerLayer = std::max(out.maxExpertsPerLayer, count);
    }
    std::error_code ec;
    const fs::path first(path);
    const fs::path dir = first.parent_path();
    const std::string stem = first.filename().string();
    const auto marker = stem.find("-00001-of-");
    if (marker != std::string::npos) {
        const std::string prefix = stem.substr(0, marker);
        for (const auto& entry : fs::directory_iterator(dir, ec)) {
            if (!ec && entry.is_regular_file() &&
                entry.path().filename().string().rfind(prefix + "-", 0) == 0 &&
                entry.path().extension() == ".gguf") {
                out.totalBytes += fs::file_size(entry.path(), ec);
            }
        }
    } else {
        out.totalBytes = fs::file_size(first, ec);
    }
    if (!out.totalBytes) out.totalBytes = loader.mappedBytes();
    if (!out.totalBytes) {
        error = "model size could not be established";
        return false;
    }
    return true;
}

static bool readText(const std::string& path, std::string& text) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return false;
    std::ostringstream buffer;
    buffer << input.rdbuf();
    text = buffer.str();
    return input.good() || input.eof();
}

static bool writePlan(const std::string& path, const std::string& json) {
    if (path.empty()) return true;
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) return false;
    output.write(json.data(), static_cast<std::streamsize>(json.size()));
    return output.good();
}

static int topology(const std::string& path, const std::string& outputPath) {
    Deep2::GGUFLoader loader;
    if (!loader.load(path)) {
        std::cerr << "GGUF_LOAD_FAILED: " << loader.error() << "\n";
        return 1;
    }

    uint64_t totalBytes = 0;
    std::error_code ec;
    const fs::path first(path);
    const fs::path directory = first.parent_path();
    const std::string filename = first.filename().string();
    const size_t marker = filename.find("-00001-of-");
    if (marker != std::string::npos) {
        const std::string prefix = filename.substr(0, marker);
        for (const auto& entry : fs::directory_iterator(directory, ec)) {
            if (!ec && entry.is_regular_file() &&
                entry.path().filename().string().rfind(prefix + "-", 0) == 0 &&
                entry.path().extension() == ".gguf") {
                totalBytes += fs::file_size(entry.path(), ec);
            }
        }
    } else {
        totalBytes = fs::file_size(first, ec);
    }
    if (!totalBytes) totalBytes = loader.mappedBytes();
    if (!totalBytes) {
        std::cerr << "MODEL_SIZE_UNAVAILABLE\n";
        return 4;
    }

    const auto tensorBytes = [&](const std::string& name) -> uint64_t {
        const auto* tensor = loader.getTensor(name);
        return tensor ? tensor->sizeBytes : 0;
    };
    const auto tensorCount = [&](const std::string& name) -> uint64_t {
        const auto* tensor = loader.getTensor(name);
        if (!tensor || tensor->shape.empty()) return 0;
        return static_cast<uint64_t>(tensor->shape.back());
    };

    uint64_t routedProjectionBytes = 0;
    uint64_t routedProjectionMinimumBytes = 0;
    uint64_t routerBytes = 0;
    uint64_t sharedExpertBytes = 0;
    uint64_t unsupportedExpertBytes = 0;
    std::set<uint32_t> moeLayers;
    json layerReports = json::array();
    const std::string architecture = loader.getMetaString("general.architecture", "");
    for (uint32_t layer = 0; layer < 256; ++layer) {
        const std::string prefix = "blk." + std::to_string(layer) + ".";
        const std::string gateName = prefix + "ffn_gate_exps.weight";
        const std::string upName = prefix + "ffn_up_exps.weight";
        const std::string downName = prefix + "ffn_down_exps.weight";
        const auto* gate = loader.getTensor(gateName);
        const auto* up = loader.getTensor(upName);
        const auto* down = loader.getTensor(downName);
        if (!gate && !up && !down) continue;
        const auto decision = RawrXD::Reap::ClassifyExpertProjections(
            gate != nullptr, up != nullptr, down != nullptr,
            gate && !gate->shape.empty(), up && !up->shape.empty(), down && !down->shape.empty(),
            gate && !gate->shape.empty() ? gate->shape.back() : 0,
            up && !up->shape.empty() ? up->shape.back() : 0,
            down && !down->shape.empty() ? down->shape.back() : 0);
        const bool pairLayout = decision.kind == RawrXD::Reap::ExpertLayoutKind::PairUpDown &&
                                supportsPairUpDownExperts(architecture);
        if (!pairLayout && decision.kind != RawrXD::Reap::ExpertLayoutKind::DeepseekTriplet) {
            std::cerr << RawrXD::Reap::LayoutRejection(decision, layer, architecture) << "\n";
            return 4;
        }
        if ((pairLayout && (!up || !down || up->shape.empty() || down->shape.empty() ||
                            up->shape.back() != down->shape.back())) ||
            (!pairLayout && (!gate || !up || !down || gate->shape.empty() || up->shape.empty() ||
            down->shape.empty() || gate->shape.back() != up->shape.back() ||
            gate->shape.back() != down->shape.back()))) {
            std::cerr << "INVALID_EXPERT_PROJECTION_TRIPLET layer=" << layer << "\n";
            return 4;
        }
        const uint64_t expertCount = static_cast<uint64_t>((pairLayout ? up : gate)->shape.back());
        const uint64_t gateBytes = pairLayout ? 0 : gate->sizeBytes;
        const uint64_t gateSlice = pairLayout ? 0 : gateBytes / expertCount;
        const uint64_t upSlice = up->sizeBytes / expertCount;
        const uint64_t downSlice = down->sizeBytes / expertCount;
        if (!expertCount || gateBytes % expertCount || up->sizeBytes % expertCount ||
            down->sizeBytes % expertCount) {
            std::cerr << "INVALID_EXPERT_PROJECTION_DIVISIBILITY layer=" << layer << "\n";
            return 4;
        }
        const uint64_t projectionBytes = gateBytes + up->sizeBytes + down->sizeBytes;
        const uint64_t minimumProjectionBytes = gateSlice + upSlice + downSlice;
        routedProjectionBytes += projectionBytes;
        routedProjectionMinimumBytes += minimumProjectionBytes;
        moeLayers.insert(layer);

        const std::string routerName = prefix + "ffn_gate_inp.weight";
        const std::string biasName = prefix + "exp_probs_b.bias";
        const uint64_t layerRouterBytes = tensorBytes(routerName) + tensorBytes(biasName);
        routerBytes += layerRouterBytes;
        json shared = json::array();
        for (const auto& name : loader.listTensors()) {
            if (name.rfind(prefix, 0) != 0) continue;
            if (name.find("shexp") == std::string::npos &&
                name.find("shared_expert") == std::string::npos) continue;
            const uint64_t bytesForTensor = tensorBytes(name);
            sharedExpertBytes += bytesForTensor;
            shared.push_back({{"name", name}, {"bytes", bytesForTensor}});
        }
        layerReports.push_back({
            {"layer", layer},
            {"layout", pairLayout ? "pair_up_down" : "deepseek_triplet"},
            {"packed_expert_count", expertCount},
            {"gate_bytes", gateBytes},
            {"up_bytes", up->sizeBytes},
            {"down_bytes", down->sizeBytes},
            {"gate_slice_bytes", gateSlice},
            {"up_slice_bytes", upSlice},
            {"down_slice_bytes", downSlice},
            {"router_bytes", layerRouterBytes},
            {"shared_expert_tensors", shared}
        });
    }

    uint64_t expertBytes = 0;
    uint64_t expertTensorCount = 0;
    for (const auto& name : loader.listTensors()) {
        const auto* tensor = loader.getTensor(name);
        if (!tensor) continue;
        const bool expert = name.find(".experts.") != std::string::npos ||
                            name.find(".expert.") != std::string::npos ||
                            name.find(".ffn_gate_exps.") != std::string::npos ||
                            name.find(".ffn_up_exps.") != std::string::npos ||
                            name.find(".ffn_down_exps.") != std::string::npos ||
                            name.find("experts.") == 0;
        if (!expert) continue;
        expertBytes += tensor->sizeBytes;
        ++expertTensorCount;
    }
    if (expertBytes >= routedProjectionBytes) unsupportedExpertBytes = expertBytes - routedProjectionBytes;
    const uint64_t nonExpertBytes = totalBytes >= expertBytes ? totalBytes - expertBytes : 0;
    const bool minimumBoundKnown = unsupportedExpertBytes == 0;
    const uint64_t minimumOutputBytes = minimumBoundKnown
        ? nonExpertBytes + routedProjectionMinimumBytes : 0;
    const int64_t blockCount = loader.getMetaInt("deepseek2.block_count", 0);
    const uint64_t reportedLayerCount = blockCount > 0 ? static_cast<uint64_t>(blockCount) : 0;

    std::ostringstream receipt;
    receipt << "{\"schema\":\"RAWRXD_REAP_TOPOLOGY_001\""
            << ",\"source\":" << json_quote(path)
            << ",\"shards\":" << loader.shardCount()
            << ",\"tensors\":" << loader.tensorCount()
            << ",\"total_bytes\":" << totalBytes
            << ",\"expert_tensor_count\":" << expertTensorCount
            << ",\"expert_bytes\":" << expertBytes
            << ",\"non_expert_bytes\":" << nonExpertBytes
            << ",\"routed_projection_bytes\":" << routedProjectionBytes
            << ",\"routed_projection_minimum_one_expert_bytes\":" << routedProjectionMinimumBytes
            << ",\"unsupported_expert_bytes\":" << unsupportedExpertBytes
            << ",\"router_bytes\":" << routerBytes
            << ",\"shared_expert_bytes\":" << sharedExpertBytes
            << ",\"reported_block_count\":" << reportedLayerCount
            << ",\"moe_layer_count\":" << moeLayers.size()
            << ",\"minimum_bound_known\":" << (minimumBoundKnown ? "true" : "false")
            << ",\"minimum_output_bytes_one_expert_per_moe_layer\":" << minimumOutputBytes
            << ",\"layers\":" << layerReports.dump() << "}\n";
    const std::string result = receipt.str();
    std::cout << result;
    if (!writePlan(outputPath, result)) {
        std::cerr << "TOPOLOGY_RECEIPT_WRITE_FAILED\n";
        return 5;
    }
    return minimumBoundKnown && !moeLayers.empty() ? 0 : 4;
}

struct CalibrationMetric {
    uint32_t layer = 0;
    uint32_t expert = 0;
    uint64_t routeCount = 0;
    double score = 0.0;
};

struct CalibrationEvidence {
    bool parsed = false;
    bool complete = false;
    bool continuous = false;
    bool continuousCompleted = false;
    bool routeMetrics = false;
    bool mlaSeal = false;
    bool calibrationComplete = false;
    bool internalPrefillParity = false;
    bool referenceParity = false;
    uint64_t generated = 0;
    std::vector<CalibrationMetric> metrics;
    std::string reason;
};

static bool loadCalibrationEvidence(const std::string& path,
                                    const std::string& model,
                                    CalibrationEvidence& out) {
    std::string text;
    if (!readText(path, text)) {
        out.reason = "calibration receipt could not be read";
        return false;
    }
    try {
        const json doc = json::parse(text);
        if (doc.value("schema", std::string{}) != "RAWRXD_REAP_CALIBRATION_001") {
            out.reason = "unsupported calibration receipt schema";
            return false;
        }
        if (doc.value("model", std::string{}) != model) {
            out.reason = "calibration receipt model does not match request";
            return false;
        }
        out.complete = doc.value("complete", false);
        out.continuous = doc.value("continuous_prefill_decode", false);
        out.continuousCompleted = doc.value("continuous_completed", false);
        out.routeMetrics = doc.value("route_metrics_available", false);
        out.mlaSeal = doc.value("mla_product_seal", false);
        out.calibrationComplete = doc.value("calibration_complete", false);
        out.internalPrefillParity = doc.value("prefill_parity_pass", false);
        out.referenceParity = doc.value("reference_parity_pass", false);
        out.generated = doc.value("generated", uint64_t{0});
        const auto it = doc.find("metrics");
        if (it != doc.end() && it->is_array()) {
            for (const auto& item : *it) {
                if (!item.is_object()) continue;
                CalibrationMetric metric;
                metric.layer = item.value("layer", 0u);
                metric.expert = item.value("expert", 0u);
                metric.routeCount = item.value("route_count", uint64_t{0});
                const double activation = item.value("activation_sum", 0.0);
                const double weight = item.value("weight_sum", 0.0);
                metric.score = std::isfinite(activation) && std::isfinite(weight)
                    ? std::max(0.0, activation) + std::max(0.0, weight)
                    : 0.0;
                out.metrics.push_back(metric);
            }
        }
        out.parsed = true;
        return true;
    } catch (const std::exception& ex) {
        out.reason = std::string("calibration receipt JSON parse failed: ") + ex.what();
        return false;
    }
}

struct SelectionLayer {
    uint32_t layer = 0;
    std::vector<std::pair<uint32_t, double>> experts;
};

static bool writeSelectionManifest(const std::string& path,
                                   const std::string& model,
                                   const std::string& calibration,
                                   const CalibrationEvidence& evidence,
                                   const ReapInventory& inventory,
                                   uint64_t activeExperts,
                                   uint64_t expertBudget,
                                   uint64_t targetSize,
                                   bool qualityFloorPass,
                                   bool authorizeRewrite,
                                   std::string& error) {
    if (path.empty()) return true;
    if (evidence.metrics.empty()) {
        error = "no route metrics available for expert selection";
        return false;
    }
    std::map<uint32_t, std::unordered_map<uint32_t, double>> byLayer;
    for (const auto& metric : evidence.metrics)
        byLayer[metric.layer][metric.expert] += metric.score;

    json layers = json::array();
    uint64_t selected = 0;
    for (auto& layer : byLayer) {
        std::vector<std::pair<uint32_t, double>> ranked(layer.second.begin(), layer.second.end());
        std::sort(ranked.begin(), ranked.end(), [](const auto& a, const auto& b) {
            if (a.second != b.second) return a.second > b.second;
            return a.first < b.first;
        });
        if (ranked.size() > activeExperts) ranked.resize(static_cast<size_t>(activeExperts));
        selected += ranked.size();
        json experts = json::array();
        for (const auto& item : ranked)
            experts.push_back({{"expert", item.first}, {"score", item.second}});
        layers.push_back({{"layer", layer.first}, {"selected", experts}});
    }
    if (inventory.moeLayers.empty()) {
        error = "model contains no complete MoE expert projection layers";
        return false;
    }
    for (const uint32_t layer : inventory.moeLayers) {
        if (byLayer.find(layer) == byLayer.end()) {
            error = "route metrics missing MoE layer " + std::to_string(layer);
            return false;
        }
    }
    const uint64_t logical = inventory.logicalExperts ? inventory.logicalExperts : 1;
    if (inventory.expertBytes != 0 && selected > std::numeric_limits<uint64_t>::max() / inventory.expertBytes) {
        error = "expert selection size arithmetic overflow";
        return false;
    }
    const uint64_t estimatedExpertBytes = inventory.expertBytes * selected / logical;
    const uint64_t estimatedOutputBytes = inventory.totalBytes >= inventory.expertBytes
        ? inventory.totalBytes - inventory.expertBytes + estimatedExpertBytes
        : inventory.totalBytes;
    if (expertBudget != 0 && estimatedExpertBytes > expertBudget) {
        error = "selected expert residency exceeds --expert-budget";
        return false;
    }
    if (targetSize != 0 && estimatedOutputBytes > targetSize) {
        error = "estimated reduced model exceeds --target-size";
        return false;
    }
    json manifest = {
        {"schema", "RAWRXD_REAP_EXPERT_SELECTION_001"},
        {"status", evidence.calibrationComplete ? "CANDIDATE" : "BLOCKED"},
        {"model", model},
        {"calibration", calibration},
        {"active_experts", activeExperts},
        {"selected_expert_slices", selected},
        {"estimated_expert_bytes", estimatedExpertBytes},
        {"estimated_output_bytes", estimatedOutputBytes},
        {"target_size", targetSize},
        {"expert_budget", expertBudget},
        {"deterministic_tie_break", "expert_id_ascending"},
        {"source_metrics", evidence.metrics.size()},
        {"layers", layers},
        {"reference_parity_pass", evidence.referenceParity},
        {"quality_floor_pass", qualityFloorPass},
        {"rewrite_authorized", authorizeRewrite && qualityFloorPass && evidence.calibrationComplete && evidence.referenceParity},
        {"reason", evidence.calibrationComplete
            ? (authorizeRewrite && qualityFloorPass && evidence.referenceParity
                ? "selection derived from complete calibrated evidence"
                : "selection derived from route metrics; explicit parity authorization is still required")
            : "continuous calibration and parity gates are incomplete"}
    };
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) { error = "selection manifest could not be opened"; return false; }
    output << manifest.dump(2) << '\n';
    if (!output.good()) { error = "selection manifest write failed"; return false; }
    return true;
}

static int reapPlan(int argc, char** argv) {
    if (argc < 3) { usage(); return 2; }

    RawrXD::Reap::CliRequest request;
    request.model = argv[2];
    request.workspace = fs::current_path().string();
    std::string calibrationPath;
    std::string selectionOutputPath;
    std::string outputModelPath;
    std::string outputPath;
    bool authorizeRewrite = false;
    bool targetSizeSeen = false;
    for (int i = 3; i < argc; ++i) {
        const std::string option = argv[i];
        if (option == "--authorize-rewrite") {
            authorizeRewrite = true;
            continue;
        }
        if (i + 1 >= argc) { usage(); return 2; }
        const std::string value = argv[++i];
        if (option == "--target-size" || option == "--size") {
            if (targetSizeSeen) {
                std::cerr << "REAP_SIZE_OPTION_CONFLICT: specify only one of --target-size or --size\n";
                return 2;
            }
            targetSizeSeen = true;
            request.targetSizeText = value;
        }
        else if (option == "--active-experts") request.activeExpertsText = value;
        else if (option == "--expert-budget") request.expertBudgetText = value;
        else if (option == "--quality-floor") request.qualityFloorText = value;
        else if (option == "--calibration") calibrationPath = value;
        else if (option == "--selection-output") selectionOutputPath = value;
        else if (option == "--output-model") outputModelPath = value;
        else if (option == "--output") outputPath = value;
        else { std::cerr << "REAP_UNKNOWN_OPTION: " << option << "\n"; return 2; }
    }

    const auto validation = RawrXD::Reap::Validate(request);
    if (!validation.ok) {
        std::cerr << validation.code << ": " << validation.message << "\n";
        return 2;
    }
    RawrXD::Reap::ParseSizeBytes(request.targetSizeText, request.targetSizeBytes);
    RawrXD::Reap::ParseSizeBytes(request.expertBudgetText, request.expertBudgetBytes);
    RawrXD::Reap::ParseActiveExperts(request.activeExpertsText, request.activeExperts);
    RawrXD::Reap::ParseQualityFloor(request.qualityFloorText, request.qualityFloor);

    Deep2::GGUFLoader loader;
    ReapInventory inventory;
    std::string inventoryError;
    if (!collectReapInventory(request.model, loader, inventory, inventoryError)) {
        std::ostringstream failed;
        failed << "{\"status\":\"FAILED\",\"reason\":"
               << json_quote(inventoryError) << ",\"model\":"
               << json_quote(request.model) << "}\n";
        const std::string receipt = failed.str();
        std::cout << receipt;
        if (!writePlan(outputPath, receipt)) return 5;
        return 4;
    }

    const auto admission = RawrXD::Reap::EvaluateAdmission(request);
    std::string reason = admission.reason;
    std::string status = "BLOCKED";
    int resultCode = 4;
    if (request.activeExperts > inventory.maxExpertsPerLayer) {
        reason = "REAP_ACTIVE_EXPERTS_EXCEEDS_MODEL";
    } else if (inventory.logicalExperts == 0) {
        reason = "REAP_MODEL_HAS_NO_VERIFIED_MOE_EXPERTS";
    } else if (inventory.totalBytes <= request.targetSizeBytes) {
        status = "NO_CHANGE_REQUIRED";
        reason = "MODEL_ALREADY_FITS_TARGET_WITHOUT_MUTATION";
        resultCode = 0;
    }

    CalibrationEvidence calibration;
    bool calibrationReadable = false;
    if (!calibrationPath.empty()) {
        calibrationReadable = loadCalibrationEvidence(calibrationPath, request.model, calibration) &&
            calibration.complete && calibration.continuous && calibration.continuousCompleted &&
            calibration.generated > 0 && calibration.routeMetrics && calibration.mlaSeal &&
            calibration.referenceParity;
        if (calibrationReadable && !calibration.calibrationComplete)
            reason = "REAP_REFERENCE_PARITY_REQUIRED";
    }
    if (status == "BLOCKED" && !calibrationPath.empty() && !calibrationReadable) {
        reason = "REAP_CALIBRATION_RECEIPT_NOT_CERTIFIED";
    }

    std::string selectionError;
    const bool selectionWritten = !selectionOutputPath.empty() &&
        writeSelectionManifest(selectionOutputPath, request.model, calibrationPath,
                               calibration, inventory, request.activeExperts,
                               request.expertBudgetBytes, request.targetSizeBytes,
                               admission.qualityFloorPass,
                               authorizeRewrite,
                               selectionError);
    if (!selectionOutputPath.empty() && !selectionWritten && status == "BLOCKED" &&
        !selectionError.empty()) {
        reason = selectionError;
    }

    Deep2::ReapMoETransformResult transform;
    if (!outputModelPath.empty()) {
        if (!selectionWritten || !authorizeRewrite || !admission.transformationEnabled ||
            !admission.rewriterCertified || !admission.selectionComplete ||
            !admission.qualityFloorPass || !calibration.calibrationComplete ||
            !calibration.referenceParity) {
            transform.error = "REAP_REWRITE_NOT_AUTHORIZED_BY_REFERENCE_PARITY";
        } else {
            Deep2::ReapMoETransformRequest transformRequest;
            transformRequest.sourceFirstShard = request.model;
            transformRequest.outputDirectory = outputModelPath;
            transformRequest.selectionManifest = selectionOutputPath;
            transformRequest.activeExperts = static_cast<uint32_t>(request.activeExperts);
            transformRequest.targetSizeBytes = request.targetSizeBytes;
            transform = Deep2::transformMoEGGUF(transformRequest);
        }
        if (!transform.success) {
            status = "BLOCKED";
            reason = transform.error.empty() ? "REAP_GGUF_REWRITE_FAILED" : transform.error;
            resultCode = 4;
        }
    }

    std::ostringstream receipt;
    receipt << "{\"status\":" << json_quote(status)
            << ",\"reason\":" << json_quote(reason)
            << ",\"model\":" << json_quote(request.model)
            << ",\"model_bytes\":" << inventory.totalBytes
            << ",\"shards\":" << loader.shardCount()
            << ",\"tensors\":" << loader.tensorCount()
            << ",\"expert_tensors\":" << inventory.expertTensors
            << ",\"expert_bytes\":" << inventory.expertBytes
            << ",\"logical_experts\":" << inventory.logicalExperts
            << ",\"max_experts_per_layer\":" << inventory.maxExpertsPerLayer
            << ",\"layer_count\":" << inventory.layerCount
            << ",\"moe_layer_count\":" << inventory.moeLayers.size()
            << ",\"target_size\":" << request.targetSizeBytes
            << ",\"active_experts\":" << request.activeExperts
            << ",\"expert_budget\":" << request.expertBudgetBytes
            << ",\"quality_floor\":" << request.qualityFloor
            << ",\"calibration_receipt\":" << json_quote(calibrationPath)
            << ",\"calibration_receipt_certified\":" << (calibrationReadable ? "true" : "false")
            << ",\"calibration_complete\":" << (calibration.calibrationComplete ? "true" : "false")
            << ",\"internal_prefill_parity\":" << (calibration.internalPrefillParity ? "true" : "false")
            << ",\"selection_manifest\":" << json_quote(selectionOutputPath)
            << ",\"selection_manifest_written\":" << (selectionWritten ? "true" : "false")
            << ",\"transformation_enabled\":"
            << ((admission.transformationEnabled && transform.success) ? "true" : "false")
            << ",\"write_allowed\":" << (transform.success ? "true" : "false")
            << ",\"gguf_rewrite_complete\":" << (transform.success ? "true" : "false")
            << ",\"reduced_model_reload_pass\":" << (transform.success ? "true" : "false")
            << ",\"output_model\":" << json_quote(transform.outputFirstShard)
            << ",\"output_bytes\":" << transform.outputBytes
            << ",\"transformed_tensors\":" << transform.transformedTensors
            << ",\"gates\":{\"mla_cert_001\":" << (admission.mlaCert001 ? "true" : "false")
            << ",\"continuous_decode\":" << (calibration.continuous && calibration.continuousCompleted ? "true" : "false")
            << ",\"calibration_complete\":" << (admission.calibrationComplete ? "true" : "false")
            << ",\"selection_complete\":" << (admission.selectionComplete ? "true" : "false")
            << ",\"rewriter_certified\":" << (admission.rewriterCertified ? "true" : "false")
            << ",\"reduced_reload_pass\":" << (transform.success ? "true" : "false") << "}}\n";
    const std::string result = receipt.str();
    std::cout << result;
    if (!writePlan(outputPath, result)) return 5;
    return resultCode;
}

int main(int argc, char** argv) {
    if (argc >= 3 && std::string(argv[1]) == "verify") {
        std::string receiptPath;
        bool structuralOnly = false;
        for (int i = 3; i < argc; ++i) {
            if (std::string(argv[i]) == "--structural-only") {
                structuralOnly = true;
                continue;
            }
            if (std::string(argv[i]) != "--receipt" || i + 1 >= argc) {
                usage();
                return 2;
            }
            receiptPath = argv[++i];
        }
        return verifyModelShards(argv[2], receiptPath, structuralOnly);
    }
    if (argc >= 3 && std::string(argv[1]) == "topology") {
        std::string outputPath;
        for (int i = 3; i < argc; ++i) {
            if (std::string(argv[i]) != "--output" || i + 1 >= argc) {
                usage();
                return 2;
            }
            outputPath = argv[++i];
        }
        return topology(argv[2], outputPath);
    }
    if (argc >= 3 && std::string(argv[1]) == "capabilities") {
        if (argc != 3) { usage(); return 2; }
        return capabilities(argv[2]);
    }
    if (argc >= 3 && (std::string(argv[1]) == "reap" || std::string(argv[1]) == "--reap")) return reapPlan(argc, argv);
    if (argc < 3 || (std::string(argv[1]) != "inspect" && std::string(argv[1]) != "plan")) { usage(); return 2; }
    if (std::string(argv[1]) == "inspect" && argc != 3) { usage(); return 2; }
    const std::string path = argv[2];
    Deep2::GGUFLoader loader;
    if (!loader.load(path)) { std::cerr << "GGUF_LOAD_FAILED: " << loader.error() << "\n"; return 1; }
    uint64_t target = 0;
    if (std::string(argv[1]) == "plan") {
        if (argc != 5 || std::string(argv[3]) != "--size" || !bytes(argv[4], target)) { usage(); return 2; }
    }
    uint64_t expertBytes = 0, expertTensors = 0;
    uint64_t logicalExperts = 0, logicalExpertBytes = 0, minTripletBytes = 0, maxTripletBytes = 0;
    std::unordered_map<std::string, uint64_t> byType;
    const std::string architecture = loader.getMetaString("general.architecture", "");
    for (const auto& name : loader.listTensors()) {
        const auto* t = loader.getTensor(name); if (!t) continue;
        const bool expert = name.find(".experts.") != std::string::npos ||
                            name.find(".expert.") != std::string::npos ||
                            name.find(".ffn_gate_exps.") != std::string::npos ||
                            name.find(".ffn_up_exps.") != std::string::npos ||
                            name.find(".ffn_down_exps.") != std::string::npos ||
                            name.find("experts.") == 0;
        if (expert) { expertBytes += t->sizeBytes; ++expertTensors; byType[std::to_string((int)t->type)] += t->sizeBytes; }
    }
    // DeepSeek R1's stacked expert projections are grouped as complete
    // gate/up/down triplets. Derive the logical count from actual tensor
    // shapes rather than treating the 174 projection tensors as experts.
    for (uint32_t layer = 0; layer < 256; ++layer) {
        const std::string prefix = "blk." + std::to_string(layer) + ".";
        const auto* gate = loader.getTensor(prefix + "ffn_gate_exps.weight");
        const auto* up = loader.getTensor(prefix + "ffn_up_exps.weight");
        const auto* down = loader.getTensor(prefix + "ffn_down_exps.weight");
        if (!gate && !up && !down) continue;
        const auto decision = RawrXD::Reap::ClassifyExpertProjections(
            gate != nullptr, up != nullptr, down != nullptr,
            gate && !gate->shape.empty(), up && !up->shape.empty(), down && !down->shape.empty(),
            gate && !gate->shape.empty() ? gate->shape.back() : 0,
            up && !up->shape.empty() ? up->shape.back() : 0,
            down && !down->shape.empty() ? down->shape.back() : 0);
        const bool pairLayout = decision.kind == RawrXD::Reap::ExpertLayoutKind::PairUpDown &&
                                supportsPairUpDownExperts(architecture);
        if (!pairLayout && decision.kind != RawrXD::Reap::ExpertLayoutKind::DeepseekTriplet) {
            auto dumpOne = [](const char* role, const Deep2::GGUFTensor* t) {
                std::cerr << role << "=";
                if (!t) { std::cerr << "ABSENT\n"; return; }
                std::cerr << "type=" << static_cast<int>(t->type)
                          << " bytes=" << t->sizeBytes << " shape=";
                for (size_t i = 0; i < t->shape.size(); ++i) {
                    if (i) std::cerr << "x";
                    std::cerr << t->shape[i];
                }
                std::cerr << "\n";
            };
            std::cerr << RawrXD::Reap::LayoutRejection(
                             decision, layer, loader.getMetaString("general.architecture", ""))
                      << "\n";
            dumpOne("gate", gate);
            dumpOne("up", up);
            dumpOne("down", down);
            for (const auto& name : loader.listTensors()) {
                if (name.rfind(prefix, 0) != 0) continue;
                if (name.find("ffn") == std::string::npos &&
                    name.find("expert") == std::string::npos &&
                    name.find("exps") == std::string::npos &&
                    name.find("moe") == std::string::npos) continue;
                const auto* tensor = loader.getTensor(name);
                std::cerr << "LAYER_TENSOR " << name;
                if (tensor) {
                    std::cerr << " type=" << static_cast<int>(tensor->type)
                              << " bytes=" << tensor->sizeBytes << " shape=";
                    for (size_t i = 0; i < tensor->shape.size(); ++i) {
                        if (i) std::cerr << "x";
                        std::cerr << tensor->shape[i];
                    }
                }
                std::cerr << "\n";
            }
            return 4;
        }
        if ((pairLayout && (!up || !down || up->shape.empty() || down->shape.empty() ||
                            up->shape.back() != down->shape.back())) ||
            (!pairLayout && (!gate || !up || !down || gate->shape.empty() || up->shape.empty() ||
                             down->shape.empty() || gate->shape.back() != up->shape.back() ||
                             gate->shape.back() != down->shape.back()))) {
            std::cerr << "INVALID_EXPERT_PROJECTION_SHAPES layer=" << layer << "\n";
            return 4;
        }
        const uint64_t count = static_cast<uint64_t>((pairLayout ? up : gate)->shape.back());
        const uint64_t gateBytes = pairLayout ? 0 : gate->sizeBytes;
        if (count == 0 || gateBytes % count || up->sizeBytes % count || down->sizeBytes % count) {
            std::cerr << "INVALID_EXPERT_SLICE_DIVISIBILITY layer=" << layer << "\n";
            return 4;
        }
        logicalExperts += count;
        const uint64_t tripletBytes = gateBytes / count + up->sizeBytes / count + down->sizeBytes / count;
        logicalExpertBytes += tripletBytes * count;
        if (minTripletBytes == 0 || tripletBytes < minTripletBytes) minTripletBytes = tripletBytes;
        if (tripletBytes > maxTripletBytes) maxTripletBytes = tripletBytes;
    }
    uint64_t total = 0;
    std::error_code ec;
    fs::path first(path); fs::path dir = first.parent_path();
    std::string stem = first.filename().string();
    auto marker = stem.find("-00001-of-");
    if (marker != std::string::npos) {
        std::string prefix = stem.substr(0, marker); std::string suffix = stem.substr(marker + 11);
        for (const auto& e : fs::directory_iterator(dir, ec)) if (!ec && e.path().filename().string().rfind(prefix + "-", 0) == 0 && e.path().extension() == ".gguf") total += fs::file_size(e.path(), ec);
    } else total = fs::file_size(first, ec);
    if (!total) total = loader.mappedBytes();
    std::cout << "{\"source\":\"" << path << "\",\"shards\":" << loader.shardCount()
              << ",\"tensors\":" << loader.tensorCount() << ",\"bytes\":" << total
              << ",\"expert_tensors\":" << expertTensors << ",\"expert_bytes\":" << expertBytes
              << ",\"logical_experts\":" << logicalExperts
              << ",\"logical_expert_bytes\":" << logicalExpertBytes
              << ",\"min_triplet_bytes\":" << minTripletBytes
              << ",\"max_triplet_bytes\":" << maxTripletBytes;
    int rc = 0;
    if (std::string(argv[1]) == "plan") {
        const bool fits = total <= target;
        const bool pruningCandidate = (!fits && expertBytes > 0);
        std::cout << ",\"target_bytes\":" << target << ",\"fits_unmodified\":" << (fits ? "true" : "false")
                  << ",\"pruning_candidate\":" << (pruningCandidate ? "true" : "false");
        if (fits) {
            std::cout << ",\"selection\":\"FITS_UNMODIFIED_NO_PRUNING\",\"writable_output\":false";
            rc = 0;
        } else if (expertBytes == 0) {
            std::cout << ",\"selection\":\"NOT_PRUNABLE_DENSE_EXCEEDS_TARGET\",\"writable_output\":false";
            rc = 4;
        } else {
            std::cout << ",\"selection\":\"PRUNING_CANDIDATE_REQUIRES_CALIBRATION_MASK\",\"writable_output\":false";
            rc = 4;
        }
    }
    std::cout << "}\n";
    return rc;
}
