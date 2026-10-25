#include "deep2/GGUFLoader.hpp"
#include "reap_cli_contract.hpp"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace fs = std::filesystem;

static void usage() {
    std::cerr << "rawr-reap inspect <first-shard.gguf>\n"
                 "rawr-reap plan <first-shard.gguf> --size <B|MB|GB|TB>\n"
                 "rawr-reap capabilities <model-file-or-directory>\n"
                 "rawr-reap reap <first-shard.gguf> --target-size <B|MB|GB|TB> "
                 "--active-experts <N> --expert-budget <B|MB|GB|TB> "
                 "--quality-floor <0..1> [--calibration <receipt.json>] "
                 "[--output <plan.json>]\n";
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
    std::cout << "{\"source\":" << json_quote(input) << ",\"format\":\"gguf\",\"inspectable\":true"
              << ",\"calibratable\":" << (tokenizer ? "true" : "false")
              << ",\"transformable\":false,\"shards\":" << l.shardCount()
              << ",\"tensors\":" << l.tensorCount()
              << ",\"reason\":\"transform_writer_and_parity_gate_required\"}\n";
    return tokenizer ? 0 : 4;
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
};

static bool collectReapInventory(const std::string& path,
                                 Deep2::GGUFLoader& loader,
                                 ReapInventory& out,
                                 std::string& error) {
    if (!loader.load(path)) {
        error = loader.error();
        return false;
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
        if (!gate || !up || !down || gate->shape.empty() || up->shape.empty() ||
            down->shape.empty() || gate->shape.back() != up->shape.back() ||
            gate->shape.back() != down->shape.back()) {
            error = "invalid expert projection triplet at layer " + std::to_string(layer);
            return false;
        }
        const uint64_t count = static_cast<uint64_t>(gate->shape.back());
        if (count == 0 || gate->sizeBytes % count || up->sizeBytes % count ||
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

static int reapPlan(int argc, char** argv) {
    if (argc < 3) { usage(); return 2; }

    RawrXD::Reap::CliRequest request;
    request.model = argv[2];
    std::string calibrationPath;
    std::string outputPath;
    for (int i = 3; i < argc; ++i) {
        const std::string option = argv[i];
        if (i + 1 >= argc) { usage(); return 2; }
        const std::string value = argv[++i];
        if (option == "--target-size") request.targetSizeText = value;
        else if (option == "--active-experts") request.activeExpertsText = value;
        else if (option == "--expert-budget") request.expertBudgetText = value;
        else if (option == "--quality-floor") request.qualityFloorText = value;
        else if (option == "--calibration") calibrationPath = value;
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

    bool calibrationReadable = false;
    if (!calibrationPath.empty()) {
        std::string text;
        if (readText(calibrationPath, text)) {
            const bool complete = text.find("\"complete\":1") != std::string::npos ||
                                  text.find("\"complete\":true") != std::string::npos;
            const bool generated = text.find("\"generated\":1") != std::string::npos ||
                                   text.find("\"generated\":true") != std::string::npos;
            const bool seal = text.find("mla_product_seal") != std::string::npos &&
                              (text.find("\"mla_product_seal\":true") != std::string::npos ||
                               text.find("\"mla_product_seal\":1") != std::string::npos);
            calibrationReadable = complete && generated && seal;
        }
    }
    if (status == "BLOCKED" && !calibrationPath.empty() && !calibrationReadable) {
        reason = "REAP_CALIBRATION_RECEIPT_NOT_CERTIFIED";
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
            << ",\"target_size\":" << request.targetSizeBytes
            << ",\"active_experts\":" << request.activeExperts
            << ",\"expert_budget\":" << request.expertBudgetBytes
            << ",\"quality_floor\":" << request.qualityFloor
            << ",\"calibration_receipt\":" << json_quote(calibrationPath)
            << ",\"calibration_receipt_certified\":" << (calibrationReadable ? "true" : "false")
            << ",\"transformation_enabled\":false"
            << ",\"write_allowed\":false"
            << ",\"gates\":{\"mla_cert_001\":false,\"calibration_complete\":false,\"selection_complete\":false,\"rewriter_certified\":false}}\n";
    const std::string result = receipt.str();
    std::cout << result;
    if (!writePlan(outputPath, result)) return 5;
    return resultCode;
}

int main(int argc, char** argv) {
    if (argc >= 3 && std::string(argv[1]) == "capabilities") return capabilities(argv[2]);
    if (argc >= 3 && (std::string(argv[1]) == "reap" || std::string(argv[1]) == "--reap")) return reapPlan(argc, argv);
    if (argc < 3 || (std::string(argv[1]) != "inspect" && std::string(argv[1]) != "plan")) { usage(); return 2; }
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
        if (!gate || !up || !down || gate->shape.empty() || up->shape.empty() || down->shape.empty() ||
            gate->shape.back() != up->shape.back() || gate->shape.back() != down->shape.back()) {
            std::cerr << "INVALID_EXPERT_TRIPLET layer=" << layer << "\n";
            return 4;
        }
        const uint64_t count = static_cast<uint64_t>(gate->shape.back());
        if (count == 0 || gate->sizeBytes % count || up->sizeBytes % count || down->sizeBytes % count) {
            std::cerr << "INVALID_EXPERT_SLICE_DIVISIBILITY layer=" << layer << "\n";
            return 4;
        }
        logicalExperts += count;
        const uint64_t tripletBytes = gate->sizeBytes / count + up->sizeBytes / count + down->sizeBytes / count;
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
