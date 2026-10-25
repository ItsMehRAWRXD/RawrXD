#include "deep2/GGUFLoader.hpp"
#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <cerrno>
#include <limits>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

namespace fs = std::filesystem;

static void usage() {
    std::cerr << "rawr-reap inspect <first-shard.gguf>\n"
                 "rawr-reap plan <first-shard.gguf> --size <B|MB|GB|TB>\n"
                 "rawr-reap capabilities <model-file-or-directory>\n";
}

static std::string json_quote(const std::string& s) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out = "\"";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') {
            out += '\\';
            out += static_cast<char>(c);
        } else if (c < 0x20) {
            out += "\\u00";
            out += hex[c >> 4];
            out += hex[c & 15];
        } else {
            out += static_cast<char>(c);
        }
    }
    return out + "\"";
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
    out = 0;
    if (s.empty()) return false;
    size_t n = 0;
    bool dot = false, digit = false;
    for (; n < s.size(); ++n) {
        const unsigned char c = static_cast<unsigned char>(s[n]);
        if (c >= '0' && c <= '9') { digit = true; continue; }
        if (c == '.' && !dot) { dot = true; continue; }
        break;
    }
    if (!digit || n == s.size()) return false;
    const std::string number = s.substr(0, n);
    char* end = nullptr;
    errno = 0;
    const long double v = std::strtold(number.c_str(), &end);
    if (errno == ERANGE || end != number.c_str() + number.size() ||
        !std::isfinite(v) || v <= 0) return false;
    std::string unit = s.substr(n);
    for (char& c : unit) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    uint64_t multiplier = 0;
    if (unit == "B") multiplier = 1;
    else if (unit == "MB" || unit == "MIB") multiplier = 1ull << 20;
    else if (unit == "GB" || unit == "GIB") multiplier = 1ull << 30;
    else if (unit == "TB" || unit == "TIB") multiplier = 1ull << 40;
    else return false;
    const long double value = v * static_cast<long double>(multiplier);
    if (!std::isfinite(value) || value < 1 ||
        value >= std::ldexp(1.0L, 64) || std::floor(value) != value) return false;
    out = static_cast<uint64_t>(value);
    return true;
}

int main(int argc, char** argv) {
    if (argc >= 2 && std::string(argv[1]) == "capabilities") {
        if (argc != 3) { usage(); return 2; }
        return capabilities(argv[2]);
    }
    if (argc < 3 || (std::string(argv[1]) != "inspect" && std::string(argv[1]) != "plan")) { usage(); return 2; }
    if (std::string(argv[1]) == "inspect" && argc != 3) { usage(); return 2; }
    uint64_t target = 0;
    if (std::string(argv[1]) == "plan" &&
        (argc != 5 || std::string(argv[3]) != "--size" || !bytes(argv[4], target))) {
        usage(); return 2;
    }
    const std::string path = argv[2];
    Deep2::GGUFLoader loader;
    if (!loader.load(path)) { std::cerr << "GGUF_LOAD_FAILED: " << loader.error() << "\n"; return 1; }
    uint64_t expertBytes = 0, expertTensors = 0;
    uint64_t logicalExperts = 0, logicalExpertBytes = 0, minTripletBytes = 0, maxTripletBytes = 0;
    for (const auto& name : loader.listTensors()) {
        const auto* t = loader.getTensor(name); if (!t) continue;
        const bool expert = name.find(".experts.") != std::string::npos ||
                            name.find(".expert.") != std::string::npos ||
                            name.find(".ffn_gate_exps.") != std::string::npos ||
                            name.find(".ffn_up_exps.") != std::string::npos ||
                            name.find(".ffn_down_exps.") != std::string::npos ||
                            name.find("experts.") == 0;
        if (expert) {
            if (t->sizeBytes > UINT64_MAX - expertBytes || expertTensors == UINT64_MAX) {
                std::cerr << "EXPERT_ACCOUNTING_OVERFLOW\n"; return 4;
            }
            expertBytes += t->sizeBytes;
            ++expertTensors;
        }
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
        const uint64_t gatePer = gate->sizeBytes / count;
        const uint64_t upPer = up->sizeBytes / count;
        const uint64_t downPer = down->sizeBytes / count;
        if (gatePer > UINT64_MAX - upPer || gatePer + upPer > UINT64_MAX - downPer ||
            count > UINT64_MAX - logicalExperts) {
            std::cerr << "EXPERT_GEOMETRY_OVERFLOW\n"; return 4;
        }
        const uint64_t tripletBytes = gatePer + upPer + downPer;
        if (tripletBytes > UINT64_MAX / count ||
            tripletBytes * count > UINT64_MAX - logicalExpertBytes) {
            std::cerr << "EXPERT_GEOMETRY_OVERFLOW\n"; return 4;
        }
        logicalExperts += count;
        logicalExpertBytes += tripletBytes * count;
        if (minTripletBytes == 0 || tripletBytes < minTripletBytes) minTripletBytes = tripletBytes;
        if (tripletBytes > maxTripletBytes) maxTripletBytes = tripletBytes;
    }
    uint64_t total = 0;
    std::error_code ec;
    fs::path first(path); fs::path dir = first.parent_path();
    const std::string stem = first.filename().string();
    const auto marker = stem.find("-00001-of-");
    if (marker != std::string::npos) {
        const std::string prefix = stem.substr(0, marker);
        const std::string suffix = stem.substr(marker + 10);
        if (suffix.size() != 10 || suffix.substr(5) != ".gguf") {
            std::cerr << "INVALID_SHARD_NAME\n"; return 4;
        }
        uint64_t expected = 0;
        for (size_t i = 0; i < 5; ++i) {
            if (suffix[i] < '0' || suffix[i] > '9') { std::cerr << "INVALID_SHARD_NAME\n"; return 4; }
            expected = expected * 10 + static_cast<unsigned>(suffix[i] - '0');
        }
        if (!expected || expected > 99999) { std::cerr << "INVALID_SHARD_COUNT\n"; return 4; }
        for (uint64_t i = 1; i <= expected; ++i) {
            std::string index = std::to_string(i);
            index.insert(0, 5 - index.size(), '0');
            std::string count = std::to_string(expected);
            count.insert(0, 5 - count.size(), '0');
            const fs::path shard = dir / (prefix + "-" + index + "-of-" + count + ".gguf");
            ec.clear();
            if (!fs::is_regular_file(shard, ec) || ec) {
                std::cerr << "MISSING_SHARD " << shard.string() << "\n"; return 4;
            }
            ec.clear();
            const uint64_t size = fs::file_size(shard, ec);
            if (ec || size > UINT64_MAX - total) {
                std::cerr << "SHARD_SIZE_ERROR\n"; return 4;
            }
            total += size;
        }
    } else {
        ec.clear();
        total = fs::file_size(first, ec);
        if (ec) { std::cerr << "FILE_SIZE_ERROR\n"; return 4; }
    }
    if (!total) { std::cerr << "EMPTY_MODEL\n"; return 4; }
    if (expertBytes > total || logicalExpertBytes > expertBytes) {
        std::cerr << "EXPERT_ACCOUNTING_INCONSISTENT\n"; return 4;
    }
    const uint64_t denseBytes = total - expertBytes;
    std::cout << "{\"source\":" << json_quote(path) << ",\"shards\":" << loader.shardCount()
              << ",\"tensors\":" << loader.tensorCount() << ",\"bytes\":" << total
              << ",\"expert_tensors\":" << expertTensors << ",\"expert_bytes\":" << expertBytes
              << ",\"non_expert_bytes\":" << denseBytes
              << ",\"logical_experts\":" << logicalExperts
              << ",\"logical_expert_bytes\":" << logicalExpertBytes
              << ",\"min_triplet_bytes\":" << minTripletBytes
              << ",\"max_triplet_bytes\":" << maxTripletBytes;
    int rc = 0;
    if (std::string(argv[1]) == "plan") {
        const bool fits = total <= target;
        const bool impossibleTarget = !fits && denseBytes > target;
        const bool pruningCandidate = (!fits && expertBytes > 0 && !impossibleTarget);
        std::cout << ",\"target_bytes\":" << target << ",\"fits_unmodified\":" << (fits ? "true" : "false")
                  << ",\"pruning_candidate\":" << (pruningCandidate ? "true" : "false");
        if (fits) {
            std::cout << ",\"selection\":\"FITS_UNMODIFIED_NO_PRUNING\",\"writable_output\":false";
            rc = 0;
        } else if (expertBytes == 0 || impossibleTarget) {
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
