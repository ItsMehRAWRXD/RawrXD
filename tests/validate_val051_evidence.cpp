/**
 * @file validate_val051_evidence.cpp
 * @brief VAL-051.2.A Evidence Validator
 *
 * Parses evidence JSON and verifies deterministic baseline values.
 * Exit 0 on success, nonzero on any mismatch.
 *
 * Build: cl /EHsc /W4 validate_val051_evidence.cpp
 * Run:   validate_val051_evidence.exe [path_to_json]
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <fstream>
#include <vector>

// Minimal JSON parser for evidence validation
struct EvidenceData {
    std::string validation_id;
    std::string validation_name;
    std::string status;
    std::string model_path;
    std::string model_hash;
    std::string prompt;
    std::string output_text;
    int64_t model_size_bytes = 0;
    int64_t input_token_count = 0;
    int64_t output_token_count = 0;
    int64_t sampled_token_id = 0;
    int64_t input_checksum = 0;
    int64_t output_checksum = 0;
    int64_t vocab_size = 0;
    int64_t embedding_dim = 0;
    int64_t layer_count = 0;
    int64_t head_count = 0;
    bool is_simulated = false;
    bool has_stages = false;
};

static const char* skipWhitespace(const char* p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') ++p;
    return p;
}

static const char* parseString(const char* p, std::string& out) {
    if (*p != '"') return nullptr;
    ++p;
    out.clear();
    while (*p && *p != '"') {
        if (*p == '\\' && *(p+1)) {
            ++p;
            switch (*p) {
                case '"': case '\\': case '/': out += *p; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                default: out += *p; break;
            }
        } else {
            out += *p;
        }
        ++p;
    }
    if (*p == '"') ++p;
    return p;
}

static const char* parseNumber(const char* p, int64_t& out) {
    bool neg = false;
    if (*p == '-') { neg = true; ++p; }
    int64_t val = 0;
    while (*p >= '0' && *p <= '9') {
        val = val * 10 + (*p - '0');
        ++p;
    }
    // Skip fractional part (e.g., 0.523938)
    if (*p == '.') {
        ++p;
        while (*p >= '0' && *p <= '9') ++p;
    }
    out = neg ? -val : val;
    return p;
}

static const char* parseBool(const char* p, bool& out) {
    if (strncmp(p, "true", 4) == 0) { out = true; return p + 4; }
    if (strncmp(p, "false", 5) == 0) { out = false; return p + 5; }
    return nullptr;
}

static const char* parseValue(const char* p, EvidenceData& data, const std::string& key);

static const char* parseObject(const char* p, EvidenceData& data) {
    if (*p != '{') return nullptr;
    ++p;
    while (true) {
        p = skipWhitespace(p);
        if (*p == '}') { ++p; break; }
        if (*p != '"') return nullptr;
        std::string key;
        p = parseString(p, key);
        if (!p) return nullptr;
        p = skipWhitespace(p);
        if (*p != ':') return nullptr;
        ++p;
        p = skipWhitespace(p);
        p = parseValue(p, data, key);
        if (!p) return nullptr;
        p = skipWhitespace(p);
        if (*p == ',') { ++p; continue; }
        if (*p == '}') { ++p; break; }
        return nullptr;
    }
    return p;
}

static const char* parseArray(const char* p) {
    if (*p != '[') return nullptr;
    ++p;
    while (true) {
        p = skipWhitespace(p);
        if (*p == ']') { ++p; break; }
        // Skip array element (object or primitive)
        if (*p == '{') {
            int depth = 1;
            ++p;
            while (*p && depth > 0) {
                if (*p == '{') ++depth;
                else if (*p == '}') --depth;
                ++p;
            }
        } else if (*p == '"') {
            std::string tmp;
            p = parseString(p, tmp);
            if (!p) return nullptr;
        } else {
            while (*p && *p != ',' && *p != ']') ++p;
        }
        p = skipWhitespace(p);
        if (*p == ',') { ++p; continue; }
        if (*p == ']') { ++p; break; }
        return nullptr;
    }
    return p;
}

static const char* parseValue(const char* p, EvidenceData& data, const std::string& key) {
    if (key == "validation_id" && *p == '"') return parseString(p, data.validation_id);
    if (key == "validation_name" && *p == '"') return parseString(p, data.validation_name);
    if (key == "status" && *p == '"') return parseString(p, data.status);
    if (key == "model_path" && *p == '"') return parseString(p, data.model_path);
    if (key == "model_hash" && *p == '"') return parseString(p, data.model_hash);
    if (key == "prompt" && *p == '"') return parseString(p, data.prompt);
    if (key == "output_text" && *p == '"') return parseString(p, data.output_text);
    if (key == "model_size_bytes") return parseNumber(p, data.model_size_bytes);
    if (key == "input_token_count") return parseNumber(p, data.input_token_count);
    if (key == "output_token_count") return parseNumber(p, data.output_token_count);
    if (key == "sampled_token_id") return parseNumber(p, data.sampled_token_id);
    if (key == "input_checksum") return parseNumber(p, data.input_checksum);
    if (key == "output_checksum") return parseNumber(p, data.output_checksum);
    if (key == "vocab_size") return parseNumber(p, data.vocab_size);
    if (key == "embedding_dim") return parseNumber(p, data.embedding_dim);
    if (key == "layer_count") return parseNumber(p, data.layer_count);
    if (key == "head_count") return parseNumber(p, data.head_count);
    if (key == "is_simulated") return parseBool(p, data.is_simulated);
    if (key == "stages") { data.has_stages = true; return parseArray(p); }
    // Skip unknown values
    if (*p == '"') { std::string tmp; return parseString(p, tmp); }
    if (*p == '{') return parseObject(p, data);
    if (*p == '[') return parseArray(p);
    if (*p == 't' || *p == 'f') { bool tmp; return parseBool(p, tmp); }
    int64_t tmp; return parseNumber(p, tmp);
}

static std::string readFile(const char* path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

int main(int argc, char* argv[]) {
    const char* defaultPaths[] = {
        "D:\\rawrxd\\evidence\\VAL-051-2-A-EXECUTED.json",
        "F:\\~dev\\evidence\\VAL-051-2-A-EXECUTED.json",
    };

    std::vector<std::string> paths;
    if (argc > 1) {
        for (int i = 1; i < argc; ++i) paths.push_back(argv[i]);
    } else {
        for (const char* p : defaultPaths) paths.push_back(p);
    }

    int maxExitCode = 0;
    int filesChecked = 0;

    for (const auto& path : paths) {
        std::string content = readFile(path.c_str());
        if (content.empty()) {
            printf("SKIP: Evidence file not found: %s\n", path.c_str());
            continue;
        }
        ++filesChecked;

        EvidenceData data;
        const char* end = parseObject(content.c_str(), data);
        if (!end || *skipWhitespace(end) != '\0') {
            printf("FAIL: Invalid JSON in %s\n", path.c_str());
            maxExitCode = std::max(maxExitCode, 2);
            continue;
        }

        std::vector<std::string> errors;

        // Required fields
        if (data.validation_id != "VAL-051-2-A") errors.push_back("validation_id mismatch");
        if (data.validation_name != "Real Token Proof Harness") errors.push_back("validation_name mismatch");
        if (data.status != "PASS") errors.push_back("status not PASS");
        if (data.model_path != "D:\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf") errors.push_back("model_path mismatch");
        if (data.model_size_bytes != 668788096) errors.push_back("model_size_bytes mismatch");
        if (data.model_hash != "sha256:size_668788096_fb_47_lb_3f") errors.push_back("model_hash mismatch");
        if (data.prompt != "Hello") errors.push_back("prompt mismatch");
        if (data.input_token_count != 1) errors.push_back("input_token_count mismatch");
        if (data.output_token_count != 1) errors.push_back("output_token_count mismatch");
        if (data.sampled_token_id != 9693) {
            char buf[256];
            snprintf(buf, sizeof(buf), "sampled_token_id: expected 9693, got %lld", (long long)data.sampled_token_id);
            errors.push_back(buf);
        }
        if (data.output_text != "otto") {
            char buf[256];
            snprintf(buf, sizeof(buf), "output_text: expected 'otto', got '%s'", data.output_text.c_str());
            errors.push_back(buf);
        }
        if (data.input_checksum != -5815713594341935019LL) errors.push_back("input_checksum mismatch");
        if (data.output_checksum != -5816521735388670104LL) errors.push_back("output_checksum mismatch");
        if (data.vocab_size != 32000) errors.push_back("vocab_size mismatch");
        if (data.embedding_dim != 2048) errors.push_back("embedding_dim mismatch");
        if (data.layer_count != 22) errors.push_back("layer_count mismatch");
        if (data.head_count != 32) errors.push_back("head_count mismatch");
        if (data.is_simulated != false) errors.push_back("is_simulated should be false");
        if (!data.has_stages) errors.push_back("missing stages array");

        if (!errors.empty()) {
            printf("FAIL: %zu error(s) in %s\n", errors.size(), path.c_str());
            for (const auto& e : errors) {
                printf("  - %s\n", e.c_str());
            }
            maxExitCode = std::max(maxExitCode, 10);
        } else {
            printf("PASS: Evidence validated: %s\n", path.c_str());
            printf("  Token: %lld -> '%s'\n", (long long)data.sampled_token_id, data.output_text.c_str());
            printf("  Checksums: in=%lld out=%lld\n", (long long)data.input_checksum, (long long)data.output_checksum);
        }
    }

    if (filesChecked == 0) {
        printf("FAIL: No evidence files found to validate\n");
        return 1;
    }

    return maxExitCode;
}
