#include "ReapRuntimePlan.hpp"

#include "deep2/GGUFLoader.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <initializer_list>
#include <limits>
#include <sstream>

namespace RawrXD::Reap {
namespace {

std::string trim(std::string_view value) {
    size_t first = 0;
    while (first < value.size() &&
           std::isspace(static_cast<unsigned char>(value[first]))) ++first;
    size_t last = value.size();
    while (last > first &&
           std::isspace(static_cast<unsigned char>(value[last - 1]))) --last;
    return std::string(value.substr(first, last - first));
}

std::string upper(std::string value) {
    for (char& c : value)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return value;
}

bool parsePositive(std::string_view text, bool expert, uint64_t& value,
                   std::string& error) {
    const std::string s = upper(trim(text));
    if (s.empty()) { error = expert ? "EMPTY_EXPERT_TARGET" : "EMPTY_PARAMETER_TARGET"; return false; }

    size_t split = 0;
    while (split < s.size() &&
           (std::isdigit(static_cast<unsigned char>(s[split])) || s[split] == '.'))
        ++split;
    if (split == 0 || (!expert && split == s.size())) {
        error = expert ? "INVALID_EXPERT_TARGET" : "INVALID_PARAMETER_TARGET";
        return false;
    }
    const std::string number = s.substr(0, split);
    const std::string suffix = s.substr(split);

    // Expert counts are cardinalities, not sizes.  Parse them as exact
    // decimal uint64 values so the full representable range is accepted
    // without long-double rounding, and reject fractional counts instead of
    // silently truncating them.
    if (expert) {
        if (number.find('.') != std::string::npos ||
            (suffix != "" && suffix != "E")) {
            error = suffix == "" || suffix == "E"
                ? "EXPERT_TARGET_MUST_BE_INTEGER"
                : "EXPERT_TARGET_MUST_BE_COUNT_OR_E_SUFFIX";
            return false;
        }
        uint64_t parsedInteger = 0;
        const auto parsed = std::from_chars(number.data(),
                                             number.data() + number.size(),
                                             parsedInteger, 10);
        if (parsed.ec == std::errc::result_out_of_range) {
            error = "EXPERT_TARGET_OVERFLOW";
            return false;
        }
        if (parsed.ec != std::errc{} || parsed.ptr != number.data() + number.size()) {
            error = "INVALID_EXPERT_TARGET";
            return false;
        }
        if (parsedInteger == 0) {
            error = "EXPERT_TARGET_ZERO";
            return false;
        }
        value = parsedInteger;
        return true;
    }

    char* end = nullptr;
    const long double parsed = std::strtold(number.c_str(), &end);
    if (!end || *end != '\0' || !std::isfinite(parsed) || parsed <= 0.0L) {
        error = expert ? "INVALID_EXPERT_TARGET" : "INVALID_PARAMETER_TARGET";
        return false;
    }

    long double multiplier = 1.0L;
    if (!expert) {
        if (suffix == "K") multiplier = 1.0e3L;
        else if (suffix == "M") multiplier = 1.0e6L;
        else if (suffix == "B") multiplier = 1.0e9L;
        else if (suffix == "T") multiplier = 1.0e12L;
        else if (suffix == "KI") multiplier = 1024.0L;
        else if (suffix == "MI") multiplier = 1024.0L * 1024.0L;
        else if (suffix == "GI") multiplier = 1024.0L * 1024.0L * 1024.0L;
        else if (suffix == "TI") multiplier = 1024.0L * 1024.0L * 1024.0L * 1024.0L;
        else { error = "INVALID_PARAMETER_SUFFIX"; return false; }
    } else {
        if (suffix == "E" || suffix.empty()) multiplier = 1.0L;
        else { error = "EXPERT_TARGET_MUST_BE_COUNT_OR_E_SUFFIX"; return false; }
    }

    const long double scaled = parsed * multiplier;
    if (!std::isfinite(scaled) ||
        scaled > static_cast<long double>(std::numeric_limits<uint64_t>::max())) {
        error = expert ? "EXPERT_TARGET_OVERFLOW" : "PARAMETER_TARGET_OVERFLOW";
        return false;
    }
    value = static_cast<uint64_t>(scaled);
    if (value == 0) {
        error = expert ? "EXPERT_TARGET_ZERO" : "PARAMETER_TARGET_ZERO";
        return false;
    }
    return true;
}

bool addChecked(uint64_t& dst, uint64_t value) {
    if (value > std::numeric_limits<uint64_t>::max() - dst) return false;
    dst += value;
    return true;
}

std::string jsonQuote(const std::string& value) {
    std::ostringstream out;
    out << '"';
    for (unsigned char c : value) {
        if (c == '\\' || c == '"') out << '\\' << static_cast<char>(c);
        else if (c == '\n') out << "\\n";
        else if (c == '\r') out << "\\r";
        else if (c == '\t') out << "\\t";
        else if (c < 0x20) out << '?';
        else out << static_cast<char>(c);
    }
    out << '"';
    return out.str();
}

uint64_t metaFirst(const Deep2::GGUFLoader& loader,
                   std::initializer_list<const char*> keys) {
    for (const char* key : keys) {
        const int64_t value = loader.getMetaInt(key, 0);
        if (value > 0) return static_cast<uint64_t>(value);
    }
    return 0;
}

uint64_t metaByArchitecture(const Deep2::GGUFLoader& loader,
                            const std::string& architecture,
                            const char* suffix) {
    if (architecture.empty() || architecture == "unknown") return 0;
    const std::string key = architecture + "." + suffix;
    const int64_t value = loader.getMetaInt(key, 0);
    return value > 0 ? static_cast<uint64_t>(value) : 0;
}

} // namespace

bool ParseRuntimeTarget(std::string_view text, RuntimeTarget& out,
                        std::string& error) {
    out = {};
    error.clear();
    const std::string value = trim(text);
    const size_t slash = value.find('/');
    if (slash == std::string::npos || value.find('/', slash + 1) != std::string::npos) {
        error = "RUNTIME_TARGET_EXPECTED_PARAMETERS_SLASH_EXPERTS";
        return false;
    }
    if (!parsePositive(std::string_view(value).substr(0, slash), false,
                       out.parameterCount, error)) return false;
    if (!parsePositive(std::string_view(value).substr(slash + 1), true,
                       out.expertCount, error)) return false;
    out.source = value;
    return true;
}

bool InspectRuntimeModel(const std::string& firstShard,
                         RuntimeModelFacts& out, std::string& error) {
    out = {};
    error.clear();
    Deep2::GGUFLoader loader;
    if (!loader.load(firstShard)) {
        error = "GGUF_LOAD_FAILED:" + loader.error();
        return false;
    }
    out.model = firstShard;
    out.architecture = loader.getMetaString("general.architecture", "unknown");
    out.shardCount = loader.shardCount();
    out.tensorCount = loader.tensorCount();
    // Prefer the model's own architecture-qualified metadata before any
    // tensor-shape fallback. Packed expert tensors often expose an internal
    // projection dimension that is not the number of physical experts.
    out.expertCount = metaFirst(loader, {
        "expert_count", "llama.expert_count", "deepseek2.expert_count",
        "qwen2moe.expert_count", "qwen35moe.expert_count", "n_experts"});
    out.expertsPerToken = metaFirst(loader, {
        "expert_used_count", "llama.expert_used_count", "deepseek2.expert_used_count",
        "qwen2moe.expert_used_count", "qwen35moe.expert_used_count",
        "n_experts_used"});
    out.layerCount = metaFirst(loader, {
        "block_count", "llama.block_count", "deepseek2.block_count",
        "qwen2moe.block_count", "qwen35moe.block_count"});
    if (out.expertCount == 0)
        out.expertCount = metaByArchitecture(loader, out.architecture, "expert_count");
    if (out.expertsPerToken == 0)
        out.expertsPerToken = metaByArchitecture(loader, out.architecture, "expert_used_count");
    if (out.layerCount == 0)
        out.layerCount = metaByArchitecture(loader, out.architecture, "block_count");

    const auto tensorNames = loader.listTensors();
    for (const std::string& name : tensorNames) {
        const Deep2::GGUFTensor* tensor = loader.getTensor(name);
        if (!tensor) continue;
        const size_t elements = tensor->numElements();
        if (elements == 0 || !addChecked(out.parameterCount,
                                         static_cast<uint64_t>(elements))) {
            error = "PARAMETER_COUNT_OVERFLOW_OR_INVALID_TENSOR:" + name;
            return false;
        }
        if (!addChecked(out.tensorBytes, static_cast<uint64_t>(tensor->sizeBytes))) {
            error = "TENSOR_BYTE_COUNT_OVERFLOW";
            return false;
        }
    }

    // Some MoE GGUFs omit expert_count metadata and pack all experts into a
    // single ffn_gate/ffn_up/ffn_down tensor.  Match the production loader's
    // geometry rule so planning and runtime admission cannot disagree.
    if (out.expertCount == 0) {
        for (const std::string& name : tensorNames) {
            if (name.find("ffn_gate") == std::string::npos &&
                name.find("ffn_up_exps") == std::string::npos &&
                name.find("ffn_down_exps") == std::string::npos) {
                continue;
            }
            const Deep2::GGUFTensor* tensor = loader.getTensor(name);
            if (!tensor || tensor->shape.size() < 3 || tensor->shape[0] == 0) continue;
            out.expertCount = (std::max)(out.expertCount,
                                         static_cast<uint64_t>(tensor->shape[0]));
        }
    }
    if (out.parameterCount == 0 || out.tensorBytes == 0) {
        error = "MODEL_HAS_NO_COUNTABLE_TENSORS";
        return false;
    }
    return true;
}

bool BuildRuntimePlan(const std::string& firstShard,
                      const RuntimeTarget& target,
                      RuntimePlan& out, std::string& error) {
    out = {};
    error.clear();
    if (target.parameterCount == 0 || target.expertCount == 0) {
        error = "RUNTIME_TARGET_VALUES_MUST_BE_NONZERO";
        return false;
    }
    if (!InspectRuntimeModel(firstShard, out.actual, error)) return false;
    out.requested = target;

    const long double ratio = static_cast<long double>(out.actual.tensorBytes) /
                              static_cast<long double>(out.actual.parameterCount);
    const long double working = ratio * static_cast<long double>(target.parameterCount);
    if (!std::isfinite(working) ||
        working > static_cast<long double>(std::numeric_limits<uint64_t>::max())) {
        error = "RUNTIME_WORKING_SET_OVERFLOW";
        return false;
    }
    out.targetWorkingSetBytes = static_cast<uint64_t>(working);
    const bool paramsUp = target.parameterCount > out.actual.parameterCount;
    const bool expertsUp = out.actual.expertCount > 0 &&
                           target.expertCount > out.actual.expertCount;
    const bool paramsDown = target.parameterCount < out.actual.parameterCount;
    const bool expertsDown = out.actual.expertCount > 0 &&
                             target.expertCount < out.actual.expertCount;
    if ((paramsUp || expertsUp) && (paramsDown || expertsDown)) out.direction = "MIXED";
    else if (paramsUp || expertsUp) out.direction = "UPSIZE";
    else if (paramsDown || expertsDown) out.direction = "DOWNSIZE";
    else out.direction = "MATCH";

    out.status = "PLAN_READY";
    out.reason = "NON_DESTRUCTIVE_RUNTIME_TARGET";
    return true;
}

std::string RuntimePlanJson(const RuntimePlan& plan) {
    std::ostringstream out;
    out << "{\"schema\":" << jsonQuote(RuntimePlan::kSchema)
        << ",\"model\":" << jsonQuote(plan.actual.model)
        << ",\"architecture\":" << jsonQuote(plan.actual.architecture)
        << ",\"injection_mode\":" << jsonQuote(plan.injectionMode)
        << ",\"streamer_path\":" << jsonQuote(plan.streamerPath)
        << ",\"requested_parameters\":" << plan.requested.parameterCount
        << ",\"requested_experts\":" << plan.requested.expertCount
        << ",\"actual_parameters\":" << plan.actual.parameterCount
        << ",\"actual_tensor_bytes\":" << plan.actual.tensorBytes
        << ",\"actual_experts\":" << plan.actual.expertCount
        << ",\"actual_experts_per_token\":" << plan.actual.expertsPerToken
        << ",\"target_working_set_bytes\":" << plan.targetWorkingSetBytes
        << ",\"direction\":" << jsonQuote(plan.direction)
        << ",\"status\":" << jsonQuote(plan.status)
        << ",\"reason\":" << jsonQuote(plan.reason)
        << ",\"source_immutable\":" << (plan.sourceImmutable ? "true" : "false")
        << ",\"writer_invoked\":" << (plan.writerInvoked ? "true" : "false")
        << ",\"shards\":" << plan.actual.shardCount
        << ",\"tensors\":" << plan.actual.tensorCount << "}\n";
    return out.str();
}

} // namespace RawrXD::Reap
