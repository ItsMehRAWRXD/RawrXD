#include "rawr_model_resolver.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <sstream>
#include <system_error>
#include <unordered_set>

namespace rawrxd::models {
namespace {

namespace fs = std::filesystem;

std::string lower(std::string value) {
    for (char& c : value) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return value;
}

std::string environmentValue(const char* name) {
#ifdef _WIN32
    char* value = nullptr;
    size_t length = 0;
    if (_dupenv_s(&value, &length, name) != 0 || value == nullptr)
        return {};
    std::string result(value);
    std::free(value);
    return result;
#else
    const char* value = std::getenv(name);
    return value != nullptr ? std::string(value) : std::string();
#endif
}

std::string canonical(std::string value) {
    value = lower(std::move(value));
    if (value.rfind("ollama:", 0) == 0) value.erase(0, 7);
    if (value.rfind("model:", 0) == 0) value.erase(0, 6);
    std::string out;
    out.reserve(value.size());
    for (char c : value) {
        if (std::isalnum(static_cast<unsigned char>(c))) out.push_back(c);
    }
    // Ollama's conventional `:latest` tag is not part of a GGUF filename.
    if (out.size() >= 6 && out.compare(out.size() - 6, 6, "latest") == 0) {
        out.erase(out.size() - 6);
    }
    return out;
}

bool isGguf(const fs::path& path) {
    return lower(path.extension().string()) == ".gguf";
}

std::vector<fs::path> roots() {
    std::vector<fs::path> result;
    std::unordered_set<std::string> seen;
    const auto add = [&](const fs::path& path) {
        if (path.empty()) return;
        std::error_code ec;
        const fs::path absolute = fs::absolute(path, ec).lexically_normal();
        if (ec) return;
        const std::string key = lower(absolute.string());
        if (seen.insert(key).second) result.push_back(absolute);
    };

    const std::string configuredRoots = environmentValue("RAWRXD_MODEL_DIRS");
    if (!configuredRoots.empty()) {
        std::string list(configuredRoots);
        size_t start = 0;
        while (start <= list.size()) {
            const size_t end = list.find_first_of(";|", start);
            add(list.substr(start, end == std::string::npos
                                      ? std::string::npos : end - start));
            if (end == std::string::npos) break;
            start = end + 1;
        }
    }

    add("F:\\rawrxd\\models");
    add("F:\\OllamaModels");
    add("F:\\models");
    add(fs::current_path() / "models");
    // Do not recursively scan the caller's working directory. In a source
    // checkout that would walk build trees, worktrees, and evidence archives,
    // creating false alias collisions and making `rawr run` appear hung.
    return result;
}

std::vector<ModelRecord> scan() {
    std::vector<ModelRecord> result;
    std::unordered_set<std::string> seen;
    for (const fs::path& root : roots()) {
        std::error_code ec;
        if (!fs::is_directory(root, ec)) continue;
        fs::recursive_directory_iterator it(
            root, fs::directory_options::skip_permission_denied, ec);
        const fs::recursive_directory_iterator end;
        for (; it != end; it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            if (!it->is_regular_file(ec) || ec || !isGguf(it->path())) continue;
            const fs::path path = it->path().lexically_normal();
            const std::string key = lower(path.string());
            if (!seen.insert(key).second) continue;
            std::error_code sizeEc;
            result.push_back({path.stem().string(), path,
                              fs::file_size(path, sizeEc)});
        }
    }
    std::sort(result.begin(), result.end(), [](const ModelRecord& a,
                                               const ModelRecord& b) {
        return lower(a.name) < lower(b.name);
    });
    return result;
}

} // namespace

ResolveResult resolve(const std::string& requested) {
    ResolveResult result;
    result.requested = requested;
    const fs::path direct(requested);
    std::error_code ec;
    if (!requested.empty() && fs::is_regular_file(direct, ec) &&
        isGguf(direct)) {
        result.found = true;
        result.path = fs::absolute(direct, ec).lexically_normal();
        return result;
    }

    const std::string wanted = canonical(requested);
    if (wanted.empty()) {
        result.error = "model name is empty";
        return result;
    }

    // Preserve the two product aliases used by existing scripts while still
    // validating that the target is a real local GGUF before returning it.
    const std::vector<fs::path> compatibilityAliases = {
        (wanted == "llama323b" || wanted == "llama32")
            ? fs::path("F:\\OllamaModels\\_r1_iso\\03_llama32_3b\\llama3.2-3b-Q2_K.gguf")
            : fs::path(),
        (wanted == "phi3mini" || wanted == "phi3miniq8")
            ? fs::path("F:\\OllamaModels\\_r1_iso\\02_phi3_mini\\Phi-3-mini-4k-instruct-q8_0.gguf")
            : fs::path(),
        wanted == "phi3medium"
            ? fs::path("F:\\OllamaModels\\_r1_iso\\06_phi3_med\\Phi-3-medium-128k-instruct-Q4_K_M.gguf")
            : fs::path(),
        (wanted == "qwen3" || wanted == "qwen38b")
            ? fs::path("F:\\models\\gguf\\library__qwen3__8b.gguf")
            : fs::path(),
        (wanted == "qwen3827b" || wanted == "qwen38")
            ? fs::path("F:\\models\\gguf\\library__qwen3.8__27b.gguf")
            : fs::path(),
        wanted == "qwen32"
            ? fs::path("F:\\models\\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf")
            : fs::path(),
        wanted == "nemotron30b"
            ? fs::path("F:\\rawrxd\\models\\nemotron-3.5-lightning-30b-Q4_K_M.gguf")
            : fs::path(),
        wanted == "nemotron35lightning30b"
            ? fs::path("F:\\rawrxd\\models\\nemotron-3.5-lightning-30b-Q4_K_M.gguf")
            : fs::path(),
        (wanted == "nemotron3nano4b" || wanted == "nemotron3nano")
            ? fs::path("F:\\OllamaModels\\NVIDIA-Nemotron-3-Nano-4B-GGUF\\NVIDIA-Nemotron-3-Nano-4B-Q8_0.gguf")
            : fs::path(),
    };
    for (const fs::path& candidate : compatibilityAliases) {
        if (!candidate.empty() && fs::is_regular_file(candidate, ec) &&
            isGguf(candidate)) {
            result.found = true;
            result.path = fs::absolute(candidate, ec).lexically_normal();
            return result;
        }
    }

    const auto files = scan();
    for (const ModelRecord& record : files) {
        const std::string candidate = canonical(record.name);
        if (candidate == wanted) {
            result.found = true;
            result.path = record.path;
            return result;
        }
    }

    // Permit a uniquely identifiable name such as `nemotron30b`, but reject
    // ambiguous partial matches instead of silently loading the wrong model.
    const ModelRecord* partial = nullptr;
    for (const ModelRecord& record : files) {
        const std::string candidate = canonical(record.name);
        // Only accept a filename that contains the complete requested model
        // identity. The reverse relation would let a generic file named
        // `tinyllama.gguf` steal a request for `tinyllama-1.1b-chat-v1.0`.
        if (candidate.find(wanted) == std::string::npos) continue;
        if (partial != nullptr) {
            result.error = "model name is ambiguous; use a GGUF path or a more specific alias";
            for (const fs::path& root : roots()) result.searchedRoots.push_back(root);
            return result;
        }
        partial = &record;
    }
    if (partial != nullptr) {
        result.found = true;
        result.path = partial->path;
        return result;
    }

    result.error = "no local GGUF matched the requested model";
    for (const fs::path& root : roots()) result.searchedRoots.push_back(root);
    return result;
}

std::vector<ModelRecord> enumerate() {
    return scan();
}

fs::path defaultWorkspace() {
    const std::string configuredWorkspace = environmentValue("RAWRXD_WORKSPACE");
    if (!configuredWorkspace.empty()) {
        std::error_code ec;
        const fs::path candidate =
            fs::absolute(configuredWorkspace, ec).lexically_normal();
        if (!ec && fs::is_directory(candidate, ec)) return candidate;
    }

    std::error_code ec;
    fs::path current = fs::current_path(ec);
    if (!ec) {
        // Prefer the actual repository root over a nested helper project such
        // as `~dev`, so an audit launched from a build directory covers the
        // IDE checkout rather than only the route subproject.
        for (fs::path probe = current;; probe = probe.parent_path()) {
            if (fs::is_directory(probe / ".git", ec)) return probe;
            const fs::path parent = probe.parent_path();
            if (parent == probe || parent.empty()) break;
        }
        for (fs::path probe = current;; probe = probe.parent_path()) {
            if (fs::is_regular_file(probe / "CMakeLists.txt", ec)) return probe;
            const fs::path parent = probe.parent_path();
            if (parent == probe || parent.empty()) break;
        }
    }

    const fs::path known("F:\\rawrxd");
    if (fs::is_directory(known, ec)) return known;
    return current;
}

} // namespace rawrxd::models
