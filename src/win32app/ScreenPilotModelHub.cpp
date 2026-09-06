#include "ScreenPilotModelHub.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace fs = std::filesystem;

namespace RawrXD::ScreenPilot {

static const std::vector<ModelRecommend> kTop = {
    {"deepseek-coder-7b", "DeepSeek Coder 7B (Flash)", "4.7 GB", "Fast inline completions",
     "inline"},
    {"qwen2.5-coder-7b", "Qwen 2.5 Coder 7B Instruct", "4.9 GB", "Balanced multi-file agent",
     "inline"},
    {"deepseek-coder-32b", "DeepSeek Coder 32B (Dense)", "19.2 GB",
     "Deep workspace architecture", "dense"},
    {"qwen2.5-coder-32b", "Qwen 2.5 Coder 32B", "19 GB", "Multi-file 8k context", "dense"},
    {"llama3-70b-q4", "Llama 3 70B Q4_K_M", "40+ GB", "Hybrid VRAM+RAM offload",
     "enterprise"},
};

const std::vector<ModelRecommend>& ModelHub::topRecommendations() { return kTop; }

std::vector<std::string> ModelHub::storageRoots() {
    std::vector<std::string> roots;
    auto add = [&](const char* p) {
        if (!p || !p[0]) return;
        std::string root = p;
        try {
            const fs::path fp(p);
            if (fs::exists(fp) && fs::is_regular_file(fp))
                root = fp.parent_path().string();
        } catch (...) {
        }
        if (GetFileAttributesA(root.c_str()) == INVALID_FILE_ATTRIBUTES) return;
        for (const auto& r : roots)
            if (r == root) return;
        roots.push_back(std::move(root));
    };
    if (const char* e = std::getenv("RAWRXD_MODELS_PATH")) add(e);
    if (const char* e = std::getenv("OLLAMA_MODELS")) add(e);
    add("G:\\OllamaModels");
    add("F:\\OllamaModels");
    add("D:\\OllamaModels");
    add("C:\\OllamaModels");
    add("F:\\~dev");
    if (const char* user = std::getenv("USERNAME"))
        add((std::string("C:\\Users\\") + user + "\\OllamaModels").c_str());
    if (const char* home = std::getenv("USERPROFILE"))
        add((std::string(home) + "\\.ollama\\models").c_str());
    return roots;
}

static size_t ollamaListNameEnd(const std::string& line) {
    for (size_t i = 0; i < line.size(); ++i) {
        if (line[i] != ' ')
            continue;
        size_t j = i;
        while (j < line.size() && line[j] == ' ')
            ++j;
        if (j - i >= 2 && i > 0)
            return i;
    }
    return line.size();
}

static std::vector<LocalModelEntry> scanOllamaCli(size_t maxEntries) {
    std::vector<LocalModelEntry> out;
    FILE* pipe = _popen("ollama list 2>nul", "r");
    if (!pipe)
        return out;
    char buf[512] = {};
    bool header = true;
    while (fgets(buf, sizeof(buf), pipe)) {
        std::string line = buf;
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
            line.pop_back();
        if (line.empty())
            continue;
        if (header) {
            header = false;
            continue;
        }
        const size_t nameLen = ollamaListNameEnd(line);
        if (nameLen == 0)
            continue;
        std::string name = line.substr(0, nameLen);
        while (!name.empty() && name.back() == ' ')
            name.pop_back();
        if (name.empty() || name == "NAME")
            continue;
        LocalModelEntry e;
        e.fileName = std::string("[Ollama] ") + name;
        e.fullPath = std::string("ollama:") + name;
        const std::string tail = line.substr(nameLen);
        size_t gb = tail.find(" GB");
        size_t mb = tail.find(" MB");
        if (gb != std::string::npos) {
            try {
                const double v = std::stod(tail.substr(0, gb));
                e.bytes = static_cast<uint64_t>(v * 1024.0 * 1024.0 * 1024.0);
            } catch (...) {
            }
        } else if (mb != std::string::npos) {
            try {
                const double v = std::stod(tail.substr(0, mb));
                e.bytes = static_cast<uint64_t>(v * 1024.0 * 1024.0);
            } catch (...) {
            }
        }
        out.push_back(std::move(e));
        if (out.size() >= maxEntries)
            break;
    }
    _pclose(pipe);
    return out;
}

std::vector<LocalModelEntry> ModelHub::scanLocalInventory(size_t maxEntries) {
    std::vector<LocalModelEntry> out;
    auto pushFile = [&](const fs::path& p) {
        if (out.size() >= maxEntries) return;
        LocalModelEntry e;
        e.fileName = p.filename().string();
        e.fullPath = p.string();
        try {
            e.bytes = static_cast<uint64_t>(fs::file_size(p));
        } catch (...) {
        }
        out.push_back(std::move(e));
    };
    for (const auto& root : storageRoots()) {
        try {
            if (!fs::exists(root) || !fs::is_directory(root)) continue;
            for (const auto& entry : fs::directory_iterator(
                     root, fs::directory_options::skip_permission_denied)) {
                if (entry.is_regular_file()) {
                    auto ext = entry.path().extension().string();
                    std::transform(ext.begin(), ext.end(), ext.begin(),
                                   [](unsigned char c) { return (char)std::tolower(c); });
                    if (ext == ".gguf" || ext == ".bin") pushFile(entry.path());
                } else if (entry.is_directory()) {
                    try {
                        for (const auto& child : fs::directory_iterator(
                                 entry.path(),
                                 fs::directory_options::skip_permission_denied)) {
                            if (!child.is_regular_file()) continue;
                            auto ext = child.path().extension().string();
                            std::transform(ext.begin(), ext.end(), ext.begin(),
                                           [](unsigned char c) {
                                               return (char)std::tolower(c);
                                           });
                            if (ext == ".gguf" || ext == ".bin") pushFile(child.path());
                            if (out.size() >= maxEntries) break;
                        }
                    } catch (...) {
                    }
                }
                if (out.size() >= maxEntries) break;
            }
        } catch (...) {
        }
    }
    for (const auto& e : scanOllamaCli(maxEntries)) {
        if (out.size() >= maxEntries)
            break;
        bool dup = false;
        for (const auto& x : out) {
            if (x.fullPath == e.fullPath) {
                dup = true;
                break;
            }
        }
        if (!dup)
            out.push_back(e);
    }
    std::sort(out.begin(), out.end(),
              [](const LocalModelEntry& a, const LocalModelEntry& b) {
                  return a.fileName < b.fileName;
              });
    return out;
}

LocalModelEntry ModelHub::findByFileName(const std::string& name,
                                         const std::vector<LocalModelEntry>& inv) {
    for (const auto& e : inv) {
        if (e.fileName == name) return e;
        std::string stem = e.fileName;
        const size_t dot = stem.find_last_of('.');
        if (dot != std::string::npos) stem = stem.substr(0, dot);
        if (stem == name) return e;
    }
    return {};
}

}  // namespace RawrXD::ScreenPilot
