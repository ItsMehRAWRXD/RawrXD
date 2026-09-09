// RawrModelAlias.hpp — local alias → model path (GGUF or Ollama blob; ext-agnostic)
#pragma once
#include "RawrModelDiscover.hpp"
#include "GgufModelPath.hpp"
#include "OllamaLocalBlobResolve.hpp"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {
namespace rawr_run {

struct AliasResolve {
    std::string alias;
    std::string path;    // file or shard directory
    uint32_t shards = 0; // 1 for single .gguf
    bool resolved = false;
};

inline bool FileExists(const char* p) {
#ifdef _WIN32
    DWORD a = GetFileAttributesA(p);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
#else
    return false;
#endif
}

inline bool DirExists(const char* p) {
#ifdef _WIN32
    DWORD a = GetFileAttributesA(p);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
#else
    return false;
#endif
}

inline uint32_t CountGgufInDir(const char* dir) {
    uint32_t n = 0;
#ifdef _WIN32
    char pat[MAX_PATH];
    snprintf(pat, sizeof(pat), "%s\\*", dir);
    WIN32_FIND_DATAA fd{};
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (_strnicmp(fd.cFileName, "mmproj", 6) == 0) continue;
        char full[MAX_PATH];
        snprintf(full, sizeof(full), "%s\\%s", dir, fd.cFileName);
        if (Deep2::GgufPath::IsLoadableModelFile(full)) ++n;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#endif
    return n;
}

inline void PushRoot(std::vector<std::string>& roots, const char* r) {
    if (r && r[0] && DirExists(r)) roots.emplace_back(r);
}

inline std::string StripOllamaTag(const char* alias) {
    if (!alias || !alias[0]) return {};
    std::string s(alias);
    // registry.ollama.ai/library/foo:tag → foo:tag
    const size_t slash = s.find_last_of("/\\");
    if (slash != std::string::npos) s = s.substr(slash + 1);
    // name:tag → name (keep path-like aliases without colon)
    const size_t colon = s.find(':');
    if (colon != std::string::npos) s = s.substr(0, colon);
    return s;
}

// Resolve any local name/path → GGUF file or shard directory.
inline bool ResolveModelAlias(const char* alias, AliasResolve& out) {
    out = {};
    if (!alias || !alias[0]) return false;
    out.alias = alias;

    if (FileExists(alias)) {
        int idx = 0, total = 0;
        const char* base = strrchr(alias, '\\');
        base = base ? base + 1 : alias;
        if (ParseShardOf(base, idx, total) && idx == 1 && total > 1) {
            // Point at shard directory so loadModel multi-shard path engages.
            std::string dir(alias);
            size_t slash = dir.find_last_of("\\/");
            out.path = slash == std::string::npos ? dir : dir.substr(0, slash);
            out.shards = (uint32_t)total;
        } else {
            out.path = alias;
            out.shards = 1;
        }
        out.resolved = true;
        return true;
    }
    if (DirExists(alias)) {
        uint32_t n = CountGgufInDir(alias);
        if (n == 0) return false;
        out.path = alias;
        out.shards = n;
        out.resolved = true;
        return true;
    }

    std::vector<std::string> roots;
    if (const char* e = std::getenv("RAWRXD_MODEL_ROOT")) PushRoot(roots, e);
    PushRoot(roots, "F:\\OllamaModels");
    PushRoot(roots, "G:\\~dev\\rawrxd\\models");
    PushRoot(roots, "G:\\~dev\\rawrxd");
    PushRoot(roots, "F:\\OllamaModels\\rawrxd_test_models");

    // Prefer bare name (ollama list uses name:tag).
    const std::string bare = StripOllamaTag(alias);
    const char* lookup = bare.empty() ? alias : bare.c_str();

    struct Map {
        const char* name;
        const char* rel;
        bool isDir;
    };
    const Map maps[] = {
        {"tinyllama", "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf", false},
        {"phi3", "Phi-3-mini-4k-instruct-q8_0.gguf", false},
        {"phi-3", "Phi-3-mini-4k-instruct-q8_0.gguf", false},
        {"phi3-mini", "Phi-3-mini-4k-instruct-q8_0.gguf", false},
        {"phi3-q8", "Phi-3-mini-4k-instruct-q8_0.gguf", false},
        {"phi3-medium",
         "Phi-3-medium-128k-instruct-14B-Q4_K_M\\"
         "Phi-3-medium-128k-instruct-Q4_K_M.gguf",
         false},
        {"llama32", "blobs\\sha256-dde5aa3fc5ffc17176b5e8bdc82f587b24b2678c6c66101bf7da77af9f7ccdff",
         false},
        {"llama3.2",
         "blobs\\sha256-dde5aa3fc5ffc17176b5e8bdc82f587b24b2678c6c66101bf7da77af9f7ccdff",
         false},
        {"llama32-q3", "llama3.2-3b-Q3_K_S.gguf", false},
        {"llama32-q2", "llama3.2-3b-Q2_K.gguf", false},
        {"gemma3", "gemma-4-E4B-it-GGUF\\gemma-4-E4B-it-Q4_K_M.gguf", false},
        {"gemma3:latest", "gemma-4-E4B-it-GGUF\\gemma-4-E4B-it-Q4_K_M.gguf",
         false},
        {"gemma3:4b", "gemma-4-E4B-it-GGUF\\gemma-4-E4B-it-Q4_K_M.gguf", false},
        {"gemma", "gemma-4-E4B-it-GGUF\\gemma-4-E4B-it-Q4_K_M.gguf", false},
        {"gemma4", "gemma-4-E4B-it-GGUF\\gemma-4-E4B-it-Q4_K_M.gguf", false},
        {"gemma4-31b", "gemma-4-31B-it-GGUF\\gemma-4-31B-it-Q4_K_M.gguf", false},
        {"llama3.2:3b",
         "blobs\\sha256-dde5aa3fc5ffc17176b5e8bdc82f587b24b2678c6c66101bf7da77af9f7ccdff",
         false},
        {"llama3.2:latest",
         "blobs\\sha256-dde5aa3fc5ffc17176b5e8bdc82f587b24b2678c6c66101bf7da77af9f7ccdff",
         false},
        {"qwen3", "DeepSeek-R1-0528-Qwen3-8B-GGUF\\"
                  "DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf",
         false},
        {"qwen3:8b", "DeepSeek-R1-0528-Qwen3-8B-GGUF\\"
                     "DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf",
         false},
        {"qwen3.8:27b", "Qwen3.8-27B-AD-Q4_K_M\\Qwen3.8-27B-AD-Q4_K_M.gguf",
         false},
        {"codestral", "rawrxd_test_models\\Codestral-22B-v0.1-Q4_K_M.gguf",
         false},
        {"qwen-coder", "Qwen2.5-Coder-14B-Instruct-Q8_0", true},
        {"qwen25-coder", "Qwen2.5-Coder-14B-Instruct-Q8_0", true},
        {"qwen35",
         "Qwen3.5-40B-Claude-4.6-Opus-Deckard-Heretic-Uncensored-Thinking."
         "Q4_K_M.gguf",
         false},
        {"qwen35-40b-heretic-q8",
         "Qwen3.5-40B-Claude-4.6-Opus-Deckard-Heretic-Uncensored-Thinking."
         "Q8_0.gguf",
         false},
        {"qwen36", "Qwen3.6-35B-A3B-GGUF\\Qwen3.6-35B-A3B-Q4_K_M.gguf", false},
        {"qwen38", "Qwen3.8-27B-AD-Q4_K_M\\Qwen3.8-27B-AD-Q4_K_M.gguf", false},
        {"qwen3.8", "Qwen3.8-27B-AD-Q4_K_M\\Qwen3.8-27B-AD-Q4_K_M.gguf", false},
        {"glm47", "GLM-4.7-Flash-GGUF\\GLM-4.7-Flash-Q4_K_M.gguf", false},
        {"nemotron",
         "NVIDIA-Nemotron-3-Nano-4B-GGUF\\NVIDIA-Nemotron-3-Nano-4B-Q8_0.gguf",
         false},
        {"nemotron-3-nano",
         "NVIDIA-Nemotron-3-Nano-4B-GGUF\\NVIDIA-Nemotron-3-Nano-4B-Q8_0.gguf",
         false},
        {"nemotron-3-nano-4b",
         "NVIDIA-Nemotron-3-Nano-4B-GGUF\\NVIDIA-Nemotron-3-Nano-4B-Q8_0.gguf",
         false},
        {"deepseek-r1-8b",
         "DeepSeek-R1-0528-Qwen3-8B-GGUF\\"
         "DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf",
         false},
        {"deepseek-r1", "DeepSeek-R1-Q4_K_M-COMPLETE", true},
        {"minimax", "MiniMax-M2.7-Q4_K_M\\MiniMax-M2.7-Q4_K_M", true},
        {"bigdaddy", "BigDaddyG-Q2_K-CHEETAH.gguf", false},
        {"bigdaddyg", "BigDaddyG-Q2_K-CHEETAH.gguf", false},
        {"bigdaddygnative", "BigDaddyG-Q2_K-CHEETAH.gguf", false},
        {"bigdaddyglocal", "BigDaddyG-Q2_K-CHEETAH.gguf", false},
        {"bigdaddyg-productivity-local", "BigDaddyG-Q2_K-CHEETAH.gguf", false},
        {"bigdaddyg-productivity-native", "BigDaddyG-Q2_K-CHEETAH.gguf", false},
        {"kimi-k2", "Kimi-K2-Instruct-0905-GGUF\\Q4_K_M", true},
        {"kimi", "Kimi-K2-Instruct-0905-GGUF\\Q4_K_M", true},
    };

    for (const auto& m : maps) {
        /* Match bare or full ollama tag (llama3.2 / llama3.2:3b). */
        if (_stricmp(lookup, m.name) != 0 && _stricmp(alias, m.name) != 0)
            continue;
        bool hitFile = false;
        for (const auto& root : roots) {
            std::string cand = root + "\\" + m.rel;
            if (!m.isDir && FileExists(cand.c_str())) {
                out.path = cand;
                out.shards = 1;
                out.resolved = true;
                return true;
            }
            if (m.isDir && DirExists(cand.c_str())) {
                uint32_t n = CountGgufInDir(cand.c_str());
                if (n == 0) continue;
                out.path = cand;
                out.shards = n;
                out.resolved = true;
                return true;
            }
            hitFile = true;
        }
        (void)hitFile;
        /* Mapped name with missing GGUF → try ollama local blob. */
        std::string blob;
        if (ResolveOllamaLocalBlob(alias, blob) ||
            ResolveOllamaLocalBlob(lookup, blob) ||
            ResolveOllamaLocalBlob(m.name, blob)) {
            out.path = blob;
            out.shards = 1;
            out.resolved = true;
            return true;
        }
    }

    /* ollama list → manifests → blobs\sha256-* (no daemon). */
    {
        std::string blob;
        if (ResolveOllamaLocalBlob(alias, blob) ||
            ResolveOllamaLocalBlob(lookup, blob)) {
            out.path = blob;
            out.shards = 1;
            out.resolved = true;
            return true;
        }
    }

    // Fuzzy discovery across every accessible local GGUF/shard pack.
    LocalModelUnit hit{};
    if (DiscoverResolve(lookup, hit) ||
        (lookup != alias && DiscoverResolve(alias, hit))) {
        out.path = hit.path;
        out.shards = hit.shards ? hit.shards : 1;
        out.resolved = true;
        return true;
    }
    return false;
}

} // namespace rawr_run
} // namespace Deep2
