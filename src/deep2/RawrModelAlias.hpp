// RawrModelAlias.hpp — local alias → GGUF/shard path (no Ollama, no network)
#pragma once
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
    std::string path;       // file or shard directory
    uint32_t shards = 0;    // 1 for single .gguf
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
    snprintf(pat, sizeof(pat), "%s\\*.gguf", dir);
    WIN32_FIND_DATAA fd{};
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) ++n;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#endif
    return n;
}

inline void PushRoot(std::vector<std::string>& roots, const char* r) {
    if (r && r[0] && DirExists(r)) roots.emplace_back(r);
}

// Resolve "tinyllama" / "phi3" / "kimi-k2" → local path. Never spawns ollama.
inline bool ResolveModelAlias(const char* alias, AliasResolve& out) {
    out = {};
    if (!alias || !alias[0]) return false;
    out.alias = alias;

    // Absolute path / existing file short-circuit.
    if (FileExists(alias)) {
        out.path = alias;
        out.shards = 1;
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
    PushRoot(roots, "G:\\~dev\\rawrxd\\models");
    PushRoot(roots, "G:\\~dev\\rawrxd");
    PushRoot(roots, "F:\\OllamaModels");

    struct Map { const char* name; const char* rel; bool isDir; };
    // rel is under a root; isDir = shard directory.
    const Map maps[] = {
        {"tinyllama", "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf", false},
        {"phi3", "phi3-mini-Q2_K.gguf", false},
        {"phi-3", "phi3-mini-Q2_K.gguf", false},
        {"phi3-q8", "Phi-3-mini-4k-instruct-q8_0.gguf", false},
        {"llama32", "llama3.2-3b-Q3_K_S.gguf", false},
        {"llama32-q3", "llama3.2-3b-Q3_K_S.gguf", false},
        {"llama32-q2", "llama3.2-3b-Q2_K.gguf", false},
        {"gemma3", "gemma3-1b-Q2_K.gguf", false},
        {"gemma", "gemma3-1b-Q2_K.gguf", false},
        {"qwen-coder", "Qwen2.5-Coder-14B-Instruct-Q8_0", true},
        {"kimi-k2", "Kimi-K2-Instruct-0905-GGUF\\Q4_K_M", true},
        {"kimi", "Kimi-K2-Instruct-0905-GGUF\\Q4_K_M", true},
    };

    for (const auto& m : maps) {
        if (_stricmp(alias, m.name) != 0) continue;
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
        }
    }
    return false;
}

} // namespace rawr_run
} // namespace Deep2
