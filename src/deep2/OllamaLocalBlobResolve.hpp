#pragma once
/* Resolve ollama list name → local blobs\sha256-* (no daemon/HTTP). ≤95. */
#include <cstdio>
#include <cstring>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {
namespace rawr_run {

inline bool FileOk(const char* p) {
#ifdef _WIN32
    DWORD a = GetFileAttributesA(p);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
#else
    (void)p;
    return false;
#endif
}

/* Parse manifest JSON for largest application/vnd.ollama.image.model digest. */
inline bool ManifestModelBlob(const char* manPath, std::string& outDigest) {
    FILE* f = nullptr;
#if defined(_MSC_VER)
    if (fopen_s(&f, manPath, "rb") != 0 || !f) return false;
#else
    f = std::fopen(manPath, "rb");
    if (!f) return false;
#endif
    std::string j;
    char buf[4096];
    while (size_t n = std::fread(buf, 1, sizeof(buf), f)) j.append(buf, n);
    std::fclose(f);
    const char* key = "application/vnd.ollama.image.model";
    size_t pos = 0, bestSz = 0;
    std::string best;
    while ((pos = j.find(key, pos)) != std::string::npos) {
        size_t d = j.find("\"digest\"", pos);
        size_t s = j.find("\"size\"", pos);
        if (d == std::string::npos || d > pos + 400) {
            pos += 8;
            continue;
        }
        size_t q1 = j.find("sha256:", d);
        if (q1 == std::string::npos || q1 > d + 80) {
            pos += 8;
            continue;
        }
        size_t q2 = j.find('"', q1);
        if (q2 == std::string::npos) break;
        std::string dig = j.substr(q1, q2 - q1); /* sha256:hex */
        size_t sz = 0;
        if (s != std::string::npos && s < d + 200) {
            size_t c = j.find_first_of("0123456789", s);
            if (c != std::string::npos) sz = (size_t)std::strtoull(j.c_str() + c, nullptr, 10);
        }
        if (sz >= bestSz) {
            bestSz = sz;
            best = dig;
        }
        pos = q2 + 1;
    }
    if (best.empty()) return false;
    outDigest = best;
    return true;
}

inline bool ResolveOllamaLocalBlob(const char* aliasOrTag, std::string& outPath) {
    if (!aliasOrTag || !aliasOrTag[0]) return false;
    std::string a(aliasOrTag);
    /* strip registry prefix */
    const char* lib = "library/";
    size_t lp = a.find(lib);
    if (lp != std::string::npos) a = a.substr(lp + 8);
    size_t slash = a.find_last_of("/\\");
    if (slash != std::string::npos) a = a.substr(slash + 1);
    std::string name = a, tag = "latest";
    size_t colon = a.find(':');
    if (colon != std::string::npos) {
        name = a.substr(0, colon);
        tag = a.substr(colon + 1);
    }
    const char* roots[] = {"F:\\OllamaModels", "F:\\OllamaModels\\models", nullptr};
    for (int r = 0; roots[r]; ++r) {
        char man[MAX_PATH];
        std::snprintf(man, sizeof(man),
                      "%s\\manifests\\registry.ollama.ai\\library\\%s\\%s",
                      roots[r], name.c_str(), tag.c_str());
        std::string dig;
        if (!ManifestModelBlob(man, dig)) continue;
        /* sha256:hex → blobs\sha256-hex */
        std::string hex = dig;
        if (hex.rfind("sha256:", 0) == 0) hex = "sha256-" + hex.substr(7);
        char blob[MAX_PATH];
        std::snprintf(blob, sizeof(blob), "%s\\blobs\\%s", roots[r], hex.c_str());
        if (FileOk(blob)) {
            outPath = blob;
            return true;
        }
        std::snprintf(blob, sizeof(blob), "F:\\OllamaModels\\blobs\\%s", hex.c_str());
        if (FileOk(blob)) {
            outPath = blob;
            return true;
        }
    }
    return false;
}

} // namespace rawr_run
} // namespace Deep2
