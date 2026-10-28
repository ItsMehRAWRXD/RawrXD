// Win32IDE_SwarmModelSelector.cpp — Multi-root local GGUF + optional Ollama tags
#include "Win32IDE_SwarmModelSelector.h"

#include <windows.h>

#include <algorithm>
#include <cstdlib>
#include <string>
#include <unordered_set>
#include <vector>

namespace RawrXD {
namespace Win32App {
namespace {

std::string wideToUtf8(PCWSTR w) {
    if (!w) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string o(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, o.data(), n, nullptr, nullptr);
    return o;
}

std::wstring utf8ToWide(const std::string& u) {
    if (u.empty()) return {};
    const int nw = MultiByteToWideChar(CP_UTF8, 0, u.c_str(), -1, nullptr, 0);
    if (nw <= 1) return {};
    std::wstring w(static_cast<size_t>(nw), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, u.c_str(), -1, w.data(), nw);
    return w;
}

bool envTruthy(const char* v) {
    return v && v[0] && v[0] != '0' &&
           !(v[0] == 'f' || v[0] == 'F' || v[0] == 'n' || v[0] == 'N');
}

unsigned envUInt(const char* key, unsigned defv) {
    const char* e = std::getenv(key);
    if (!e || !e[0]) return defv;
    unsigned v = 0;
    for (const char* p = e; *p >= '0' && *p <= '9'; ++p)
        v = v * 10u + static_cast<unsigned>(*p - '0');
    return (e[0] >= '0' && e[0] <= '9') ? v : defv;
}

void addRoot(std::vector<std::wstring>& roots, std::unordered_set<std::wstring>& seen,
             const std::wstring& dirW) {
    if (dirW.empty()) return;
    const DWORD a = GetFileAttributesW(dirW.c_str());
    if (a == INVALID_FILE_ATTRIBUTES || (a & FILE_ATTRIBUTE_DIRECTORY) == 0) return;
    if (!seen.insert(dirW).second) return;
    roots.push_back(dirW);
}

void addRootUtf8(std::vector<std::wstring>& roots, std::unordered_set<std::wstring>& seen,
                 const char* utf8) {
    if (!utf8 || !utf8[0]) return;
    addRoot(roots, seen, utf8ToWide(utf8));
}

void addSemiList(std::vector<std::wstring>& roots, std::unordered_set<std::wstring>& seen,
                 const char* list) {
    if (!list || !list[0]) return;
    const std::string s(list);
    size_t start = 0;
    while (start < s.size()) {
        const size_t semi = s.find(';', start);
        addRootUtf8(roots, seen,
                    ((semi == std::string::npos) ? s.substr(start)
                                                 : s.substr(start, semi - start))
                        .c_str());
        if (semi == std::string::npos) break;
        start = semi + 1;
    }
}

void appendGguf(const std::wstring& dirW, std::vector<std::string>& out, unsigned maxEntries) {
    if (out.size() >= maxEntries || dirW.empty()) return;
    const std::wstring pattern = dirW + L"\\*.gguf";
    WIN32_FIND_DATAW fd{};
    const HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) continue;
        out.push_back(wideToUtf8((dirW + L"\\" + fd.cFileName).c_str()));
    } while (out.size() < maxEntries && FindNextFileW(h, &fd) != 0);
    FindClose(h);
}

// Local manifests only (no HTTP / no cloud). LOCAL_ONLY_NO_OLLAMA skips tags.
void appendOllamaTags(const std::wstring& rootW, std::vector<std::string>& out,
                      unsigned maxEntries) {
    if (out.size() >= maxEntries) return;
    if (envTruthy(std::getenv("LOCAL_ONLY_NO_OLLAMA"))) return;
    const std::wstring lib = rootW + L"\\manifests\\registry.ollama.ai\\library";
    WIN32_FIND_DATAW nameFd{};
    const HANDLE hName = FindFirstFileW((lib + L"\\*").c_str(), &nameFd);
    if (hName == INVALID_HANDLE_VALUE) return;
    do {
        if ((nameFd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) continue;
        if (nameFd.cFileName[0] == L'.') continue;
        const std::wstring nameDir = lib + L"\\" + nameFd.cFileName;
        WIN32_FIND_DATAW tagFd{};
        const HANDLE hTag = FindFirstFileW((nameDir + L"\\*").c_str(), &tagFd);
        if (hTag == INVALID_HANDLE_VALUE) continue;
        do {
            if ((tagFd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) continue;
            if (tagFd.cFileName[0] == L'.') continue;
            const std::string id =
                wideToUtf8(nameFd.cFileName) + ":" + wideToUtf8(tagFd.cFileName);
            out.push_back(id);
        } while (out.size() < maxEntries && FindNextFileW(hTag, &tagFd) != 0);
        FindClose(hTag);
    } while (out.size() < maxEntries && FindNextFileW(hName, &nameFd) != 0);
    FindClose(hName);
}

void collectRoots(std::vector<std::wstring>& roots) {
    std::unordered_set<std::wstring> seen;
    addSemiList(roots, seen, std::getenv("RAWRXD_SWARM_MODEL_DIR"));
    addSemiList(roots, seen, std::getenv("RAWRXD_MODELS"));
    addSemiList(roots, seen, std::getenv("RAWRXD_MODELS_PATH"));
    addSemiList(roots, seen, std::getenv("OLLAMA_MODELS"));
    wchar_t profile[MAX_PATH]{};
    if (GetEnvironmentVariableW(L"USERPROFILE", profile, MAX_PATH) > 0)
        addRoot(roots, seen, std::wstring(profile) + L"\\.ollama\\models");
    wchar_t localApp[MAX_PATH]{};
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", localApp, MAX_PATH) > 0)
        addRoot(roots, seen, std::wstring(localApp) + L"\\Ollama\\models");
    addRootUtf8(roots, seen, "F:\\OllamaModels");
    addRootUtf8(roots, seen, "G:\\OllamaModels");
    addRootUtf8(roots, seen, "D:\\OllamaModels");
    addRootUtf8(roots, seen, "C:\\OllamaModels");
    addRootUtf8(roots, seen, "D:\\models");
    addRootUtf8(roots, seen, "F:\\models");
    wchar_t exePath[MAX_PATH]{};
    const DWORD n = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        std::wstring exe(exePath);
        const size_t slash = exe.find_last_of(L"\\/");
        if (slash != std::wstring::npos)
            addRoot(roots, seen, exe.substr(0, slash) + L"\\models");
    }
}

} // namespace

std::vector<std::string> enumerateSwarmModelCandidates(unsigned maxEntries) {
    std::vector<std::string> out;
    if (maxEntries == 0) return out;
    out.reserve(std::min(maxEntries, 512u));
    std::vector<std::wstring> roots;
    collectRoots(roots);
    for (const auto& r : roots) {
        appendGguf(r, out, maxEntries);
        if (out.size() >= maxEntries) break;
    }
    // Live local Ollama /api/tags when 127.0.0.1:11434 reachable (no cloud).
    if (out.size() < maxEntries)
        appendLocalOllamaHttpTags(out, maxEntries);
    // Filesystem manifests as secondary (offline) inventory.
    if (out.size() < maxEntries) {
        for (const auto& r : roots) {
            appendOllamaTags(r, out, maxEntries);
            if (out.size() >= maxEntries) break;
        }
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out; // may be empty — caller must fail-closed (no fakes)
}

SwarmModelOrchPlan resolveSwarmModelOrchPlan(unsigned requestedN) {
    SwarmModelOrchPlan plan;
    plan.models = enumerateSwarmModelCandidates(512);
    if (plan.models.empty()) {
        plan.taskCount = 0;
        plan.maxParallel = 1;
        plan.emptyFailClosed = true;
        return plan;
    }
    unsigned n = requestedN ? requestedN : envUInt("RAWRXD_SWARM_N", 4);
    if (n < 1) n = 1;
    if (n > kSwarmOrchCap) n = kSwarmOrchCap;
    if (n > static_cast<unsigned>(plan.models.size()))
        n = static_cast<unsigned>(plan.models.size());
    plan.models.resize(n);
    plan.taskCount = n;
    plan.sequential = envTruthy(std::getenv("RAWRXD_SWARM_SEQUENTIAL"));
    unsigned mp = plan.sequential ? 1u : envUInt("RAWRXD_SWARM_MAX_PARALLEL", n);
    if (mp < 1) mp = 1;
    if (mp > n) mp = n;
    plan.maxParallel = mp;
    plan.emptyFailClosed = false;
    return plan;
}

} // namespace Win32App
} // namespace RawrXD
