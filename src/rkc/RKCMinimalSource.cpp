// RKCMinimalSource.cpp — GPU-fallback pack + minimal vs naive selection
#include "RKCMinimalSource.hpp"
#include "RKCCodeWorld.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_set>

namespace fs = std::filesystem;
namespace RawrXD {
namespace RKC {
namespace {

std::string Lower(std::string s) {
    for (char& c : s)
        c = (char)std::tolower((unsigned char)c);
    return s;
}

std::string Slurp(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    std::ostringstream ss; ss << in.rdbuf();
    return ss.str();
}

uint64_t FileBytes(const std::string& path) {
    std::error_code ec;
    auto n = fs::file_size(path, ec);
    return ec ? 0ull : (uint64_t)n;
}

void PutReal(World& w, const std::string& k, const std::string& v,
             const std::string& src) {
    KnowledgeAtom a;
    a.key = k; a.value = v; a.state = EpistemicState::Real;
    a.kind = AtomKind::Fact; a.source = src;
    w.putAtom(a);
}
void PutNeg(World& w, const std::string& k, EpistemicState st,
            const std::string& v, const std::string& src) {
    KnowledgeAtom a;
    a.key = k; a.value = v; a.state = st;
    a.kind = AtomKind::Negative; a.source = src;
    w.putAtom(a);
}

struct PackSym { const char* name; const char* rel; };
static const PackSym kGpu[] = {
    {"DispatchGemvDevice", "include/vulkan_compute.h"},
    {"DispatchGemvQuant", "include/vulkan_compute.h"},
    {"vulkanGemvFallbackCount", "src/deep2/Deep2Engine.h"},
    {"Deep2Engine_GpuForward", "src/deep2/Deep2Engine_GpuForward.cpp"},
};

bool TopicGpuFallback(const std::string& q) {
    return q.find("gpu") != std::string::npos &&
           (q.find("fallback") != std::string::npos ||
            q.find("gemv") != std::string::npos ||
            q.find("fix") != std::string::npos);
}

bool NaiveName(const std::string& name) {
    const std::string n = Lower(name);
    return n.find("gpu") != std::string::npos ||
           n.find("vulkan") != std::string::npos ||
           n.find("gemv") != std::string::npos ||
           n.find("forward") != std::string::npos ||
           n.find("weight") != std::string::npos;
}

} // namespace

void ObserveGpuFallbackPack(World& world, const std::string& repoRoot) {
    for (const auto& s : kGpu) {
        const std::string path = repoRoot + "/" + s.rel;
        const bool isFileSym = std::strcmp(s.name, "Deep2Engine_GpuForward") == 0;
        const bool ok = isFileSym
            ? fs::exists(path)
            : [&]() {
                  const std::string text = Slurp(path);
                  return !text.empty() && text.find(s.name) != std::string::npos;
              }();
        const std::string key = std::string("symbol_defined.") + s.name;
        if (ok) {
            PutReal(world, key, "1", std::string("src:") + s.rel);
            PutReal(world, std::string("symbol_file.") + s.name, s.rel,
                    std::string("src:") + s.rel);
        } else {
            PutNeg(world, key, EpistemicState::NotPresent, "0",
                   std::string("src:") + s.rel);
        }
    }
    // Caller edge: GpuForward references DispatchGemvDevice
    const std::string fwd = repoRoot + "/src/deep2/Deep2Engine_GpuForward.cpp";
    const std::string t = Slurp(fwd);
    if (!t.empty() && t.find("DispatchGemvDevice") != std::string::npos) {
        PutReal(world, "call.Deep2Engine_GpuForward.DispatchGemvDevice", "1",
                "src:Deep2Engine_GpuForward.cpp");
    }
}

MinimalSourceResult SelectMinimalSource(World& world, const std::string& query,
                                        const std::string& repoRoot) {
    MinimalSourceResult r;
    const std::string q = Lower(query);
    r.goalKey = TopicGpuFallback(q) ? "fix_gpu_fallback" : "generic_source";

    auto addReq = [&](const char* sym, const char* rel) {
        SourceHit h;
        h.symbol = sym; h.relPath = rel;
        h.bytes = FileBytes(repoRoot + "/" + rel);
        r.required.push_back(h);
        r.bytesRkc += h.bytes;
    };

    if (TopicGpuFallback(q)) {
        // Exact missing knowledge → only these units (example from roadmap).
        if (world.get("symbol_defined.DispatchGemvDevice") &&
            world.get("symbol_defined.DispatchGemvDevice")->value == "1")
            addReq("DispatchGemvDevice", "include/vulkan_compute.h");
        if (world.get("symbol_defined.Deep2Engine_GpuForward") &&
            world.get("symbol_defined.Deep2Engine_GpuForward")->value == "1")
            addReq("caller_contract", "src/deep2/Deep2Engine_GpuForward.cpp");
        if (world.get("symbol_defined.vulkanGemvFallbackCount") &&
            world.get("symbol_defined.vulkanGemvFallbackCount")->value == "1")
            addReq("fallback_state", "src/deep2/Deep2Engine.h");
        // Live ownership entry (from code world) — one file, not whole tree.
        if (CodeWorldReachable(world, "generate", "LivePath_BeginGenerate") ||
            world.get("symbol_defined.LivePath_BeginGenerate"))
            addReq("LivePath_BeginGenerate", "src/deep2/Deep2LivePath.cpp");
    }

    // Dedupe files
    std::unordered_set<std::string> seen;
    std::vector<SourceHit> uniq;
    for (const auto& h : r.required) {
        if (seen.insert(h.relPath).second) uniq.push_back(h);
    }
    r.required.swap(uniq);
    r.filesRkc = (uint32_t)r.required.size();
    r.bytesRkc = 0;
    for (const auto& h : r.required) r.bytesRkc += h.bytes;

    // Naive: broad deep2 + include dump by name heuristics (deduped)
    std::unordered_set<std::string> naiveSeen;
    std::error_code ec;
    auto scan = [&](const fs::path& dir) {
        if (!fs::exists(dir, ec)) return;
        for (auto it = fs::recursive_directory_iterator(dir, ec);
             !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (!it->is_regular_file(ec)) continue;
            const auto ext = it->path().extension().string();
            if (ext != ".cpp" && ext != ".hpp" && ext != ".h") continue;
            if (!NaiveName(it->path().filename().string())) continue;
            SourceHit h;
            h.relPath = fs::relative(it->path(), repoRoot, ec).string();
            if (h.relPath.empty()) h.relPath = it->path().string();
            if (!naiveSeen.insert(h.relPath).second) continue;
            h.symbol = "*";
            h.bytes = FileBytes(it->path().string());
            r.naive.push_back(h);
            r.bytesNaive += h.bytes;
        }
    };
    scan(fs::path(repoRoot) / "src" / "deep2");
    scan(fs::path(repoRoot) / "include");
    scan(fs::path(repoRoot) / "src");
    r.filesNaive = (uint32_t)r.naive.size();

    std::unordered_set<std::string> reqSet;
    for (const auto& h : r.required) reqSet.insert(h.relPath);
    for (const auto& h : r.naive)
        if (!reqSet.count(h.relPath)) ++r.irrelevantFiles;

    std::ostringstream o;
    o << "[SOURCE_REQUIRED]\n";
    o << "goal=" << r.goalKey << "\n";
    for (const auto& h : r.required)
        o << h.symbol << "  " << h.relPath << "  bytes=" << h.bytes << "\n";
    o << "[SOURCE_METRICS]\n";
    o << "context_bytes_old=" << r.bytesNaive << "\n";
    o << "context_bytes_rkc=" << r.bytesRkc << "\n";
    o << "files_supplied=" << r.filesRkc << "\n";
    o << "files_naive=" << r.filesNaive << "\n";
    o << "irrelevant_source_supplied=" << r.irrelevantFiles << "\n";
    r.emit = o.str();
    return r;
}

} // namespace RKC
} // namespace RawrXD
