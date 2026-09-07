// RKCCodeWorld.cpp — observe symbols/calls from live-path sources
#include "RKCCodeWorld.hpp"
#include "deep2w0/W0GraphStore.hpp"
#include "deep2w0/W0UniversalIR.hpp"
#include <fstream>
#include <queue>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace RawrXD {
namespace RKC {
namespace {

std::string Slurp(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    std::ostringstream ss; ss << in.rdbuf();
    return ss.str();
}

bool HasToken(const std::string& text, const std::string& tok) {
    return !tok.empty() && text.find(tok) != std::string::npos;
}

void PutReal(World& w, const std::string& key, const std::string& val,
             const std::string& src) {
    KnowledgeAtom a;
    a.key = key; a.value = val; a.state = EpistemicState::Real;
    a.kind = AtomKind::Fact; a.source = src;
    w.putAtom(a);
}

void PutNeg(World& w, const std::string& key, EpistemicState st,
            const std::string& val, const std::string& src) {
    KnowledgeAtom a;
    a.key = key; a.value = val; a.state = st;
    a.kind = AtomKind::Negative; a.source = src;
    w.putAtom(a);
}

struct SymDef { const char* name; const char* relPath; };
struct CallEdge { const char* from; const char* to; const char* inFile; };

// Ownership graph for live generate (verified by source text presence).
static const SymDef kSyms[] = {
    {"generate", "src/deep2/Deep2Engine.cpp"},
    {"runK2NativeStreamPartial", "src/deep2/Deep2Engine.cpp"},
    {"K2LivePolicy_Apply", "src/deep2/K2LivePolicy_Apply.cpp"},
    {"LivePath_BeginGenerate", "src/deep2/Deep2LivePath.cpp"},
    {"LivePath_EndGenerate", "src/deep2/Deep2LivePath.cpp"},
    {"LivePath_ApplyMechEnv", "src/deep2/Deep2LivePath.cpp"},
    {"FakeRemoteInfer", "src/deep2/Deep2Engine.cpp"}, // expected ABSENT
};
static const CallEdge kEdges[] = {
    {"generate", "K2LivePolicy_Apply", "src/deep2/Deep2Engine.cpp"},
    {"generate", "LivePath_BeginGenerate", "src/deep2/Deep2Engine.cpp"},
    {"runK2NativeStreamPartial", "K2LivePolicy_Apply", "src/deep2/Deep2Engine.cpp"},
    {"runK2NativeStreamPartial", "LivePath_BeginGenerate", "src/deep2/Deep2Engine.cpp"},
    {"LivePath_BeginGenerate", "LivePath_ApplyMechEnv", "src/deep2/Deep2LivePath.cpp"},
};

} // namespace

bool CodeWorldReachable(const World& world, const std::string& from,
                        const std::string& to) {
    if (from == to) {
        const auto* a = world.get("symbol_defined." + from);
        return a && a->value == "1" && a->state == EpistemicState::Real;
    }
    std::unordered_map<std::string, std::vector<std::string>> adj;
    for (const auto& kv : world.atoms()) {
        const auto& k = kv.first;
        if (k.rfind("call.", 0) != 0) continue;
        if (kv.second.value != "1") continue;
        // call.<from>.<to>
        const size_t a = 5;
        const size_t dot = k.find('.', a);
        if (dot == std::string::npos) continue;
        adj[k.substr(a, dot - a)].push_back(k.substr(dot + 1));
    }
    std::queue<std::string> q;
    std::unordered_set<std::string> seen;
    q.push(from); seen.insert(from);
    while (!q.empty()) {
        auto u = q.front(); q.pop();
        if (u == to) return true;
        for (const auto& v : adj[u]) {
            if (seen.insert(v).second) q.push(v);
        }
    }
    return false;
}

CodeWorldStats ObserveCodeWorld(World& world, const std::string& repoRoot) {
    CodeWorldStats st{};
    auto& g = world.graph();
    std::unordered_map<std::string, uint64_t> ids;
    std::unordered_set<std::string> filesSeen;

    for (const auto& s : kSyms) {
        const std::string path = repoRoot + "/" + s.relPath;
        const std::string text = Slurp(path);
        if (filesSeen.insert(path).second && !text.empty()) {
            ++st.files;
            W0::KnowledgeNode fn;
            fn.kind = W0::NodeKind::File;
            fn.name = s.relPath;
            fn.content = path;
            fn.provenance = {"code_world", 0, W0::VerificationLevel::SourceCode};
            g.addNode(std::move(fn), W0::KnowledgeScope::Project);
        }
        const bool def = !text.empty() && HasToken(text, s.name);
        const std::string key = std::string("symbol_defined.") + s.name;
        if (def) {
            PutReal(world, key, "1", std::string("src:") + s.relPath);
            ++st.symbols;
            W0::KnowledgeNode sn;
            sn.kind = W0::NodeKind::Function;
            sn.name = s.name;
            sn.content = s.relPath;
            sn.provenance = {"code_world", 0, W0::VerificationLevel::SourceCode};
            ids[s.name] = g.addNode(std::move(sn), W0::KnowledgeScope::Project);
        } else {
            PutNeg(world, key, EpistemicState::NotPresent, "0",
                   std::string("src:") + s.relPath);
        }
    }

    for (const auto& e : kEdges) {
        const std::string path = repoRoot + "/" + e.inFile;
        const std::string text = Slurp(path);
        const bool ok = HasToken(text, e.from) && HasToken(text, e.to);
        const std::string key =
            std::string("call.") + e.from + "." + e.to;
        if (ok) {
            PutReal(world, key, "1", std::string("src:") + e.inFile);
            ++st.callEdges;
            auto itF = ids.find(e.from), itT = ids.find(e.to);
            if (itF != ids.end() && itT != ids.end()) {
                W0::KnowledgeEdge ke;
                ke.from = itF->second; ke.to = itT->second;
                ke.relation = W0::Relation::Calls;
                ke.sourceId = e.inFile;
                g.addEdge(ke);
            }
        } else {
            PutNeg(world, key, EpistemicState::NotObserved, "0",
                   std::string("src:") + e.inFile);
        }
    }

    // Reachability recipes (Derived from REAL call edges).
    auto mark = [&](const char* from, const char* to, const char* atomKey) {
        if (CodeWorldReachable(world, from, to)) {
            KnowledgeAtom a;
            a.key = atomKey; a.value = "1";
            a.state = EpistemicState::Derived;
            a.parents = {std::string("call.") + from + "." + to};
            a.source = "recipe:reachable";
            world.putAtom(a);
            ++st.reachable;
        } else {
            PutNeg(world, atomKey, EpistemicState::NotReachable, "0",
                   "recipe:reachable");
            ++st.notReachable;
        }
    };
    mark("generate", "LivePath_BeginGenerate",
         "symbol_reachable_from_generate.LivePath_BeginGenerate");
    mark("generate", "K2LivePolicy_Apply",
         "symbol_reachable_from_generate.K2LivePolicy_Apply");
    mark("runK2NativeStreamPartial", "LivePath_BeginGenerate",
         "symbol_reachable_from_stream.LivePath_BeginGenerate");
    mark("generate", "FakeRemoteInfer",
         "symbol_reachable_from_generate.FakeRemoteInfer");

    PutReal(world, "code_world_ingested", "1", "code_world");
    PutReal(world, "code_world_files", std::to_string(st.files), "code_world");
    PutReal(world, "code_world_symbols", std::to_string(st.symbols), "code_world");
    PutReal(world, "code_world_call_edges", std::to_string(st.callEdges),
            "code_world");
    return st;
}

} // namespace RKC
} // namespace RawrXD
