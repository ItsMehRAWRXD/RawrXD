#pragma once
// RawrXD Sovereign Agent Core — C++20, standard library only.
// Integrate with Deep2 by implementing ModelAdapter::next().
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rawrxd {
namespace fs = std::filesystem;

enum class DecisionKind { Final, Tool, Invalid };
struct ToolRequest { std::string name, path, query; };
struct Decision { DecisionKind kind = DecisionKind::Invalid; std::string answer; ToolRequest tool; };
struct Observation { std::string tool, path, query, output, error; bool executed=false, ok=false, cached=false; std::uint64_t receipt=0; };
struct Message { enum class Role { System, User, Assistant, Tool }; Role role; std::string content; };
struct AgentState { std::uint64_t id=0; std::vector<Message> history; std::vector<Observation> ledger; unsigned turns=0; };
struct Result { bool ok=false; std::string answer, error; AgentState state; };

// No model simulation: caller MUST supply a real Deep2-backed adapter.
struct ModelAdapter {
    virtual ~ModelAdapter() = default;
    virtual Decision next(const AgentState& state) = 0;
};

inline std::string ascii_lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
inline bool source_file(const fs::path& p) {
    static const std::set<std::string> extensions = {
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
        ".asm", ".inc", ".inl", ".ixx", ".cmake", ".bat", ".cmd", ".ps1"
    };
    return extensions.contains(ascii_lower(p.extension().string())) || p.filename() == "CMakeLists.txt";
}
inline bool ignored_directory(const fs::path& p) {
    const auto name = ascii_lower(p.filename().string());
    return name == ".git" || name == ".vs" || name == "node_modules" ||
           name == "__pycache__" || name == "cmakefiles" || name == "build" ||
           name == "build_test_suite" || name == "_build" || name == "dist" ||
           name == "debug" || name == "release";
}
inline bool within(const fs::path& root, const fs::path& candidate) {
    auto a = root.begin(), b = candidate.begin();
    for (; a != root.end(); ++a, ++b) if (b == candidate.end() || *a != *b) return false;
    return true;
}

class SourceSearch {
    fs::path root_;
    std::size_t maxFiles_, maxMatches_, maxFileBytes_;
public:
    explicit SourceSearch(fs::path root, std::size_t maxFiles=50000,
                          std::size_t maxMatches=200, std::size_t maxFileBytes=4*1024*1024)
        : root_(fs::weakly_canonical(std::move(root))), maxFiles_(maxFiles),
          maxMatches_(maxMatches), maxFileBytes_(maxFileBytes) {}
    const fs::path& root() const { return root_; }

    Observation search(const ToolRequest& req) const {
        Observation o; o.tool=req.name; o.path=req.path; o.query=req.query;
        o.executed=true;
        if (req.query.empty()) { o.error="empty search query"; return o; }
        if (req.query.size()>4096) { o.error="query too long"; return o; }
        std::error_code ec;
        fs::path relative(req.path);
        if (relative.is_absolute()) { o.error="absolute tool paths prohibited"; return o; }
        fs::path target=fs::weakly_canonical(root_/relative,ec);
        if (ec || !within(root_,target) || !fs::is_directory(target,ec)) {
            o.error="invalid or outside-root search directory"; return o;
        }
        std::size_t scanned=0, matches=0, unreadable=0;
        std::ostringstream found;
        fs::recursive_directory_iterator it(target,fs::directory_options::skip_permission_denied,ec), end;
        if (ec) { o.error="directory iteration failed: "+ec.message(); return o; }
        for (; it!=end; it.increment(ec)) {
            if (ec) { o.error="directory iteration failed: "+ec.message(); return o; }
            const fs::directory_entry& ent=*it;
            if (ent.is_symlink(ec)) { if (ent.is_directory(ec)) it.disable_recursion_pending(); continue; }
            if (ent.is_directory(ec)) { if (ignored_directory(ent.path())) it.disable_recursion_pending(); continue; }
            if (!ent.is_regular_file(ec) || !source_file(ent.path())) continue;
            if (++scanned>maxFiles_) { o.error="file scan limit reached"; return o; }
            const auto size=ent.file_size(ec);
            if (ec || size>maxFileBytes_) { ++unreadable; continue; }
            std::ifstream in(ent.path(),std::ios::binary);
            if (!in) { ++unreadable; continue; }
            std::string data((std::istreambuf_iterator<char>(in)),std::istreambuf_iterator<char>());
            if (in.bad()) { ++unreadable; continue; }
            if (data.find(req.query)!=std::string::npos) {
                ++matches;
                found << ent.path().lexically_relative(root_).generic_string() << '\n';
                if (matches>=maxMatches_) break;
            }
        }
        o.ok=true;
        std::ostringstream out;
        out << "query=" << req.query << "\nroot=" << target.string()
            << "\nfiles_scanned=" << scanned << "\nmatching_files=" << matches
            << "\nunreadable_or_oversize=" << unreadable << '\n' << found.str();
        if (matches>=maxMatches_) out << "[match limit reached]\n";
        o.output=out.str(); return o;
    }
};

class HostTools {
    SourceSearch search_;
    mutable std::mutex mu_;
    std::map<std::string,Observation> cache_;
    std::atomic<std::uint64_t> seq_{1};
public:
    explicit HostTools(fs::path workspace) : search_(std::move(workspace)) {}
    Observation invoke(const ToolRequest& req) {
        if (req.name!="search_text") {
            Observation o; o.tool=req.name; o.path=req.path; o.query=req.query;
            o.error="unknown or unauthorized tool"; return o;
        }
        // Length-prefix fields to avoid delimiter collisions. Cache scoped to HostTools instance.
        const auto part=[](const std::string& s){return std::to_string(s.size())+":"+s;};
        const std::string cacheKey=part(req.name)+part(req.path)+part(req.query);
        std::lock_guard<std::mutex> lock(mu_);
        if (auto it=cache_.find(cacheKey); it!=cache_.end()) {
            Observation copy=it->second; copy.cached=true; copy.executed=false; return copy;
        }
        Observation o=search_.search(req);
        o.receipt=seq_.fetch_add(1);
        if (o.ok) cache_.emplace(cacheKey,o);
        return o;
    }
    void invalidate() { std::lock_guard<std::mutex> lock(mu_); cache_.clear(); }
};

class AgentRunner {
    ModelAdapter& model_;
    HostTools& tools_;
    unsigned maxTurns_, maxToolCalls_;
public:
    AgentRunner(ModelAdapter& model, HostTools& tools, unsigned maxTurns=16,
                unsigned maxToolCalls=8)
        : model_(model), tools_(tools), maxTurns_(maxTurns), maxToolCalls_(maxToolCalls) {}
    Result run(AgentState state, const std::string& userPrompt) {
        state.history.push_back({Message::Role::User,userPrompt});
        unsigned toolCalls=0;
        for (unsigned turn=0; turn<maxTurns_; ++turn) {
            ++state.turns;
            Decision d;
            try { d=model_.next(state); }
            catch (const std::exception& e) { return {false,"",std::string("model failure: ")+e.what(),std::move(state)}; }
            if (d.kind==DecisionKind::Final) {
                if (d.answer.empty()) return {false,"","empty model answer",std::move(state)};
                state.history.push_back({Message::Role::Assistant,d.answer});
                return {true,d.answer,"",std::move(state)};
            }
            if (d.kind!=DecisionKind::Tool) return {false,"","invalid model decision",std::move(state)};
            if (++toolCalls>maxToolCalls_) return {false,"","tool-call budget exceeded",std::move(state)};
            Observation o=tools_.invoke(d.tool);
            state.ledger.push_back(o);
            std::ostringstream msg;
            msg << "tool=" << o.tool << " receipt=" << o.receipt
                << " executed=" << (o.executed?1:0) << " cached=" << (o.cached?1:0)
                << " ok=" << (o.ok?1:0) << '\n' << (o.ok?o.output:o.error);
            state.history.push_back({Message::Role::Tool,msg.str()});
            // Repeated identical cached requests cannot run indefinitely.
            if (o.cached) {
                state.history.push_back({Message::Role::System,
                    "Duplicate observation. Do not request this tool again with identical arguments; answer or change approach."});
            }
        }
        return {false,"","agent turn budget exceeded",std::move(state)};
    }
};

inline std::string evidence_summary(const AgentState& state) {
    std::ostringstream out;
    std::size_t executed=0, successful=0, cached=0;
    for (const auto& o : state.ledger) {
        if (o.executed) ++executed;
        if (o.executed && o.ok) ++successful;
        if (o.cached) ++cached;
    }
    out << "[host-evidence] executed=" << executed << " successful=" << successful
        << " cache_reuses=" << cached << '\n';
    for (const auto& o : state.ledger)
        if (o.executed) out << "[host-receipt] id=" << o.receipt << " tool=" << o.tool
                            << " ok=" << (o.ok?1:0) << '\n';
    return out.str();
}
} // namespace rawrxd
