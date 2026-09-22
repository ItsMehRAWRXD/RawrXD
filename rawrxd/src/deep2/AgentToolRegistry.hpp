#pragma once
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cctype>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace RawrXD::Agentic {

// Forward-declared counters defined in AgentToolAuthority.cpp
extern std::atomic<uint64_t> g_agentToolInvocations;
extern std::atomic<uint64_t> g_directAgentToolBypasses;

// Forward-declared authority state (defined in AgentToolAuthority.cpp)
bool IsAgentToolAuthorityBound() noexcept;

enum class AgentToolSurface : uint8_t {
    Unknown = 0,
    CLI,
    GUI,
    Headless,
    AgentCore,
    LocalServer
};

struct AgentToolAuthoritySnapshot {
    uint64_t dispatch_count = 0;
    uint64_t cli_dispatch_count = 0;
    uint64_t gui_dispatch_count = 0;
    uint64_t headless_dispatch_count = 0;
    uint64_t agent_core_dispatch_count = 0;
    uint64_t local_server_dispatch_count = 0;
    uint64_t failed_dispatch_count = 0;
    uint64_t rejected_tool_count = 0;
    uint64_t registry_invocations = 0;    // via AgentToolRegistry::invoke() boundary
    uint64_t successful_invocations = 0;
    uint64_t direct_bypasses = 0;       // detected direct system/process calls
    uint64_t legacy_bypasses = 0;       // legacy registry / direct spawn bypasses

    uint64_t file_calls = 0;
    uint64_t search_calls = 0;
    uint64_t shell_calls = 0;
    uint64_t build_calls = 0;
    uint64_t test_calls = 0;
    uint64_t git_calls = 0;
    uint64_t process_calls = 0;
};

/// RAWRXD_AGENT_TOOL_AUTHORITY_003 — Surface-level authority receipt.
/// Produced after each certification pass; captures all counters required
/// for end-to-end Tool Authority provenance.
struct AgentToolAuthorityReceipt {
    std::string surface;       // HEADLESS / CLI / IDE
    std::string workflow_id;

    uint64_t registry_invocations = 0;
    uint64_t successful_invocations = 0;
    uint64_t failed_invocations = 0;

    uint64_t file_calls = 0;
    uint64_t search_calls = 0;
    uint64_t shell_calls = 0;
    uint64_t build_calls = 0;
    uint64_t test_calls = 0;
    uint64_t git_calls = 0;
    uint64_t process_calls = 0;

    uint64_t direct_agent_bypasses = 0;
    uint64_t legacy_bypasses = 0;

    bool authority_bound = false;
    bool fail_closed = false;

    bool result_pass = false;
};

struct ToolRequest {
    uint64_t run_id = 0;
    uint64_t action_id = 0;
    AgentToolSurface surface = AgentToolSurface::Unknown;
    std::string tool_id;
    std::vector<std::string> args;
    std::string stdin_text;
    std::filesystem::path working_directory;
};

struct ToolResult {
    int exit_code = 0;
    std::string stdout_text;
    std::string stderr_text;

    bool ok() const noexcept { return exit_code == 0; }
};

struct ToolContext {
    std::function<bool()> cancelled;
};

struct ToolDescriptor {
    std::string id;
    std::vector<std::string> aliases;
    std::string description;
};

class AgentToolRegistry {
public:
    using Handler = std::function<ToolResult(const ToolRequest&, ToolContext&)>;

    void registerTool(ToolDescriptor descriptor, Handler handler) {
        if (!handler) throw std::invalid_argument("tool handler is empty");
        descriptor.id = canonicalId(descriptor.id);
        if (descriptor.id.empty()) throw std::invalid_argument("tool id is empty");

        std::unique_lock lock(mu_);
        if (entries_.contains(descriptor.id) || aliases_.contains(descriptor.id))
            throw std::invalid_argument("duplicate tool id: " + descriptor.id);

        std::vector<std::string> canonical_aliases;
        canonical_aliases.reserve(descriptor.aliases.size());
        for (const auto& alias : descriptor.aliases) {
            auto a = canonicalId(alias);
            if (a.empty() || a == descriptor.id) continue;
            if (entries_.contains(a) || aliases_.contains(a))
                throw std::invalid_argument("duplicate tool alias: " + a);
            canonical_aliases.push_back(std::move(a));
        }

        Entry entry{descriptor, std::move(handler)};
        entry.descriptor.aliases = canonical_aliases;
        entries_.emplace(entry.descriptor.id, std::move(entry));
        for (const auto& alias : canonical_aliases) aliases_.emplace(alias, descriptor.id);
    }

    bool unregisterTool(std::string_view id) {
        auto key = canonicalId(id);
        std::unique_lock lock(mu_);
        if (auto a = aliases_.find(key); a != aliases_.end()) key = a->second;
        auto it = entries_.find(key);
        if (it == entries_.end()) return false;
        for (const auto& alias : it->second.descriptor.aliases) aliases_.erase(alias);
        entries_.erase(it);
        return true;
    }

    bool contains(std::string_view id) const {
        const auto key = canonicalId(id);
        std::shared_lock lock(mu_);
        return entries_.contains(key) || aliases_.contains(key);
    }

    std::optional<ToolDescriptor> describe(std::string_view id) const {
        auto key = canonicalId(id);
        std::shared_lock lock(mu_);
        if (auto a = aliases_.find(key); a != aliases_.end()) key = a->second;
        auto it = entries_.find(key);
        if (it == entries_.end()) return std::nullopt;
        return it->second.descriptor;
    }

    std::vector<ToolDescriptor> list() const {
        std::shared_lock lock(mu_);
        std::vector<ToolDescriptor> out;
        out.reserve(entries_.size());
        for (const auto& [_, entry] : entries_) out.push_back(entry.descriptor);
        std::sort(out.begin(), out.end(), [](const auto& a, const auto& b){ return a.id < b.id; });
        return out;
    }

    ToolResult invoke(ToolRequest request, ToolContext context) const {
        dispatch_count_.fetch_add(1, std::memory_order_relaxed);
        accountSurface(request.surface);
        g_agentToolInvocations.fetch_add(1, std::memory_order_relaxed);

        auto fail = [this](ToolResult r) {
            failed_dispatch_count_.fetch_add(1, std::memory_order_relaxed);
            return r;
        };

        auto key = canonicalId(request.tool_id);
        Handler handler;
        std::string resolved_id;
        {
            std::shared_lock lock(mu_);
            if (auto a = aliases_.find(key); a != aliases_.end()) key = a->second;
            auto it = entries_.find(key);
            if (it == entries_.end()) {
                rejected_tool_count_.fetch_add(1, std::memory_order_relaxed);
                ToolResult r;
                r.exit_code = 127;
                r.stderr_text = "unregistered tool: " + request.tool_id;
                return fail(std::move(r));
            }
            handler = it->second.handler;
            resolved_id = it->second.descriptor.id;
        }

        request.tool_id = std::move(resolved_id);
        accountToolType(request.tool_id);
        if (context.cancelled && context.cancelled()) {
            ToolResult r;
            r.exit_code = 130;
            r.stderr_text = "tool dispatch cancelled";
            return fail(std::move(r));
        }

        try {
            ToolResult r = handler(request, context);
            if (!r.ok()) {
                failed_dispatch_count_.fetch_add(1, std::memory_order_relaxed);
            } else {
                successful_invocations_.fetch_add(1, std::memory_order_relaxed);
            }
            return r;
        } catch (const std::exception& e) {
            ToolResult r;
            r.exit_code = 125;
            r.stderr_text = std::string("tool threw exception: ") + e.what();
            return fail(std::move(r));
        } catch (...) {
            ToolResult r;
            r.exit_code = 125;
            r.stderr_text = "tool threw unknown exception";
            return fail(std::move(r));
        }
    }

    AgentToolAuthoritySnapshot authoritySnapshot() const noexcept {
        AgentToolAuthoritySnapshot s;
        s.dispatch_count = dispatch_count_.load(std::memory_order_relaxed);
        s.cli_dispatch_count = cli_dispatch_count_.load(std::memory_order_relaxed);
        s.gui_dispatch_count = gui_dispatch_count_.load(std::memory_order_relaxed);
        s.headless_dispatch_count = headless_dispatch_count_.load(std::memory_order_relaxed);
        s.agent_core_dispatch_count = agent_core_dispatch_count_.load(std::memory_order_relaxed);
        s.local_server_dispatch_count = local_server_dispatch_count_.load(std::memory_order_relaxed);
        s.failed_dispatch_count = failed_dispatch_count_.load(std::memory_order_relaxed);
        s.rejected_tool_count = rejected_tool_count_.load(std::memory_order_relaxed);
        s.registry_invocations = g_agentToolInvocations.load(std::memory_order_relaxed);
        s.successful_invocations = successful_invocations_.load(std::memory_order_relaxed);
        s.direct_bypasses = g_directAgentToolBypasses.load(std::memory_order_relaxed);
        s.legacy_bypasses = legacy_bypasses_.load(std::memory_order_relaxed);
        s.file_calls = file_calls_.load(std::memory_order_relaxed);
        s.search_calls = search_calls_.load(std::memory_order_relaxed);
        s.shell_calls = shell_calls_.load(std::memory_order_relaxed);
        s.build_calls = build_calls_.load(std::memory_order_relaxed);
        s.test_calls = test_calls_.load(std::memory_order_relaxed);
        s.git_calls = git_calls_.load(std::memory_order_relaxed);
        s.process_calls = process_calls_.load(std::memory_order_relaxed);
        return s;
    }

    void resetAuthorityMetrics() noexcept {
        dispatch_count_.store(0, std::memory_order_relaxed);
        cli_dispatch_count_.store(0, std::memory_order_relaxed);
        gui_dispatch_count_.store(0, std::memory_order_relaxed);
        headless_dispatch_count_.store(0, std::memory_order_relaxed);
        agent_core_dispatch_count_.store(0, std::memory_order_relaxed);
        local_server_dispatch_count_.store(0, std::memory_order_relaxed);
        failed_dispatch_count_.store(0, std::memory_order_relaxed);
        rejected_tool_count_.store(0, std::memory_order_relaxed);
        g_agentToolInvocations.store(0, std::memory_order_relaxed);
        g_directAgentToolBypasses.store(0, std::memory_order_relaxed);
        successful_invocations_.store(0, std::memory_order_relaxed);
        legacy_bypasses_.store(0, std::memory_order_relaxed);
        file_calls_.store(0, std::memory_order_relaxed);
        search_calls_.store(0, std::memory_order_relaxed);
        shell_calls_.store(0, std::memory_order_relaxed);
        build_calls_.store(0, std::memory_order_relaxed);
        test_calls_.store(0, std::memory_order_relaxed);
        git_calls_.store(0, std::memory_order_relaxed);
        process_calls_.store(0, std::memory_order_relaxed);
    }

    AgentToolAuthorityReceipt toReceipt(std::string_view surface, std::string_view workflow_id) const {
        const AgentToolAuthoritySnapshot s = authoritySnapshot();
        AgentToolAuthorityReceipt r;
        r.surface = surface;
        r.workflow_id = workflow_id;
        r.registry_invocations = s.registry_invocations;
        r.successful_invocations = s.successful_invocations;
        r.failed_invocations = s.failed_dispatch_count;
        r.file_calls = s.file_calls;
        r.search_calls = s.search_calls;
        r.shell_calls = s.shell_calls;
        r.build_calls = s.build_calls;
        r.test_calls = s.test_calls;
        r.git_calls = s.git_calls;
        r.process_calls = s.process_calls;
        r.direct_agent_bypasses = s.direct_bypasses;
        r.legacy_bypasses = s.legacy_bypasses;
        r.authority_bound = IsAgentToolAuthorityBound();
        r.fail_closed = true; // Product build requires bound authority; unbound path throws.
        r.result_pass = (s.direct_bypasses == 0 && s.legacy_bypasses == 0 && r.authority_bound);
        return r;
    }

    static std::filesystem::path resolveExecutable(
        const std::filesystem::path& configured,
        const std::vector<std::filesystem::path>& search_roots) {
        if (configured.empty()) throw std::invalid_argument("empty executable path");

        auto validate = [](const std::filesystem::path& p) -> std::optional<std::filesystem::path> {
            std::error_code ec;
            const auto canonical = std::filesystem::weakly_canonical(p, ec);
            if (ec || canonical.empty()) return std::nullopt;
            if (!std::filesystem::exists(canonical, ec) || ec) return std::nullopt;
            if (!std::filesystem::is_regular_file(canonical, ec) || ec) return std::nullopt;
            return canonical;
        };

        if (configured.is_absolute()) {
            if (auto p = validate(configured)) return *p;
            throw std::runtime_error("configured tool executable does not exist: " + configured.string());
        }

        for (const auto& root : search_roots) {
            if (root.empty()) continue;
            if (auto p = validate(root / configured)) return *p;
        }

        throw std::runtime_error("unable to resolve tool executable: " + configured.string());
    }

    static std::string canonicalId(std::string_view raw) {
        size_t first = 0;
        while (first < raw.size() && std::isspace(static_cast<unsigned char>(raw[first]))) ++first;
        size_t last = raw.size();
        while (last > first && std::isspace(static_cast<unsigned char>(raw[last - 1]))) --last;
        std::string out;
        out.reserve(last - first);
        bool sep = false;
        for (size_t i = first; i < last; ++i) {
            unsigned char c = static_cast<unsigned char>(raw[i]);
            if (c == '/' || c == '\\' || c == ':' || c == '.' || c == '_' || c == '-' || std::isspace(c)) {
                if (!out.empty()) sep = true;
                continue;
            }
            if (sep) { out.push_back('-'); sep = false; }
            out.push_back(static_cast<char>(std::tolower(c)));
        }
        while (!out.empty() && out.back() == '-') out.pop_back();
        return out;
    }

private:
    void accountSurface(AgentToolSurface surface) const noexcept {
        switch (surface) {
            case AgentToolSurface::CLI:
                cli_dispatch_count_.fetch_add(1, std::memory_order_relaxed);
                break;
            case AgentToolSurface::GUI:
                gui_dispatch_count_.fetch_add(1, std::memory_order_relaxed);
                break;
            case AgentToolSurface::Headless:
                headless_dispatch_count_.fetch_add(1, std::memory_order_relaxed);
                break;
            case AgentToolSurface::AgentCore:
                agent_core_dispatch_count_.fetch_add(1, std::memory_order_relaxed);
                break;
            case AgentToolSurface::LocalServer:
                local_server_dispatch_count_.fetch_add(1, std::memory_order_relaxed);
                break;
            case AgentToolSurface::Unknown:
            default:
                break;
        }
    }

    struct Entry {
        ToolDescriptor descriptor;
        Handler handler;
    };

    mutable std::shared_mutex mu_;
    std::unordered_map<std::string, Entry> entries_;
    std::unordered_map<std::string, std::string> aliases_;

    mutable std::atomic<uint64_t> dispatch_count_{0};
    mutable std::atomic<uint64_t> cli_dispatch_count_{0};
    mutable std::atomic<uint64_t> gui_dispatch_count_{0};
    mutable std::atomic<uint64_t> headless_dispatch_count_{0};
    mutable std::atomic<uint64_t> agent_core_dispatch_count_{0};
    mutable std::atomic<uint64_t> local_server_dispatch_count_{0};
    mutable std::atomic<uint64_t> failed_dispatch_count_{0};
    mutable std::atomic<uint64_t> rejected_tool_count_{0};
    mutable std::atomic<uint64_t> successful_invocations_{0};
    mutable std::atomic<uint64_t> legacy_bypasses_{0};
    mutable std::atomic<uint64_t> file_calls_{0};
    mutable std::atomic<uint64_t> search_calls_{0};
    mutable std::atomic<uint64_t> shell_calls_{0};
    mutable std::atomic<uint64_t> build_calls_{0};
    mutable std::atomic<uint64_t> test_calls_{0};
    mutable std::atomic<uint64_t> git_calls_{0};
    mutable std::atomic<uint64_t> process_calls_{0};

    void accountToolType(const std::string& tool_id) const noexcept {
        if (tool_id == "read-file" || tool_id == "write-file" || tool_id == "list-dir" || tool_id == "workspace.list" || tool_id == "file.read") {
            file_calls_.fetch_add(1, std::memory_order_relaxed);
        } else if (tool_id == "code.search" || tool_id == "symbol.find" || tool_id == "symbol.references") {
            search_calls_.fetch_add(1, std::memory_order_relaxed);
        } else if (tool_id == "run-shell" || tool_id == "run-command") {
            shell_calls_.fetch_add(1, std::memory_order_relaxed);
        } else if (tool_id == "build.target" || tool_id == "build.project") {
            build_calls_.fetch_add(1, std::memory_order_relaxed);
        } else if (tool_id == "test.run" || tool_id == "test.suite") {
            test_calls_.fetch_add(1, std::memory_order_relaxed);
        } else if (tool_id.rfind("git.", 0) == 0) {
            git_calls_.fetch_add(1, std::memory_order_relaxed);
        } else if (tool_id == "process.spawn" || tool_id == "process.exec") {
            process_calls_.fetch_add(1, std::memory_order_relaxed);
        }
    }
};

} // namespace RawrXD::Agentic
