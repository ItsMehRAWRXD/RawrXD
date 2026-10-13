#include "native_agent_bridge.hpp"
#include <algorithm>
#include <fstream>
#include <iterator>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace RawrXD::NativeBridge {
bool ToolRegistry::registerTool(std::string name, Tool tool) {
    if (name.empty() || !tool) return false;
    std::lock_guard<std::mutex> lock(mu_);
    return tools_.emplace(std::move(name), std::move(tool)).second;
}
Result ToolRegistry::execute(const std::string& name, const std::vector<std::string>& args,
                             const std::atomic<bool>& cancel) const {
    if (cancel.load()) return {false, {}, "cancelled"};
    Tool fn;
    { std::lock_guard<std::mutex> lock(mu_);
      auto it = tools_.find(name);
      if (it == tools_.end()) return {false, {}, "unknown tool: " + name};
      fn = it->second;
    }
    try { return fn(args, cancel); }
    catch (const std::exception& e) { return {false, {}, e.what()}; }
    catch (...) { return {false, {}, "unknown tool exception"}; }
}
std::vector<std::string> ToolRegistry::names() const {
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<std::string> result;
    for (const auto& item : tools_) result.push_back(item.first);
    return result;
}
bool Planner::add(Task task) {
    if (task.id.empty() || task.tool.empty()) return false;
    if (std::any_of(tasks_.begin(), tasks_.end(), [&](const Task& t){return t.id == task.id;})) return false;
    tasks_.push_back(std::move(task)); return true;
}
std::vector<TaskResult> Planner::execute(const ToolRegistry& tools, const std::atomic<bool>& cancel) const {
    std::vector<TaskResult> results;
    std::set<std::string> completed;
    std::set<std::string> attempted;
    while (attempted.size() < tasks_.size()) {
        if (cancel.load()) break;
        bool progressed = false;
        for (const auto& task : tasks_) {
            if (attempted.count(task.id)) continue;
            bool ready = std::all_of(task.dependencies.begin(), task.dependencies.end(),
                                     [&](const std::string& dep){return completed.count(dep) != 0;});
            if (!ready) continue;
            auto r = tools.execute(task.tool, task.args, cancel);
            attempted.insert(task.id);
            if (r.ok) completed.insert(task.id);
            results.push_back({task.id, std::move(r)});
            progressed = true;
            if (cancel.load()) break;
        }
        if (!progressed) break;
    }
    for (const auto& task : tasks_)
        if (!attempted.count(task.id)) results.push_back({task.id, {false, {}, cancel.load() ? "cancelled" : "dependency unavailable or failed"}});
    return results;
}
static bool validKey(const std::string& key) {
    return !key.empty() && key != "." && key != ".." &&
           std::all_of(key.begin(), key.end(), [](unsigned char c){
               return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '_' || c == '-';
           });
}
AgentMemory::AgentMemory(std::filesystem::path root) : root_(std::move(root)) {}
bool AgentMemory::save(const std::string& key, const std::string& value, std::string& error) const {
    if (!validKey(key)) { error = "invalid key"; return false; }
    std::error_code ec;
    std::filesystem::create_directories(root_, ec);
    if (ec) { error = ec.message(); return false; }
    auto path = root_ / (key + ".txt");
    auto tmp = root_ / (key + ".tmp");
    { std::ofstream file(tmp, std::ios::binary | std::ios::trunc);
      if (!file || !file.write(value.data(), static_cast<std::streamsize>(value.size()))) {
          error = "write failed"; return false;
      }
    }
    std::filesystem::rename(tmp, path, ec);
    if (ec) { error = ec.message(); std::filesystem::remove(tmp); return false; }
    return true;
}
std::optional<std::string> AgentMemory::load(const std::string& key, std::string& error) const {
    if (!validKey(key)) { error = "invalid key"; return std::nullopt; }
    std::ifstream file(root_ / (key + ".txt"), std::ios::binary);
    if (!file) { error = "not found"; return std::nullopt; }
    std::string data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (file.bad()) { error = "read failed"; return std::nullopt; }
    return data;
}
Result CEOAgent::plan(const std::string& goal, const std::atomic<bool>& cancel) const {
    if (cancel.load()) return {false, {}, "cancelled"};
    if (goal.empty()) return {false, {}, "empty goal"};
    if (!inference_) return {false, {}, "no inference provider configured"};
    return inference_("Produce a concrete dependency-ordered implementation plan for:\n" + goal, cancel);
}
std::string buildFIM(const std::string& prefix, const std::string& suffix,
                     const std::string& start, const std::string& middle, const std::string& end) {
    return start + prefix + middle + suffix + end;
}
static std::optional<std::filesystem::path> confined(const std::filesystem::path& root,
                                                       const std::string& relative) {
    auto rel = std::filesystem::path(relative);
    if (rel.empty() || rel.is_absolute() || rel.has_root_name()) return std::nullopt;
    for (const auto& part : rel) if (part == "..") return std::nullopt;
    std::error_code ec;
    auto base = std::filesystem::weakly_canonical(root, ec);
    if (ec) return std::nullopt;
    auto candidate = std::filesystem::weakly_canonical(base / rel, ec);
    if (ec) return std::nullopt;
    auto b = base.begin(), c = candidate.begin();
    for (; b != base.end(); ++b, ++c) if (c == candidate.end() || *b != *c) return std::nullopt;
    return candidate;
}
void registerFileTools(ToolRegistry& tools, std::filesystem::path workspace) {
    tools.registerTool("read_file", [workspace](const std::vector<std::string>& args, const std::atomic<bool>& cancel)->Result {
        if (args.size() != 1) return {false, {}, "read_file expects one path"};
        auto path = confined(workspace, args[0]);
        if (!path) return {false, {}, "path outside workspace"};
        std::ifstream f(*path, std::ios::binary);
        if (!f) return {false, {}, "file open failed"};
        std::string data;
        char buf[65536];
        while (f && !cancel.load()) {
            f.read(buf, sizeof(buf));
            data.append(buf, static_cast<size_t>(f.gcount()));
            if (data.size() > 16 * 1024 * 1024) return {false, {}, "file exceeds 16 MiB limit"};
        }
        if (cancel.load()) return {false, {}, "cancelled"};
        if (f.bad()) return {false, {}, "read failed"};
        return {true, std::move(data), {}};
    });
    tools.registerTool("list_files", [workspace](const std::vector<std::string>& args, const std::atomic<bool>& cancel)->Result {
        if (args.size() != 1) return {false, {}, "list_files expects one directory"};
        auto path = confined(workspace, args[0]);
        if (!path) return {false, {}, "path outside workspace"};
        std::error_code ec;
        std::ostringstream output;
        for (std::filesystem::directory_iterator it(*path, ec), end; !ec && it != end; it.increment(ec)) {
            if (cancel.load()) return {false, {}, "cancelled"};
            output << it->path().filename().string() << '\n';
        }
        if (ec) return {false, {}, ec.message()};
        return {true, output.str(), {}};
    });
}
}
