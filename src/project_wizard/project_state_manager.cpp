// =============================================================================
// project_state_manager.cpp — Durable project storage
// =============================================================================
#include "project_state_manager.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace rawrxd {
namespace project {

namespace fs = std::filesystem;

namespace {

std::string ProjectSubdir(const std::string& root, const std::string& project_id) {
    return (fs::path(root) / ".rawr" / "projects" / project_id).string();
}

std::string ReadFileOrEmpty(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return std::string();
    return {std::istreambuf_iterator<char>(f), {}};
}

} // namespace

ProjectStateManager::ProjectStateManager(std::string workspace_root)
    : workspace_root_(std::move(workspace_root)) {}

std::string ProjectStateManager::CreateProject(const ProjectSpec& spec) {
    namespace fs = std::filesystem;
    // Reject duplicate names.
    auto existing = ListProjects();
    for (const auto& e : existing)
        if (e.name == spec.name) return std::string();

    std::string id = spec.project_id.empty()
        ? std::string("proj_") + detail::Hex(detail::Fnv1a(spec.name + "|" + spec.created_at))
        : spec.project_id;

    if (!EnsureProjectDir(id)) return std::string();

    ProjectSpec mutable_spec = spec;
    mutable_spec.project_id = id;
    mutable_spec.updated_at = mutable_spec.created_at;

    fs::path dir = fs::path(workspace_root_) / ".rawr" / "projects" / id;
    if (!SaveSpec(id, mutable_spec)) return std::string();

    ProjectState state;
    state.project_id = id;
    state.stage = ProjectStage::kInterview;
    state.updated_at = mutable_spec.created_at;
    if (!SaveState(id, state)) return std::string();

    // Touch the index.
    auto entries = ListProjects();
    ProjectIndexEntry entry;
    entry.project_id = id;
    entry.name = mutable_spec.name;
    entry.path = dir.string();
    entry.stage = ProjectStage::kInterview;
    entry.updated_at = mutable_spec.created_at;
    entry.language = LanguageName(mutable_spec.language);
    entry.build_system = BuildSystemName(mutable_spec.build_system);
    entries.push_back(entry);
    SaveIndex(entries);

    return id;
}

bool ProjectStateManager::LoadProject(const std::string& project_id,
                                      ProjectSpec& out_spec,
                                      ProjectState& out_state) const {
    fs::path dir = fs::path(workspace_root_) / ".rawr" / "projects" / project_id;
    std::string spec_text = ReadFileOrEmpty((dir / "spec.json").string());
    std::string state_text = ReadFileOrEmpty((dir / "state.json").string());
    if (spec_text.empty() || state_text.empty()) return false;
    try {
        out_spec = ProjectSpec::FromJson(spec_text);
        out_state = ProjectState::FromJson(state_text);
        return true;
    } catch (...) {
        return false;
    }
}

bool ProjectStateManager::SaveSpec(const std::string& project_id, const ProjectSpec& spec) {
    if (!EnsureProjectDir(project_id)) return false;
    fs::path path = fs::path(workspace_root_) / ".rawr" / "projects" / project_id / "spec.json";
    return !WriteAtomically(path.string(), spec.ToJsonString()).empty();
}

bool ProjectStateManager::SaveState(const std::string& project_id, const ProjectState& state) {
    if (!EnsureProjectDir(project_id)) return false;
    fs::path path = fs::path(workspace_root_) / ".rawr" / "projects" / project_id / "state.json";
    return !WriteAtomically(path.string(), state.ToJsonString()).empty();
}

bool ProjectStateManager::SavePlan(const std::string& project_id, const json& plan) {
    if (!EnsureProjectDir(project_id)) return false;
    fs::path path = fs::path(workspace_root_) / ".rawr" / "projects" / project_id / "plan.json";
    return !WriteAtomically(path.string(), plan.dump(2)).empty();
}

bool ProjectStateManager::AppendEspEvent(const std::string& project_id, const json& event) {
    if (!EnsureProjectDir(project_id)) return false;
    fs::path path = fs::path(workspace_root_) / ".rawr" / "projects" / project_id / "esp.jsonl";
    std::ofstream f(path, std::ios::out | std::ios::app | std::ios::binary);
    if (!f) return false;
    f << event.dump() << "\n";
    f.flush();
    return f.good();
}

bool ProjectStateManager::AppendHistory(const std::string& project_id, const json& event) {
    if (!EnsureProjectDir(project_id)) return false;
    fs::path path = fs::path(workspace_root_) / ".rawr" / "projects" / project_id / "history.jsonl";
    std::ofstream f(path, std::ios::out | std::ios::app | std::ios::binary);
    if (!f) return false;
    f << event.dump() << "\n";
    f.flush();
    return f.good();
}

std::vector<ProjectIndexEntry> ProjectStateManager::ListProjects() const {
    std::vector<ProjectIndexEntry> entries;
    fs::path index_path = fs::path(workspace_root_) / ".rawr" / "projects" / "index.json";
    std::string text = ReadFileOrEmpty(index_path.string());
    if (text.empty()) return entries;
    try {
        json arr = json::parse(text);
        if (!arr.is_array()) return entries;
        for (const auto& e : arr) entries.push_back(ProjectIndexEntry::FromJson(e));
    } catch (...) {
        return entries;
    }
    std::sort(entries.begin(), entries.end(),
              [](const ProjectIndexEntry& a, const ProjectIndexEntry& b) {
                  return a.updated_at > b.updated_at;
              });
    return entries;
}

std::string ProjectStateManager::ProjectDir(const std::string& project_id) const {
    return ProjectSubdir(workspace_root_, project_id);
}

bool ProjectStateManager::EnsureProjectDir(const std::string& project_id) const {
    std::error_code ec;
    fs::create_directories(fs::path(workspace_root_) / ".rawr" / "projects" / project_id, ec);
    return !ec;
}

bool ProjectStateManager::LoadIndex(std::vector<ProjectIndexEntry>& out) const {
    fs::path index_path = fs::path(workspace_root_) / ".rawr" / "projects" / "index.json";
    std::string text = ReadFileOrEmpty(index_path.string());
    if (text.empty()) return true;
    try {
        json arr = json::parse(text);
        if (!arr.is_array()) return false;
        out.clear();
        for (const auto& e : arr) out.push_back(ProjectIndexEntry::FromJson(e));
        return true;
    } catch (...) {
        return false;
    }
}

bool ProjectStateManager::SaveIndex(const std::vector<ProjectIndexEntry>& entries) const {
    fs::path dir = fs::path(workspace_root_) / ".rawr" / "projects";
    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) return false;
    json arr = json::array();
    for (const auto& e : entries) arr.push_back(e.ToJson());
    return !WriteAtomically((dir / "index.json").string(), arr.dump(2)).empty();
}

std::string ProjectStateManager::WriteAtomically(const std::string& path, const std::string& content) {
    fs::path p(path);
    if (!fs::exists(p.parent_path())) {
        std::error_code ec;
        fs::create_directories(p.parent_path(), ec);
        if (ec) return std::string();
    }
    fs::path tmp = p;
    tmp += ".rawr_tmp";
    std::error_code ec;
    fs::remove(tmp, ec);
    {
        std::ofstream o(tmp, std::ios::binary | std::ios::trunc);
        if (!o) return std::string();
        o.write(content.data(), static_cast<std::streamsize>(content.size()));
        o.flush();
        if (!o) { fs::remove(tmp, ec); return std::string(); }
    }
#ifdef _WIN32
    if (fs::exists(p)) {
        if (!ReplaceFileW(p.c_str(), tmp.c_str(), nullptr, REPLACEFILE_IGNORE_MERGE_ERRORS, nullptr, nullptr)) {
            fs::remove(tmp, ec);
            return std::string();
        }
    } else {
        fs::rename(tmp, p, ec);
        if (ec) { fs::remove(tmp, ec); return std::string(); }
    }
#else
    fs::rename(tmp, p, ec);
    if (ec) { fs::remove(tmp, ec); return std::string(); }
#endif
    return path;
}

} // namespace project
} // namespace rawrxd
