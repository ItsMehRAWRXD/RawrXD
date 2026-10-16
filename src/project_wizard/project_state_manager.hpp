#pragma once
// =============================================================================
// project_state_manager.hpp — Durable project storage for the RawrXD Wizard
//
// Every project lives under .rawr/projects/<project_id>/:
//
//   spec.json        — the project specification (model-rotation safe)
//   state.json       — durable progress (stage, build/test results, ESP metrics)
//   plan.json        — generated implementation plan + acceptance criteria
//   esp.jsonl        — ESP telemetry events (inference TPS, tool calls, builds)
//   history.jsonl    — conversation / follow-up history
//
// A top-level index.json maps project_id -> entry so a session can resume any
// project regardless of which model (or cloud model rotation) launched it.
// =============================================================================
#ifndef RAWRXD_PROJECT_STATE_MANAGER_HPP
#define RAWRXD_PROJECT_STATE_MANAGER_HPP

#include "project_spec.hpp"

#include <string>
#include <vector>

namespace rawrxd {
namespace project {

class ProjectStateManager {
public:
    // Root is the workspace root; projects live at <root>/.rawr/projects/.
    explicit ProjectStateManager(std::string workspace_root);

    // ---- Project lifecycle -------------------------------------------------

    // Create a new project directory and write its initial spec. Returns the
    // project id. Fails (empty id) if a project with the same name already
    // exists in this workspace.
    std::string CreateProject(const ProjectSpec& spec);

    // Load an existing project's spec + state. Returns false if absent.
    bool LoadProject(const std::string& project_id,
                     ProjectSpec& out_spec,
                     ProjectState& out_state) const;

    // Save (create or overwrite) spec and state, atomically, and touch the
    // project index. Returns true on success.
    bool SaveSpec(const std::string& project_id, const ProjectSpec& spec);
    bool SaveState(const std::string& project_id, const ProjectState& state);
    bool SavePlan(const std::string& project_id, const json& plan);

    // Append a single ESP telemetry event line to the project's esp.jsonl.
    bool AppendEspEvent(const std::string& project_id, const json& event);

    // Append a history line (conversation turn or follow-up) to history.jsonl.
    bool AppendHistory(const std::string& project_id, const json& event);

    // List all known projects in this workspace (most recent first).
    std::vector<ProjectIndexEntry> ListProjects() const;

    // Resolve project id -> absolute directory.
    std::string ProjectDir(const std::string& project_id) const;

    const std::string& WorkspaceRoot() const { return workspace_root_; }

private:
    bool EnsureProjectDir(const std::string& project_id) const;
    bool LoadIndex(std::vector<ProjectIndexEntry>& out) const;
    bool SaveIndex(const std::vector<ProjectIndexEntry>& entries) const;
    static std::string WriteAtomically(const std::string& path, const std::string& content);

    std::string workspace_root_;
};

} // namespace project
} // namespace rawrxd

#endif // RAWRXD_PROJECT_STATE_MANAGER_HPP
