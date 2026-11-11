#pragma once
// =============================================================================
// project_wizard.hpp — RawrXD Project Wizard interview
//
// Interactive, question-by-question project intake (stdin/stdout) plus a
// fully noninteractive flag-driven path. Both produce the same ProjectSpec,
// which the ProjectStateManager durably stores so model rotation never loses
// the work.
// =============================================================================
#ifndef RAWRXD_PROJECT_WIZARD_HPP
#define RAWRXD_PROJECT_WIZARD_HPP

#include "project_spec.hpp"

#include <map>
#include <string>
#include <vector>

namespace rawrxd {
namespace project {

// ---------------------------------------------------------------------------
// All interview answers, populated either interactively or from CLI flags
// ---------------------------------------------------------------------------

struct WizardAnswers {
    std::string name;             // required
    std::string idea;             // required
    ProjectType type = ProjectType::kUnknown;
    Language language = Language::kUnknown;
    BuildSystem build_system = BuildSystem::kUnknown;
    AutonomyLevel autonomy = AutonomyLevel::kUnknown;
    std::string framework;
    std::string platform;
    std::vector<std::string> dependencies;
    std::vector<std::string> tests;
    std::string architecture;
    std::vector<std::string> acceptance_criteria;
};

// ---------------------------------------------------------------------------
// Wizard — runs the interview and builds a ProjectSpec
// ---------------------------------------------------------------------------

class Wizard {
public:
    // io: if non-null, used to read a line (interactive). If null, the wizard
    // is noninteractive and every answer must come from `flags`.
    using ReadLine = std::function<bool(std::string& out)>;

    Wizard(std::string workspace_root, ReadLine read_line = nullptr,
           std::map<std::string, std::string> flags = {});

    // Run the interview. Returns the completed spec, or an empty project_id
    // when input is incomplete / cancelled.
    ProjectSpec Run();

    // Noninteractive: build a spec purely from flags (no stdin interaction).
    static ProjectSpec BuildFromFlags(const std::map<std::string, std::string>& flags);

    // Print a human-readable spec preview (the "specification preview").
    static void PrintPreview(const ProjectSpec& spec);

    const std::string& WorkspaceRoot() const { return workspace_root_; }

private:
    bool AskRequired(std::string& out, const std::string& prompt);
    bool AskChoice(std::string& out, const std::string& prompt,
                   const std::vector<std::string>& options);
    bool AskOptional(std::string& out, const std::string& prompt);
    bool AskList(std::vector<std::string>& out, const std::string& prompt);

    bool Flag(const std::string& key, std::string& out) const;
    static bool FlagList(const std::map<std::string, std::string>& flags,
                         const std::string& key,
                         std::vector<std::string>& out);

    std::string PromptLine(const std::string& prompt);
    std::string Trim(const std::string& s) const;

    std::string workspace_root_;
    ReadLine read_line_;
    std::map<std::string, std::string> flags_;
    bool noninteractive_ = false;
};

// ---------------------------------------------------------------------------
// Convenience: parse wizard-specific flags out of a raw `rawr run` arg list.
// Returns the flags map plus whether "new project" was requested.
// ---------------------------------------------------------------------------

struct WizardCli {
    bool is_new_project = false;
    bool is_follow_up = false;
    FollowUp follow_up{};            // valid when is_follow_up
    std::map<std::string, std::string> flags;
    std::string model;
};

WizardCli ParseWizardCli(int argc, char** argv);

} // namespace project
} // namespace rawrxd

#endif // RAWRXD_PROJECT_WIZARD_HPP
