#pragma once
// =============================================================================
// project_spec.hpp — RawrXD Project Wizard specification data model
//
// C++20, dependency-free beyond nlohmann/json (vendored). Describes a
// user's project intent (name, idea, type, language, build system, autonomy,
// framework, platform, dependencies, tests, architecture, acceptance criteria)
// plus a durable, model-rotation-safe project state.
//
// The spec is stored as JSON under .rawr/projects/<project_id>/spec.json and
// is deliberately decoupled from the model that produced it: switching
// models (including rotating OpenRouter free models) never loses the work.
// =============================================================================
#ifndef RAWRXD_PROJECT_SPEC_HPP
#define RAWRXD_PROJECT_SPEC_HPP

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace rawrxd {
namespace project {

// ---------------------------------------------------------------------------
// Detail helpers (FNV-1a 64-bit + hex), used by spec + state manager
// ---------------------------------------------------------------------------
namespace detail {

inline uint64_t Fnv1a(std::string_view s) {
    uint64_t h = 14695981039346656037ull;
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ull;
    }
    return h;
}
inline std::string Hex(uint64_t v) {
    std::ostringstream os;
    os << std::hex << std::setfill('0') << std::setw(16) << v;
    return os.str();
}

inline std::string StrLower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower((unsigned char)c));
    return s;
}

inline std::string NowIso8601() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec);
    return std::string(buf);
}

} // namespace detail

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// Enumerations (string-safe for JSON and CLI flag parsing)
// ---------------------------------------------------------------------------

enum class ProjectType {
    kDesktopApp,
    kCLITool,
    kWebApp,
    kGame,
    kLibrary,
    kUnknown
};

enum class Language {
    kCpp20,
    kRust,
    kPython,
    kCSharp,
    kTypeScript,
    kUnknown
};

enum class BuildSystem {
    kCMake,
    kMSBuild,
    kCargo,
    kOther,
    kUnknown
};

enum class AutonomyLevel {
    kAskBeforeChanges,
    kGenerateAndVerify,
    kAutonomousCheckpoints,
    kUnknown
};

enum class ProjectStage {
    kInterview,
    kPlanning,
    kScaffolding,
    kImplementing,
    kBuilding,
    kVerifying,
    kDone,
    kBlocked,
    kUnknown
};

inline const char* ProjectTypeName(ProjectType t) {
    switch (t) {
        case ProjectType::kDesktopApp: return "Desktop application";
        case ProjectType::kCLITool:    return "CLI tool";
        case ProjectType::kWebApp:     return "Web application";
        case ProjectType::kGame:       return "Game";
        case ProjectType::kLibrary:    return "Library / API";
        default:                       return "Unknown";
    }
}
inline ProjectType ProjectTypeFromString(const std::string& s) {
    std::string k = s; for (auto& c : k) c = static_cast<char>(std::tolower((unsigned char)c));
    if (k == "desktop application" || k == "desktop" || k == "gui") return ProjectType::kDesktopApp;
    if (k == "cli tool" || k == "cli" || k == "command-line") return ProjectType::kCLITool;
    if (k == "web application" || k == "web") return ProjectType::kWebApp;
    if (k == "game") return ProjectType::kGame;
    if (k == "library / api" || k == "library" || k == "api") return ProjectType::kLibrary;
    return ProjectType::kUnknown;
}

inline const char* LanguageName(Language l) {
    switch (l) {
        case Language::kCpp20:   return "C++20";
        case Language::kRust:    return "Rust";
        case Language::kPython:  return "Python";
        case Language::kCSharp:  return "C#";
        case Language::kTypeScript: return "TypeScript";
        default:                 return "Unknown";
    }
}
inline Language LanguageFromString(const std::string& s) {
    std::string k = s; for (auto& c : k) c = static_cast<char>(std::tolower((unsigned char)c));
    if (k == "c++20" || k == "c++" || k == "cpp") return Language::kCpp20;
    if (k == "rust") return Language::kRust;
    if (k == "python") return Language::kPython;
    if (k == "c#" || k == "csharp") return Language::kCSharp;
    if (k == "typescript" || k == "ts") return Language::kTypeScript;
    return Language::kUnknown;
}

inline const char* BuildSystemName(BuildSystem b) {
    switch (b) {
        case BuildSystem::kCMake: return "CMake";
        case BuildSystem::kMSBuild: return "MSBuild";
        case BuildSystem::kCargo: return "Cargo";
        case BuildSystem::kOther: return "Other";
        default: return "Unknown";
    }
}
inline BuildSystem BuildSystemFromString(const std::string& s) {
    std::string k = s; for (auto& c : k) c = static_cast<char>(std::tolower((unsigned char)c));
    if (k == "cmake") return BuildSystem::kCMake;
    if (k == "msbuild") return BuildSystem::kMSBuild;
    if (k == "cargo") return BuildSystem::kCargo;
    if (k == "other") return BuildSystem::kOther;
    return BuildSystem::kUnknown;
}

inline const char* AutonomyName(AutonomyLevel a) {
    switch (a) {
        case AutonomyLevel::kAskBeforeChanges: return "Ask before changes";
        case AutonomyLevel::kGenerateAndVerify: return "Generate and verify";
        case AutonomyLevel::kAutonomousCheckpoints: return "Autonomous with checkpoints";
        default: return "Unknown";
    }
}
inline AutonomyLevel AutonomyFromString(const std::string& s) {
    std::string k = s; for (auto& c : k) c = static_cast<char>(std::tolower((unsigned char)c));
    if (k == "ask before changes" || k == "ask") return AutonomyLevel::kAskBeforeChanges;
    if (k == "generate and verify" || k == "verify") return AutonomyLevel::kGenerateAndVerify;
    if (k == "autonomous with checkpoints" || k == "autonomous") return AutonomyLevel::kAutonomousCheckpoints;
    return AutonomyLevel::kUnknown;
}

inline const char* StageName(ProjectStage s) {
    switch (s) {
        case ProjectStage::kInterview: return "interview";
        case ProjectStage::kPlanning: return "planning";
        case ProjectStage::kScaffolding: return "scaffolding";
        case ProjectStage::kImplementing: return "implementing";
        case ProjectStage::kBuilding: return "building";
        case ProjectStage::kVerifying: return "verifying";
        case ProjectStage::kDone: return "done";
        case ProjectStage::kBlocked: return "blocked";
        default: return "unknown";
    }
}
inline ProjectStage StageFromString(const std::string& s) {
    std::string k = s; for (auto& c : k) c = static_cast<char>(std::tolower((unsigned char)c));
    if (k == "interview") return ProjectStage::kInterview;
    if (k == "planning") return ProjectStage::kPlanning;
    if (k == "scaffolding") return ProjectStage::kScaffolding;
    if (k == "implementing") return ProjectStage::kImplementing;
    if (k == "building") return ProjectStage::kBuilding;
    if (k == "verifying") return ProjectStage::kVerifying;
    if (k == "done") return ProjectStage::kDone;
    if (k == "blocked") return ProjectStage::kBlocked;
    return ProjectStage::kUnknown;
}

// ---------------------------------------------------------------------------
// Evidence results (certified from real process exit codes, not model claims)
// ---------------------------------------------------------------------------

struct BuildResult {
    bool tool_ok = false;
    int process_exit_code = -1;
    std::string build_target;
    std::string build_configuration;
    bool artifacts_verified = false;
    int compiler_errors = 0;
    int compiler_warnings = 0;
    std::string log_path;
    std::string command;
    double elapsed_seconds = 0.0;
    std::vector<std::string> artifact_paths;

    bool Succeeded() const { return tool_ok && process_exit_code == 0 && artifacts_verified; }
};

struct TestResult {
    bool tool_ok = false;
    int process_exit_code = -1;
    int tests_passed = 0;
    int tests_failed = 0;
    int tests_total = 0;
    std::string log_path;
    std::string command;
    double elapsed_seconds = 0.0;
    std::vector<std::string> failures;

    bool Succeeded() const { return tool_ok && process_exit_code == 0 && tests_failed == 0; }
};

// ---------------------------------------------------------------------------
// Project specification — the immutable intent, versioned by model rotation
// ---------------------------------------------------------------------------

struct ProjectSpec {
    std::string project_id;          // stable id: FNV1a(name + created_at) hex
    std::string name;                // e.g. MyNewProject
    std::string idea;                // "what should the application do?"
    ProjectType type = ProjectType::kUnknown;
    Language language = Language::kUnknown;
    BuildSystem build_system = BuildSystem::kUnknown;
    AutonomyLevel autonomy = AutonomyLevel::kUnknown;
    std::string framework;           // e.g. Qt, Win32, ASP.NET Core, SDL, ...
    std::string platform;            // Windows, Linux, cross-platform
    std::vector<std::string> dependencies; // e.g. "fmt", "opengl", "cpr"
    std::vector<std::string> tests;        // test requirements
    std::string architecture;        // free-form architecture notes
    std::vector<std::string> acceptance_criteria;
    std::string created_at;          // ISO-8601 local timestamp
    std::string updated_at;          // last spec mutation
    int model_rotation_count = 0;    // incremented when a different model re-opens

    // --- JSON serialization -------------------------------------------------
    json ToJson() const;
    static ProjectSpec FromJson(const json& j);
    static ProjectSpec FromJson(const std::string& text);
    std::string ToJsonString() const { return ToJson().dump(2); }

    // --- Helpers ------------------------------------------------------------
    bool IsComplete() const {
        return !name.empty() && !idea.empty() &&
               type != ProjectType::kUnknown &&
               language != Language::kUnknown &&
               build_system != BuildSystem::kUnknown &&
               autonomy != AutonomyLevel::kUnknown;
    }
};

// ---------------------------------------------------------------------------
// Project state — durable progress, survives model rotation and restarts
// ---------------------------------------------------------------------------

struct ProjectState {
    std::string project_id;
    ProjectStage stage = ProjectStage::kInterview;
    std::vector<std::string> completed_steps;
    std::string current_step;
    std::string plan_path;               // relative to project dir
    std::string scaffold_dir;            // relative to project dir
    std::string executable_path;         // final built executable (absolute)
    BuildResult build_result;
    TestResult test_result;
    double tokens_per_second = 0.0;      // last measured inference TPS
    int64_t total_tokens = 0;            // cumulative generated tokens
    int64_t total_inference_ms = 0;      // cumulative inference wall time
    int build_attempts = 0;
    int repair_attempts = 0;
    std::string last_error;
    std::vector<std::string> file_list;  // source files created by the wizard
    std::string updated_at;

    json ToJson() const;
    static ProjectState FromJson(const json& j);
    static ProjectState FromJson(const std::string& text);
    std::string ToJsonString() const { return ToJson().dump(2); }

    bool StepDone(const std::string& step) const {
        return std::find(completed_steps.begin(), completed_steps.end(), step) != completed_steps.end();
    }
    void MarkDone(const std::string& step) {
        if (!StepDone(step)) completed_steps.push_back(step);
    }
};

// ---------------------------------------------------------------------------
// Project index entry (for listing / resuming across models)
// ---------------------------------------------------------------------------

struct ProjectIndexEntry {
    std::string project_id;
    std::string name;
    std::string path;            // absolute project dir
    ProjectStage stage = ProjectStage::kUnknown;
    std::string updated_at;
    std::string language;
    std::string build_system;

    json ToJson() const;
    static ProjectIndexEntry FromJson(const json& j);
};

// ---------------------------------------------------------------------------
// Follow-up intent detection (natural language: "add a GUI", "switch to C++", ...)
// ---------------------------------------------------------------------------

enum class FollowUpKind {
    kNone,
    kNewProject,              // "new project"
    kAddGui,                  // "add a GUI"
    kSwitchLanguage,          // "switch to C++" / "rewrite in Rust"
    kSetOffline,              // "make it offline" / "no network"
    kAddTests,                // "add tests"
    kContinueBuild,           // "continue building" / "keep going"
    kChangeAutonomy,          // "ask before changes" / "autonomous"
    kUpdateIdea,              // refine what the app should do
    kUnknownFollowUp,         // recognized as follow-up but not classified
};

struct FollowUp {
    FollowUpKind kind = FollowUpKind::kNone;
    std::string target_project;   // project named in the follow-up (if any)
    std::string detail;           // free-form detail (e.g. "C++", "offline")
    std::string raw;              // original user text
};

// Detect whether the user's text is a "new project" workflow or a follow-up
// to an existing project. Returns kNone when it is neither.
FollowUp DetectFollowUp(const std::string& text);

// Resolve a named project against the local index, or fall back to the most
// recently updated project when no name is given.
bool ResolveProject(const std::string& workspace_root,
                    const std::string& name_or_empty,
                    std::string& out_project_id,
                    std::string& out_project_dir);

} // namespace project
} // namespace rawrxd

#endif // RAWRXD_PROJECT_SPEC_HPP
