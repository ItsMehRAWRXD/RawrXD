// =============================================================================
// project_spec.cpp — ProjectSpec / ProjectState JSON serialization
// =============================================================================
#include "project_spec.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace rawrxd {
namespace project {

namespace {

std::string NowIso8601() {
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

std::string StrLower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower((unsigned char)c));
    return s;
}

} // namespace

// ---------------------------------------------------------------------------
// ProjectSpec
// ---------------------------------------------------------------------------

json ProjectSpec::ToJson() const {
    json j;
    j["project_id"] = project_id;
    j["name"] = name;
    j["idea"] = idea;
    j["type"] = ProjectTypeName(type);
    j["language"] = LanguageName(language);
    j["build_system"] = BuildSystemName(build_system);
    j["autonomy"] = AutonomyName(autonomy);
    j["framework"] = framework;
    j["platform"] = platform;
    j["dependencies"] = dependencies;
    j["tests"] = tests;
    j["architecture"] = architecture;
    j["acceptance_criteria"] = acceptance_criteria;
    j["created_at"] = created_at;
    j["updated_at"] = updated_at;
    j["model_rotation_count"] = model_rotation_count;
    return j;
}

ProjectSpec ProjectSpec::FromJson(const json& j) {
    ProjectSpec s;
    s.project_id = j.value("project_id", std::string());
    s.name = j.value("name", std::string());
    s.idea = j.value("idea", std::string());
    s.type = ProjectTypeFromString(j.value("type", std::string("Unknown")));
    s.language = LanguageFromString(j.value("language", std::string("Unknown")));
    s.build_system = BuildSystemFromString(j.value("build_system", std::string("Unknown")));
    s.autonomy = AutonomyFromString(j.value("autonomy", std::string("Unknown")));
    s.framework = j.value("framework", std::string());
    s.platform = j.value("platform", std::string());
    if (j.contains("dependencies") && j["dependencies"].is_array())
        for (const auto& d : j["dependencies"]) s.dependencies.push_back(d.get<std::string>());
    if (j.contains("tests") && j["tests"].is_array())
        for (const auto& t : j["tests"]) s.tests.push_back(t.get<std::string>());
    s.architecture = j.value("architecture", std::string());
    if (j.contains("acceptance_criteria") && j["acceptance_criteria"].is_array())
        for (const auto& c : j["acceptance_criteria"]) s.acceptance_criteria.push_back(c.get<std::string>());
    s.created_at = j.value("created_at", std::string());
    s.updated_at = j.value("updated_at", std::string());
    s.model_rotation_count = j.value("model_rotation_count", 0);
    return s;
}

ProjectSpec ProjectSpec::FromJson(const std::string& text) {
    return FromJson(json::parse(text));
}

// ---------------------------------------------------------------------------
// ProjectState
// ---------------------------------------------------------------------------

json ProjectState::ToJson() const {
    json j;
    j["project_id"] = project_id;
    j["stage"] = StageName(stage);
    j["completed_steps"] = completed_steps;
    j["current_step"] = current_step;
    j["plan_path"] = plan_path;
    j["scaffold_dir"] = scaffold_dir;
    j["executable_path"] = executable_path;
    j["build_result"] = {
        {"tool_ok", build_result.tool_ok},
        {"process_exit_code", build_result.process_exit_code},
        {"build_target", build_result.build_target},
        {"build_configuration", build_result.build_configuration},
        {"artifacts_verified", build_result.artifacts_verified},
        {"compiler_errors", build_result.compiler_errors},
        {"compiler_warnings", build_result.compiler_warnings},
        {"log_path", build_result.log_path},
        {"command", build_result.command},
        {"elapsed_seconds", build_result.elapsed_seconds},
        {"artifact_paths", build_result.artifact_paths},
        {"succeeded", build_result.Succeeded()},
    };
    j["test_result"] = {
        {"tool_ok", test_result.tool_ok},
        {"process_exit_code", test_result.process_exit_code},
        {"tests_passed", test_result.tests_passed},
        {"tests_failed", test_result.tests_failed},
        {"tests_total", test_result.tests_total},
        {"log_path", test_result.log_path},
        {"command", test_result.command},
        {"elapsed_seconds", test_result.elapsed_seconds},
        {"failures", test_result.failures},
        {"succeeded", test_result.Succeeded()},
    };
    j["tokens_per_second"] = tokens_per_second;
    j["total_tokens"] = total_tokens;
    j["total_inference_ms"] = total_inference_ms;
    j["build_attempts"] = build_attempts;
    j["repair_attempts"] = repair_attempts;
    j["last_error"] = last_error;
    j["file_list"] = file_list;
    j["updated_at"] = updated_at;
    return j;
}

ProjectState ProjectState::FromJson(const json& j) {
    ProjectState s;
    s.project_id = j.value("project_id", std::string());
    s.stage = StageFromString(j.value("stage", std::string("unknown")));
    if (j.contains("completed_steps") && j["completed_steps"].is_array())
        for (const auto& x : j["completed_steps"]) s.completed_steps.push_back(x.get<std::string>());
    s.current_step = j.value("current_step", std::string());
    s.plan_path = j.value("plan_path", std::string());
    s.scaffold_dir = j.value("scaffold_dir", std::string());
    s.executable_path = j.value("executable_path", std::string());
    if (j.contains("build_result")) {
        auto& b = j["build_result"];
        s.build_result.tool_ok = b.value("tool_ok", false);
        s.build_result.process_exit_code = b.value("process_exit_code", -1);
        s.build_result.build_target = b.value("build_target", std::string());
        s.build_result.build_configuration = b.value("build_configuration", std::string());
        s.build_result.artifacts_verified = b.value("artifacts_verified", false);
        s.build_result.compiler_errors = b.value("compiler_errors", 0);
        s.build_result.compiler_warnings = b.value("compiler_warnings", 0);
        s.build_result.log_path = b.value("log_path", std::string());
        s.build_result.command = b.value("command", std::string());
        s.build_result.elapsed_seconds = b.value("elapsed_seconds", 0.0);
        if (b.contains("artifact_paths") && b["artifact_paths"].is_array())
            for (const auto& p : b["artifact_paths"]) s.build_result.artifact_paths.push_back(p.get<std::string>());
    }
    if (j.contains("test_result")) {
        auto& t = j["test_result"];
        s.test_result.tool_ok = t.value("tool_ok", false);
        s.test_result.process_exit_code = t.value("process_exit_code", -1);
        s.test_result.tests_passed = t.value("tests_passed", 0);
        s.test_result.tests_failed = t.value("tests_failed", 0);
        s.test_result.tests_total = t.value("tests_total", 0);
        s.test_result.log_path = t.value("log_path", std::string());
        s.test_result.command = t.value("command", std::string());
        s.test_result.elapsed_seconds = t.value("elapsed_seconds", 0.0);
        if (t.contains("failures") && t["failures"].is_array())
            for (const auto& f : t["failures"]) s.test_result.failures.push_back(f.get<std::string>());
    }
    s.tokens_per_second = j.value("tokens_per_second", 0.0);
    s.total_tokens = j.value("total_tokens", int64_t(0));
    s.total_inference_ms = j.value("total_inference_ms", int64_t(0));
    s.build_attempts = j.value("build_attempts", 0);
    s.repair_attempts = j.value("repair_attempts", 0);
    s.last_error = j.value("last_error", std::string());
    if (j.contains("file_list") && j["file_list"].is_array())
        for (const auto& f : j["file_list"]) s.file_list.push_back(f.get<std::string>());
    s.updated_at = j.value("updated_at", std::string());
    return s;
}

ProjectState ProjectState::FromJson(const std::string& text) {
    return FromJson(json::parse(text));
}

// ---------------------------------------------------------------------------
// ProjectIndexEntry
// ---------------------------------------------------------------------------

json ProjectIndexEntry::ToJson() const {
    json j;
    j["project_id"] = project_id;
    j["name"] = name;
    j["path"] = path;
    j["stage"] = StageName(stage);
    j["updated_at"] = updated_at;
    j["language"] = language;
    j["build_system"] = build_system;
    return j;
}

ProjectIndexEntry ProjectIndexEntry::FromJson(const json& j) {
    ProjectIndexEntry e;
    e.project_id = j.value("project_id", std::string());
    e.name = j.value("name", std::string());
    e.path = j.value("path", std::string());
    e.stage = StageFromString(j.value("stage", std::string("unknown")));
    e.updated_at = j.value("updated_at", std::string());
    e.language = j.value("language", std::string());
    e.build_system = j.value("build_system", std::string());
    return e;
}

// ---------------------------------------------------------------------------
// Follow-up detection
// ---------------------------------------------------------------------------

FollowUp DetectFollowUp(const std::string& text) {
    FollowUp fu;
    fu.raw = text;
    std::string t = StrLower(text);

    auto contains = [&](const std::string& sub) { return t.find(sub) != std::string::npos; };

    // "new project" — always a fresh workflow, never a follow-up.
    if (t.find("new project") != std::string::npos) {
        fu.kind = FollowUpKind::kNewProject;
        return fu;
    }

    // A follow-up references an existing project. Look for change-intent verbs.
    bool is_followup = contains("add") || contains("switch") || contains("rewrite") ||
                       contains("make it") || contains("continue") || contains("keep going") ||
                       contains("resume") || contains("change") || contains("update") ||
                       contains("offline") || contains("tests");

    if (!is_followup) {
        fu.kind = FollowUpKind::kNone;
        return fu;
    }

    if (contains("gui") || contains("graphical") || contains("window")) fu.kind = FollowUpKind::kAddGui;
    else if (contains("switch") || contains("rewrite")) fu.kind = FollowUpKind::kSwitchLanguage;
    else if (contains("offline")) fu.kind = FollowUpKind::kSetOffline;
    else if (contains("test")) fu.kind = FollowUpKind::kAddTests;
    else if (contains("continue") || contains("keep going") || contains("resume")) fu.kind = FollowUpKind::kContinueBuild;
    else if (contains("ask before") || contains("autonomous") || contains("generate and verify")) fu.kind = FollowUpKind::kChangeAutonomy;
    else if (contains("idea") || contains("should do") || contains("what should")) fu.kind = FollowUpKind::kUpdateIdea;
    else fu.kind = FollowUpKind::kUnknownFollowUp;

    // Extract a trailing detail token (e.g. "switch to C++" -> "C++").
    static const std::vector<std::pair<std::string, std::string>> detail_hints = {
        {"c++20", "C++20"}, {"c++", "C++20"}, {"cpp", "C++20"},
        {"rust", "Rust"}, {"python", "Python"}, {"c#", "C#"}, {"csharp", "C#"},
        {"typescript", "TypeScript"}, {"cmake", "CMake"}, {"msbuild", "MSBuild"}, {"cargo", "Cargo"},
        {"gui", "GUI"}, {"offline", "offline"}, {"tests", "tests"},
    };
    for (const auto& [hint, value] : detail_hints) {
        if (t.find(hint) != std::string::npos) { fu.detail = value; break; }
    }
    return fu;
}

bool ResolveProject(const std::string& workspace_root,
                    const std::string& name_or_empty,
                    std::string& out_project_id,
                    std::string& out_project_dir) {
    namespace fs = std::filesystem;
    fs::path index_path = fs::path(workspace_root) / ".rawr" / "projects" / "index.json";
    if (!fs::exists(index_path)) return false;

    std::vector<ProjectIndexEntry> entries;
    try {
        std::ifstream f(index_path);
        json arr = json::parse(f);
        if (arr.is_array())
            for (const auto& e : arr) entries.push_back(ProjectIndexEntry::FromJson(e));
    } catch (...) {
        return false;
    }
    if (entries.empty()) return false;

    // Most recently updated first.
    std::sort(entries.begin(), entries.end(),
              [](const ProjectIndexEntry& a, const ProjectIndexEntry& b) {
                  return a.updated_at > b.updated_at;
              });

    if (!name_or_empty.empty()) {
        for (const auto& e : entries) {
            if (e.name == name_or_empty || e.project_id == name_or_empty) {
                out_project_id = e.project_id;
                out_project_dir = e.path;
                return true;
            }
        }
        return false;
    }

    // No name given: resume the most recently updated project.
    out_project_id = entries.front().project_id;
    out_project_dir = entries.front().path;
    return true;
}

} // namespace project
} // namespace rawrxd
