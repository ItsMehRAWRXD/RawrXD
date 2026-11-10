// =============================================================================
// project_wizard.cpp — RawrXD Project Wizard interview
// =============================================================================
#include "project_wizard.hpp"

#include <chrono>
#include <iostream>
#include <sstream>

namespace rawrxd {
namespace project {

namespace {

std::string Lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower((unsigned char)c));
    return s;
}

std::string Join(const std::vector<std::string>& v, const std::string& sep) {
    std::ostringstream os;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) os << sep;
        os << v[i];
    }
    return os.str();
}

std::string TrimStatic(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return std::string();
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

} // namespace

// ---------------------------------------------------------------------------
// WizardCli parsing
// ---------------------------------------------------------------------------

WizardCli ParseWizardCli(int argc, char** argv) {
    WizardCli cli;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a.rfind("--", 0) != 0) continue;
        std::string body = a.substr(2);
        auto eq = body.find('=');
        std::string key, value;
        if (eq != std::string::npos) {
            key = body.substr(0, eq);
            value = body.substr(eq + 1);
        } else if (i + 1 < argc && argv[i + 1][0] != '-') {
            key = body;
            value = argv[++i];
        } else {
            key = body;
            value = "true";
        }
        if (key == "model") { cli.model = value; continue; }
        cli.flags.emplace(std::move(key), std::move(value));
    }
    auto it = cli.flags.find("task");
    if (it != cli.flags.end() && Lower(it->second) == "new project") {
        cli.is_new_project = true;
    }
    return cli;
}

// ---------------------------------------------------------------------------
// Wizard
// ---------------------------------------------------------------------------

Wizard::Wizard(std::string workspace_root, ReadLine read_line,
               std::map<std::string, std::string> flags)
    : workspace_root_(std::move(workspace_root)),
      read_line_(std::move(read_line)),
      flags_(std::move(flags)) {
    noninteractive_ = read_line_ == nullptr;
}

ProjectSpec Wizard::Run() {
    WizardAnswers a;

    if (noninteractive_) {
        return BuildFromFlags(flags_);
    }

    std::cout << "\n";
    std::cout << "RawrXD Project Wizard\n";
    std::cout << "=====================\n";
    std::cout << "Answer each question. Press Enter to accept a default where shown.\n";
    std::cout << "Type /exit at any time to cancel.\n";
    std::cout << "\n";

    // 1. Project name
    if (!AskRequired(a.name, "Project name")) return ProjectSpec();
    // 2. Idea
    if (!AskRequired(a.idea, "Describe your idea\nWhat should the application do?")) return ProjectSpec();

    // 3. Type
    {
        std::vector<std::string> opts = {
            "Desktop application", "CLI tool", "Web application", "Game", "Library / API"
        };
        std::string picked;
        if (!AskChoice(picked, "What are you building?", opts)) return ProjectSpec();
        a.type = ProjectTypeFromString(picked);
    }

    // 4. Language
    {
        std::vector<std::string> opts = {"C++20", "Rust", "Python", "C#", "TypeScript"};
        std::string picked;
        if (!AskChoice(picked, "Which programming language?", opts)) return ProjectSpec();
        a.language = LanguageFromString(picked);
    }

    // 5. Build system
    {
        std::vector<std::string> opts = {"CMake", "MSBuild", "Cargo", "Other"};
        std::string picked;
        if (!AskChoice(picked, "Which build system?", opts)) return ProjectSpec();
        a.build_system = BuildSystemFromString(picked);
    }

    // 6. Autonomy
    {
        std::vector<std::string> opts = {
            "Ask before changes", "Generate and verify", "Autonomous with checkpoints"
        };
        std::string picked;
        if (!AskChoice(picked, "How much autonomy?", opts)) return ProjectSpec();
        a.autonomy = AutonomyFromString(picked);
    }

    // 7-11. Optional deep-dive
    if (!AskOptional(a.framework, "Which framework? (optional, e.g. Qt, Win32, SDL, ASP.NET)")) return ProjectSpec();
    if (!AskOptional(a.platform, "Target platform? (optional, e.g. Windows, Linux, cross-platform)")) return ProjectSpec();
    if (!AskList(a.dependencies, "Dependencies? (optional, comma-separated libraries/packages)")) return ProjectSpec();
    if (!AskList(a.tests, "Tests? (optional, comma-separated test requirements)")) return ProjectSpec();
    if (!AskOptional(a.architecture, "Architecture notes? (optional)")) return ProjectSpec();

    ProjectSpec spec;
    spec.name = a.name;
    spec.idea = a.idea;
    spec.type = a.type;
    spec.language = a.language;
    spec.build_system = a.build_system;
    spec.autonomy = a.autonomy;
    spec.framework = a.framework;
    spec.platform = a.platform;
    spec.dependencies = a.dependencies;
    spec.tests = a.tests;
    spec.architecture = a.architecture;
    spec.acceptance_criteria = a.acceptance_criteria;
    spec.project_id = "proj_" + detail::Hex(detail::Fnv1a(spec.name + "|" + detail::NowIso8601()));
    spec.created_at = detail::NowIso8601();
    spec.updated_at = spec.created_at;

    PrintPreview(spec);
    return spec;
}

ProjectSpec Wizard::BuildFromFlags(const std::map<std::string, std::string>& flags) {
    ProjectSpec spec;
    auto get = [&](const std::string& key) -> std::string {
        auto it = flags.find(key);
        return it == flags.end() ? std::string() : it->second;
    };
    spec.name = get("wizard-name");
    spec.idea = get("wizard-idea");
    spec.type = ProjectTypeFromString(get("wizard-type"));
    spec.language = LanguageFromString(get("wizard-language"));
    spec.build_system = BuildSystemFromString(get("wizard-build-system"));
    spec.autonomy = AutonomyFromString(get("wizard-autonomy"));
    spec.framework = get("wizard-framework");
    spec.platform = get("wizard-platform");
    FlagList(flags, "wizard-deps", spec.dependencies);
    FlagList(flags, "wizard-tests", spec.tests);
    spec.architecture = get("wizard-architecture");
    if (!get("wizard-acceptance").empty()) {
        std::istringstream iss(get("wizard-acceptance"));
        std::string line;
        while (std::getline(iss, line, ';')) {
            line = TrimStatic(line);
            if (!line.empty()) spec.acceptance_criteria.push_back(line);
        }
    }
    spec.project_id = "proj_" + detail::Hex(detail::Fnv1a(spec.name + "|" + detail::NowIso8601()));
    spec.created_at = detail::NowIso8601();
    spec.updated_at = spec.created_at;
    return spec;
}

void Wizard::PrintPreview(const ProjectSpec& spec) {
    std::cout << "\n";
    std::cout << "RawrXD Project Wizard\n";
    std::cout << "Project: " << spec.name << "\n";
    std::cout << "Id:      " << spec.project_id << "\n";
    std::cout << "Idea:    " << spec.idea << "\n";
    std::cout << "Type:    " << ProjectTypeName(spec.type) << "\n";
    std::cout << "Lang:    " << LanguageName(spec.language) << "\n";
    std::cout << "Build:   " << BuildSystemName(spec.build_system) << "\n";
    std::cout << "Autonomy:" << AutonomyName(spec.autonomy) << "\n";
    if (!spec.framework.empty())  std::cout << "Framework: " << spec.framework << "\n";
    if (!spec.platform.empty())   std::cout << "Platform:  " << spec.platform << "\n";
    if (!spec.dependencies.empty()) std::cout << "Deps:      " << Join(spec.dependencies, ", ") << "\n";
    if (!spec.tests.empty())       std::cout << "Tests:     " << Join(spec.tests, ", ") << "\n";
    if (!spec.architecture.empty()) std::cout << "Arch:      " << spec.architecture << "\n";
    if (!spec.acceptance_criteria.empty()) {
        std::cout << "Acceptance:\n";
        for (const auto& c : spec.acceptance_criteria)
            std::cout << "  - " << c << "\n";
    }
    std::cout << "\nThis is an interactive specification preview. The flags shown are proposed "
              << "and require implementation in RawrXD.\n";
    std::cout << "\n";
}

bool Wizard::AskRequired(std::string& out, const std::string& prompt) {
    while (true) {
        std::string line = PromptLine(prompt);
        if (line == "/exit") return false;
        line = TrimStatic(line);
        if (!line.empty()) { out = line; return true; }
        std::cout << "  (required — please answer)\n";
    }
}

bool Wizard::AskChoice(std::string& out, const std::string& prompt,
                       const std::vector<std::string>& options) {
    std::cout << "\n" << prompt << "\n";
    for (size_t i = 0; i < options.size(); ++i)
        std::cout << "  " << (i + 1) << ") " << options[i] << "\n";
    std::cout << "\n";
    while (true) {
        std::string line = PromptLine("> ");
        if (line == "/exit") return false;
        line = TrimStatic(line);
        if (line.empty()) continue;
        // Allow picking by number or by name.
        bool picked = false;
        try {
            size_t n = std::stoul(line);
            if (n >= 1 && n <= options.size()) { out = options[n - 1]; picked = true; }
        } catch (...) {}
        if (!picked) {
            for (const auto& o : options)
                if (Lower(o) == Lower(line)) { out = o; picked = true; break; }
        }
        if (picked) return true;
        std::cout << "  (choose a number or name from the list)\n";
    }
}

bool Wizard::AskOptional(std::string& out, const std::string& prompt) {
    std::string line = PromptLine(prompt);
    if (line == "/exit") return false;
    out = TrimStatic(line);
    return true;
}

bool Wizard::AskList(std::vector<std::string>& out, const std::string& prompt) {
    std::string line = PromptLine(prompt);
    if (line == "/exit") return false;
    line = TrimStatic(line);
    if (!line.empty()) {
        std::istringstream iss(line);
        std::string item;
        while (std::getline(iss, item, ',')) {
            item = TrimStatic(item);
            if (!item.empty()) out.push_back(item);
        }
    }
    return true;
}

bool Wizard::Flag(const std::string& key, std::string& out) const {
    auto it = flags_.find(key);
    if (it == flags_.end()) return false;
    out = it->second;
    return true;
}

// static
bool Wizard::FlagList(const std::map<std::string, std::string>& flags,
                      const std::string& key, std::vector<std::string>& out) {
    auto it = flags.find(key);
    if (it == flags.end()) return true;
    std::istringstream iss(it->second);
    std::string item;
    while (std::getline(iss, item, ',')) {
        item = TrimStatic(item);
        if (!item.empty()) out.push_back(item);
    }
    return true;
}

std::string Wizard::PromptLine(const std::string& prompt) {
    std::cout << prompt << " " << std::flush;
    std::string line;
    if (read_line_) {
        if (!read_line_(line)) return std::string();
    } else {
        if (!std::getline(std::cin, line)) return std::string();
    }
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
    return line;
}

std::string Wizard::Trim(const std::string& s) const {
    return TrimStatic(s);
}

} // namespace project
} // namespace rawrxd
