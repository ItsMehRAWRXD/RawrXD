// onboarding.cpp — Onboarding & Welcome Implementation
#include "onboarding.hpp"
#include <algorithm>
#include <random>
#include <chrono>

namespace RawrXD {
namespace UX {

OnboardingManager& OnboardingManager::Get() {
    static OnboardingManager instance;
    return instance;
}

void OnboardingManager::Initialize() {
    RegisterDefaultSteps();
    RegisterDefaultTips();
}

bool OnboardingManager::IsOnboardingComplete() const {
    return m_onboardingComplete;
}

void OnboardingManager::CompleteOnboarding() {
    m_onboardingComplete = true;
    if (m_onComplete) m_onComplete();
}

void OnboardingManager::ResetOnboarding() {
    m_onboardingComplete = false;
    m_currentStep = 0;
}

const OnboardingStep* OnboardingManager::GetStep(int index) const {
    if (index < 0 || index >= static_cast<int>(m_steps.size())) return nullptr;
    return &m_steps[index];
}

bool OnboardingManager::NextStep() {
    if (m_currentStep >= static_cast<int>(m_steps.size()) - 1) {
        CompleteOnboarding();
        return false;
    }
    m_currentStep++;
    if (m_onStepChanged) m_onStepChanged(m_currentStep, GetTotalSteps());
    return true;
}

bool OnboardingManager::SkipStep() {
    if (m_steps[m_currentStep].isSkippable) {
        return NextStep();
    }
    return false;
}

bool OnboardingManager::ExecuteStepAction(int index) {
    if (index < 0 || index >= static_cast<int>(m_steps.size())) return false;
    const auto& step = m_steps[index];
    if (!step.actionCommand.empty()) {
        // Execute the command
        // TODO: Dispatch to command palette
        return true;
    }
    return false;
}

WelcomeContent OnboardingManager::GetWelcomeContent() const {
    WelcomeContent content;
    content.title = "Welcome to RawrXD";
    content.subtitle = "Autonomous AI Development Platform";

    content.quickActions = {
        {"New File", "file.new"},
        {"Open File...", "file.open"},
        {"Open Folder...", "workspace.addFolder"},
        {"Clone Repository...", "git.clone"},
        {"Open Command Palette", "view.commandPalette"},
        {"Run Build Task", "run.build"},
        {"Start Debugging", "run.debug"},
        {"Open Settings", "settings.open"}
    };

    content.recentProjects = m_recentProjects;

    // Add tips
    auto tip = GetTipOfTheDay();
    if (!tip.title.empty()) {
        content.tips.push_back(tip.title + ": " + tip.content);
    }

    return content;
}

TipOfTheDay OnboardingManager::GetTipOfTheDay() const {
    if (m_tips.empty()) return {};

    // Find a tip that hasn't been shown
    for (const auto& tip : m_tips) {
        if (std::find(m_shownTips.begin(), m_shownTips.end(), tip.title) == m_shownTips.end()) {
            return tip;
        }
    }

    // All shown, return first
    return m_tips[0];
}

void OnboardingManager::MarkTipShown(const std::string& tipId) {
    if (std::find(m_shownTips.begin(), m_shownTips.end(), tipId) == m_shownTips.end()) {
        m_shownTips.push_back(tipId);
    }
}

void OnboardingManager::AddRecentProject(const std::string& name, const std::string& path) {
    // Remove if already exists
    m_recentProjects.erase(
        std::remove_if(m_recentProjects.begin(), m_recentProjects.end(),
            [&](const auto& p) { return p.second == path; }),
        m_recentProjects.end()
    );

    // Add to front
    m_recentProjects.insert(m_recentProjects.begin(), {name, path});

    // Keep only last 10
    if (m_recentProjects.size() > 10) {
        m_recentProjects.resize(10);
    }
}

std::vector<std::pair<std::string, std::string>> OnboardingManager::GetRecentProjects() const {
    return m_recentProjects;
}

void OnboardingManager::RegisterDefaultSteps() {
    m_steps = {
        {
            "welcome",
            "Welcome to RawrXD",
            "RawrXD is an autonomous AI development platform. Let's get you started.",
            "",
            "Get Started",
            "onboarding.next",
            true, true
        },
        {
            "interface",
            "Interface Overview",
            "The IDE has four main areas: Activity Bar (left), Side Bar, Editor (center), and Panel (bottom).",
            "",
            "Next",
            "onboarding.next",
            false, true
        },
        {
            "ai",
            "AI-Powered Development",
            "RawrXD has 8 specialized AI agents: Planner, Coder, Reviewer, Tester, Optimizer, Debugger, Security, and Performance.",
            "",
            "Try AI Assistant",
            "ai.openChat",
            false, true
        },
        {
            "commands",
            "Command Palette",
            "Press Ctrl+Shift+P to open the Command Palette. This is your gateway to all IDE features.",
            "",
            "Open Command Palette",
            "view.commandPalette",
            false, true
        },
        {
            "extensions",
            "Extensions & Marketplace",
            "RawrXD supports VS Code extensions. Install them from the Extensions view.",
            "",
            "Open Extensions",
            "extensions.open",
            false, true
        },
        {
            "terminal",
            "Integrated Terminal",
            "Press Ctrl+` to open the integrated terminal. Run commands without leaving the IDE.",
            "",
            "Open Terminal",
            "terminal.new",
            false, true
        },
        {
            "debug",
            "Debugging",
            "Set breakpoints and press F5 to debug your code. RawrXD supports DAP-compatible debuggers.",
            "",
            "Learn About Debugging",
            "help.debugging",
            false, true
        },
        {
            "git",
            "Version Control",
            "RawrXD has built-in Git integration. View changes, commit, and manage branches.",
            "",
            "Open Source Control",
            "view.scm",
            false, true
        },
        {
            "build",
            "Build & Tasks",
            "Press Ctrl+Shift+B to run build tasks. RawrXD auto-detects CMake, MSBuild, npm, and more.",
            "",
            "Run Build",
            "run.build",
            false, true
        },
        {
            "complete",
            "You're Ready!",
            "You now know the basics. Explore the IDE and let the AI agents help you build amazing things.",
            "",
            "Start Coding",
            "file.new",
            false, false
        }
    };
}

void OnboardingManager::RegisterDefaultTips() {
    m_tips = {
        {"Quick Open", "Press Ctrl+P to quickly open files by name.", "Navigation", "file.open"},
        {"Command Palette", "Press Ctrl+Shift+P to access all commands.", "Navigation", "view.commandPalette"},
        {"Multi-Cursor", "Press Alt+Click to add multiple cursors.", "Editing", ""},
        {"Find in Files", "Press Ctrl+Shift+F to search across all files.", "Search", ""},
        {"Split Editor", "Press Ctrl+\\ to split the editor.", "View", ""},
        {"Terminal Toggle", "Press Ctrl+` to toggle the integrated terminal.", "Terminal", "terminal.new"},
        {"Build Shortcut", "Press Ctrl+Shift+B to run the default build task.", "Build", "run.build"},
        {"Debug Shortcut", "Press F5 to start debugging.", "Debug", "run.debug"},
        {"AI Chat", "Press Ctrl+I to open AI inline chat.", "AI", "ai.openChat"},
        {"AI Agent", "Type /agent in chat to invoke specialized agents.", "AI", ""},
        {"Rename Symbol", "Press F2 to rename a symbol across the project.", "Editing", ""},
        {"Go to Definition", "Press F12 to go to a symbol's definition.", "Navigation", ""},
        {"Peek Definition", "Press Alt+F12 to peek at a definition inline.", "Navigation", ""},
        {"Format Document", "Press Shift+Alt+F to format the current document.", "Editing", ""},
        {"Indent Selection", "Press Ctrl+] to indent the selection.", "Editing", ""},
        {"Comment Line", "Press Ctrl+/ to toggle line comment.", "Editing", ""},
        {"Block Comment", "Press Shift+Alt+A to toggle block comment.", "Editing", ""},
        {"Zen Mode", "Press Ctrl+K Z to enter distraction-free Zen Mode.", "View", ""},
        {"Settings", "Press Ctrl+, to open settings.", "Settings", "settings.open"},
        {"Keyboard Shortcuts", "Press Ctrl+K Ctrl+S to view keyboard shortcuts.", "Help", "help.keyboardShortcuts"},
        {"Extensions", "Press Ctrl+Shift+X to open the Extensions view.", "Extensions", "extensions.open"},
        {"Source Control", "Press Ctrl+Shift+G to open Source Control.", "Git", "view.scm"},
        {"Problems Panel", "Press Ctrl+Shift+M to open the Problems panel.", "Debug", ""},
        {"Output Panel", "Press Ctrl+Shift+U to open the Output panel.", "Debug", ""},
        {"Toggle Sidebar", "Press Ctrl+B to toggle the sidebar visibility.", "View", ""},
        {"Close Tab", "Press Ctrl+W to close the current editor tab.", "File", "file.close"},
        {"Save All", "Press Ctrl+K S to save all files.", "File", "file.saveAll"},
        {"New Window", "Press Ctrl+Shift+N to open a new window.", "File", ""},
        {"Close Window", "Press Ctrl+Shift+W to close the window.", "File", ""},
        {"AI Auto-Build", "RawrXD can auto-build after AI edits. Enable in settings.", "AI", ""},
    };
}

} // namespace UX
} // namespace RawrXD
