// onboarding.hpp — Onboarding & Welcome Flow
#pragma once

#include <string>
#include <vector>
#include <functional>
#include <mutex>

namespace RawrXD {
namespace UX {

// ============================================================================
// Onboarding Step
// ============================================================================
struct OnboardingStep {
    std::string id;
    std::string title;
    std::string description;
    std::string image;          // Path to illustration
    std::string actionLabel;    // Button text
    std::string actionCommand;  // Command to execute on action
    bool isRequired = false;    // Must be completed
    bool isSkippable = true;
};

// ============================================================================
// Tip of the Day
// ============================================================================
struct TipOfTheDay {
    std::string title;
    std::string content;
    std::string category;
    std::string relatedCommand;
};

// ============================================================================
// Welcome Page Content
// ============================================================================
struct WelcomeContent {
    std::string title;
    std::string subtitle;
    std::vector<std::pair<std::string, std::string>> quickActions; // label -> command
    std::vector<std::pair<std::string, std::string>> recentProjects; // name -> path
    std::vector<std::string> tips;
};

// ============================================================================
// Onboarding Manager
// ============================================================================
class OnboardingManager {
public:
    static OnboardingManager& Get();

    // Initialize onboarding
    void Initialize();

    // Check if onboarding is complete
    bool IsOnboardingComplete() const;

    // Mark onboarding as complete
    void CompleteOnboarding();

    // Reset onboarding
    void ResetOnboarding();

    // Get current step
    int GetCurrentStep() const { return m_currentStep; }

    // Get total steps
    int GetTotalSteps() const { return static_cast<int>(m_steps.size()); }

    // Get step by index
    const OnboardingStep* GetStep(int index) const;

    // Advance to next step
    bool NextStep();

    // Skip current step
    bool SkipStep();

    // Execute step action
    bool ExecuteStepAction(int index);

    // Get welcome content
    WelcomeContent GetWelcomeContent() const;

    // Get tip of the day
    TipOfTheDay GetTipOfTheDay() const;

    // Mark tip as shown
    void MarkTipShown(const std::string& tipId);

    // Get recent projects
    void AddRecentProject(const std::string& name, const std::string& path);
    std::vector<std::pair<std::string, std::string>> GetRecentProjects() const;

    // Events
    using OnboardingCallback = std::function<void(int step, int total)>;
    void OnStepChanged(OnboardingCallback callback) { m_onStepChanged = callback; }
    void OnOnboardingComplete(std::function<void()> callback) { m_onComplete = callback; }

private:
    OnboardingManager() = default;
    void RegisterDefaultSteps();
    void RegisterDefaultTips();

    std::vector<OnboardingStep> m_steps;
    std::vector<TipOfTheDay> m_tips;
    std::vector<std::string> m_shownTips;
    std::vector<std::pair<std::string, std::string>> m_recentProjects;
    int m_currentStep = 0;
    bool m_onboardingComplete = false;
    OnboardingCallback m_onStepChanged;
    std::function<void()> m_onComplete;
    mutable std::mutex m_mutex;
};

} // namespace UX
} // namespace RawrXD
