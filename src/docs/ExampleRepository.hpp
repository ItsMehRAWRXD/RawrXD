// RawrXD Example Repository
// Phase Z.2: Code examples and sample applications
// Comprehensive collection of usage examples

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>

namespace RawrXD {
namespace Docs {

// Example category
enum class ExampleCategory {
    BASIC,          // Basic usage
    INTERMEDIATE,   // Intermediate features
    ADVANCED,       // Advanced features
    INTEGRATION,    // Integration examples
    PERFORMANCE,    // Performance optimization
    DEPLOYMENT      // Deployment examples
};

// Example metadata
struct ExampleMetadata {
    std::string id;
    std::string title;
    std::string description;
    ExampleCategory category;
    std::string language;       // "cpp", "python", "powershell", "bash"
    std::vector<std::string> tags;
    std::vector<std::string> prerequisites;
    std::chrono::seconds estimatedTime;
    std::string difficulty;     // "beginner", "intermediate", "advanced"
    std::map<std::string, std::string> requirements;
    bool isRunnable{true};
    bool hasTests{false};
};

// Code example
struct CodeExample {
    ExampleMetadata metadata;
    std::string sourceCode;
    std::string expectedOutput;
    std::string explanation;
    std::vector<std::string> screenshots;
    std::map<std::string, std::string> additionalFiles;
};

// Example repository
class ExampleRepository {
public:
    ExampleRepository();
    ~ExampleRepository();
    
    // Initialization
    bool initialize(const std::string& repositoryPath);
    bool scanForExamples();
    
    // Example management
    void registerExample(const CodeExample& example);
    void unregisterExample(const std::string& exampleId);
    CodeExample getExample(const std::string& exampleId) const;
    std::vector<CodeExample> getAllExamples() const;
    
    // Filtering
    std::vector<CodeExample> getExamplesByCategory(ExampleCategory category) const;
    std::vector<CodeExample> getExamplesByLanguage(const std::string& language) const;
    std::vector<CodeExample> getExamplesByTag(const std::string& tag) const;
    std::vector<CodeExample> getExamplesByDifficulty(const std::string& difficulty) const;
    std::vector<CodeExample> searchExamples(const std::string& query) const;
    
    // Execution
    bool runExample(const std::string& exampleId);
    bool runExampleWithOutput(const std::string& exampleId, std::string& output);
    bool validateExample(const std::string& exampleId);
    
    // Export
    bool exportExample(const std::string& exampleId, const std::string& outputPath);
    bool exportAllExamples(const std::string& outputDirectory);
    
    // Statistics
    struct ExampleStats {
        uint32_t totalExamples;
        uint32_t runnableExamples;
        uint32_t testedExamples;
        std::map<ExampleCategory, uint32_t> byCategory;
        std::map<std::string, uint32_t> byLanguage;
        std::map<std::string, uint32_t> byDifficulty;
    };
    ExampleStats getStats() const;

private:
    std::map<std::string, CodeExample> examples_;
    std::string repositoryPath_;
};

// Tutorial builder
class TutorialBuilder {
public:
    TutorialBuilder();
    
    struct TutorialStep {
        int stepNumber;
        std::string title;
        std::string description;
        std::string code;
        std::string expectedOutput;
        std::vector<std::string> checkpoints;
        std::chrono::seconds estimatedTime;
    };
    
    struct Tutorial {
        std::string id;
        std::string title;
        std::string description;
        std::string difficulty;
        std::vector<std::string> prerequisites;
        std::vector<TutorialStep> steps;
        std::map<std::string, std::string> resources;
    };
    
    TutorialBuilder& withTitle(const std::string& title);
    TutorialBuilder& withDescription(const std::string& description);
    TutorialBuilder& withDifficulty(const std::string& difficulty);
    TutorialBuilder& addPrerequisite(const std::string& prereq);
    TutorialBuilder& addStep(const TutorialStep& step);
    TutorialBuilder& addResource(const std::string& name, const std::string& path);
    
    Tutorial build();
    bool saveToFile(const std::string& path);

private:
    Tutorial tutorial_;
};

// Interactive tutorial runner
class InteractiveTutorial {
public:
    InteractiveTutorial();
    
    bool loadTutorial(const std::string& path);
    bool start();
    bool nextStep();
    bool previousStep();
    bool runCurrentStep();
    bool checkProgress();
    
    int getCurrentStep() const;
    int getTotalSteps() const;
    bool isComplete() const;
    
    using ProgressCallback = std::function<void(int currentStep, int totalSteps)>;
    void onProgress(ProgressCallback callback);

private:
    TutorialBuilder::Tutorial tutorial_;
    int currentStep_{0};
    ProgressCallback progressCallback_;
};

} // namespace Docs
} // namespace RawrXD
