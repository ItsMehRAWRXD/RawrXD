// RawrXD Example Repository Implementation
// Phase Z.2: Code examples and sample applications

#include "ExampleRepository.hpp"
#include <filesystem>
#include <fstream>
#include <algorithm>

namespace RawrXD {
namespace Docs {

// ============================================================================
// ExampleRepository Implementation
// ============================================================================

ExampleRepository::ExampleRepository() = default;

ExampleRepository::~ExampleRepository() = default;

bool ExampleRepository::initialize(const std::string& repositoryPath) {
    repositoryPath_ = repositoryPath;
    
    if (!std::filesystem::exists(repositoryPath_)) {
        std::filesystem::create_directories(repositoryPath_);
    }
    
    return scanForExamples();
}

bool ExampleRepository::scanForExamples() {
    if (!std::filesystem::exists(repositoryPath_)) {
        return false;
    }
    
    for (const auto& entry : std::filesystem::directory_iterator(repositoryPath_)) {
        if (entry.is_regular_file()) {
            std::string ext = entry.path().extension().string();
            if (ext == ".cpp" || ext == ".py" || ext == ".ps1") {
                // Would parse example metadata from file
                CodeExample example;
                example.metadata.id = entry.path().stem().string();
                example.metadata.title = example.metadata.id;
                
                std::ifstream file(entry.path());
                if (file) {
                    std::stringstream buffer;
                    buffer << file.rdbuf();
                    example.sourceCode = buffer.str();
                }
                
                examples_[example.metadata.id] = example;
            }
        }
    }
    
    return true;
}

void ExampleRepository::registerExample(const CodeExample& example) {
    examples_[example.metadata.id] = example;
}

void ExampleRepository::unregisterExample(const std::string& exampleId) {
    examples_.erase(exampleId);
}

CodeExample ExampleRepository::getExample(const std::string& exampleId) const {
    auto it = examples_.find(exampleId);
    if (it != examples_.end()) {
        return it->second;
    }
    return CodeExample{};
}

std::vector<CodeExample> ExampleRepository::getAllExamples() const {
    std::vector<CodeExample> result;
    for (const auto& [id, example] : examples_) {
        result.push_back(example);
    }
    return result;
}

std::vector<CodeExample> ExampleRepository::getExamplesByCategory(ExampleCategory category) const {
    std::vector<CodeExample> result;
    for (const auto& [id, example] : examples_) {
        if (example.metadata.category == category) {
            result.push_back(example);
        }
    }
    return result;
}

std::vector<CodeExample> ExampleRepository::getExamplesByLanguage(const std::string& language) const {
    std::vector<CodeExample> result;
    for (const auto& [id, example] : examples_) {
        if (example.metadata.language == language) {
            result.push_back(example);
        }
    }
    return result;
}

std::vector<CodeExample> ExampleRepository::getExamplesByTag(const std::string& tag) const {
    std::vector<CodeExample> result;
    for (const auto& [id, example] : examples_) {
        const auto& tags = example.metadata.tags;
        if (std::find(tags.begin(), tags.end(), tag) != tags.end()) {
            result.push_back(example);
        }
    }
    return result;
}

std::vector<CodeExample> ExampleRepository::getExamplesByDifficulty(const std::string& difficulty) const {
    std::vector<CodeExample> result;
    for (const auto& [id, example] : examples_) {
        if (example.metadata.difficulty == difficulty) {
            result.push_back(example);
        }
    }
    return result;
}

std::vector<CodeExample> ExampleRepository::searchExamples(const std::string& query) const {
    std::vector<CodeExample> result;
    for (const auto& [id, example] : examples_) {
        if (example.metadata.title.find(query) != std::string::npos ||
            example.metadata.description.find(query) != std::string::npos) {
            result.push_back(example);
        }
    }
    return result;
}

bool ExampleRepository::runExample(const std::string& exampleId) {
    auto example = getExample(exampleId);
    if (example.metadata.id.empty()) {
        return false;
    }
    
    // Would execute the example
    return true;
}

bool ExampleRepository::runExampleWithOutput(const std::string& exampleId, std::string& output) {
    // Would run example and capture output
    return true;
}

bool ExampleRepository::validateExample(const std::string& exampleId) {
    auto example = getExample(exampleId);
    if (example.metadata.id.empty()) {
        return false;
    }
    
    // Would validate example code
    return true;
}

bool ExampleRepository::exportExample(const std::string& exampleId, const std::string& outputPath) {
    auto example = getExample(exampleId);
    if (example.metadata.id.empty()) {
        return false;
    }
    
    std::ofstream file(outputPath);
    if (!file) return false;
    
    file << "// " << example.metadata.title << "\n";
    file << "// " << example.metadata.description << "\n\n";
    file << example.sourceCode << "\n";
    
    return true;
}

bool ExampleRepository::exportAllExamples(const std::string& outputDirectory) {
    if (!std::filesystem::exists(outputDirectory)) {
        std::filesystem::create_directories(outputDirectory);
    }
    
    for (const auto& [id, example] : examples_) {
        std::string outputPath = outputDirectory + "/" + id + ".cpp";
        exportExample(id, outputPath);
    }
    
    return true;
}

ExampleRepository::ExampleStats ExampleRepository::getStats() const {
    ExampleStats stats{};
    stats.totalExamples = static_cast<uint32_t>(examples_.size());
    
    for (const auto& [id, example] : examples_) {
        if (example.metadata.isRunnable) {
            stats.runnableExamples++;
        }
        if (example.metadata.hasTests) {
            stats.testedExamples++;
        }
        
        stats.byCategory[example.metadata.category]++;
        stats.byLanguage[example.metadata.language]++;
        stats.byDifficulty[example.metadata.difficulty]++;
    }
    
    return stats;
}

// ============================================================================
// TutorialBuilder Implementation
// ============================================================================

TutorialBuilder::TutorialBuilder() = default;

TutorialBuilder& TutorialBuilder::withTitle(const std::string& title) {
    tutorial_.title = title;
    return *this;
}

TutorialBuilder& TutorialBuilder::withDescription(const std::string& description) {
    tutorial_.description = description;
    return *this;
}

TutorialBuilder& TutorialBuilder::withDifficulty(const std::string& difficulty) {
    tutorial_.difficulty = difficulty;
    return *this;
}

TutorialBuilder& TutorialBuilder::addPrerequisite(const std::string& prereq) {
    tutorial_.prerequisites.push_back(prereq);
    return *this;
}

TutorialBuilder& TutorialBuilder::addStep(const TutorialStep& step) {
    tutorial_.steps.push_back(step);
    return *this;
}

TutorialBuilder& TutorialBuilder::addResource(const std::string& name, const std::string& path) {
    tutorial_.resources[name] = path;
    return *this;
}

TutorialBuilder::Tutorial TutorialBuilder::build() {
    tutorial_.id = "tutorial_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    return tutorial_;
}

bool TutorialBuilder::saveToFile(const std::string& path) {
    std::ofstream file(path);
    if (!file) return false;
    
    file << "# " << tutorial_.title << "\n\n";
    file << tutorial_.description << "\n\n";
    file << "**Difficulty:** " << tutorial_.difficulty << "\n\n";
    
    if (!tutorial_.prerequisites.empty()) {
        file << "## Prerequisites\n\n";
        for (const auto& prereq : tutorial_.prerequisites) {
            file << "- " << prereq << "\n";
        }
        file << "\n";
    }
    
    file << "## Steps\n\n";
    for (const auto& step : tutorial_.steps) {
        file << "### Step " << step.stepNumber << ": " << step.title << "\n\n";
        file << step.description << "\n\n";
        
        if (!step.code.empty()) {
            file << "```cpp\n" << step.code << "\n```\n\n";
        }
    }
    
    return true;
}

// ============================================================================
// InteractiveTutorial Implementation
// ============================================================================

InteractiveTutorial::InteractiveTutorial() = default;

bool InteractiveTutorial::loadTutorial(const std::string& path) {
    // Would load tutorial from file
    return true;
}

bool InteractiveTutorial::start() {
    currentStep_ = 0;
    return true;
}

bool InteractiveTutorial::nextStep() {
    if (currentStep_ < static_cast<int>(tutorial_.steps.size()) - 1) {
        currentStep_++;
        if (progressCallback_) {
            progressCallback_(currentStep_, static_cast<int>(tutorial_.steps.size()));
        }
        return true;
    }
    return false;
}

bool InteractiveTutorial::previousStep() {
    if (currentStep_ > 0) {
        currentStep_--;
        if (progressCallback_) {
            progressCallback_(currentStep_, static_cast<int>(tutorial_.steps.size()));
        }
        return true;
    }
    return false;
}

bool InteractiveTutorial::runCurrentStep() {
    if (currentStep_ >= 0 && currentStep_ < static_cast<int>(tutorial_.steps.size())) {
        // Would execute step code
        return true;
    }
    return false;
}

bool InteractiveTutorial::checkProgress() {
    // Would check if step is complete
    return true;
}

int InteractiveTutorial::getCurrentStep() const {
    return currentStep_;
}

int InteractiveTutorial::getTotalSteps() const {
    return static_cast<int>(tutorial_.steps.size());
}

bool InteractiveTutorial::isComplete() const {
    return currentStep_ >= static_cast<int>(tutorial_.steps.size()) - 1;
}

void InteractiveTutorial::onProgress(ProgressCallback callback) {
    progressCallback_ = callback;
}

} // namespace Docs
} // namespace RawrXD
