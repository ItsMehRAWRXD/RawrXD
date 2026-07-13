// RawrXD Documentation Generator
// Phase Z.1: Automated documentation generation
// Generates API reference, tutorials, and examples from source code

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>

namespace RawrXD {
namespace Docs {

// Documentation type
enum class DocType {
    API_REFERENCE,      // API documentation
    TUTORIAL,           // Step-by-step tutorial
    EXAMPLE,            // Code example
    GUIDE,              // User guide
    FAQ,                // Frequently asked questions
    CHANGELOG,          // Version changelog
    README              // Project readme
};

// Documentation section
struct DocSection {
    std::string title;
    std::string content;
    std::vector<DocSection> subsections;
    std::map<std::string, std::string> metadata;
};

// API documentation entry
struct APIEntry {
    std::string name;
    std::string type;           // "class", "function", "enum", "typedef"
    std::string signature;
    std::string description;
    std::string brief;
    std::vector<std::string> parameters;
    std::string returnType;
    std::string returnDescription;
    std::vector<std::string> exceptions;
    std::vector<std::string> seeAlso;
    std::string filePath;
    int lineNumber{0};
    std::string sinceVersion;
    bool isDeprecated{false};
    std::string deprecationMessage;
    std::map<std::string, std::string> codeExamples;
};

// Tutorial step
struct TutorialStep {
    int stepNumber;
    std::string title;
    std::string description;
    std::string code;
    std::string expectedOutput;
    std::vector<std::string> prerequisites;
    std::chrono::seconds estimatedTime;
};

// Tutorial
struct Tutorial {
    std::string id;
    std::string title;
    std::string description;
    std::string difficulty;     // "beginner", "intermediate", "advanced"
    std::vector<std::string> topics;
    std::vector<TutorialStep> steps;
    std::chrono::seconds totalTime;
    std::map<std::string, std::string> metadata;
};

// Code example
struct CodeExample {
    std::string id;
    std::string title;
    std::string description;
    std::string language;       // "cpp", "python", "powershell"
    std::string code;
    std::string output;
    std::vector<std::string> tags;
    std::map<std::string, std::string> requirements;
};

// Documentation generator
class DocumentationGenerator {
public:
    DocumentationGenerator();
    ~DocumentationGenerator();
    
    // Initialization
    bool initialize(const std::string& outputDirectory);
    bool generateAll();
    
    // API documentation
    bool parseSourceFiles(const std::vector<std::string>& paths);
    bool parseHeaderFile(const std::string& path);
    std::vector<APIEntry> extractAPIEntries(const std::string& content);
    bool generateAPIDocumentation();
    bool generateClassReference(const std::string& className);
    bool generateFunctionReference(const std::string& functionName);
    
    // Tutorial generation
    bool generateTutorials();
    bool generateTutorial(const Tutorial& tutorial);
    Tutorial createTutorial(const std::string& title, const std::string& difficulty);
    void addTutorialStep(Tutorial& tutorial, const TutorialStep& step);
    
    // Example generation
    bool generateExamples();
    bool generateExample(const CodeExample& example);
    CodeExample createExample(const std::string& title, const std::string& language);
    std::vector<CodeExample> extractExamplesFromTests(const std::string& testDirectory);
    
    // Guide generation
    bool generateUserGuide();
    bool generateDeveloperGuide();
    bool generateDeploymentGuide();
    bool generateTroubleshootingGuide();
    
    // Output formats
    bool generateMarkdown(const std::string& outputPath);
    bool generateHTML(const std::string& outputPath);
    bool generatePDF(const std::string& outputPath);
    bool generateManPages(const std::string& outputPath);
    
    // Search index
    bool generateSearchIndex();
    bool generateTagIndex();
    bool generateCrossReferences();
    
    // Statistics
    struct DocStats {
        uint32_t totalFilesGenerated;
        uint32_t totalAPIEntries;
        uint32_t totalTutorials;
        uint32_t totalExamples;
        uint32_t totalLinesDocumented;
        std::map<DocType, uint32_t> byType;
    };
    DocStats getStats() const;
    
    // Custom generators
    using CustomGenerator = std::function<bool(const std::string& outputPath)>;
    void registerCustomGenerator(DocType type, CustomGenerator generator);

private:
    std::string extractBrief(const std::string& comment);
    std::string extractDescription(const std::string& comment);
    std::vector<std::string> extractParameters(const std::string& comment);
    std::string extractReturnDescription(const std::string& comment);
    std::string generateMarkdownForEntry(const APIEntry& entry);
    std::string generateHTMLForEntry(const APIEntry& entry);
    
    std::string outputDirectory_;
    std::vector<APIEntry> apiEntries_;
    std::vector<Tutorial> tutorials_;
    std::vector<CodeExample> examples_;
    std::map<DocType, std::vector<CustomGenerator>> customGenerators_;
    DocStats stats_{};
};

// README generator
class READMEGenerator {
public:
    READMEGenerator();
    
    bool generate(const std::string& outputPath);
    bool generateSection(const std::string& sectionName, const std::string& outputPath);
    
    void setProjectName(const std::string& name);
    void setProjectDescription(const std::string& description);
    void setVersion(const std::string& version);
    void setLicense(const std::string& license);
    void setRepositoryURL(const std::string& url);
    void addFeature(const std::string& feature);
    void addInstallationStep(const std::string& step);
    void addQuickStartExample(const std::string& example);

private:
    std::string projectName_;
    std::string projectDescription_;
    std::string version_;
    std::string license_;
    std::string repositoryURL_;
    std::vector<std::string> features_;
    std::vector<std::string> installationSteps_;
    std::vector<std::string> quickStartExamples_;
};

// Changelog generator
class ChangelogGenerator {
public:
    ChangelogGenerator();
    
    struct VersionEntry {
        std::string version;
        std::string date;
        std::vector<std::string> added;
        std::vector<std::string> changed;
        std::vector<std::string> deprecated;
        std::vector<std::string> removed;
        std::vector<std::string> fixed;
        std::vector<std::string> security;
    };
    
    void addVersion(const VersionEntry& entry);
    bool generateMarkdown(const std::string& outputPath);
    bool generateJSON(const std::string& outputPath);
    
    std::vector<VersionEntry> parseGitHistory(const std::string& repoPath);

private:
    std::vector<VersionEntry> versions_;
};

// FAQ generator
class FAQGenerator {
public:
    FAQGenerator();
    
    struct FAQEntry {
        std::string question;
        std::string answer;
        std::vector<std::string> tags;
        std::string category;
    };
    
    void addEntry(const FAQEntry& entry);
    bool generateMarkdown(const std::string& outputPath);
    bool generateHTML(const std::string& outputPath);
    
    std::vector<FAQEntry> search(const std::string& query) const;
    std::vector<std::string> getCategories() const;

private:
    std::vector<FAQEntry> entries_;
};

} // namespace Docs
} // namespace RawrXD
