// ============================================================================
// DocGenerator.hpp - API Documentation, User Manual, Architecture Docs Generator
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace Sovereign {

enum class DocFormat { MARKDOWN, HTML, PDF, DITA, LATEX, ASCIIDOC };
enum class DocType { API, USER_MANUAL, ARCHITECTURE, CONTRIBUTING, EXAMPLES, CHANGELOG };

struct DocConfig {
    std::string projectName = "Sovereign IDE";
    std::string version = "1.0.0";
    std::string author = "Sovereign Team";
    std::string outputDir = "./docs";
    DocFormat format = DocFormat::MARKDOWN;
    bool includeSource = true;
    bool includeDiagrams = true;
    bool includeExamples = true;
    std::vector<std::string> inputPaths;
};

struct DocSection {
    std::string title;
    std::string content;
    int level;
    std::vector<DocSection> subsections;
};

struct DocPage {
    std::string title;
    std::string filename;
    std::vector<DocSection> sections;
    DocType type;
};

class DocGenerator {
public:
    DocGenerator();
    ~DocGenerator();

    bool Initialize(const DocConfig& config);
    void Shutdown();

    // API documentation
    std::vector<DocPage> GenerateAPIDocs(const std::vector<std::string>& sourceFiles);
    DocPage GenerateClassDoc(const std::string& className, const std::vector<std::string>& methods, const std::vector<std::string>& fields);
    DocPage GenerateFunctionDoc(const std::string& funcName, const std::vector<std::string>& params, const std::string& returnType, const std::string& description);

    // User manual
    std::vector<DocPage> GenerateUserManual();
    DocPage GenerateInstallGuide();
    DocPage GenerateQuickStart();
    DocPage GenerateConfigurationGuide();
    DocPage GenerateTroubleshootingGuide();

    // Architecture docs
    std::vector<DocPage> GenerateArchitectureDocs();
    DocPage GenerateComponentDiagram();
    DocPage GenerateDataFlowDiagram();
    DocPage GenerateDeploymentDiagram();

    // Contributing guide
    DocPage GenerateContributingGuide();
    DocPage GenerateCodeStyleGuide();
    DocPage GeneratePRTemplate();

    // Code examples
    std::vector<DocPage> GenerateExamples();
    DocPage GenerateExample(const std::string& name, const std::string& code, const std::string& description);

    // Output
    bool WriteDocs(const std::vector<DocPage>& pages);
    bool WriteDocPage(const DocPage& page);
    std::string RenderToMarkdown(const DocPage& page);
    std::string RenderToHTML(const DocPage& page);

    struct DocStats { uint64_t totalPages; uint64_t totalSections; uint64_t totalWords; };
    DocStats GetStats() const { return stats_; }

private:
    DocConfig config_;
    DocStats stats_;
    bool initialized_ = false;
    mutable std::mutex mutex_;
    
    std::string SanitizeFilename(const std::string& name) const;
    std::string RenderSection(const DocSection& section, int depth = 0) const;
};

} // namespace Sovereign
