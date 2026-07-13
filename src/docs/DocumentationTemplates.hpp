/**
 * DocumentationTemplates.hpp
 *
 * Phase J Batch 5/5: Documentation Examples & Templates
 *
 * Pre-built documentation templates, examples, and guides
 * for common documentation scenarios.
 */

#pragma once

#include <string>
#include <vector>
#include <map>

namespace Docs {

// ============================================================================
// Template Categories
// ============================================================================

enum class DocTemplateCategory {
    API_REFERENCE,
    USER_GUIDE,
    TUTORIAL,
    README,
    CONTRIBUTING,
    CHANGELOG,
    LICENSE,
    CODE_OF_CONDUCT,
    SECURITY,
    FAQ,
    TROUBLESHOOTING,
    ARCHITECTURE,
    DEPLOYMENT,
    TESTING
};

// ============================================================================
// Documentation Template
// ============================================================================

/**
 * Documentation template.
 */
struct DocumentationTemplate {
    std::string id;
    std::string name;
    std::string description;
    DocTemplateCategory category;
    std::string content;
    std::vector<std::string> variables;
    std::map<std::string, std::string> defaultValues;
    std::vector<std::string> tags;
    std::string language;
};

// ============================================================================
// Template Library
// ============================================================================

/**
 * Library of documentation templates.
 */
class TemplateLibrary {
public:
    TemplateLibrary();
    
    // Registration
    void RegisterTemplate(const DocumentationTemplate& tmpl);
    void RegisterTemplates(const std::vector<DocumentationTemplate>& templates);
    
    // Query
    std::vector<DocumentationTemplate> GetTemplates() const;
    std::vector<DocumentationTemplate> GetTemplatesByCategory(DocTemplateCategory category) const;
    std::vector<DocumentationTemplate> GetTemplatesByTag(const std::string& tag) const;
    std::optional<DocumentationTemplate> GetTemplate(const std::string& id) const;
    
    // Rendering
    std::string RenderTemplate(const std::string& id,
                                const std::map<std::string, std::string>& variables) const;
    
    // Built-in templates
    static std::vector<DocumentationTemplate> GetBuiltInTemplates();
    
private:
    std::vector<DocumentationTemplate> templates_;
    
    void InitializeBuiltInTemplates();
    std::string ReplaceVariables(const std::string& content,
                                  const std::map<std::string, std::string>& variables) const;
};

// ============================================================================
// Example Library
// ============================================================================

/**
 * Library of documentation examples.
 */
class ExampleLibrary {
public:
    struct Example {
        std::string id;
        std::string title;
        std::string description;
        std::string category;
        std::string language;
        std::string code;
        std::string explanation;
        std::vector<std::string> tags;
        std::map<std::string, std::string> metadata;
    };
    
    ExampleLibrary();
    
    // Registration
    void AddExample(const Example& example);
    void AddExamples(const std::vector<Example>& examples);
    
    // Query
    std::vector<Example> GetExamples() const;
    std::vector<Example> GetExamplesByCategory(const std::string& category) const;
    std::vector<Example> GetExamplesByLanguage(const std::string& language) const;
    std::vector<Example> GetExamplesByTag(const std::string& tag) const;
    std::optional<Example> GetExample(const std::string& id) const;
    
    // Search
    std::vector<Example> Search(const std::string& query) const;
    
    // Built-in examples
    static std::vector<Example> GetBuiltInExamples();
    
private:
    std::vector<Example> examples_;
    
    void InitializeBuiltInExamples();
};

// ============================================================================
// Guide Library
// ============================================================================

/**
 * Library of documentation guides.
 */
class GuideLibrary {
public:
    struct Guide {
        std::string id;
        std::string title;
        std::string description;
        std::string category;
        int difficulty;  // 1-5
        int estimatedTimeMinutes;
        std::vector<std::string> prerequisites;
        std::vector<std::string> steps;
        std::string conclusion;
        std::vector<std::string> relatedGuides;
        std::vector<std::string> tags;
    };
    
    GuideLibrary();
    
    // Registration
    void AddGuide(const Guide& guide);
    void AddGuides(const std::vector<Guide>& guides);
    
    // Query
    std::vector<Guide> GetGuides() const;
    std::vector<Guide> GetGuidesByCategory(const std::string& category) const;
    std::vector<Guide> GetGuidesByDifficulty(int difficulty) const;
    std::vector<Guide> GetGuidesByTag(const std::string& tag) const;
    std::optional<Guide> GetGuide(const std::string& id) const;
    
    // Learning paths
    std::vector<Guide> GetLearningPath(const std::string& goal) const;
    std::vector<Guide> GetRecommendedGuides(const std::vector<std::string>& completed) const;
    
    // Built-in guides
    static std::vector<Guide> GetBuiltInGuides();
    
private:
    std::vector<Guide> guides_;
    
    void InitializeBuiltInGuides();
};

// ============================================================================
// Cheat Sheet Library
// ============================================================================

/**
 * Library of cheat sheets.
 */
class CheatSheetLibrary {
public:
    struct CheatSheet {
        std::string id;
        std::string title;
        std::string description;
        std::string category;
        std::vector<std::pair<std::string, std::string>> sections;
        std::map<std::string, std::vector<std::pair<std::string, std::string>>> commands;
        std::vector<std::string> tags;
    };
    
    CheatSheetLibrary();
    
    // Registration
    void AddCheatSheet(const CheatSheet& sheet);
    void AddCheatSheets(const std::vector<CheatSheet>& sheets);
    
    // Query
    std::vector<CheatSheet> GetCheatSheets() const;
    std::vector<CheatSheet> GetCheatSheetsByCategory(const std::string& category) const;
    std::optional<CheatSheet> GetCheatSheet(const std::string& id) const;
    
    // Rendering
    std::string RenderMarkdown(const CheatSheet& sheet) const;
    std::string RenderHtml(const CheatSheet& sheet) const;
    std::string RenderPdf(const CheatSheet& sheet) const;
    
    // Built-in cheat sheets
    static std::vector<CheatSheet> GetBuiltInCheatSheets();
    
private:
    std::vector<CheatSheet> cheatSheets_;
    
    void InitializeBuiltInCheatSheets();
};

// ============================================================================
// Glossary
// ============================================================================

/**
 * Documentation glossary.
 */
class Glossary {
public:
    struct Term {
        std::string term;
        std::string definition;
        std::string shortDefinition;
        std::vector<std::string> synonyms;
        std::vector<std::string> relatedTerms;
        std::string category;
        std::string example;
    };
    
    Glossary();
    
    // Terms
    void AddTerm(const Term& term);
    void RemoveTerm(const std::string& term);
    std::optional<Term> GetTerm(const std::string& term) const;
    std::vector<Term> GetTerms() const;
    std::vector<Term> GetTermsByCategory(const std::string& category) const;
    std::vector<Term> Search(const std::string& query) const;
    
    // Auto-linking
    std::string AutoLinkTerms(const std::string& content) const;
    std::string GetTooltip(const std::string& term) const;
    
    // Export
    std::string GenerateMarkdown() const;
    std::string GenerateHtml() const;
    std::string GenerateJson() const;
    
    // Built-in terms
    static std::vector<Term> GetBuiltInTerms();
    
private:
    std::vector<Term> terms_;
    
    void InitializeBuiltInTerms();
};

// ============================================================================
// FAQ Library
// ============================================================================

/**
 * Library of frequently asked questions.
 */
class FAQLibrary {
public:
    struct Question {
        std::string id;
        std::string question;
        std::string answer;
        std::string category;
        int frequency;  // How often asked
        std::vector<std::string> tags;
        std::vector<std::string> relatedQuestions;
        std::optional<std::string> lastUpdated;
    };
    
    FAQLibrary();
    
    // Questions
    void AddQuestion(const Question& q);
    void RemoveQuestion(const std::string& id);
    std::vector<Question> GetQuestions() const;
    std::vector<Question> GetQuestionsByCategory(const std::string& category) const;
    std::vector<Question> GetPopularQuestions(uint32_t count = 10) const;
    std::optional<Question> GetQuestion(const std::string& id) const;
    
    // Search
    std::vector<Question> Search(const std::string& query) const;
    std::vector<Question> Suggest(const std::string& partial) const;
    
    // Export
    std::string GenerateMarkdown() const;
    std::string GenerateHtml() const;
    std::string GenerateJsonLd() const;
    
    // Built-in FAQs
    static std::vector<Question> GetBuiltInFAQs();
    
private:
    std::vector<Question> questions_;
    
    void InitializeBuiltInFAQs();
};

// ============================================================================
// Troubleshooting Guide
// ============================================================================

/**
 * Troubleshooting guide library.
 */
class TroubleshootingLibrary {
public:
    struct Issue {
        std::string id;
        std::string title;
        std::string description;
        std::vector<std::string> symptoms;
        std::vector<std::string> causes;
        std::vector<std::pair<std::string, std::string>> solutions;
        std::string category;
        std::string severity;  // critical, high, medium, low
        std::vector<std::string> tags;
    };
    
    TroubleshootingLibrary();
    
    // Issues
    void AddIssue(const Issue& issue);
    std::vector<Issue> GetIssues() const;
    std::vector<Issue> GetIssuesByCategory(const std::string& category) const;
    std::vector<Issue> GetIssuesBySeverity(const std::string& severity) const;
    std::optional<Issue> GetIssue(const std::string& id) const;
    
    // Diagnosis
    std::vector<Issue> Diagnose(const std::vector<std::string>& symptoms) const;
    std::vector<Issue> Search(const std::string& query) const;
    
    // Export
    std::string GenerateMarkdown() const;
    std::string GenerateHtml() const;
    std::string GenerateDecisionTree() const;
    
    // Built-in issues
    static std::vector<Issue> GetBuiltInIssues();
    
private:
    std::vector<Issue> issues_;
    
    void InitializeBuiltInIssues();
};

// ============================================================================
// Best Practices Library
// ============================================================================

/**
 * Library of best practices.
 */
class BestPracticesLibrary {
public:
    struct Practice {
        std::string id;
        std::string title;
        std::string description;
        std::string rationale;
        std::string category;
        std::vector<std::string> examples;
        std::vector<std::string> antiPatterns;
        std::vector<std::string> references;
        int importance;  // 1-5
        std::vector<std::string> tags;
    };
    
    BestPracticesLibrary();
    
    // Practices
    void AddPractice(const Practice& practice);
    std::vector<Practice> GetPractices() const;
    std::vector<Practice> GetPracticesByCategory(const std::string& category) const;
    std::vector<Practice> GetPracticesByImportance(int minImportance) const;
    std::optional<Practice> GetPractice(const std::string& id) const;
    
    // Checklists
    std::vector<Practice> GetChecklist(const std::string& category) const;
    std::string GenerateChecklistMarkdown(const std::string& category) const;
    
    // Export
    std::string GenerateMarkdown() const;
    std::string GenerateHtml() const;
    
    // Built-in practices
    static std::vector<Practice> GetBuiltInPractices();
    
private:
    std::vector<Practice> practices_;
    
    void InitializeBuiltInPractices();
};

// ============================================================================
// Documentation Generator
// ============================================================================

/**
 * Generates complete documentation from templates.
 */
class DocumentationGenerator {
public:
    struct Config {
        std::string projectName;
        std::string projectDescription;
        std::string projectVersion;
        std::string author;
        std::string license;
        std::string repository;
        std::string outputDirectory;
        std::vector<DocTemplateCategory> categories;
        bool includeExamples = true;
        bool includeGuides = true;
        bool includeGlossary = true;
        bool includeFAQ = true;
        bool includeTroubleshooting = true;
        bool includeBestPractices = true;
    };
    
    explicit DocumentationGenerator(const Config& config);
    
    // Generation
    bool GenerateAll();
    bool GenerateReadme();
    bool GenerateContributing();
    bool GenerateChangelog();
    bool GenerateLicense();
    bool GenerateCodeOfConduct();
    bool GenerateSecurity();
    bool GenerateAPIReference();
    bool GenerateUserGuide();
    bool GenerateTutorials();
    bool GenerateArchitecture();
    bool GenerateDeployment();
    bool GenerateTesting();
    
    // Custom generation
    bool GenerateFromTemplate(const std::string& templateId,
                               const std::string& outputPath);
    bool GenerateSection(const std::string& sectionName,
                         const std::vector<std::string& templateIds);
    
    // Statistics
    struct Stats {
        uint32_t filesGenerated;
        uint32_t templatesUsed;
        uint32_t examplesIncluded;
        uint32_t guidesIncluded;
        uint64_t totalSize;
    };
    Stats GetStats() const;
    
private:
    Config config_;
    Stats stats_;
    
    TemplateLibrary templateLibrary_;
    ExampleLibrary exampleLibrary_;
    GuideLibrary guideLibrary_;
    Glossary glossary_;
    FAQLibrary faqLibrary_;
    TroubleshootingLibrary troubleshootingLibrary_;
    BestPracticesLibrary bestPracticesLibrary_;
    
    bool WriteFile(const std::string& path, const std::string& content);
    std::string GetTemplateVariables() const;
};

// ============================================================================
// Template Variables
// ============================================================================

/**
 * Standard template variables.
 */
struct StandardVariables {
    // Project info
    std::string projectName;
    std::string projectDescription;
    std::string projectVersion;
    std::string projectUrl;
    std::string repositoryUrl;
    std::string documentationUrl;
    
    // Author info
    std::string authorName;
    std::string authorEmail;
    std::string authorUrl;
    std::string organization;
    
    // License
    std::string licenseType;
    std::string licenseUrl;
    std::string copyrightYear;
    
    // Support
    std::string supportEmail;
    std::string issuesUrl;
    std::string discussionsUrl;
    std::string wikiUrl;
    
    // Social
    std::string twitterHandle;
    std::string discordUrl;
    std::string slackUrl;
    
    // Badges
    std::string buildStatusBadge;
    std::string coverageBadge;
    std::string versionBadge;
    std::string licenseBadge;
    std::string downloadsBadge;
    
    std::map<std::string, std::string> ToMap() const;
};

// ============================================================================
// Quick Start
// ============================================================================

/**
 * Quick start guide generator.
 */
class QuickStartGenerator {
public:
    struct Config {
        std::string projectName;
        std::string installCommand;
        std::string quickExample;
        std::string nextStepsUrl;
        std::vector<std::string> prerequisites;
        std::vector<std::pair<std::string, std::string>> commonCommands;
    };
    
    explicit QuickStartGenerator(const Config& config);
    
    std::string GenerateMarkdown() const;
    std::string GenerateHtml() const;
    std::string GenerateTerminal() const;
    
private:
    Config config_;
};

} // namespace Docs
