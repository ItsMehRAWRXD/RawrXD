// Phase D.11 Batch 1/5: Automated Documentation System
// Comprehensive documentation generation and management
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>

namespace Sovereign {
namespace Documentation {

// ============================================================================
// Documentation Types
// ============================================================================

enum class DocFormat {
    MARKDOWN = 0,
    HTML = 1,
    PDF = 2,
    JSON = 3,
    XML = 4,
    MAN_PAGE = 5,
    LATEX = 6
};

enum class DocType {
    API_REFERENCE = 0,
    USER_GUIDE = 1,
    DEVELOPER_GUIDE = 2,
    ARCHITECTURE = 3,
    OPERATIONS = 4,
    TROUBLESHOOTING = 5,
    CHANGELOG = 6,
    FAQ = 7
};

struct Document {
    std::string id;
    std::string title;
    std::string content;
    DocType type;
    DocFormat format;
    std::string version;
    std::vector<std::string> tags;
    std::map<std::string, std::string> metadata;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point updated_at;
    std::string author;
    std::vector<std::string> contributors;
    bool published = false;
};

// ============================================================================
// Code Documentation Parser
// ============================================================================

struct CodeSymbol {
    std::string name;
    std::string type;  // class, function, variable, enum, typedef
    std::string signature;
    std::string description;
    std::vector<std::string> parameters;
    std::string return_description;
    std::vector<std::string> exceptions;
    std::vector<std::string> see_also;
    std::string since_version;
    std::string deprecated;
    std::string file_path;
    int line_number = 0;
    std::string access_level;  // public, private, protected
    std::vector<std::string> template_params;
    std::map<std::string, std::string> annotations;
};

class CodeDocumentationParser {
public:
    struct Config {
        std::vector<std::string> source_paths;
        std::vector<std::string> exclude_patterns;
        std::vector<std::string> languages;  // cpp, python, javascript, etc.
        bool parse_comments = true;
        bool parse_doxygen = true;
        bool parse_javadoc = true;
        bool extract_cross_refs = true;
    };
    
    explicit CodeDocumentationParser(const Config& config);
    
    bool Initialize();
    void Shutdown();
    
    // Parsing
    bool ParseFile(const std::string& path);
    bool ParseDirectory(const std::string& path);
    bool ParseRepository(const std::string& repo_path);
    
    // Symbol access
    std::vector<CodeSymbol> GetSymbols() const;
    std::vector<CodeSymbol> GetSymbolsByType(const std::string& type) const;
    std::vector<CodeSymbol> GetSymbolsByFile(const std::string& file) const;
    CodeSymbol GetSymbol(const std::string& name) const;
    
    // Cross-references
    std::vector<std::string> GetReferences(const std::string& symbol_name) const;
    std::map<std::string, std::vector<std::string>> GetDependencyGraph() const;
    
    // Search
    std::vector<CodeSymbol> Search(const std::string& query);
    std::vector<CodeSymbol> SearchByTag(const std::string& tag);
    
private:
    Config config_;
    std::vector<CodeSymbol> symbols_;
    std::map<std::string, std::vector<std::string>> references_;
    mutable std::mutex symbols_mutex_;
    
    CodeSymbol ParseSymbol(const std::string& source, size_t& pos);
    std::string ExtractComment(const std::string& source, size_t pos);
    void BuildCrossReferences();
};

// ============================================================================
// API Documentation Generator
// ============================================================================

struct APIEndpoint {
    std::string path;
    std::string method;
    std::string summary;
    std::string description;
    std::vector<std::string> tags;
    std::map<std::string, std::string> parameters;
    std::string request_body_schema;
    std::map<int, std::string> responses;
    std::vector<std::string> security;
    std::vector<std::string> examples;
    bool deprecated = false;
};

struct APISchema {
    std::string name;
    std::string type;
    std::map<std::string, APISchema> properties;
    std::vector<std::string> required;
    std::string description;
    std::string example;
    std::vector<std::string> enum_values;
};

class APIDocumentationGenerator {
public:
    struct Config {
        std::string title = "Sovereign API";
        std::string version = "1.0.0";
        std::string description;
        std::vector<std::string> servers;
        bool include_examples = true;
        bool include_schemas = true;
    };
    
    explicit APIDocumentationGenerator(const Config& config);
    
    // Endpoint registration
    void RegisterEndpoint(const APIEndpoint& endpoint);
    void RegisterSchema(const std::string& name, const APISchema& schema);
    
    // Generation
    std::string GenerateOpenAPI3();
    std::string GenerateSwagger2();
    std::string GenerateAsyncAPI();
    std::string GenerateGraphQLSchema();
    
    // Output
    bool WriteToFile(const std::string& path, DocFormat format);
    bool GenerateStaticSite(const std::string& output_dir);
    bool GeneratePDF(const std::string& output_path);
    
    // Client SDK generation
    bool GenerateClientSDK(const std::string& language, const std::string& output_path);
    bool GenerateServerStub(const std::string& language, const std::string& output_path);
    
private:
    Config config_;
    std::vector<APIEndpoint> endpoints_;
    std::map<std::string, APISchema> schemas_;
    
    std::string GenerateOpenAPIPaths();
    std::string GenerateOpenAPIComponents();
};

// ============================================================================
// Documentation Builder
// ============================================================================

class DocumentationBuilder {
public:
    struct Config {
        std::string output_directory;
        std::string template_directory;
        std::string theme = "default";
        bool enable_search = true;
        bool enable_navigation = true;
        bool generate_source_links = true;
        bool minify_output = true;
    };
    
    explicit DocumentationBuilder(const Config& config);
    
    // Content addition
    void AddDocument(const Document& doc);
    void AddCodeDocumentation(const std::vector<CodeSymbol>& symbols);
    void AddAPIDocumentation(const APIDocumentationGenerator& api_docs);
    
    // Building
    bool Build();
    bool BuildIndex();
    bool BuildSearchIndex();
    bool BuildNavigation();
    
    // Output formats
    bool ExportToHTML();
    bool ExportToPDF();
    bool ExportToMarkdown();
    bool ExportToConfluence(const std::string& base_url);
    
    // Theming
    void SetTheme(const std::string& theme_name);
    void CustomizeTheme(const std::map<std::string, std::string>& colors);
    
private:
    Config config_;
    std::vector<Document> documents_;
    std::vector<CodeSymbol> code_symbols_;
    std::unique_ptr<APIDocumentationGenerator> api_docs_;
    
    std::string GenerateHTMLHeader();
    std::string GenerateHTMLFooter();
    std::string GenerateNavigation();
    std::string GenerateSearchBox();
};

// ============================================================================
// Documentation Server
// ============================================================================

class DocumentationServer {
public:
    struct Config {
        int port = 3000;
        std::string bind_address = "0.0.0.0";
        std::string document_root;
        bool enable_hot_reload = true;
        bool enable_auth = false;
        std::map<std::string, std::string> auth_config;
    };
    
    explicit DocumentationServer(const Config& config);
    ~DocumentationServer();
    
    bool Initialize();
    void Shutdown();
    
    // Serving
    bool Start();
    void Stop();
    bool IsRunning() const;
    
    // Content management
    void ServeDirectory(const std::string& path, const std::string& url_prefix);
    void AddRoute(const std::string& path, std::function<std::string()> handler);
    
    // Real-time updates
    void EnableHotReload();
    void BroadcastUpdate(const std::string& document_id);
    
    // Analytics
    struct ViewStats {
        std::string document_id;
        int view_count = 0;
        std::chrono::steady_clock::time_point last_viewed;
        std::vector<std::string> search_terms;
    };
    
    std::vector<ViewStats> GetViewStats() const;
    void TrackSearch(const std::string& query, int results_count);
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    std::thread server_thread_;
    std::map<std::string, ViewStats> view_stats_;
    mutable std::mutex stats_mutex_;
    
    void ServerLoop();
    void HandleRequest(int client_fd);
};

// ============================================================================
// Documentation Versioning
// ============================================================================

class DocumentationVersioning {
public:
    struct Version {
        std::string version_string;
        std::string tag;
        std::chrono::steady_clock::time_point released_at;
        std::string changelog;
        bool is_latest = false;
        bool is_deprecated = false;
    };
    
    // Version management
    void CreateVersion(const std::string& version, const std::string& tag);
    void DeprecateVersion(const std::string& version);
    void SetLatestVersion(const std::string& version);
    
    // Version access
    std::vector<Version> GetVersions() const;
    Version GetVersion(const std::string& version) const;
    Version GetLatestVersion() const;
    
    // Comparison
    std::vector<std::string> GetChangesBetween(const std::string& from, 
                                                const std::string& to);
    bool IsVersionDeprecated(const std::string& version) const;
    
    // Migration guides
    std::string GenerateMigrationGuide(const std::string& from, 
                                        const std::string& to);
    
private:
    std::vector<Version> versions_;
    mutable std::mutex versions_mutex_;
};

// ============================================================================
// Documentation Runtime
// ============================================================================

class DocumentationRuntime {
public:
    struct Config {
        CodeDocumentationParser::Config parser;
        APIDocumentationGenerator::Config api_generator;
        DocumentationBuilder::Config builder;
        DocumentationServer::Config server;
    };
    
    explicit DocumentationRuntime(const Config& config);
    ~DocumentationRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    CodeDocumentationParser* GetParser();
    APIDocumentationGenerator* GetAPIGenerator();
    DocumentationBuilder* GetBuilder();
    DocumentationServer* GetServer();
    DocumentationVersioning* GetVersioning();
    
    // Workflow
    bool ParseSourceCode(const std::string& path);
    bool GenerateAPIDocs();
    bool BuildDocumentation();
    bool ServeDocumentation();
    
    // Integration
    bool IntegrateWithCI(const std::string& ci_config_path);
    bool AutoGenerateOnCommit(const std::string& repo_path);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<CodeDocumentationParser> parser_;
    std::unique_ptr<APIDocumentationGenerator> api_generator_;
    std::unique_ptr<DocumentationBuilder> builder_;
    std::unique_ptr<DocumentationServer> server_;
    std::unique_ptr<DocumentationVersioning> versioning_;
};

} // namespace Documentation
} // namespace Sovereign
