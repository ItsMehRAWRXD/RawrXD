/**
 * DocumentationServer.hpp
 *
 * Phase J Batch 4/5: Documentation Server & Portal
 *
 * Web-based documentation server with search, versioning,
 * and interactive features.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>

namespace Docs {

// ============================================================================
// Forward Declarations
// ============================================================================

class DocumentationServer;
class DocumentationPortal;
class SearchEngine;
class VersionManager;

// ============================================================================
// Documentation Page
// ============================================================================

/**
 * Single documentation page.
 */
struct DocPage {
    std::string id;
    std::string title;
    std::string path;
    std::string content;
    std::string html;
    std::string category;
    std::vector<std::string> tags;
    std::map<std::string, std::string> metadata;
    uint64_t lastModified;
    uint32_t viewCount;
    
    // Navigation
    std::optional<std::string> previousPage;
    std::optional<std::string> nextPage;
    std::optional<std::string> parentPage;
    std::vector<std::string> childPages;
};

// ============================================================================
// Documentation Section
// ============================================================================

/**
 * Documentation section/category.
 */
struct DocSection {
    std::string id;
    std::string title;
    std::string description;
    std::string icon;
    int order;
    std::vector<DocPage> pages;
    std::vector<DocSection> subsections;
};

// ============================================================================
// Search Result
// ============================================================================

/**
 * Search result.
 */
struct SearchResult {
    std::string pageId;
    std::string title;
    std::string excerpt;
    std::string url;
    double relevance;
    std::vector<std::string> matchedTerms;
    std::optional<std::string> highlight;
};

// ============================================================================
// Search Engine
// ============================================================================

/**
 * Full-text search engine for documentation.
 */
class SearchEngine {
public:
    struct Config {
        bool enableStemming = true;
        bool enableSynonyms = false;
        bool enableFuzzy = true;
        double fuzzyThreshold = 0.7;
        uint32_t maxResults = 50;
        uint32_t snippetLength = 200;
    };
    
    explicit SearchEngine(const Config& config);
    ~SearchEngine();
    
    // Indexing
    void IndexPage(const DocPage& page);
    void IndexPages(const std::vector<DocPage>& pages);
    void RemovePage(const std::string& pageId);
    void ClearIndex();
    
    // Search
    std::vector<SearchResult> Search(const std::string& query);
    std::vector<SearchResult> Search(const std::string& query,
                                         const std::vector<std::string>& categories);
    std::vector<SearchResult> Search(const std::string& query, uint32_t maxResults);
    
    // Suggestions
    std::vector<std::string> GetSuggestions(const std::string& partial);
    std::vector<std::string> GetRelatedQueries(const std::string& query);
    
    // Facets
    std::map<std::string, uint32_t> GetCategoryFacets(const std::string& query);
    std::map<std::string, uint32_t> GetTagFacets(const std::string& query);
    
    // Statistics
    struct Stats {
        uint32_t totalDocuments;
        uint32_t totalTerms;
        double averageDocumentLength;
        uint64_t indexSize;
    };
    Stats GetStats() const;
    
    // Synonyms
    void AddSynonym(const std::string& term, const std::string& synonym);
    void RemoveSynonym(const std::string& term, const std::string& synonym);
    
    // Stop words
    void AddStopWord(const std::string& word);
    void RemoveStopWord(const std::string& word);
    
private:
    Config config_;
    
    struct IndexEntry {
        std::string term;
        std::map<std::string, std::vector<uint32_t>> positions;  // pageId -> positions
        uint32_t documentFrequency;
    };
    
    std::map<std::string, IndexEntry> index_;  // term -> entry
    std::map<std::string, DocPage> pages_;     // pageId -> page
    std::map<std::string, std::set<std::string>> synonyms_;
    std::set<std::string> stopWords_;
    mutable std::mutex mutex_;
    
    std::vector<std::string> Tokenize(const std::string& text);
    std::string Stem(const std::string& word);
    double CalculateTfIdf(const std::string& term, const std::string& pageId);
    std::string GenerateSnippet(const std::string& content,
                                 const std::vector<std::string>& terms);
};

// ============================================================================
// Version Manager
// ============================================================================

/**
 * Documentation version management.
 */
class VersionManager {
public:
    struct Version {
        std::string name;
        std::string displayName;
        std::string path;
        bool isDefault;
        bool isStable;
        bool isLatest;
        std::string releaseDate;
        std::string eolDate;
        std::string baseUrl;
    };
    
    VersionManager(const std::string& versionsFile);
    
    // Versions
    void AddVersion(const Version& version);
    void RemoveVersion(const std::string& name);
    std::vector<Version> GetVersions() const;
    std::optional<Version> GetVersion(const std::string& name) const;
    std::optional<Version> GetDefaultVersion() const;
    std::optional<Version> GetLatestVersion() const;
    std::optional<Version> GetStableVersion() const;
    
    // Switching
    void SetDefaultVersion(const std::string& name);
    std::string GetVersionForPath(const std::string& path) const;
    std::string NormalizePath(const std::string& path) const;
    
    // Comparison
    int CompareVersions(const std::string& v1, const std::string& v2) const;
    bool IsVersionInRange(const std::string& version,
                          const std::string& min,
                          const std::string& max) const;
    
    // Redirects
    void AddRedirect(const std::string& from, const std::string& to);
    std::optional<std::string> GetRedirect(const std::string& path) const;
    
    // Diff
    struct DiffResult {
        std::vector<std::string> added;
        std::vector<std::string> removed;
        std::vector<std::string> modified;
    };
    DiffResult DiffVersions(const std::string& v1, const std::string& v2) const;
    
private:
    std::vector<Version> versions_;
    std::map<std::string, std::string> redirects_;
    mutable std::mutex mutex_;
    
    std::vector<int> ParseVersion(const std::string& version) const;
};

// ============================================================================
// Documentation Server
// ============================================================================

/**
 * HTTP server for documentation.
 */
class DocumentationServer {
public:
    struct Config {
        std::string bindAddress = "0.0.0.0";
        uint16_t port = 8080;
        std::string documentRoot;
        std::string basePath = "/";
        bool enableCors = true;
        bool enableCompression = true;
        bool enableCaching = true;
        uint64_t cacheMaxAge = 3600;
        std::string sslCert;
        std::string sslKey;
        bool enableSearch = true;
        bool enableVersions = true;
    };
    
    explicit DocumentationServer(const Config& config);
    ~DocumentationServer();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsRunning() const;
    
    // Content
    void SetContentProvider(std::function<std::optional<DocPage>(const std::string&)> provider);
    void SetSectionProvider(std::function<std::vector<DocSection>()> provider);
    
    // Search
    void SetSearchEngine(std::shared_ptr<SearchEngine> engine);
    
    // Versions
    void SetVersionManager(std::shared_ptr<VersionManager> manager);
    
    // Handlers
    using RequestHandler = std::function<std::string(const std::map<std::string, std::string>&)>;
    void RegisterHandler(const std::string& path, RequestHandler handler);
    void RegisterStaticFiles(const std::string& urlPath, const std::string& dirPath);
    
    // Middleware
    using MiddlewareFunc = std::function<bool(const std::map<std::string, std::string>&,
                                                  std::map<std::string, std::string>&)>;
    void AddMiddleware(MiddlewareFunc middleware);
    
    // Start/Stop
    void Start();
    void Stop();
    
    // Status
    struct Status {
        bool running;
        uint32_t activeConnections;
        uint64_t totalRequests;
        uint64_t uptimeSeconds;
    };
    Status GetStatus() const;
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    std::atomic<bool> initialized_{false};
    
    std::function<std::optional<DocPage>(const std::string&)> contentProvider_;
    std::function<std::vector<DocSection>()> sectionProvider_;
    std::shared_ptr<SearchEngine> searchEngine_;
    std::shared_ptr<VersionManager> versionManager_;
    
    std::map<std::string, RequestHandler> handlers_;
    std::map<std::string, std::string> staticFiles_;
    std::vector<MiddlewareFunc> middleware_;
    
    std::thread serverThread_;
    void* serverHandle_ = nullptr;
    
    void ServerLoop();
    void HandleRequest(void* connection);
    std::string RenderPage(const DocPage& page);
    std::string RenderSearchResults(const std::vector<SearchResult>& results);
    std::string RenderError(int code, const std::string& message);
};

// ============================================================================
// Documentation Portal
// ============================================================================

/**
 * Complete documentation portal.
 */
class DocumentationPortal {
public:
    struct Config {
        std::string title;
        std::string description;
        std::string logo;
        std::string favicon;
        std::string primaryColor;
        std::string accentColor;
        std::string googleAnalyticsId;
        std::string algoliaAppId;
        std::string algoliaApiKey;
        std::string algoliaIndexName;
        bool enableDarkMode = true;
        bool enableEditLink = true;
        std::string editUrlTemplate;
        bool enableLastModified = true;
        bool enableFeedback = true;
        bool enableShare = true;
        bool enablePrint = true;
        bool enablePdfExport = true;
    };
    
    explicit DocumentationPortal(const Config& config);
    
    // Content
    void AddPage(const DocPage& page);
    void AddSection(const DocSection& section);
    void SetPages(const std::vector<DocPage>& pages);
    void SetSections(const std::vector<DocSection>& sections);
    
    // Navigation
    void SetHomePage(const std::string& pageId);
    void SetNotFoundPage(const std::string& pageId);
    void AddToSidebar(const std::string& section, const std::string& pageId);
    void AddToHeader(const std::string& title, const std::string& url);
    void AddToFooter(const std::string& title, const std::string& url);
    
    // Features
    void EnableFeature(const std::string& feature);
    void DisableFeature(const std::string& feature);
    void ConfigureFeature(const std::string& feature,
                        const std::map<std::string, std::string>& options);
    
    // Search
    void ConfigureSearch(const std::map<std::string, std::string>& options);
    void SetSearchEngine(std::shared_ptr<SearchEngine> engine);
    
    // Versions
    void ConfigureVersions(const std::vector<VersionManager::Version>& versions);
    void SetVersionManager(std::shared_ptr<VersionManager> manager);
    
    // API
    void SetOpenApiSpec(const std::string& url);
    void SetGraphQlEndpoint(const std::string& url);
    
    // Build
    bool Build(const std::string& outputDirectory);
    bool BuildStatic(const std::string& outputDirectory);
    bool BuildServer(const std::string& outputDirectory);
    
    // Serve
    void Serve(uint16_t port = 8080);
    void Stop();
    
    // Export
    bool ExportToPdf(const std::string& outputPath);
    bool ExportToEpub(const std::string& outputPath);
    bool ExportToMobi(const std::string& outputPath);
    
private:
    Config config_;
    std::vector<DocPage> pages_;
    std::vector<DocSection> sections_;
    std::map<std::string, std::vector<std::string>> sidebar_;
    std::vector<std::pair<std::string, std::string>> headerLinks_;
    std::vector<std::pair<std::string, std::string>> footerLinks_;
    
    std::shared_ptr<SearchEngine> searchEngine_;
    std::shared_ptr<VersionManager> versionManager_;
    std::shared_ptr<DocumentationServer> server_;
    
    std::string homePageId_;
    std::string notFoundPageId_;
    std::string openApiSpec_;
    std::string graphQlEndpoint_;
    
    std::string GenerateHtml(const DocPage& page);
    std::string GenerateSidebar();
    std::string GenerateHeader();
    std::string GenerateFooter();
    std::string GenerateSearchPage();
    std::string GenerateVersionSelector();
};

// ============================================================================
// Theme System
// ============================================================================

/**
 * Documentation theme system.
 */
class DocTheme {
public:
    struct Colors {
        std::string primary;
        std::string secondary;
        std::string accent;
        std::string background;
        std::string surface;
        std::string text;
        std::string textMuted;
        std::string border;
        std::string success;
        std::string warning;
        std::string error;
        std::string info;
    };
    
    struct Typography {
        std::string fontFamily;
        std::string fontFamilyMono;
        int baseSize;
        double lineHeight;
        std::map<std::string, int> headingSizes;
    };
    
    struct Layout {
        int maxWidth;
        int sidebarWidth;
        int tocWidth;
        std::string sidebarPosition;  // left, right
        bool stickyHeader;
        bool stickySidebar;
    };
    
    struct Components {
        int borderRadius;
        int spacing;
        std::string buttonStyle;  // filled, outlined, text
        bool enableShadows;
        bool enableAnimations;
    };
    
    struct Config {
        std::string name;
        Colors colors;
        Typography typography;
        Layout layout;
        Components components;
        std::map<std::string, std::string> customCss;
        std::map<std::string, std::string> customJs;
    };
    
    explicit DocTheme(const Config& config);
    
    // CSS generation
    std::string GenerateCss() const;
    std::string GenerateVariables() const;
    
    // Customization
    void SetColor(const std::string& name, const std::string& value);
    void SetFont(const std::string& name, const std::string& value);
    void AddCustomCss(const std::string& selector, const std::string& rules);
    void AddCustomJs(const std::string& name, const std::string& code);
    
    // Presets
    static DocTheme Default();
    static DocTheme Dark();
    static DocTheme Minimal();
    static DocTheme Modern();
    static DocTheme Classic();
    
private:
    Config config_;
};

// ============================================================================
// Plugin System
// ============================================================================

/**
 * Plugin system for documentation.
 */
class DocPlugin {
public:
    virtual ~DocPlugin() = default;
    
    virtual std::string GetName() const = 0;
    virtual std::string GetVersion() const = 0;
    virtual std::string GetDescription() const = 0;
    
    virtual bool Initialize(DocumentationPortal* portal) = 0;
    virtual void Shutdown() = 0;
    
    virtual void OnPageRender(DocPage& page) {}
    virtual void OnSearch(SearchEngine* engine) {}
    virtual void OnBuild(const std::string& outputDirectory) {}
};

/**
 * Plugin manager.
 */
class PluginManager {
public:
    void LoadPlugin(std::shared_ptr<DocPlugin> plugin);
    void UnloadPlugin(const std::string& name);
    std::vector<std::shared_ptr<DocPlugin>> GetPlugins() const;
    std::shared_ptr<DocPlugin> GetPlugin(const std::string& name) const;
    
    void InitializeAll(DocumentationPortal* portal);
    void ShutdownAll();
    
    void NotifyPageRender(DocPage& page);
    void NotifySearch(SearchEngine* engine);
    void NotifyBuild(const std::string& outputDirectory);
    
private:
    std::vector<std::shared_ptr<DocPlugin>> plugins_;
    mutable std::mutex mutex_;
};

} // namespace Docs
