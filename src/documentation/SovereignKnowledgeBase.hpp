// Phase D.11 Batch 3/5: Knowledge Base
// Searchable wiki, troubleshooting guides, and FAQs
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
// Knowledge Base Types
// ============================================================================

enum class ArticleType {
    TROUBLESHOOTING = 0,
    HOW_TO = 1,
    FAQ = 2,
    CONCEPT = 3,
    REFERENCE = 4,
    TUTORIAL = 5,
    BEST_PRACTICE = 6
};

enum class ArticleStatus {
    DRAFT = 0,
    REVIEW = 1,
    PUBLISHED = 2,
    ARCHIVED = 3
};

struct KnowledgeArticle {
    std::string id;
    std::string title;
    std::string content;
    ArticleType type;
    ArticleStatus status;
    std::vector<std::string> tags;
    std::vector<std::string> categories;
    std::vector<std::string> related_articles;
    std::vector<std::string> related_issues;
    std::map<std::string, std::string> metadata;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point updated_at;
    std::string author;
    std::vector<std::string> contributors;
    int view_count = 0;
    int helpful_count = 0;
    int not_helpful_count = 0;
    double rating = 0.0;
};

struct FAQEntry {
    std::string id;
    std::string question;
    std::string answer;
    std::vector<std::string> tags;
    std::vector<std::string> related_faqs;
    int view_count = 0;
    int helpful_count = 0;
    ArticleStatus status = ArticleStatus::PUBLISHED;
};

struct TroubleshootingGuide {
    std::string id;
    std::string title;
    std::string description;
    std::vector<std::string> symptoms;
    std::vector<std::string> causes;
    std::vector<std::pair<std::string, std::string>> solutions;
    std::vector<std::string> prevention_tips;
    std::vector<std::string> related_guides;
    std::map<std::string, std::string> diagnostic_commands;
};

// ============================================================================
// Knowledge Base Engine
// ============================================================================

class KnowledgeBaseEngine {
public:
    struct Config {
        std::string storage_path;
        bool enable_full_text_search = true;
        bool enable_semantic_search = true;
        int search_result_limit = 20;
        float relevance_threshold = 0.7f;
    };
    
    explicit KnowledgeBaseEngine(const Config& config);
    ~KnowledgeBaseEngine();
    
    bool Initialize();
    void Shutdown();
    
    // Article management
    bool CreateArticle(const KnowledgeArticle& article);
    bool UpdateArticle(const std::string& id, const KnowledgeArticle& article);
    bool DeleteArticle(const std::string& id);
    KnowledgeArticle GetArticle(const std::string& id) const;
    
    // Search
    std::vector<KnowledgeArticle> Search(const std::string& query) const;
    std::vector<KnowledgeArticle> SearchByTag(const std::string& tag) const;
    std::vector<KnowledgeArticle> SearchByCategory(const std::string& category) const;
    std::vector<KnowledgeArticle> SemanticSearch(const std::string& query) const;
    
    // Advanced search
    std::vector<KnowledgeArticle> AdvancedSearch(
        const std::string& query,
        const std::vector<ArticleType>& types,
        const std::vector<std::string>& categories,
        const std::vector<std::string>& tags);
    
    // Auto-complete
    std::vector<std::string> GetSuggestions(const std::string& partial_query) const;
    
    // Indexing
    bool RebuildIndex();
    bool IndexArticle(const KnowledgeArticle& article);
    bool RemoveFromIndex(const std::string& id);
    
private:
    Config config_;
    std::map<std::string, KnowledgeArticle> articles_;
    mutable std::mutex articles_mutex_;
    
    // Search index
    struct SearchIndex {
        std::map<std::string, std::vector<std::string>> term_to_articles;
        std::map<std::string, std::vector<float>> article_vectors;
    };
    
    SearchIndex index_;
    mutable std::mutex index_mutex_;
    
    std::vector<std::string> Tokenize(const std::string& text) const;
    float CalculateRelevance(const std::string& query, const KnowledgeArticle& article) const;
    std::vector<float> Vectorize(const std::string& text) const;
};

// ============================================================================
// FAQ Manager
// ============================================================================

class FAQManager {
public:
    struct Config {
        bool enable_auto_categorization = true;
        bool enable_duplicate_detection = true;
        float similarity_threshold = 0.85f;
    };
    
    explicit FAQManager(const Config& config);
    
    // FAQ management
    bool AddFAQ(const FAQEntry& faq);
    bool UpdateFAQ(const std::string& id, const FAQEntry& faq);
    bool DeleteFAQ(const std::string& id);
    FAQEntry GetFAQ(const std::string& id) const;
    
    // Search
    std::vector<FAQEntry> Search(const std::string& query) const;
    std::vector<FAQEntry> SearchByTag(const std::string& tag) const;
    FAQEntry FindBestMatch(const std::string& question) const;
    
    // Auto-generation
    std::vector<FAQEntry> GenerateFromSupportTickets(const std::string& tickets_path);
    std::vector<FAQEntry> GenerateFromDocumentation(const std::string& docs_path);
    
    // Analytics
    std::vector<FAQEntry> GetMostViewed(int limit = 10) const;
    std::vector<FAQEntry> GetMostHelpful(int limit = 10) const;
    std::vector<FAQEntry> GetUnhelpfulFAQs() const;
    
    // Feedback
    void RecordFeedback(const std::string& faq_id, bool helpful);
    
private:
    Config config_;
    std::map<std::string, FAQEntry> faqs_;
    mutable std::mutex faqs_mutex_;
    
    float CalculateSimilarity(const std::string& q1, const std::string& q2) const;
};

// ============================================================================
// Troubleshooting Guide Manager
// ============================================================================

class TroubleshootingManager {
public:
    // Guide management
    bool AddGuide(const TroubleshootingGuide& guide);
    bool UpdateGuide(const std::string& id, const TroubleshootingGuide& guide);
    bool DeleteGuide(const std::string& id);
    TroubleshootingGuide GetGuide(const std::string& id) const;
    
    // Symptom-based search
    std::vector<TroubleshootingGuide> FindBySymptom(const std::string& symptom) const;
    std::vector<TroubleshootingGuide> FindByError(const std::string& error_message) const;
    std::vector<TroubleshootingGuide> FindByLogPattern(const std::string& log_pattern) const;
    
    // Diagnostic flow
    struct DiagnosticStep {
        std::string question;
        std::vector<std::pair<std::string, std::string>> options;
        std::string next_step_if_yes;
        std::string next_step_if_no;
        std::string solution;
    };
    
    std::vector<DiagnosticStep> BuildDiagnosticFlow(const std::string& symptom);
    
    // Interactive troubleshooting
    std::string GetNextDiagnosticQuestion(const std::vector<std::string>& answers);
    std::string GetRecommendedSolution(const std::vector<std::string>& symptoms);
    
    // Auto-generation from incidents
    TroubleshootingGuide GenerateFromIncident(const std::string& incident_id);
    
private:
    std::map<std::string, TroubleshootingGuide> guides_;
    mutable std::mutex guides_mutex_;
};

// ============================================================================
// Wiki System
// ============================================================================

struct WikiPage {
    std::string id;
    std::string title;
    std::string content;
    std::string parent_id;
    std::vector<std::string> child_ids;
    std::vector<std::string> tags;
    int version = 1;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point updated_at;
    std::string author;
    std::string last_editor;
    bool is_protected = false;
};

class WikiSystem {
public:
    struct Config {
        std::string storage_path;
        bool enable_versioning = true;
        int max_versions = 50;
        bool enable_markdown = true;
        bool enable_wysiwyg = true;
    };
    
    explicit WikiSystem(const Config& config);
    
    // Page management
    bool CreatePage(const WikiPage& page);
    bool UpdatePage(const std::string& id, const WikiPage& page);
    bool DeletePage(const std::string& id);
    WikiPage GetPage(const std::string& id) const;
    WikiPage GetPageByPath(const std::string& path) const;
    
    // Hierarchy
    std::vector<WikiPage> GetChildPages(const std::string& parent_id) const;
    std::vector<WikiPage> GetRootPages() const;
    std::vector<std::string> GetPagePath(const std::string& id) const;
    bool MovePage(const std::string& id, const std::string& new_parent_id);
    
    // Versioning
    std::vector<WikiPage> GetPageVersions(const std::string& id) const;
    bool RevertToVersion(const std::string& id, int version);
    WikiPage CompareVersions(const std::string& id, int v1, int v2);
    
    // Links
    std::vector<std::string> GetOutgoingLinks(const std::string& id) const;
    std::vector<std::string> GetIncomingLinks(const std::string& id) const;
    std::vector<WikiPage> GetOrphanedPages() const;
    
    // Search
    std::vector<WikiPage> Search(const std::string& query) const;
    std::vector<WikiPage> SearchByTag(const std::string& tag) const;
    
private:
    Config config_;
    std::map<std::string, WikiPage> pages_;
    std::map<std::string, std::vector<WikiPage>> versions_;
    mutable std::mutex pages_mutex_;
};

// ============================================================================
// Content Recommendation
// ============================================================================

class ContentRecommendation {
public:
    // Personalized recommendations
    std::vector<KnowledgeArticle> RecommendForUser(const std::string& user_id,
                                                  int limit = 5);
    std::vector<FAQEntry> RecommendFAQs(const std::string& context, int limit = 5);
    std::vector<TroubleshootingGuide> RecommendGuides(const std::string& issue_description);
    
    // Related content
    std::vector<KnowledgeArticle> GetRelatedArticles(const std::string& article_id);
    std::vector<WikiPage> GetRelatedPages(const std::string& page_id);
    
    // Trending content
    std::vector<KnowledgeArticle> GetTrendingArticles(int limit = 10);
    std::vector<WikiPage> GetTrendingPages(int limit = 10);
    
    // Gap analysis
    std::vector<std::string> IdentifyContentGaps();
    std::vector<std::string> SuggestNewArticles();
    
private:
    std::map<std::string, std::vector<std::string>> user_history_;
    mutable std::mutex history_mutex_;
};

// ============================================================================
// Knowledge Base Analytics
// ============================================================================

struct KnowledgeBaseMetrics {
    int total_articles = 0;
    int total_faqs = 0;
    int total_guides = 0;
    int total_wiki_pages = 0;
    
    std::map<ArticleType, int> articles_by_type;
    std::map<ArticleStatus, int> articles_by_status;
    
    int total_views = 0;
    int total_searches = 0;
    double avg_search_results = 0.0;
    double search_success_rate = 0.0;
    
    std::vector<std::pair<std::string, int>> top_searches;
    std::vector<std::pair<std::string, int>> failed_searches;
};

class KnowledgeBaseAnalytics {
public:
    // Metrics collection
    void RecordArticleView(const std::string& article_id);
    void RecordSearch(const std::string& query, int results_count, bool success);
    void RecordFeedback(const std::string& content_id, bool helpful);
    
    // Reports
    KnowledgeBaseMetrics GetMetrics() const;
    void GenerateUsageReport(const std::string& output_path);
    void GenerateContentQualityReport(const std::string& output_path);
    
    // Insights
    std::vector<std::string> GetPopularSearchTerms() const;
    std::vector<std::string> GetUnansweredQueries() const;
    std::vector<KnowledgeArticle> GetUnderperformingContent() const;
    
    // Improvement suggestions
    std::vector<std::string> SuggestContentImprovements();
    std::vector<std::string> IdentifyOutdatedContent();
    
private:
    KnowledgeBaseMetrics metrics_;
    mutable std::mutex metrics_mutex_;
    
    std::vector<std::string> search_queries_;
    std::map<std::string, int> query_counts_;
};

// ============================================================================
// Knowledge Base Runtime
// ============================================================================

class KnowledgeBaseRuntime {
public:
    struct Config {
        KnowledgeBaseEngine::Config engine;
        FAQManager::Config faq;
        TroubleshootingManager::Config troubleshooting;
        WikiSystem::Config wiki;
    };
    
    explicit KnowledgeBaseRuntime(const Config& config);
    ~KnowledgeBaseRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    KnowledgeBaseEngine* GetEngine();
    FAQManager* GetFAQManager();
    TroubleshootingManager* GetTroubleshootingManager();
    WikiSystem* GetWikiSystem();
    ContentRecommendation* GetRecommendationEngine();
    KnowledgeBaseAnalytics* GetAnalytics();
    
    // Unified search
    struct SearchResult {
        enum ResultType { ARTICLE, FAQ, GUIDE, WIKI } type;
        std::string id;
        std::string title;
        std::string snippet;
        float relevance = 0.0f;
    };
    
    std::vector<SearchResult> UnifiedSearch(const std::string& query);
    
    // Import/Export
    bool ImportFromConfluence(const std::string& export_path);
    bool ImportFromMarkdown(const std::string& directory);
    bool ExportToHTML(const std::string& output_dir);
    bool ExportToPDF(const std::string& output_path);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<KnowledgeBaseEngine> engine_;
    std::unique_ptr<FAQManager> faq_manager_;
    std::unique_ptr<TroubleshootingManager> troubleshooting_;
    std::unique_ptr<WikiSystem> wiki_;
    std::unique_ptr<ContentRecommendation> recommendation_;
    std::unique_ptr<KnowledgeBaseAnalytics> analytics_;
};

} // namespace Documentation
} // namespace Sovereign
