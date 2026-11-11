// Win32IDE_ProjectRagLite.cpp - Full Implementation
// Semantic code search using vector embeddings and local vector database
// Enables natural language search across project files

#include "Win32IDE.h"
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <queue>
#include <mutex>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <cmath>
#include <chrono>

namespace RawrXD {
namespace Search {

// ============================================================================
// Vector Embedding (Simplified TF-IDF + Cosine Similarity)
// ============================================================================

struct DocumentEmbedding
{
    std::string filePath;
    std::string content;
    std::map<std::string, float> termFrequencies;
    std::vector<float> vector;
    std::chrono::system_clock::time_point lastIndexed;
    size_t tokenCount = 0;
};

struct SearchResult
{
    std::string filePath;
    float relevanceScore;
    std::string matchedExcerpt;
    size_t lineNumber;
};

// Simple tokenizer for code
static std::vector<std::string> Tokenize(const std::string& text)
{
    std::vector<std::string> tokens;
    std::string current;
    
    for (char c : text)
    {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_')
        {
            current += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        else if (!current.empty())
        {
            if (current.length() > 2) // Filter out very short tokens
                tokens.push_back(current);
            current.clear();
        }
    }
    
    if (!current.empty() && current.length() > 2)
        tokens.push_back(current);
    
    return tokens;
}

static std::map<std::string, float> ComputeTFIDF(const std::vector<std::string>& tokens, 
                                                   const std::map<std::string, size_t>& documentFrequency,
                                                   size_t totalDocuments)
{
    std::map<std::string, size_t> termCounts;
    for (const auto& token : tokens)
    {
        termCounts[token]++;
    }
    
    std::map<std::string, float> tfidf;
    for (const auto& [term, count] : termCounts)
    {
        float tf = static_cast<float>(count) / tokens.size();
        auto dfIt = documentFrequency.find(term);
        size_t df = (dfIt != documentFrequency.end()) ? dfIt->second : 1;
        float idf = std::log(static_cast<float>(totalDocuments) / df);
        tfidf[term] = tf * idf;
    }
    
    return tfidf;
}

static float CosineSimilarity(const std::map<std::string, float>& vec1, 
                               const std::map<std::string, float>& vec2)
{
    float dotProduct = 0.0f;
    float mag1 = 0.0f;
    float mag2 = 0.0f;
    
    for (const auto& [term, weight] : vec1)
    {
        mag1 += weight * weight;
        auto it = vec2.find(term);
        if (it != vec2.end())
        {
            dotProduct += weight * it->second;
        }
    }
    
    for (const auto& [term, weight] : vec2)
    {
        mag2 += weight * weight;
    }
    
    if (mag1 == 0.0f || mag2 == 0.0f) return 0.0f;
    
    return dotProduct / (std::sqrt(mag1) * std::sqrt(mag2));
}

// ============================================================================
// ProjectRagLite Index Manager
// ============================================================================

class ProjectIndex
{
private:
    std::map<std::string, DocumentEmbedding> m_documents;
    std::map<std::string, size_t> m_documentFrequency;
    mutable std::mutex m_mutex;
    std::string m_projectRoot;
    std::set<std::string> m_extensions;
    size_t m_maxFileSize = 1024 * 1024; // 1MB max
    
public:
    ProjectIndex() 
    {
        // Supported code file extensions
        m_extensions = {
            ".cpp", ".h", ".hpp", ".c", ".cc",
            ".py", ".js", ".ts", ".java", ".cs",
            ".go", ".rs", ".swift", ".kt", ".scala",
            ".rb", ".php", ".sh", ".ps1", ".bat",
            ".md", ".txt", ".json", ".xml", ".yaml", ".yml"
        };
    }
    
    void SetProjectRoot(const std::string& root) { m_projectRoot = root; }
    
    bool IndexFile(const std::string& filePath)
    {
        std::filesystem::path p(filePath);
        std::string ext = p.extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), 
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        
        if (m_extensions.find(ext) == m_extensions.end())
            return false;
        
        std::error_code ec;
        auto fileSize = std::filesystem::file_size(p, ec);
        if (ec || fileSize > m_maxFileSize)
            return false;
        
        std::ifstream file(filePath);
        if (!file) return false;
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string content = buffer.str();
        
        auto tokens = Tokenize(content);
        if (tokens.empty()) return false;
        
        DocumentEmbedding doc;
        doc.filePath = filePath;
        doc.content = content;
        doc.tokenCount = tokens.size();
        doc.lastIndexed = std::chrono::system_clock::now();
        
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            
            // Update document frequency
            std::set<std::string> uniqueTerms(tokens.begin(), tokens.end());
            for (const auto& term : uniqueTerms)
            {
                m_documentFrequency[term]++;
            }
            
            // Compute TF-IDF
            doc.termFrequencies = ComputeTFIDF(tokens, m_documentFrequency, m_documents.size() + 1);
            m_documents[filePath] = std::move(doc);
        }
        
        return true;
    }
    
    size_t IndexDirectory(const std::string& dirPath, bool recursive = true)
    {
        size_t count = 0;
        std::error_code ec;
        
        if (recursive)
        {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(dirPath, ec))
            {
                if (ec) continue;
                if (entry.is_regular_file(ec))
                {
                    if (IndexFile(entry.path().string()))
                        count++;
                }
            }
        }
        else
        {
            for (const auto& entry : std::filesystem::directory_iterator(dirPath, ec))
            {
                if (ec) continue;
                if (entry.is_regular_file(ec))
                {
                    if (IndexFile(entry.path().string()))
                        count++;
                }
            }
        }
        
        return count;
    }
    
    std::vector<SearchResult> Search(const std::string& query, size_t maxResults = 10)
    {
        std::vector<SearchResult> results;
        
        auto queryTokens = Tokenize(query);
        if (queryTokens.empty()) return results;
        
        std::map<std::string, float> queryVector;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            queryVector = ComputeTFIDF(queryTokens, m_documentFrequency, m_documents.size());
            
            for (const auto& [path, doc] : m_documents)
            {
                float score = CosineSimilarity(queryVector, doc.termFrequencies);
                if (score > 0.01f) // Minimum relevance threshold
                {
                    SearchResult result;
                    result.filePath = path;
                    result.relevanceScore = score;
                    
                    // Find best matching excerpt
                    size_t bestPos = 0;
                    float bestExcerptScore = 0.0f;
                    
                    for (size_t i = 0; i < doc.content.length() - 100; i += 50)
                    {
                        std::string excerpt = doc.content.substr(i, 200);
                        auto excerptTokens = Tokenize(excerpt);
                        auto excerptVec = ComputeTFIDF(excerptTokens, m_documentFrequency, m_documents.size());
                        float excerptScore = CosineSimilarity(queryVector, excerptVec);
                        
                        if (excerptScore > bestExcerptScore)
                        {
                            bestExcerptScore = excerptScore;
                            bestPos = i;
                        }
                    }
                    
                    result.matchedExcerpt = doc.content.substr(bestPos, 200);
                    result.lineNumber = std::count(doc.content.begin(), doc.content.begin() + bestPos, '\n') + 1;
                    
                    results.push_back(result);
                }
            }
        }
        
        // Sort by relevance
        std::sort(results.begin(), results.end(), 
            [](const SearchResult& a, const SearchResult& b) {
                return a.relevanceScore > b.relevanceScore;
            });
        
        if (results.size() > maxResults)
            results.resize(maxResults);
        
        return results;
    }
    
    size_t GetDocumentCount() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_documents.size();
    }
    
    void Clear()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_documents.clear();
        m_documentFrequency.clear();
    }
};

static std::unique_ptr<ProjectIndex> g_projectIndex;
static std::atomic<bool> g_ragLiteInitialized{false};

// ============================================================================
// Public API
// ============================================================================

bool InitializeProjectRagLite()
{
    if (g_ragLiteInitialized) return true;
    
    g_projectIndex = std::make_unique<ProjectIndex>();
    g_ragLiteInitialized = true;
    
    OutputDebugStringA("[ProjectRagLite] Semantic search engine initialized\n");
    return true;
}

void ShutdownProjectRagLite()
{
    if (!g_ragLiteInitialized) return;
    
    if (g_projectIndex)
    {
        g_projectIndex->Clear();
        g_projectIndex.reset();
    }
    
    g_ragLiteInitialized = false;
    OutputDebugStringA("[ProjectRagLite] Shutdown complete\n");
}

bool IndexProjectDirectory(const std::string& projectRoot)
{
    if (!g_ragLiteInitialized || !g_projectIndex) return false;
    
    g_projectIndex->SetProjectRoot(projectRoot);
    size_t count = g_projectIndex->IndexDirectory(projectRoot, true);
    
    std::string msg = "[ProjectRagLite] Indexed " + std::to_string(count) + " files from " + projectRoot + "\n";
    OutputDebugStringA(msg.c_str());
    
    return count > 0;
}

std::vector<SearchResult> SemanticSearch(const std::string& query, size_t maxResults)
{
    if (!g_ragLiteInitialized || !g_projectIndex) return {};
    
    return g_projectIndex->Search(query, maxResults);
}

size_t GetIndexedDocumentCount()
{
    if (!g_ragLiteInitialized || !g_projectIndex) return 0;
    return g_projectIndex->GetDocumentCount();
}

bool IsProjectRagLiteActive()
{
    return g_ragLiteInitialized;
}

} // namespace Search
} // namespace RawrXD

// ============================================================================
// C API for Win32IDE Integration
// ============================================================================

extern "C" void Win32IDE_InitProjectRagLite()
{
    RawrXD::Search::InitializeProjectRagLite();
}

extern "C" bool Win32IDE_IndexProject(const char* projectRoot)
{
    if (!projectRoot) return false;
    return RawrXD::Search::IndexProjectDirectory(projectRoot);
}

extern "C" bool Win32IDE_IsProjectRagLiteActive()
{
    return RawrXD::Search::IsProjectRagLiteActive();
}

extern "C" size_t Win32IDE_GetIndexedDocumentCount()
{
    return RawrXD::Search::GetIndexedDocumentCount();
}
