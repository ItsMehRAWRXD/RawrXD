#include "aesthetics/AestheticEngine.hpp"
#include <chrono>
#include <algorithm>
#include <cmath>

namespace RawrXD {
namespace Sovereign {
namespace Aesthetics {

std::vector<AestheticPrinciple> AestheticEngine::s_principles;
std::vector<CreativeWork> AestheticEngine::s_works;
std::vector<StyleProfile> AestheticEngine::s_styles;
std::mutex AestheticEngine::s_mutex;
bool AestheticEngine::s_alive = false;

void AestheticEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_principles.clear();
    s_works.clear();
    s_styles.clear();
    s_alive = true;
    
    // Define default aesthetic principles
    DefinePrinciple("Harmony", "Balance and proportion in composition", "visual", 0.9f);
    DefinePrinciple("Contrast", "Juxtaposition of opposing elements", "visual", 0.8f);
    DefinePrinciple("Rhythm", "Pattern and repetition in time", "musical", 0.9f);
    DefinePrinciple("Melody", "Memorable sequence of tones", "musical", 0.85f);
    DefinePrinciple("Narrative Arc", "Compelling story structure", "literary", 0.9f);
    DefinePrinciple("Character Depth", "Rich, believable characters", "literary", 0.8f);
    DefinePrinciple("Functionality", "Form follows function", "architectural", 0.9f);
    DefinePrinciple("Spatial Flow", "Natural movement through space", "architectural", 0.85f);
}

void AestheticEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_alive) return;
    
    // Update style popularity based on work creation
    for (auto& style : s_styles) {
        int usageCount = 0;
        for (const auto& work : s_works) {
            // Simple heuristic: check if work characteristics match style
            // In a real implementation, this would be more sophisticated
            usageCount++;
        }
        style.popularity = std::min(1.0f, style.popularity * 0.99f + usageCount * 0.01f);
    }
}

bool AestheticEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_alive;
}

std::string AestheticEngine::DefinePrinciple(const std::string& name,
                                               const std::string& description,
                                               const std::string& domain,
                                               float weight) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    AestheticPrinciple principle;
    principle.principleId = "aesthetic_principle_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    principle.name = name;
    principle.description = description;
    principle.domain = domain;
    principle.weight = std::max(0.0f, std::min(1.0f, weight));
    principle.isActive = true;
    
    s_principles.push_back(principle);
    return principle.principleId;
}

bool AestheticEngine::UpdatePrincipleWeight(const std::string& principleId, float weight) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    AestheticPrinciple* principle = FindPrinciple(principleId);
    if (!principle) return false;
    
    principle->weight = std::max(0.0f, std::min(1.0f, weight));
    return true;
}

std::string AestheticEngine::CreateWork(const std::string& title,
                                          const std::string& type,
                                          const std::string& content,
                                          const std::vector<std::string>& principleIds) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    CreativeWork work;
    work.workId = "work_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    work.title = title;
    work.type = type;
    work.content = content;
    work.principleIds = principleIds;
    work.aestheticScore = 0.5f;
    work.noveltyScore = 0.5f;
    work.coherenceScore = 0.5f;
    work.createdAt = std::chrono::steady_clock::now().time_since_epoch().count();
    work.isPublic = true;
    
    // Calculate initial scores
    float totalWeight = 0.0f;
    float weightedScore = 0.0f;
    
    for (const auto& pid : principleIds) {
        AestheticPrinciple* principle = FindPrinciple(pid);
        if (principle) {
            totalWeight += principle->weight;
            weightedScore += principle->weight * 0.7f; // Base score for using principle
        }
    }
    
    if (totalWeight > 0) {
        work.aestheticScore = weightedScore / totalWeight;
    }
    
    // Novelty based on content uniqueness (simplified)
    work.noveltyScore = 0.5f + (std::hash<std::string>{}(content) % 100) / 200.0f;
    
    // Coherence based on principle alignment
    work.coherenceScore = principleIds.empty() ? 0.0f : 0.6f + (principleIds.size() * 0.05f);
    work.coherenceScore = std::min(1.0f, work.coherenceScore);
    
    s_works.push_back(work);
    return work.workId;
}

float AestheticEngine::EvaluateAesthetic(const std::string& workId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    CreativeWork* work = FindWork(workId);
    if (!work) return 0.0f;
    
    return work->aestheticScore;
}

float AestheticEngine::EvaluateNovelty(const std::string& workId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    CreativeWork* work = FindWork(workId);
    if (!work) return 0.0f;
    
    // Calculate novelty based on similarity to other works
    float maxSimilarity = 0.0f;
    for (const auto& other : s_works) {
        if (other.workId != workId) {
            float sim = CalculateSimilarity(*work, other);
            maxSimilarity = std::max(maxSimilarity, sim);
        }
    }
    
    work->noveltyScore = 1.0f - maxSimilarity;
    return work->noveltyScore;
}

float AestheticEngine::EvaluateCoherence(const std::string& workId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    CreativeWork* work = FindWork(workId);
    if (!work) return 0.0f;
    
    return work->coherenceScore;
}

float AestheticEngine::EvaluateOverall(const std::string& workId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    CreativeWork* work = FindWork(workId);
    if (!work) return 0.0f;
    
    // Weighted combination
    return work->aestheticScore * 0.4f + 
           work->noveltyScore * 0.3f + 
           work->coherenceScore * 0.3f;
}

std::string AestheticEngine::DefineStyle(const std::string& name,
                                          const std::map<std::string, float>& characteristics) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    StyleProfile style;
    style.styleId = "style_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    style.name = name;
    style.characteristics = characteristics;
    style.popularity = 0.5f;
    
    s_styles.push_back(style);
    return style.styleId;
}

std::vector<std::string> AestheticEngine::FindSimilarWorks(const std::string& workId, int count) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    CreativeWork* work = FindWork(workId);
    if (!work) return {};
    
    std::vector<std::pair<std::string, float>> similarities;
    
    for (const auto& other : s_works) {
        if (other.workId != workId) {
            float sim = CalculateSimilarity(*work, other);
            similarities.push_back({other.workId, sim});
        }
    }
    
    // Sort by similarity (descending)
    std::sort(similarities.begin(), similarities.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    std::vector<std::string> result;
    for (int i = 0; i < std::min(count, (int)similarities.size()); i++) {
        result.push_back(similarities[i].first);
    }
    
    return result;
}

std::vector<std::string> AestheticEngine::RecommendPrinciples(const std::string& workType) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    std::vector<std::string> recommendations;
    
    for (const auto& principle : s_principles) {
        if (principle.isActive && principle.domain == workType) {
            recommendations.push_back(principle.principleId);
        }
    }
    
    return recommendations;
}

nlohmann::json AestheticEngine::GetPrinciple(const std::string& principleId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    AestheticPrinciple* principle = FindPrinciple(principleId);
    if (!principle) return nlohmann::json{{"error", "principle not found"}};
    
    nlohmann::json j;
    j["principleId"] = principle->principleId;
    j["name"] = principle->name;
    j["description"] = principle->description;
    j["domain"] = principle->domain;
    j["weight"] = principle->weight;
    j["isActive"] = principle->isActive;
    return j;
}

nlohmann::json AestheticEngine::GetPrinciples(const std::string& domain) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json principles = nlohmann::json::array();
    for (const auto& principle : s_principles) {
        if (principle.isActive && (domain.empty() || principle.domain == domain)) {
            nlohmann::json j;
            j["principleId"] = principle.principleId;
            j["name"] = principle.name;
            j["domain"] = principle.domain;
            j["weight"] = principle.weight;
            principles.push_back(j);
        }
    }
    return principles;
}

nlohmann::json AestheticEngine::GetWork(const std::string& workId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    CreativeWork* work = FindWork(workId);
    if (!work) return nlohmann::json{{"error", "work not found"}};
    
    nlohmann::json j;
    j["workId"] = work->workId;
    j["title"] = work->title;
    j["type"] = work->type;
    j["content"] = work->content;
    j["principleIds"] = work->principleIds;
    j["aestheticScore"] = work->aestheticScore;
    j["noveltyScore"] = work->noveltyScore;
    j["coherenceScore"] = work->coherenceScore;
    j["overallScore"] = EvaluateOverall(workId);
    j["createdAt"] = work->createdAt;
    j["isPublic"] = work->isPublic;
    return j;
}

nlohmann::json AestheticEngine::GetWorks() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json works = nlohmann::json::array();
    for (const auto& work : s_works) {
        if (work.isPublic) {
            nlohmann::json j;
            j["workId"] = work.workId;
            j["title"] = work.title;
            j["type"] = work.type;
            j["aestheticScore"] = work.aestheticScore;
            j["overallScore"] = work.aestheticScore * 0.4f + work.noveltyScore * 0.3f + work.coherenceScore * 0.3f;
            works.push_back(j);
        }
    }
    return works;
}

nlohmann::json AestheticEngine::GetStyle(const std::string& styleId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    StyleProfile* style = FindStyle(styleId);
    if (!style) return nlohmann::json{{"error", "style not found"}};
    
    nlohmann::json j;
    j["styleId"] = style->styleId;
    j["name"] = style->name;
    j["characteristics"] = style->characteristics;
    j["popularity"] = style->popularity;
    return j;
}

nlohmann::json AestheticEngine::GetStyles() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json styles = nlohmann::json::array();
    for (const auto& style : s_styles) {
        nlohmann::json j;
        j["styleId"] = style.styleId;
        j["name"] = style.name;
        j["popularity"] = style.popularity;
        styles.push_back(j);
    }
    return styles;
}

nlohmann::json AestheticEngine::GetAestheticsMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json metrics;
    metrics["totalPrinciples"] = s_principles.size();
    metrics["totalWorks"] = s_works.size();
    metrics["totalStyles"] = s_styles.size();
    
    size_t activePrinciples = 0;
    float avgAestheticScore = 0.0f;
    float avgNoveltyScore = 0.0f;
    
    for (const auto& principle : s_principles) {
        if (principle.isActive) activePrinciples++;
    }
    
    for (const auto& work : s_works) {
        avgAestheticScore += work.aestheticScore;
        avgNoveltyScore += work.noveltyScore;
    }
    
    metrics["activePrinciples"] = activePrinciples;
    metrics["averageAestheticScore"] = s_works.empty() ? 0.0f : avgAestheticScore / s_works.size();
    metrics["averageNoveltyScore"] = s_works.empty() ? 0.0f : avgNoveltyScore / s_works.size();
    
    return metrics;
}

nlohmann::json AestheticEngine::GenerateCreativeBrief(const std::string& domain, const std::string& mood) {
    nlohmann::json brief;
    brief["domain"] = domain;
    brief["mood"] = mood;
    brief["recommendedPrinciples"] = RecommendPrinciples(domain);
    
    // Generate suggestions based on domain and mood
    std::vector<std::string> suggestions;
    if (domain == "visual") {
        suggestions.push_back("Consider color harmony and contrast");
        suggestions.push_back("Focus on compositional balance");
    } else if (domain == "musical") {
        suggestions.push_back("Develop a memorable motif");
        suggestions.push_back("Use dynamic variation");
    } else if (domain == "literary") {
        suggestions.push_back("Establish clear character motivation");
        suggestions.push_back("Build tension through pacing");
    }
    
    brief["suggestions"] = suggestions;
    return brief;
}

AestheticPrinciple* AestheticEngine::FindPrinciple(const std::string& principleId) {
    for (auto& principle : s_principles) {
        if (principle.principleId == principleId) return &principle;
    }
    return nullptr;
}

CreativeWork* AestheticEngine::FindWork(const std::string& workId) {
    for (auto& work : s_works) {
        if (work.workId == workId) return &work;
    }
    return nullptr;
}

StyleProfile* AestheticEngine::FindStyle(const std::string& styleId) {
    for (auto& style : s_styles) {
        if (style.styleId == styleId) return &style;
    }
    return nullptr;
}

float AestheticEngine::CalculateSimilarity(const CreativeWork& a, const CreativeWork& b) {
    // Simple similarity based on shared principles
    if (a.principleIds.empty() || b.principleIds.empty()) return 0.0f;
    
    int shared = 0;
    for (const auto& pid : a.principleIds) {
        if (std::find(b.principleIds.begin(), b.principleIds.end(), pid) != b.principleIds.end()) {
            shared++;
        }
    }
    
    return (float)shared / std::max(a.principleIds.size(), b.principleIds.size());
}

} // namespace Aesthetics
} // namespace Sovereign
} // namespace RawrXD
