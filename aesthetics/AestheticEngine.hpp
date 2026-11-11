#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Sovereign {
namespace Aesthetics {

struct AestheticPrinciple {
    std::string principleId;
    std::string name;
    std::string description;
    std::string domain; // "visual", "musical", "literary", "architectural"
    float weight;
    bool isActive;
};

struct CreativeWork {
    std::string workId;
    std::string title;
    std::string type; // "composition", "design", "narrative", "structure"
    std::string content;
    std::vector<std::string> principleIds;
    float aestheticScore;
    float noveltyScore;
    float coherenceScore;
    int64_t createdAt;
    bool isPublic;
};

struct StyleProfile {
    std::string styleId;
    std::string name;
    std::map<std::string, float> characteristics;
    std::vector<std::string> exampleWorks;
    float popularity;
};

class AestheticEngine {
public:
    static void Init();
    static void OnTick();
    static bool IsAlive();

    static std::string DefinePrinciple(const std::string& name,
                                         const std::string& description,
                                         const std::string& domain,
                                         float weight);
    static bool UpdatePrincipleWeight(const std::string& principleId, float weight);
    
    static std::string CreateWork(const std::string& title,
                                   const std::string& type,
                                   const std::string& content,
                                   const std::vector<std::string>& principleIds);
    
    static float EvaluateAesthetic(const std::string& workId);
    static float EvaluateNovelty(const std::string& workId);
    static float EvaluateCoherence(const std::string& workId);
    static float EvaluateOverall(const std::string& workId);
    
    static std::string DefineStyle(const std::string& name,
                                    const std::map<std::string, float>& characteristics);
    static std::vector<std::string> FindSimilarWorks(const std::string& workId, int count);
    static std::vector<std::string> RecommendPrinciples(const std::string& workType);
    
    static nlohmann::json GetPrinciple(const std::string& principleId);
    static nlohmann::json GetPrinciples(const std::string& domain);
    static nlohmann::json GetWork(const std::string& workId);
    static nlohmann::json GetWorks();
    static nlohmann::json GetStyle(const std::string& styleId);
    static nlohmann::json GetStyles();
    
    static nlohmann::json GetAestheticsMetrics();
    static nlohmann::json GenerateCreativeBrief(const std::string& domain, const std::string& mood);

private:
    static std::vector<AestheticPrinciple> s_principles;
    static std::vector<CreativeWork> s_works;
    static std::vector<StyleProfile> s_styles;
    static std::mutex s_mutex;
    static bool s_alive;
    
    static AestheticPrinciple* FindPrinciple(const std::string& principleId);
    static CreativeWork* FindWork(const std::string& workId);
    static StyleProfile* FindStyle(const std::string& styleId);
    static float CalculateSimilarity(const CreativeWork& a, const CreativeWork& b);
};

} // namespace Aesthetics
} // namespace Sovereign
} // namespace RawrXD
