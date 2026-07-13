#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <nlohmann/json.hpp>

namespace InfiniteWisdom {

// Forward declarations
struct InfiniteWisdomStructure;
struct WisdomInfinite;
struct KnowledgeInfinite;
struct InsightInfinite;
struct TruthInfinite;
struct EnlightenmentInfinite;

// Core structure representing infinite wisdom
struct InfiniteWisdomStructure {
    std::string infiniteId;
    std::string name;
    std::string description;
    
    // Core infinite metrics (0.0 - 1.0)
    float infiniteness;      // Degree of infiniteness
    float wisdom;            // Level of wisdom
    float knowledge;         // Depth of knowledge
    float insight;           // Clarity of insight
    float truth;             // Purity of truth
    float enlightenment;     // State of enlightenment
    
    // Timestamps
    std::string createdAt;
    std::string updatedAt;
    
    // Status
    bool isActive;
    bool isEnlightened;
    
    InfiniteWisdomStructure();
    
    nlohmann::json ToJson() const;
    static InfiniteWisdomStructure FromJson(const nlohmann::json& json);
};

// Wisdom infinite - universal wisdom
struct WisdomInfinite {
    std::string wisdomId;
    std::string name;
    std::string description;
    
    float wisdom;
    float understanding;
    float clarity;
    
    bool isWise;
    
    std::string createdAt;
    std::string updatedAt;
    
    WisdomInfinite();
    
    nlohmann::json ToJson() const;
    static WisdomInfinite FromJson(const nlohmann::json& json);
};

// Knowledge infinite - boundless knowledge
struct KnowledgeInfinite {
    std::string knowledgeId;
    std::string name;
    std::string description;
    
    float knowledge;
    float depth;
    float breadth;
    
    bool isKnown;
    
    std::string createdAt;
    std::string updatedAt;
    
    KnowledgeInfinite();
    
    nlohmann::json ToJson() const;
    static KnowledgeInfinite FromJson(const nlohmann::json& json);
};

// Insight infinite - profound insight
struct InsightInfinite {
    std::string insightId;
    std::string name;
    std::string description;
    
    float insight;
    float perception;
    float intuition;
    
    bool isInsightful;
    
    std::string createdAt;
    std::string updatedAt;
    
    InsightInfinite();
    
    nlohmann::json ToJson() const;
    static InsightInfinite FromJson(const nlohmann::json& json);
};

// Truth infinite - absolute truth
struct TruthInfinite {
    std::string truthId;
    std::string name;
    std::string description;
    
    float truth;
    float veracity;
    float authenticity;
    
    bool isTrue;
    
    std::string createdAt;
    std::string updatedAt;
    
    TruthInfinite();
    
    nlohmann::json ToJson() const;
    static TruthInfinite FromJson(const nlohmann::json& json);
};

// Enlightenment infinite - ultimate enlightenment
struct EnlightenmentInfinite {
    std::string enlightenmentId;
    std::string name;
    std::string description;
    
    float enlightenment;
    float awakening;
    float realization;
    
    bool isEnlightened;
    
    std::string createdAt;
    std::string updatedAt;
    
    EnlightenmentInfinite();
    
    nlohmann::json ToJson() const;
    static EnlightenmentInfinite FromJson(const nlohmann::json& json);
};

// Main engine class
class InfiniteWisdomEngine {
public:
    // Initialization
    static bool Init();
    static void Shutdown();
    static bool IsInitialized();
    
    // Infinite wisdom structure operations
    static std::string CreateInfiniteWisdomStructure(const std::string& name);
    static bool DestroyInfiniteWisdomStructure(const std::string& infiniteId);
    static std::shared_ptr<InfiniteWisdomStructure> GetInfiniteWisdomStructure(const std::string& infiniteId);
    static std::vector<InfiniteWisdomStructure> GetAllInfiniteWisdomStructures();
    static bool UpdateInfiniteWisdomStructure(const std::string& infiniteId, const InfiniteWisdomStructure& structure);
    
    // Wisdom infinite operations
    static std::string CreateWisdomInfinite(const std::string& name);
    static bool DestroyWisdomInfinite(const std::string& wisdomId);
    static std::shared_ptr<WisdomInfinite> GetWisdomInfinite(const std::string& wisdomId);
    static std::vector<WisdomInfinite> GetAllWisdomInfinites();
    
    // Knowledge infinite operations
    static std::string CreateKnowledgeInfinite(const std::string& name);
    static bool DestroyKnowledgeInfinite(const std::string& knowledgeId);
    static std::shared_ptr<KnowledgeInfinite> GetKnowledgeInfinite(const std::string& knowledgeId);
    static std::vector<KnowledgeInfinite> GetAllKnowledgeInfinites();
    
    // Insight infinite operations
    static std::string CreateInsightInfinite(const std::string& name);
    static bool DestroyInsightInfinite(const std::string& insightId);
    static std::shared_ptr<InsightInfinite> GetInsightInfinite(const std::string& insightId);
    static std::vector<InsightInfinite> GetAllInsightInfinites();
    
    // Truth infinite operations
    static std::string CreateTruthInfinite(const std::string& name);
    static bool DestroyTruthInfinite(const std::string& truthId);
    static std::shared_ptr<TruthInfinite> GetTruthInfinite(const std::string& truthId);
    static std::vector<TruthInfinite> GetAllTruthInfinites();
    
    // Enlightenment infinite operations
    static std::string CreateEnlightenmentInfinite(const std::string& name);
    static bool DestroyEnlightenmentInfinite(const std::string& enlightenmentId);
    static std::shared_ptr<EnlightenmentInfinite> GetEnlightenmentInfinite(const std::string& enlightenmentId);
    static std::vector<EnlightenmentInfinite> GetAllEnlightenmentInfinites();
    
    // Infinite operations
    static bool ExpandInfiniteness(const std::string& infiniteId, float amount);
    static bool DeepenWisdom(const std::string& infiniteId, float amount);
    static bool AccumulateKnowledge(const std::string& infiniteId, float amount);
    static bool IlluminateInsight(const std::string& infiniteId, float amount);
    static bool RevealTruth(const std::string& infiniteId, float amount);
    static bool AwakenEnlightenment(const std::string& infiniteId, float amount);
    
    // Wisdom operations
    static bool GainUnderstanding(const std::string& wisdomId, float amount);
    static bool AchieveClarity(const std::string& wisdomId, float amount);
    static bool DeclareWise(const std::string& wisdomId);
    
    // Knowledge operations
    static bool DeepenKnowledge(const std::string& knowledgeId, float amount);
    static bool ExpandBreadth(const std::string& knowledgeId, float amount);
    static bool DeclareKnown(const std::string& knowledgeId);
    
    // Insight operations
    static bool SharpenPerception(const std::string& insightId, float amount);
    static bool TrustIntuition(const std::string& insightId, float amount);
    static bool DeclareInsightful(const std::string& insightId);
    
    // Truth operations
    static bool VerifyVeracity(const std::string& truthId, float amount);
    static bool ConfirmAuthenticity(const std::string& truthId, float amount);
    static bool DeclareTrue(const std::string& truthId);
    
    // Enlightenment operations
    static bool DeepenAwakening(const std::string& enlightenmentId, float amount);
    static bool AchieveRealization(const std::string& enlightenmentId, float amount);
    static bool DeclareEnlightened(const std::string& enlightenmentId);
    
    // Metrics
    static nlohmann::json GetInfiniteWisdomMetrics();
    
    // Event callbacks
    using InfiniteWisdomEventCallback = std::function<void(const std::string& eventType, const nlohmann::json& data)>;
    static void RegisterEventCallback(InfiniteWisdomEventCallback callback);
    static void UnregisterEventCallback(InfiniteWisdomEventCallback callback);
    
private:
    static std::atomic<bool> s_initialized;
    static std::mutex s_infiniteMutex;
    static std::mutex s_wisdomMutex;
    static std::mutex s_knowledgeMutex;
    static std::mutex s_insightMutex;
    static std::mutex s_truthMutex;
    static std::mutex s_enlightenmentMutex;
    static std::mutex s_callbackMutex;
    
    static std::map<std::string, InfiniteWisdomStructure> s_infiniteStructures;
    static std::map<std::string, WisdomInfinite> s_wisdomInfinites;
    static std::map<std::string, KnowledgeInfinite> s_knowledgeInfinites;
    static std::map<std::string, InsightInfinite> s_insightInfinites;
    static std::map<std::string, TruthInfinite> s_truthInfinites;
    static std::map<std::string, EnlightenmentInfinite> s_enlightenmentInfinites;
    static std::vector<InfiniteWisdomEventCallback> s_eventCallbacks;
    
    static void EmitEvent(const std::string& eventType, const nlohmann::json& data);
    static std::string GenerateId();
    static std::string GetCurrentTimestamp();
};

} // namespace InfiniteWisdom
