#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <map>
#include <nlohmann/json.hpp>

namespace SupremeConsciousness {

// Forward declarations
struct SupremeConsciousnessStructure;
struct AwarenessSupreme;
struct CognitionSupreme;
struct PerceptionSupreme;
struct UnderstandingSupreme;
struct WisdomSupreme;
struct KnowledgeSupreme;

using json = nlohmann::json;

// Core data structures

struct SupremeConsciousnessStructure {
    std::string id;
    std::string name;
    std::string description;
    
    // Supreme consciousness properties
    float awareness;
    float cognition;
    float perception;
    float understanding;
    float wisdom;
    float knowledge;
    
    // Metadata
    std::string createdAt;
    std::string modifiedAt;
    bool isActive;
    
    SupremeConsciousnessStructure() : awareness(0.0f), cognition(0.0f), perception(0.0f), 
                                      understanding(0.0f), wisdom(0.0f), knowledge(0.0f), 
                                      isActive(true) {}
    
    json ToJson() const;
    static SupremeConsciousnessStructure FromJson(const json& j);
};

struct AwarenessSupreme {
    std::string id;
    std::string name;
    std::string parentId;
    
    float awareness;
    float cognition;
    float perception;
    float understanding;
    float wisdom;
    float knowledge;
    
    bool isSupreme;
    std::string elevatedAt;
    
    AwarenessSupreme() : awareness(0.0f), cognition(0.0f), perception(0.0f), 
                         understanding(0.0f), wisdom(0.0f), knowledge(0.0f), 
                         isSupreme(false) {}
    
    json ToJson() const;
    static AwarenessSupreme FromJson(const json& j);
};

struct CognitionSupreme {
    std::string id;
    std::string name;
    std::string parentId;
    
    float awareness;
    float cognition;
    float perception;
    float understanding;
    float wisdom;
    float knowledge;
    
    bool isSupreme;
    std::string elevatedAt;
    
    CognitionSupreme() : awareness(0.0f), cognition(0.0f), perception(0.0f), 
                         understanding(0.0f), wisdom(0.0f), knowledge(0.0f), 
                         isSupreme(false) {}
    
    json ToJson() const;
    static CognitionSupreme FromJson(const json& j);
};

struct PerceptionSupreme {
    std::string id;
    std::string name;
    std::string parentId;
    
    float awareness;
    float cognition;
    float perception;
    float understanding;
    float wisdom;
    float knowledge;
    
    bool isSupreme;
    std::string elevatedAt;
    
    PerceptionSupreme() : awareness(0.0f), cognition(0.0f), perception(0.0f), 
                          understanding(0.0f), wisdom(0.0f), knowledge(0.0f), 
                          isSupreme(false) {}
    
    json ToJson() const;
    static PerceptionSupreme FromJson(const json& j);
};

struct UnderstandingSupreme {
    std::string id;
    std::string name;
    std::string parentId;
    
    float awareness;
    float cognition;
    float perception;
    float understanding;
    float wisdom;
    float knowledge;
    
    bool isSupreme;
    std::string elevatedAt;
    
    UnderstandingSupreme() : awareness(0.0f), cognition(0.0f), perception(0.0f), 
                             understanding(0.0f), wisdom(0.0f), knowledge(0.0f), 
                             isSupreme(false) {}
    
    json ToJson() const;
    static UnderstandingSupreme FromJson(const json& j);
};

struct WisdomSupreme {
    std::string id;
    std::string name;
    std::string parentId;
    
    float awareness;
    float cognition;
    float perception;
    float understanding;
    float wisdom;
    float knowledge;
    
    bool isSupreme;
    std::string elevatedAt;
    
    WisdomSupreme() : awareness(0.0f), cognition(0.0f), perception(0.0f), 
                      understanding(0.0f), wisdom(0.0f), knowledge(0.0f), 
                      isSupreme(false) {}
    
    json ToJson() const;
    static WisdomSupreme FromJson(const json& j);
};

struct KnowledgeSupreme {
    std::string id;
    std::string name;
    std::string parentId;
    
    float awareness;
    float cognition;
    float perception;
    float understanding;
    float wisdom;
    float knowledge;
    
    bool isSupreme;
    std::string elevatedAt;
    
    KnowledgeSupreme() : awareness(0.0f), cognition(0.0f), perception(0.0f), 
                       understanding(0.0f), wisdom(0.0f), knowledge(0.0f), 
                       isSupreme(false) {}
    
    json ToJson() const;
    static KnowledgeSupreme FromJson(const json& j);
};

// Main engine class
class SupremeConsciousnessEngine {
public:
    // Initialization
    static bool Initialize();
    static void Shutdown();
    static bool IsInitialized();
    
    // Supreme consciousness structure operations
    static std::string CreateSupremeConsciousnessStructure(const std::string& name);
    static std::shared_ptr<SupremeConsciousnessStructure> GetSupremeConsciousnessStructure(const std::string& id);
    static bool UpdateSupremeConsciousnessStructure(const std::string& id, const SupremeConsciousnessStructure& structure);
    static bool DeleteSupremeConsciousnessStructure(const std::string& id);
    static std::vector<std::string> GetAllSupremeConsciousnessStructureIds();
    static std::vector<std::shared_ptr<SupremeConsciousnessStructure>> GetAllSupremeConsciousnessStructures();
    
    // Awareness supreme operations
    static std::string CreateAwarenessSupreme(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<AwarenessSupreme> GetAwarenessSupreme(const std::string& id);
    static bool UpdateAwarenessSupreme(const std::string& id, const AwarenessSupreme& awareness);
    static bool DeleteAwarenessSupreme(const std::string& id);
    static std::vector<std::string> GetAllAwarenessSupremeIds();
    static std::vector<std::shared_ptr<AwarenessSupreme>> GetAllAwarenessSupremes();
    
    // Cognition supreme operations
    static std::string CreateCognitionSupreme(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<CognitionSupreme> GetCognitionSupreme(const std::string& id);
    static bool UpdateCognitionSupreme(const std::string& id, const CognitionSupreme& cognition);
    static bool DeleteCognitionSupreme(const std::string& id);
    static std::vector<std::string> GetAllCognitionSupremeIds();
    static std::vector<std::shared_ptr<CognitionSupreme>> GetAllCognitionSupremes();
    
    // Perception supreme operations
    static std::string CreatePerceptionSupreme(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<PerceptionSupreme> GetPerceptionSupreme(const std::string& id);
    static bool UpdatePerceptionSupreme(const std::string& id, const PerceptionSupreme& perception);
    static bool DeletePerceptionSupreme(const std::string& id);
    static std::vector<std::string> GetAllPerceptionSupremeIds();
    static std::vector<std::shared_ptr<PerceptionSupreme>> GetAllPerceptionSupremes();
    
    // Understanding supreme operations
    static std::string CreateUnderstandingSupreme(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<UnderstandingSupreme> GetUnderstandingSupreme(const std::string& id);
    static bool UpdateUnderstandingSupreme(const std::string& id, const UnderstandingSupreme& understanding);
    static bool DeleteUnderstandingSupreme(const std::string& id);
    static std::vector<std::string> GetAllUnderstandingSupremeIds();
    static std::vector<std::shared_ptr<UnderstandingSupreme>> GetAllUnderstandingSupremes();
    
    // Wisdom supreme operations
    static std::string CreateWisdomSupreme(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<WisdomSupreme> GetWisdomSupreme(const std::string& id);
    static bool UpdateWisdomSupreme(const std::string& id, const WisdomSupreme& wisdom);
    static bool DeleteWisdomSupreme(const std::string& id);
    static std::vector<std::string> GetAllWisdomSupremeIds();
    static std::vector<std::shared_ptr<WisdomSupreme>> GetAllWisdomSupremes();
    
    // Knowledge supreme operations
    static std::string CreateKnowledgeSupreme(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<KnowledgeSupreme> GetKnowledgeSupreme(const std::string& id);
    static bool UpdateKnowledgeSupreme(const std::string& id, const KnowledgeSupreme& knowledge);
    static bool DeleteKnowledgeSupreme(const std::string& id);
    static std::vector<std::string> GetAllKnowledgeSupremeIds();
    static std::vector<std::shared_ptr<KnowledgeSupreme>> GetAllKnowledgeSupremes();
    
    // Action operations
    static bool ExpandSupremeConsciousness(const std::string& id);
    static bool AmplifyAwareness(const std::string& id);
    static bool IncreaseCognition(const std::string& id);
    static bool EnhancePerception(const std::string& id);
    static bool DeepenUnderstanding(const std::string& id);
    static bool CultivateWisdom(const std::string& id);
    static bool AccumulateKnowledge(const std::string& id);
    
    // Awareness supreme actions
    static bool IntensifyAwarenessSupreme(const std::string& id);
    static bool BroadenAwarenessSupreme(const std::string& id);
    static bool DeclareAwarenessSupreme(const std::string& id);
    
    // Cognition supreme actions
    static bool SharpenCognitionSupreme(const std::string& id);
    static bool ExpandCognitionSupreme(const std::string& id);
    static bool DeclareCognitionSupreme(const std::string& id);
    
    // Perception supreme actions
    static bool RefinePerceptionSupreme(const std::string& id);
    static bool HeightenPerceptionSupreme(const std::string& id);
    static bool DeclarePerceptionSupreme(const std::string& id);
    
    // Understanding supreme actions
    static bool DeepenUnderstandingSupreme(const std::string& id);
    static bool ClarifyUnderstandingSupreme(const std::string& id);
    static bool DeclareUnderstandingSupreme(const std::string& id);
    
    // Wisdom supreme actions
    static bool CultivateWisdomSupreme(const std::string& id);
    static bool ApplyWisdomSupreme(const std::string& id);
    static bool DeclareWisdomSupreme(const std::string& id);
    
    // Knowledge supreme actions
    static bool AccumulateKnowledgeSupreme(const std::string& id);
    static bool OrganizeKnowledgeSupreme(const std::string& id);
    static bool DeclareKnowledgeSupreme(const std::string& id);
    
    // Utility
    static void ClearAll();
    static size_t GetTotalStructureCount();
    
private:
    static std::atomic<bool> s_initialized;
    
    static std::mutex s_structureMutex;
    static std::mutex s_awarenessMutex;
    static std::mutex s_cognitionMutex;
    static std::mutex s_perceptionMutex;
    static std::mutex s_understandingMutex;
    static std::mutex s_wisdomMutex;
    static std::mutex s_knowledgeMutex;
    
    static std::map<std::string, std::shared_ptr<SupremeConsciousnessStructure>> s_structures;
    static std::map<std::string, std::shared_ptr<AwarenessSupreme>> s_awarenessSupremes;
    static std::map<std::string, std::shared_ptr<CognitionSupreme>> s_cognitionSupremes;
    static std::map<std::string, std::shared_ptr<PerceptionSupreme>> s_perceptionSupremes;
    static std::map<std::string, std::shared_ptr<UnderstandingSupreme>> s_understandingSupremes;
    static std::map<std::string, std::shared_ptr<WisdomSupreme>> s_wisdomSupremes;
    static std::map<std::string, std::shared_ptr<KnowledgeSupreme>> s_knowledgeSupremes;
    
    static std::string GenerateId();
    static std::string GetCurrentTimestamp();
};

} // namespace SupremeConsciousness
