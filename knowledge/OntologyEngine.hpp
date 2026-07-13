#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Sovereign {
namespace Knowledge {

struct Concept {
    std::string conceptId;
    std::string name;
    std::string description;
    std::vector<std::string> parentIds;
    std::vector<std::string> childIds;
    std::map<std::string, std::string> properties;
    float confidence;
    int64_t createdAt;
    bool isActive;
};

struct Relationship {
    std::string relationshipId;
    std::string sourceId;
    std::string targetId;
    std::string type;
    float strength;
    int64_t establishedAt;
    bool isActive;
};

class OntologyEngine {
public:
    static void Init();
    static void OnTick();
    static bool IsAlive();

    static std::string DefineConcept(const std::string& name, 
                                      const std::string& description,
                                      const std::vector<std::string>& parentIds);
    static bool AddParent(const std::string& conceptId, const std::string& parentId);
    static bool AddProperty(const std::string& conceptId, 
                            const std::string& key, 
                            const std::string& value);
    
    static std::string DefineRelationship(const std::string& sourceId,
                                          const std::string& targetId,
                                          const std::string& type,
                                          float strength);
    static bool UpdateRelationshipStrength(const std::string& relationshipId, float strength);
    
    static std::vector<std::string> GetAncestors(const std::string& conceptId);
    static std::vector<std::string> GetDescendants(const std::string& conceptId);
    static std::vector<std::string> GetRelated(const std::string& conceptId, const std::string& type);
    
    static nlohmann::json GetConcept(const std::string& conceptId);
    static nlohmann::json GetConcepts();
    static nlohmann::json GetRelationships(const std::string& conceptId);
    static nlohmann::json QueryOntology(const std::string& query);
    
    static nlohmann::json GetOntologyMetrics();
    static nlohmann::json GetKnowledgeGraph();

private:
    static std::vector<Concept> s_concepts;
    static std::vector<Relationship> s_relationships;
    static std::mutex s_mutex;
    static bool s_alive;
    
    static Concept* FindConcept(const std::string& conceptId);
    static Relationship* FindRelationship(const std::string& relationshipId);
    static void GetAncestorsRecursive(const std::string& conceptId, 
                                       std::vector<std::string>& ancestors,
                                       int depth);
    static void GetDescendantsRecursive(const std::string& conceptId,
                                         std::vector<std::string>& descendants,
                                         int depth);
};

} // namespace Knowledge
} // namespace Sovereign
} // namespace RawrXD
