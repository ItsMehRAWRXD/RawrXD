#include "knowledge/OntologyEngine.hpp"
#include <chrono>
#include <algorithm>

namespace RawrXD {
namespace Sovereign {
namespace Knowledge {

std::vector<Concept> OntologyEngine::s_concepts;
std::vector<Relationship> OntologyEngine::s_relationships;
std::mutex OntologyEngine::s_mutex;
bool OntologyEngine::s_alive = false;

void OntologyEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_concepts.clear();
    s_relationships.clear();
    s_alive = true;
}

void OntologyEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_alive) return;
    
    // Decay confidence of concepts over time
    for (auto& concept : s_concepts) {
        if (concept.confidence > 0.01f) {
            concept.confidence *= 0.9999f;
        }
    }
}

bool OntologyEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_alive;
}

std::string OntologyEngine::DefineConcept(const std::string& name, 
                                           const std::string& description,
                                           const std::vector<std::string>& parentIds) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Concept concept;
    concept.conceptId = "concept_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    concept.name = name;
    concept.description = description;
    concept.parentIds = parentIds;
    concept.confidence = 1.0f;
    concept.createdAt = std::chrono::steady_clock::now().time_since_epoch().count();
    concept.isActive = true;
    
    // Add as child to parents
    for (const auto& parentId : parentIds) {
        Concept* parent = FindConcept(parentId);
        if (parent) {
            parent->childIds.push_back(concept.conceptId);
        }
    }
    
    s_concepts.push_back(concept);
    return concept.conceptId;
}

bool OntologyEngine::AddParent(const std::string& conceptId, const std::string& parentId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Concept* concept = FindConcept(conceptId);
    Concept* parent = FindConcept(parentId);
    
    if (!concept || !parent) return false;
    
    // Check if already parent
    if (std::find(concept->parentIds.begin(), concept->parentIds.end(), parentId) != concept->parentIds.end()) {
        return false;
    }
    
    concept->parentIds.push_back(parentId);
    parent->childIds.push_back(conceptId);
    return true;
}

bool OntologyEngine::AddProperty(const std::string& conceptId, 
                                  const std::string& key, 
                                  const std::string& value) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Concept* concept = FindConcept(conceptId);
    if (!concept) return false;
    
    concept->properties[key] = value;
    return true;
}

std::string OntologyEngine::DefineRelationship(const std::string& sourceId,
                                                const std::string& targetId,
                                                const std::string& type,
                                                float strength) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    // Verify both concepts exist
    if (!FindConcept(sourceId) || !FindConcept(targetId)) return "";
    
    Relationship rel;
    rel.relationshipId = "rel_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    rel.sourceId = sourceId;
    rel.targetId = targetId;
    rel.type = type;
    rel.strength = strength;
    rel.establishedAt = std::chrono::steady_clock::now().time_since_epoch().count();
    rel.isActive = true;
    
    s_relationships.push_back(rel);
    return rel.relationshipId;
}

bool OntologyEngine::UpdateRelationshipStrength(const std::string& relationshipId, float strength) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Relationship* rel = FindRelationship(relationshipId);
    if (!rel) return false;
    
    rel->strength = std::max(0.0f, std::min(1.0f, strength));
    return true;
}

std::vector<std::string> OntologyEngine::GetAncestors(const std::string& conceptId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<std::string> ancestors;
    GetAncestorsRecursive(conceptId, ancestors, 0);
    return ancestors;
}

std::vector<std::string> OntologyEngine::GetDescendants(const std::string& conceptId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<std::string> descendants;
    GetDescendantsRecursive(conceptId, descendants, 0);
    return descendants;
}

std::vector<std::string> OntologyEngine::GetRelated(const std::string& conceptId, const std::string& type) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    std::vector<std::string> related;
    for (const auto& rel : s_relationships) {
        if (rel.isActive && rel.type == type) {
            if (rel.sourceId == conceptId) {
                related.push_back(rel.targetId);
            } else if (rel.targetId == conceptId) {
                related.push_back(rel.sourceId);
            }
        }
    }
    return related;
}

nlohmann::json OntologyEngine::GetConcept(const std::string& conceptId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Concept* concept = FindConcept(conceptId);
    if (!concept) return nlohmann::json{{"error", "concept not found"}};
    
    nlohmann::json j;
    j["conceptId"] = concept->conceptId;
    j["name"] = concept->name;
    j["description"] = concept->description;
    j["parentIds"] = concept->parentIds;
    j["childIds"] = concept->childIds;
    j["properties"] = concept->properties;
    j["confidence"] = concept->confidence;
    j["createdAt"] = concept->createdAt;
    j["isActive"] = concept->isActive;
    return j;
}

nlohmann::json OntologyEngine::GetConcepts() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json concepts = nlohmann::json::array();
    for (const auto& concept : s_concepts) {
        if (concept.isActive) {
            nlohmann::json j;
            j["conceptId"] = concept.conceptId;
            j["name"] = concept.name;
            j["parentCount"] = concept.parentIds.size();
            j["childCount"] = concept.childIds.size();
            j["confidence"] = concept.confidence;
            concepts.push_back(j);
        }
    }
    return concepts;
}

nlohmann::json OntologyEngine::GetRelationships(const std::string& conceptId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json relationships = nlohmann::json::array();
    for (const auto& rel : s_relationships) {
        if (rel.isActive && (rel.sourceId == conceptId || rel.targetId == conceptId)) {
            nlohmann::json j;
            j["relationshipId"] = rel.relationshipId;
            j["sourceId"] = rel.sourceId;
            j["targetId"] = rel.targetId;
            j["type"] = rel.type;
            j["strength"] = rel.strength;
            relationships.push_back(j);
        }
    }
    return relationships;
}

nlohmann::json OntologyEngine::QueryOntology(const std::string& query) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    // Simple query: search concept names
    nlohmann::json results = nlohmann::json::array();
    for (const auto& concept : s_concepts) {
        if (concept.isActive && concept.name.find(query) != std::string::npos) {
            nlohmann::json j;
            j["conceptId"] = concept.conceptId;
            j["name"] = concept.name;
            results.push_back(j);
        }
    }
    return results;
}

nlohmann::json OntologyEngine::GetOntologyMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json metrics;
    metrics["totalConcepts"] = s_concepts.size();
    metrics["totalRelationships"] = s_relationships.size();
    
    size_t activeConcepts = 0;
    float avgConfidence = 0.0f;
    for (const auto& concept : s_concepts) {
        if (concept.isActive) activeConcepts++;
        avgConfidence += concept.confidence;
    }
    
    metrics["activeConcepts"] = activeConcepts;
    metrics["averageConfidence"] = s_concepts.empty() ? 0.0f : avgConfidence / s_concepts.size();
    return metrics;
}

nlohmann::json OntologyEngine::GetKnowledgeGraph() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json graph;
    nlohmann::json nodes = nlohmann::json::array();
    nlohmann::json edges = nlohmann::json::array();
    
    for (const auto& concept : s_concepts) {
        if (concept.isActive) {
            nlohmann::json node;
            node["id"] = concept.conceptId;
            node["name"] = concept.name;
            node["confidence"] = concept.confidence;
            nodes.push_back(node);
        }
    }
    
    for (const auto& rel : s_relationships) {
        if (rel.isActive) {
            nlohmann::json edge;
            edge["source"] = rel.sourceId;
            edge["target"] = rel.targetId;
            edge["type"] = rel.type;
            edge["strength"] = rel.strength;
            edges.push_back(edge);
        }
    }
    
    graph["nodes"] = nodes;
    graph["edges"] = edges;
    return graph;
}

Concept* OntologyEngine::FindConcept(const std::string& conceptId) {
    for (auto& concept : s_concepts) {
        if (concept.conceptId == conceptId) return &concept;
    }
    return nullptr;
}

Relationship* OntologyEngine::FindRelationship(const std::string& relationshipId) {
    for (auto& rel : s_relationships) {
        if (rel.relationshipId == relationshipId) return &rel;
    }
    return nullptr;
}

void OntologyEngine::GetAncestorsRecursive(const std::string& conceptId, 
                                            std::vector<std::string>& ancestors,
                                            int depth) {
    if (depth > 10) return; // Prevent infinite recursion
    
    Concept* concept = FindConcept(conceptId);
    if (!concept) return;
    
    for (const auto& parentId : concept->parentIds) {
        if (std::find(ancestors.begin(), ancestors.end(), parentId) == ancestors.end()) {
            ancestors.push_back(parentId);
            GetAncestorsRecursive(parentId, ancestors, depth + 1);
        }
    }
}

void OntologyEngine::GetDescendantsRecursive(const std::string& conceptId,
                                              std::vector<std::string>& descendants,
                                              int depth) {
    if (depth > 10) return; // Prevent infinite recursion
    
    Concept* concept = FindConcept(conceptId);
    if (!concept) return;
    
    for (const auto& childId : concept->childIds) {
        if (std::find(descendants.begin(), descendants.end(), childId) == descendants.end()) {
            descendants.push_back(childId);
            GetDescendantsRecursive(childId, descendants, depth + 1);
        }
    }
}

} // namespace Knowledge
} // namespace Sovereign
} // namespace RawrXD
