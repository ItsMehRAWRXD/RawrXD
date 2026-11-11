#include "OmniGenesisEngine.hpp"
#include <chrono>
#include <algorithm>

namespace OmniGenesis {

// Static member definitions
bool OmniGenesisEngine::s_initialized = false;
std::mutex OmniGenesisEngine::s_omniMutex;
std::mutex OmniGenesisEngine::s_genesisMutex;
std::mutex OmniGenesisEngine::s_creationMutex;
std::mutex OmniGenesisEngine::s_originMutex;
std::mutex OmniGenesisEngine::s_sourceMutex;

std::vector<std::shared_ptr<OmniGenesisStructure>> OmniGenesisEngine::s_omniStructures;
std::vector<std::shared_ptr<GenesisOmni>> OmniGenesisEngine::s_genesisOmnis;
std::vector<std::shared_ptr<CreationOmni>> OmniGenesisEngine::s_creationOmnis;
std::vector<std::shared_ptr<OriginOmni>> OmniGenesisEngine::s_originOmnis;
std::vector<std::shared_ptr<SourceOmni>> OmniGenesisEngine::s_sourceOmnis;

std::atomic<int64_t> OmniGenesisEngine::s_omniCounter{0};
std::atomic<int64_t> OmniGenesisEngine::s_genesisCounter{0};
std::atomic<int64_t> OmniGenesisEngine::s_creationCounter{0};
std::atomic<int64_t> OmniGenesisEngine::s_originCounter{0};
std::atomic<int64_t> OmniGenesisEngine::s_sourceCounter{0};

// JSON serialization implementations
nlohmann::json OmniGenesisStructure::ToJson() const {
    return {
        {"omniId", omniId},
        {"name", name},
        {"omniscience", omniscience},
        {"genesis", genesis},
        {"creation", creation},
        {"origin", origin},
        {"source", source},
        {"createdAt", createdAt},
        {"lastModified", lastModified},
        {"isActive", isActive}
    };
}

OmniGenesisStructure OmniGenesisStructure::FromJson(const nlohmann::json& j) {
    OmniGenesisStructure s;
    s.omniId = j.value("omniId", "");
    s.name = j.value("name", "");
    s.omniscience = j.value("omniscience", 0.0f);
    s.genesis = j.value("genesis", 0.0f);
    s.creation = j.value("creation", 0.0f);
    s.origin = j.value("origin", 0.0f);
    s.source = j.value("source", 0.0f);
    s.createdAt = j.value("createdAt", 0);
    s.lastModified = j.value("lastModified", 0);
    s.isActive = j.value("isActive", true);
    return s;
}

nlohmann::json GenesisOmni::ToJson() const {
    return {
        {"genesisId", genesisId},
        {"name", name},
        {"genesis", genesis},
        {"omniscience", omniscience},
        {"birth", birth},
        {"emergence", emergence},
        {"isBorn", isBorn},
        {"createdAt", createdAt}
    };
}

GenesisOmni GenesisOmni::FromJson(const nlohmann::json& j) {
    GenesisOmni g;
    g.genesisId = j.value("genesisId", "");
    g.name = j.value("name", "");
    g.genesis = j.value("genesis", 0.0f);
    g.omniscience = j.value("omniscience", 0.0f);
    g.birth = j.value("birth", 0.0f);
    g.emergence = j.value("emergence", 0.0f);
    g.isBorn = j.value("isBorn", false);
    g.createdAt = j.value("createdAt", 0);
    return g;
}

nlohmann::json CreationOmni::ToJson() const {
    return {
        {"creationId", creationId},
        {"name", name},
        {"creation", creation},
        {"omniscience", omniscience},
        {"manifestation", manifestation},
        {"formation", formation},
        {"createdAt", createdAt}
    };
}

CreationOmni CreationOmni::FromJson(const nlohmann::json& j) {
    CreationOmni c;
    c.creationId = j.value("creationId", "");
    c.name = j.value("name", "");
    c.creation = j.value("creation", 0.0f);
    c.omniscience = j.value("omniscience", 0.0f);
    c.manifestation = j.value("manifestation", 0.0f);
    c.formation = j.value("formation", 0.0f);
    c.createdAt = j.value("createdAt", 0);
    return c;
}

nlohmann::json OriginOmni::ToJson() const {
    return {
        {"originId", originId},
        {"name", name},
        {"origin", origin},
        {"omniscience", omniscience},
        {"beginning", beginning},
        {"inception", inception},
        {"isOriginated", isOriginated},
        {"createdAt", createdAt}
    };
}

OriginOmni OriginOmni::FromJson(const nlohmann::json& j) {
    OriginOmni o;
    o.originId = j.value("originId", "");
    o.name = j.value("name", "");
    o.origin = j.value("origin", 0.0f);
    o.omniscience = j.value("omniscience", 0.0f);
    o.beginning = j.value("beginning", 0.0f);
    o.inception = j.value("inception", 0.0f);
    o.isOriginated = j.value("isOriginated", false);
    o.createdAt = j.value("createdAt", 0);
    return o;
}

nlohmann::json SourceOmni::ToJson() const {
    return {
        {"sourceId", sourceId},
        {"name", name},
        {"source", source},
        {"omniscience", omniscience},
        {"fountain", fountain},
        {"wellspring", wellspring},
        {"createdAt", createdAt}
    };
}

SourceOmni SourceOmni::FromJson(const nlohmann::json& j) {
    SourceOmni s;
    s.sourceId = j.value("sourceId", "");
    s.name = j.value("name", "");
    s.source = j.value("source", 0.0f);
    s.omniscience = j.value("omniscience", 0.0f);
    s.fountain = j.value("fountain", 0.0f);
    s.wellspring = j.value("wellspring", 0.0f);
    s.createdAt = j.value("createdAt", 0);
    return s;
}

// Engine implementation
void OmniGenesisEngine::Init() {
    if (s_initialized) return;
    s_initialized = true;
}

void OmniGenesisEngine::Shutdown() {
    if (!s_initialized) return;
    
    std::lock_guard<std::mutex> lock1(s_omniMutex);
    std::lock_guard<std::mutex> lock2(s_genesisMutex);
    std::lock_guard<std::mutex> lock3(s_creationMutex);
    std::lock_guard<std::mutex> lock4(s_originMutex);
    std::lock_guard<std::mutex> lock5(s_sourceMutex);
    
    s_omniStructures.clear();
    s_genesisOmnis.clear();
    s_creationOmnis.clear();
    s_originOmnis.clear();
    s_sourceOmnis.clear();
    
    s_initialized = false;
}

bool OmniGenesisEngine::IsInitialized() {
    return s_initialized;
}

// Omni Genesis Structure operations
std::string OmniGenesisEngine::CreateOmniGenesisStructure(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_omniMutex);
    
    auto structure = std::make_shared<OmniGenesisStructure>();
    structure->omniId = "omni_" + std::to_string(s_omniCounter++);
    structure->name = name;
    structure->omniscience = 0.0f;
    structure->genesis = 0.0f;
    structure->creation = 0.0f;
    structure->origin = 0.0f;
    structure->source = 0.0f;
    structure->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    structure->lastModified = structure->createdAt;
    structure->isActive = true;
    
    s_omniStructures.push_back(structure);
    return structure->omniId;
}

bool OmniGenesisEngine::DestroyOmniGenesisStructure(const std::string& omniId) {
    std::lock_guard<std::mutex> lock(s_omniMutex);
    
    auto it = std::remove_if(s_omniStructures.begin(), s_omniStructures.end(),
        [&omniId](const auto& s) { return s->omniId == omniId; });
    
    if (it != s_omniStructures.end()) {
        s_omniStructures.erase(it, s_omniStructures.end());
        return true;
    }
    return false;
}

std::shared_ptr<OmniGenesisStructure> OmniGenesisEngine::GetOmniGenesisStructure(const std::string& omniId) {
    std::lock_guard<std::mutex> lock(s_omniMutex);
    
    for (auto& s : s_omniStructures) {
        if (s->omniId == omniId) {
            return s;
        }
    }
    return nullptr;
}

std::vector<OmniGenesisStructure> OmniGenesisEngine::GetAllOmniGenesisStructures() {
    std::lock_guard<std::mutex> lock(s_omniMutex);
    
    std::vector<OmniGenesisStructure> result;
    for (auto& s : s_omniStructures) {
        result.push_back(*s);
    }
    return result;
}

bool OmniGenesisEngine::ExpandOmniscience(const std::string& omniId, float amount) {
    std::lock_guard<std::mutex> lock(s_omniMutex);
    
    for (auto& s : s_omniStructures) {
        if (s->omniId == omniId) {
            s->omniscience = std::min(1.0f, s->omniscience + amount);
            s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return true;
        }
    }
    return false;
}

bool OmniGenesisEngine::CatalyzeGenesis(const std::string& omniId, float amount) {
    std::lock_guard<std::mutex> lock(s_omniMutex);
    
    for (auto& s : s_omniStructures) {
        if (s->omniId == omniId) {
            s->genesis = std::min(1.0f, s->genesis + amount);
            s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return true;
        }
    }
    return false;
}

bool OmniGenesisEngine::ManifestCreation(const std::string& omniId, float amount) {
    std::lock_guard<std::mutex> lock(s_omniMutex);
    
    for (auto& s : s_omniStructures) {
        if (s->omniId == omniId) {
            s->creation = std::min(1.0f, s->creation + amount);
            s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return true;
        }
    }
    return false;
}

bool OmniGenesisEngine::EstablishOrigin(const std::string& omniId, float amount) {
    std::lock_guard<std::mutex> lock(s_omniMutex);
    
    for (auto& s : s_omniStructures) {
        if (s->omniId == omniId) {
            s->origin = std::min(1.0f, s->origin + amount);
            s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return true;
        }
    }
    return false;
}

bool OmniGenesisEngine::TapSource(const std::string& omniId, float amount) {
    std::lock_guard<std::mutex> lock(s_omniMutex);
    
    for (auto& s : s_omniStructures) {
        if (s->omniId == omniId) {
            s->source = std::min(1.0f, s->source + amount);
            s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return true;
        }
    }
    return false;
}

// Genesis Omni operations
std::string OmniGenesisEngine::CreateGenesisOmni(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_genesisMutex);
    
    auto genesis = std::make_shared<GenesisOmni>();
    genesis->genesisId = "genesis_" + std::to_string(s_genesisCounter++);
    genesis->name = name;
    genesis->genesis = 0.0f;
    genesis->omniscience = 0.0f;
    genesis->birth = 0.0f;
    genesis->emergence = 0.0f;
    genesis->isBorn = false;
    genesis->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_genesisOmnis.push_back(genesis);
    return genesis->genesisId;
}

bool OmniGenesisEngine::DestroyGenesisOmni(const std::string& genesisId) {
    std::lock_guard<std::mutex> lock(s_genesisMutex);
    
    auto it = std::remove_if(s_genesisOmnis.begin(), s_genesisOmnis.end(),
        [&genesisId](const auto& g) { return g->genesisId == genesisId; });
    
    if (it != s_genesisOmnis.end()) {
        s_genesisOmnis.erase(it, s_genesisOmnis.end());
        return true;
    }
    return false;
}

std::shared_ptr<GenesisOmni> OmniGenesisEngine::GetGenesisOmni(const std::string& genesisId) {
    std::lock_guard<std::mutex> lock(s_genesisMutex);
    
    for (auto& g : s_genesisOmnis) {
        if (g->genesisId == genesisId) {
            return g;
        }
    }
    return nullptr;
}

std::vector<GenesisOmni> OmniGenesisEngine::GetAllGenesisOmnis() {
    std::lock_guard<std::mutex> lock(s_genesisMutex);
    
    std::vector<GenesisOmni> result;
    for (auto& g : s_genesisOmnis) {
        result.push_back(*g);
    }
    return result;
}

bool OmniGenesisEngine::NurtureBirth(const std::string& genesisId, float amount) {
    std::lock_guard<std::mutex> lock(s_genesisMutex);
    
    for (auto& g : s_genesisOmnis) {
        if (g->genesisId == genesisId) {
            g->birth = std::min(1.0f, g->birth + amount);
            return true;
        }
    }
    return false;
}

bool OmniGenesisEngine::FosterEmergence(const std::string& genesisId, float amount) {
    std::lock_guard<std::mutex> lock(s_genesisMutex);
    
    for (auto& g : s_genesisOmnis) {
        if (g->genesisId == genesisId) {
            g->emergence = std::min(1.0f, g->emergence + amount);
            return true;
        }
    }
    return false;
}

bool OmniGenesisEngine::DeclareBorn(const std::string& genesisId) {
    std::lock_guard<std::mutex> lock(s_genesisMutex);
    
    for (auto& g : s_genesisOmnis) {
        if (g->genesisId == genesisId) {
            g->isBorn = true;
            g->genesis = 1.0f;
            return true;
        }
    }
    return false;
}

// Creation Omni operations
std::string OmniGenesisEngine::CreateCreationOmni(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_creationMutex);
    
    auto creation = std::make_shared<CreationOmni>();
    creation->creationId = "creation_" + std::to_string(s_creationCounter++);
    creation->name = name;
    creation->creation = 0.0f;
    creation->omniscience = 0.0f;
    creation->manifestation = 0.0f;
    creation->formation = 0.0f;
    creation->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_creationOmnis.push_back(creation);
    return creation->creationId;
}

bool OmniGenesisEngine::DestroyCreationOmni(const std::string& creationId) {
    std::lock_guard<std::mutex> lock(s_creationMutex);
    
    auto it = std::remove_if(s_creationOmnis.begin(), s_creationOmnis.end(),
        [&creationId](const auto& c) { return c->creationId == creationId; });
    
    if (it != s_creationOmnis.end()) {
        s_creationOmnis.erase(it, s_creationOmnis.end());
        return true;
    }
    return false;
}

std::shared_ptr<CreationOmni> OmniGenesisEngine::GetCreationOmni(const std::string& creationId) {
    std::lock_guard<std::mutex> lock(s_creationMutex);
    
    for (auto& c : s_creationOmnis) {
        if (c->creationId == creationId) {
            return c;
        }
    }
    return nullptr;
}

std::vector<CreationOmni> OmniGenesisEngine::GetAllCreationOmnis() {
    std::lock_guard<std::mutex> lock(s_creationMutex);
    
    std::vector<CreationOmni> result;
    for (auto& c : s_creationOmnis) {
        result.push_back(*c);
    }
    return result;
}

bool OmniGenesisEngine::EnableManifestation(const std::string& creationId, float amount) {
    std::lock_guard<std::mutex> lock(s_creationMutex);
    
    for (auto& c : s_creationOmnis) {
        if (c->creationId == creationId) {
            c->manifestation = std::min(1.0f, c->manifestation + amount);
            return true;
        }
    }
    return false;
}

bool OmniGenesisEngine::GuideFormation(const std::string& creationId, float amount) {
    std::lock_guard<std::mutex> lock(s_creationMutex);
    
    for (auto& c : s_creationOmnis) {
        if (c->creationId == creationId) {
            c->formation = std::min(1.0f, c->formation + amount);
            return true;
        }
    }
    return false;
}

// Origin Omni operations
std::string OmniGenesisEngine::CreateOriginOmni(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_originMutex);
    
    auto origin = std::make_shared<OriginOmni>();
    origin->originId = "origin_" + std::to_string(s_originCounter++);
    origin->name = name;
    origin->origin = 0.0f;
    origin->omniscience = 0.0f;
    origin->beginning = 0.0f;
    origin->inception = 0.0f;
    origin->isOriginated = false;
    origin->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_originOmnis.push_back(origin);
    return origin->originId;
}

bool OmniGenesisEngine::DestroyOriginOmni(const std::string& originId) {
    std::lock_guard<std::mutex> lock(s_originMutex);
    
    auto it = std::remove_if(s_originOmnis.begin(), s_originOmnis.end(),
        [&originId](const auto& o) { return o->originId == originId; });
    
    if (it != s_originOmnis.end()) {
        s_originOmnis.erase(it, s_originOmnis.end());
        return true;
    }
    return false;
}

std::shared_ptr<OriginOmni> OmniGenesisEngine::GetOriginOmni(const std::string& originId) {
    std::lock_guard<std::mutex> lock(s_originMutex);
    
    for (auto& o : s_originOmnis) {
        if (o->originId == originId) {
            return o;
        }
    }
    return nullptr;
}

std::vector<OriginOmni> OmniGenesisEngine::GetAllOriginOmnis() {
    std::lock_guard<std::mutex> lock(s_originMutex);
    
    std::vector<OriginOmni> result;
    for (auto& o : s_originOmnis) {
        result.push_back(*o);
    }
    return result;
}

bool OmniGenesisEngine::MarkBeginning(const std::string& originId, float amount) {
    std::lock_guard<std::mutex> lock(s_originMutex);
    
    for (auto& o : s_originOmnis) {
        if (o->originId == originId) {
            o->beginning = std::min(1.0f, o->beginning + amount);
            return true;
        }
    }
    return false;
}

bool OmniGenesisEngine::CommenceInception(const std::string& originId, float amount) {
    std::lock_guard<std::mutex> lock(s_originMutex);
    
    for (auto& o : s_originOmnis) {
        if (o->originId == originId) {
            o->inception = std::min(1.0f, o->inception + amount);
            return true;
        }
    }
    return false;
}

bool OmniGenesisEngine::DeclareOriginated(const std::string& originId) {
    std::lock_guard<std::mutex> lock(s_originMutex);
    
    for (auto& o : s_originOmnis) {
        if (o->originId == originId) {
            o->isOriginated = true;
            o->origin = 1.0f;
            return true;
        }
    }
    return false;
}

// Source Omni operations
std::string OmniGenesisEngine::CreateSourceOmni(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_sourceMutex);
    
    auto source = std::make_shared<SourceOmni>();
    source->sourceId = "source_" + std::to_string(s_sourceCounter++);
    source->name = name;
    source->source = 0.0f;
    source->omniscience = 0.0f;
    source->fountain = 0.0f;
    source->wellspring = 0.0f;
    source->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_sourceOmnis.push_back(source);
    return source->sourceId;
}

bool OmniGenesisEngine::DestroySourceOmni(const std::string& sourceId) {
    std::lock_guard<std::mutex> lock(s_sourceMutex);
    
    auto it = std::remove_if(s_sourceOmnis.begin(), s_sourceOmnis.end(),
        [&sourceId](const auto& s) { return s->sourceId == sourceId; });
    
    if (it != s_sourceOmnis.end()) {
        s_sourceOmnis.erase(it, s_sourceOmnis.end());
        return true;
    }
    return false;
}

std::shared_ptr<SourceOmni> OmniGenesisEngine::GetSourceOmni(const std::string& sourceId) {
    std::lock_guard<std::mutex> lock(s_sourceMutex);
    
    for (auto& s : s_sourceOmnis) {
        if (s->sourceId == sourceId) {
            return s;
        }
    }
    return nullptr;
}

std::vector<SourceOmni> OmniGenesisEngine::GetAllSourceOmnis() {
    std::lock_guard<std::mutex> lock(s_sourceMutex);
    
    std::vector<SourceOmni> result;
    for (auto& s : s_sourceOmnis) {
        result.push_back(*s);
    }
    return result;
}

bool OmniGenesisEngine::ChannelFountain(const std::string& sourceId, float amount) {
    std::lock_guard<std::mutex> lock(s_sourceMutex);
    
    for (auto& s : s_sourceOmnis) {
        if (s->sourceId == sourceId) {
            s->fountain = std::min(1.0f, s->fountain + amount);
            return true;
        }
    }
    return false;
}

bool OmniGenesisEngine::AccessWellspring(const std::string& sourceId, float amount) {
    std::lock_guard<std::mutex> lock(s_sourceMutex);
    
    for (auto& s : s_sourceOmnis) {
        if (s->sourceId == sourceId) {
            s->wellspring = std::min(1.0f, s->wellspring + amount);
            return true;
        }
    }
    return false;
}

// Metrics and reporting
nlohmann::json OmniGenesisEngine::GetOmniGenesisMetrics() {
    std::lock_guard<std::mutex> lock1(s_omniMutex);
    std::lock_guard<std::mutex> lock2(s_genesisMutex);
    std::lock_guard<std::mutex> lock3(s_creationMutex);
    std::lock_guard<std::mutex> lock4(s_originMutex);
    std::lock_guard<std::mutex> lock5(s_sourceMutex);
    
    float totalOmniscience = 0.0f, totalGenesis = 0.0f, totalCreation = 0.0f, totalOrigin = 0.0f, totalSource = 0.0f;
    
    for (auto& s : s_omniStructures) {
        totalOmniscience += s->omniscience;
        totalGenesis += s->genesis;
        totalCreation += s->creation;
        totalOrigin += s->origin;
        totalSource += s->source;
    }
    
    int bornCount = 0;
    for (auto& g : s_genesisOmnis) {
        if (g->isBorn) bornCount++;
    }
    
    int originatedCount = 0;
    for (auto& o : s_originOmnis) {
        if (o->isOriginated) originatedCount++;
    }
    
    return {
        {"omniStructureCount", s_omniStructures.size()},
        {"genesisOmniCount", s_genesisOmnis.size()},
        {"creationOmniCount", s_creationOmnis.size()},
        {"originOmniCount", s_originOmnis.size()},
        {"sourceOmniCount", s_sourceOmnis.size()},
        {"totalOmniscience", totalOmniscience},
        {"totalGenesis", totalGenesis},
        {"totalCreation", totalCreation},
        {"totalOrigin", totalOrigin},
        {"totalSource", totalSource},
        {"bornCount", bornCount},
        {"originatedCount", originatedCount}
    };
}

nlohmann::json OmniGenesisEngine::GenerateOmniGenesisReport() {
    auto report = GetOmniGenesisMetrics();
    
    std::lock_guard<std::mutex> lock(s_omniMutex);
    nlohmann::json structures = nlohmann::json::array();
    for (auto& s : s_omniStructures) {
        structures.push_back(s->ToJson());
    }
    report["structures"] = structures;
    
    return report;
}

} // namespace OmniGenesis
