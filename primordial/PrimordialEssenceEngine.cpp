#include "PrimordialEssenceEngine.hpp"
#include <chrono>
#include <iomanip>
#include <sstream>
#include <random>

namespace PrimordialEssence {

// Static member definitions
std::atomic<bool> PrimordialEssenceEngine::s_initialized{false};
std::mutex PrimordialEssenceEngine::s_primordialMutex;
std::mutex PrimordialEssenceEngine::s_originMutex;
std::mutex PrimordialEssenceEngine::s_sourceMutex;
std::mutex PrimordialEssenceEngine::s_rootMutex;
std::mutex PrimordialEssenceEngine::s_foundationMutex;
std::mutex PrimordialEssenceEngine::s_groundMutex;
std::mutex PrimordialEssenceEngine::s_callbackMutex;

std::map<std::string, PrimordialEssenceStructure> PrimordialEssenceEngine::s_primordialStructures;
std::map<std::string, OriginAbsolute> PrimordialEssenceEngine::s_originAbsolutes;
std::map<std::string, SourceAbsolute> PrimordialEssenceEngine::s_sourceAbsolutes;
std::map<std::string, RootAbsolute> PrimordialEssenceEngine::s_rootAbsolutes;
std::map<std::string, FoundationAbsolute> PrimordialEssenceEngine::s_foundationAbsolutes;
std::map<std::string, GroundAbsolute> PrimordialEssenceEngine::s_groundAbsolutes;
std::vector<PrimordialEventCallback> PrimordialEssenceEngine::s_eventCallbacks;

// Structure implementations
PrimordialEssenceStructure::PrimordialEssenceStructure()
    : primordiality(0.0f)
    , origin(0.0f)
    , source(0.0f)
    , root(0.0f)
    , foundation(0.0f)
    , ground(0.0f)
    , isActive(true)
    , isPrimordial(false) {
}

nlohmann::json PrimordialEssenceStructure::ToJson() const {
    nlohmann::json j;
    j["primordialId"] = primordialId;
    j["name"] = name;
    j["description"] = description;
    j["primordiality"] = primordiality;
    j["origin"] = origin;
    j["source"] = source;
    j["root"] = root;
    j["foundation"] = foundation;
    j["ground"] = ground;
    j["createdAt"] = createdAt;
    j["updatedAt"] = updatedAt;
    j["isActive"] = isActive;
    j["isPrimordial"] = isPrimordial;
    return j;
}

PrimordialEssenceStructure PrimordialEssenceStructure::FromJson(const nlohmann::json& json) {
    PrimordialEssenceStructure s;
    s.primordialId = json.value("primordialId", "");
    s.name = json.value("name", "");
    s.description = json.value("description", "");
    s.primordiality = json.value("primordiality", 0.0f);
    s.origin = json.value("origin", 0.0f);
    s.source = json.value("source", 0.0f);
    s.root = json.value("root", 0.0f);
    s.foundation = json.value("foundation", 0.0f);
    s.ground = json.value("ground", 0.0f);
    s.createdAt = json.value("createdAt", "");
    s.updatedAt = json.value("updatedAt", "");
    s.isActive = json.value("isActive", true);
    s.isPrimordial = json.value("isPrimordial", false);
    return s;
}

OriginAbsolute::OriginAbsolute()
    : origin(0.0f)
    , beginning(0.0f)
    , inception(0.0f)
    , isOriginated(false) {
}

nlohmann::json OriginAbsolute::ToJson() const {
    nlohmann::json j;
    j["originId"] = originId;
    j["name"] = name;
    j["description"] = description;
    j["origin"] = origin;
    j["beginning"] = beginning;
    j["inception"] = inception;
    j["isOriginated"] = isOriginated;
    j["createdAt"] = createdAt;
    j["updatedAt"] = updatedAt;
    return j;
}

OriginAbsolute OriginAbsolute::FromJson(const nlohmann::json& json) {
    OriginAbsolute o;
    o.originId = json.value("originId", "");
    o.name = json.value("name", "");
    o.description = json.value("description", "");
    o.origin = json.value("origin", 0.0f);
    o.beginning = json.value("beginning", 0.0f);
    o.inception = json.value("inception", 0.0f);
    o.isOriginated = json.value("isOriginated", false);
    o.createdAt = json.value("createdAt", "");
    o.updatedAt = json.value("updatedAt", "");
    return o;
}

SourceAbsolute::SourceAbsolute()
    : source(0.0f)
    , wellspring(0.0f)
    , fountain(0.0f)
    , isSourced(false) {
}

nlohmann::json SourceAbsolute::ToJson() const {
    nlohmann::json j;
    j["sourceId"] = sourceId;
    j["name"] = name;
    j["description"] = description;
    j["source"] = source;
    j["wellspring"] = wellspring;
    j["fountain"] = fountain;
    j["isSourced"] = isSourced;
    j["createdAt"] = createdAt;
    j["updatedAt"] = updatedAt;
    return j;
}

SourceAbsolute SourceAbsolute::FromJson(const nlohmann::json& json) {
    SourceAbsolute s;
    s.sourceId = json.value("sourceId", "");
    s.name = json.value("name", "");
    s.description = json.value("description", "");
    s.source = json.value("source", 0.0f);
    s.wellspring = json.value("wellspring", 0.0f);
    s.fountain = json.value("fountain", 0.0f);
    s.isSourced = json.value("isSourced", false);
    s.createdAt = json.value("createdAt", "");
    s.updatedAt = json.value("updatedAt", "");
    return s;
}

RootAbsolute::RootAbsolute()
    : root(0.0f)
    , basis(0.0f)
    , core(0.0f)
    , isRooted(false) {
}

nlohmann::json RootAbsolute::ToJson() const {
    nlohmann::json j;
    j["rootId"] = rootId;
    j["name"] = name;
    j["description"] = description;
    j["root"] = root;
    j["basis"] = basis;
    j["core"] = core;
    j["isRooted"] = isRooted;
    j["createdAt"] = createdAt;
    j["updatedAt"] = updatedAt;
    return j;
}

RootAbsolute RootAbsolute::FromJson(const nlohmann::json& json) {
    RootAbsolute r;
    r.rootId = json.value("rootId", "");
    r.name = json.value("name", "");
    r.description = json.value("description", "");
    r.root = json.value("root", 0.0f);
    r.basis = json.value("basis", 0.0f);
    r.core = json.value("core", 0.0f);
    r.isRooted = json.value("isRooted", false);
    r.createdAt = json.value("createdAt", "");
    r.updatedAt = json.value("updatedAt", "");
    return r;
}

FoundationAbsolute::FoundationAbsolute()
    : foundation(0.0f)
    , groundwork(0.0f)
    , underpinning(0.0f)
    , isFounded(false) {
}

nlohmann::json FoundationAbsolute::ToJson() const {
    nlohmann::json j;
    j["foundationId"] = foundationId;
    j["name"] = name;
    j["description"] = description;
    j["foundation"] = foundation;
    j["groundwork"] = groundwork;
    j["underpinning"] = underpinning;
    j["isFounded"] = isFounded;
    j["createdAt"] = createdAt;
    j["updatedAt"] = updatedAt;
    return j;
}

FoundationAbsolute FoundationAbsolute::FromJson(const nlohmann::json& json) {
    FoundationAbsolute f;
    f.foundationId = json.value("foundationId", "");
    f.name = json.value("name", "");
    f.description = json.value("description", "");
    f.foundation = json.value("foundation", 0.0f);
    f.groundwork = json.value("groundwork", 0.0f);
    f.underpinning = json.value("underpinning", 0.0f);
    f.isFounded = json.value("isFounded", false);
    f.createdAt = json.value("createdAt", "");
    f.updatedAt = json.value("updatedAt", "");
    return f;
}

GroundAbsolute::GroundAbsolute()
    : ground(0.0f)
    , soil(0.0f)
    , bedrock(0.0f)
    , isGrounded(false) {
}

nlohmann::json GroundAbsolute::ToJson() const {
    nlohmann::json j;
    j["groundId"] = groundId;
    j["name"] = name;
    j["description"] = description;
    j["ground"] = ground;
    j["soil"] = soil;
    j["bedrock"] = bedrock;
    j["isGrounded"] = isGrounded;
    j["createdAt"] = createdAt;
    j["updatedAt"] = updatedAt;
    return j;
}

GroundAbsolute GroundAbsolute::FromJson(const nlohmann::json& json) {
    GroundAbsolute g;
    g.groundId = json.value("groundId", "");
    g.name = json.value("name", "");
    g.description = json.value("description", "");
    g.ground = json.value("ground", 0.0f);
    g.soil = json.value("soil", 0.0f);
    g.bedrock = json.value("bedrock", 0.0f);
    g.isGrounded = json.value("isGrounded", false);
    g.createdAt = json.value("createdAt", "");
    g.updatedAt = json.value("updatedAt", "");
    return g;
}

// Engine implementation
bool PrimordialEssenceEngine::Init() {
    if (s_initialized.load()) return true;
    s_initialized.store(true);
    EmitEvent("engine_initialized", {});
    return true;
}

void PrimordialEssenceEngine::Shutdown() {
    if (!s_initialized.load()) return;
    
    std::lock_guard<std::mutex> lock1(s_primordialMutex);
    std::lock_guard<std::mutex> lock2(s_originMutex);
    std::lock_guard<std::mutex> lock3(s_sourceMutex);
    std::lock_guard<std::mutex> lock4(s_rootMutex);
    std::lock_guard<std::mutex> lock5(s_foundationMutex);
    std::lock_guard<std::mutex> lock6(s_groundMutex);
    
    s_primordialStructures.clear();
    s_originAbsolutes.clear();
    s_sourceAbsolutes.clear();
    s_rootAbsolutes.clear();
    s_foundationAbsolutes.clear();
    s_groundAbsolutes.clear();
    
    s_initialized.store(false);
    EmitEvent("engine_shutdown", {});
}

bool PrimordialEssenceEngine::IsInitialized() {
    return s_initialized.load();
}

std::string PrimordialEssenceEngine::CreatePrimordialEssenceStructure(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_primordialMutex);
    
    PrimordialEssenceStructure s;
    s.primordialId = GenerateId();
    s.name = name;
    s.description = "Primordial essence structure";
    s.createdAt = GetCurrentTimestamp();
    s.updatedAt = s.createdAt;
    s.primordiality = 0.1f;
    s.origin = 0.1f;
    s.source = 0.1f;
    s.root = 0.1f;
    s.foundation = 0.1f;
    s.ground = 0.1f;
    
    s_primordialStructures[s.primordialId] = s;
    
    nlohmann::json eventData;
    eventData["primordialId"] = s.primordialId;
    eventData["name"] = name;
    EmitEvent("structure_created", eventData);
    
    return s.primordialId;
}

bool PrimordialEssenceEngine::DestroyPrimordialEssenceStructure(const std::string& primordialId) {
    std::lock_guard<std::mutex> lock(s_primordialMutex);
    auto it = s_primordialStructures.find(primordialId);
    if (it == s_primordialStructures.end()) return false;
    
    s_primordialStructures.erase(it);
    
    nlohmann::json eventData;
    eventData["primordialId"] = primordialId;
    EmitEvent("structure_destroyed", eventData);
    return true;
}

std::shared_ptr<PrimordialEssenceStructure> PrimordialEssenceEngine::GetPrimordialEssenceStructure(const std::string& primordialId) {
    std::lock_guard<std::mutex> lock(s_primordialMutex);
    auto it = s_primordialStructures.find(primordialId);
    if (it != s_primordialStructures.end()) {
        return std::make_shared<PrimordialEssenceStructure>(it->second);
    }
    return nullptr;
}

std::vector<PrimordialEssenceStructure> PrimordialEssenceEngine::GetAllPrimordialEssenceStructures() {
    std::lock_guard<std::mutex> lock(s_primordialMutex);
    std::vector<PrimordialEssenceStructure> result;
    for (auto& pair : s_primordialStructures) {
        result.push_back(pair.second);
    }
    return result;
}

bool PrimordialEssenceEngine::UpdatePrimordialEssenceStructure(const std::string& primordialId, const PrimordialEssenceStructure& structure) {
    std::lock_guard<std::mutex> lock(s_primordialMutex);
    auto it = s_primordialStructures.find(primordialId);
    if (it == s_primordialStructures.end()) return false;
    
    PrimordialEssenceStructure updated = structure;
    updated.primordialId = primordialId;
    updated.updatedAt = GetCurrentTimestamp();
    s_primordialStructures[primordialId] = updated;
    
    EmitEvent("structure_updated", updated.ToJson());
    return true;
}

// Origin Absolute operations
std::string PrimordialEssenceEngine::CreateOriginAbsolute(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_originMutex);
    
    OriginAbsolute o;
    o.originId = GenerateId();
    o.name = name;
    o.description = "Origin absolute";
    o.createdAt = GetCurrentTimestamp();
    o.updatedAt = o.createdAt;
    o.origin = 0.1f;
    o.beginning = 0.1f;
    o.inception = 0.1f;
    
    s_originAbsolutes[o.originId] = o;
    return o.originId;
}

bool PrimordialEssenceEngine::DestroyOriginAbsolute(const std::string& originId) {
    std::lock_guard<std::mutex> lock(s_originMutex);
    return s_originAbsolutes.erase(originId) > 0;
}

std::shared_ptr<OriginAbsolute> PrimordialEssenceEngine::GetOriginAbsolute(const std::string& originId) {
    std::lock_guard<std::mutex> lock(s_originMutex);
    auto it = s_originAbsolutes.find(originId);
    if (it != s_originAbsolutes.end()) {
        return std::make_shared<OriginAbsolute>(it->second);
    }
    return nullptr;
}

std::vector<OriginAbsolute> PrimordialEssenceEngine::GetAllOriginAbsolutes() {
    std::lock_guard<std::mutex> lock(s_originMutex);
    std::vector<OriginAbsolute> result;
    for (auto& pair : s_originAbsolutes) {
        result.push_back(pair.second);
    }
    return result;
}

// Source Absolute operations
std::string PrimordialEssenceEngine::CreateSourceAbsolute(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_sourceMutex);
    
    SourceAbsolute s;
    s.sourceId = GenerateId();
    s.name = name;
    s.description = "Source absolute";
    s.createdAt = GetCurrentTimestamp();
    s.updatedAt = s.createdAt;
    s.source = 0.1f;
    s.wellspring = 0.1f;
    s.fountain = 0.1f;
    
    s_sourceAbsolutes[s.sourceId] = s;
    return s.sourceId;
}

bool PrimordialEssenceEngine::DestroySourceAbsolute(const std::string& sourceId) {
    std::lock_guard<std::mutex> lock(s_sourceMutex);
    return s_sourceAbsolutes.erase(sourceId) > 0;
}

std::shared_ptr<SourceAbsolute> PrimordialEssenceEngine::GetSourceAbsolute(const std::string& sourceId) {
    std::lock_guard<std::mutex> lock(s_sourceMutex);
    auto it = s_sourceAbsolutes.find(sourceId);
    if (it != s_sourceAbsolutes.end()) {
        return std::make_shared<SourceAbsolute>(it->second);
    }
    return nullptr;
}

std::vector<SourceAbsolute> PrimordialEssenceEngine::GetAllSourceAbsolutes() {
    std::lock_guard<std::mutex> lock(s_sourceMutex);
    std::vector<SourceAbsolute> result;
    for (auto& pair : s_sourceAbsolutes) {
        result.push_back(pair.second);
    }
    return result;
}

// Root Absolute operations
std::string PrimordialEssenceEngine::CreateRootAbsolute(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_rootMutex);
    
    RootAbsolute r;
    r.rootId = GenerateId();
    r.name = name;
    r.description = "Root absolute";
    r.createdAt = GetCurrentTimestamp();
    r.updatedAt = r.createdAt;
    r.root = 0.1f;
    r.basis = 0.1f;
    r.core = 0.1f;
    
    s_rootAbsolutes[r.rootId] = r;
    return r.rootId;
}

bool PrimordialEssenceEngine::DestroyRootAbsolute(const std::string& rootId) {
    std::lock_guard<std::mutex> lock(s_rootMutex);
    return s_rootAbsolutes.erase(rootId) > 0;
}

std::shared_ptr<RootAbsolute> PrimordialEssenceEngine::GetRootAbsolute(const std::string& rootId) {
    std::lock_guard<std::mutex> lock(s_rootMutex);
    auto it = s_rootAbsolutes.find(rootId);
    if (it != s_rootAbsolutes.end()) {
        return std::make_shared<RootAbsolute>(it->second);
    }
    return nullptr;
}

std::vector<RootAbsolute> PrimordialEssenceEngine::GetAllRootAbsolutes() {
    std::lock_guard<std::mutex> lock(s_rootMutex);
    std::vector<RootAbsolute> result;
    for (auto& pair : s_rootAbsolutes) {
        result.push_back(pair.second);
    }
    return result;
}

// Foundation Absolute operations
std::string PrimordialEssenceEngine::CreateFoundationAbsolute(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_foundationMutex);
    
    FoundationAbsolute f;
    f.foundationId = GenerateId();
    f.name = name;
    f.description = "Foundation absolute";
    f.createdAt = GetCurrentTimestamp();
    f.updatedAt = f.createdAt;
    f.foundation = 0.1f;
    f.groundwork = 0.1f;
    f.underpinning = 0.1f;
    
    s_foundationAbsolutes[f.foundationId] = f;
    return f.foundationId;
}

bool PrimordialEssenceEngine::DestroyFoundationAbsolute(const std::string& foundationId) {
    std::lock_guard<std::mutex> lock(s_foundationMutex);
    return s_foundationAbsolutes.erase(foundationId) > 0;
}

std::shared_ptr<FoundationAbsolute> PrimordialEssenceEngine::GetFoundationAbsolute(const std::string& foundationId) {
    std::lock_guard<std::mutex> lock(s_foundationMutex);
    auto it = s_foundationAbsolutes.find(foundationId);
    if (it != s_foundationAbsolutes.end()) {
        return std::make_shared<FoundationAbsolute>(it->second);
    }
    return nullptr;
}

std::vector<FoundationAbsolute> PrimordialEssenceEngine::GetAllFoundationAbsolutes() {
    std::lock_guard<std::mutex> lock(s_foundationMutex);
    std::vector<FoundationAbsolute> result;
    for (auto& pair : s_foundationAbsolutes) {
        result.push_back(pair.second);
    }
    return result;
}

// Ground Absolute operations
std::string PrimordialEssenceEngine::CreateGroundAbsolute(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_groundMutex);
    
    GroundAbsolute g;
    g.groundId = GenerateId();
    g.name = name;
    g.description = "Ground absolute";
    g.createdAt = GetCurrentTimestamp();
    g.updatedAt = g.createdAt;
    g.ground = 0.1f;
    g.soil = 0.1f;
    g.bedrock = 0.1f;
    
    s_groundAbsolutes[g.groundId] = g;
    return g.groundId;
}

bool PrimordialEssenceEngine::DestroyGroundAbsolute(const std::string& groundId) {
    std::lock_guard<std::mutex> lock(s_groundMutex);
    return s_groundAbsolutes.erase(groundId) > 0;
}

std::shared_ptr<GroundAbsolute> PrimordialEssenceEngine::GetGroundAbsolute(const std::string& groundId) {
    std::lock_guard<std::mutex> lock(s_groundMutex);
    auto it = s_groundAbsolutes.find(groundId);
    if (it != s_groundAbsolutes.end()) {
        return std::make_shared<GroundAbsolute>(it->second);
    }
    return nullptr;
}

std::vector<GroundAbsolute> PrimordialEssenceEngine::GetAllGroundAbsolutes() {
    std::lock_guard<std::mutex> lock(s_groundMutex);
    std::vector<GroundAbsolute> result;
    for (auto& pair : s_groundAbsolutes) {
        result.push_back(pair.second);
    }
    return result;
}

// Primordial operations
bool PrimordialEssenceEngine::DeepenPrimordiality(const std::string& primordialId, float amount) {
    std::lock_guard<std::mutex> lock(s_primordialMutex);
    auto it = s_primordialStructures.find(primordialId);
    if (it == s_primordialStructures.end()) return false;
    
    it->second.primordiality = std::min(1.0f, it->second.primordiality + amount);
    it->second.updatedAt = GetCurrentTimestamp();
    return true;
}

bool PrimordialEssenceEngine::TraceOrigin(const std::string& primordialId, float amount) {
    std::lock_guard<std::mutex> lock(s_primordialMutex);
    auto it = s_primordialStructures.find(primordialId);
    if (it == s_primordialStructures.end()) return false;
    
    it->second.origin = std::min(1.0f, it->second.origin + amount);
    it->second.updatedAt = GetCurrentTimestamp();
    return true;
}

bool PrimordialEssenceEngine::TapSource(const std::string& primordialId, float amount) {
    std::lock_guard<std::mutex> lock(s_primordialMutex);
    auto it = s_primordialStructures.find(primordialId);
    if (it == s_primordialStructures.end()) return false;
    
    it->second.source = std::min(1.0f, it->second.source + amount);
    it->second.updatedAt = GetCurrentTimestamp();
    return true;
}

bool PrimordialEssenceEngine::ExtendRoot(const std::string& primordialId, float amount) {
    std::lock_guard<std::mutex> lock(s_primordialMutex);
    auto it = s_primordialStructures.find(primordialId);
    if (it == s_primordialStructures.end()) return false;
    
    it->second.root = std::min(1.0f, it->second.root + amount);
    it->second.updatedAt = GetCurrentTimestamp();
    return true;
}

bool PrimordialEssenceEngine::LayFoundation(const std::string& primordialId, float amount) {
    std::lock_guard<std::mutex> lock(s_primordialMutex);
    auto it = s_primordialStructures.find(primordialId);
    if (it == s_primordialStructures.end()) return false;
    
    it->second.foundation = std::min(1.0f, it->second.foundation + amount);
    it->second.updatedAt = GetCurrentTimestamp();
    return true;
}

bool PrimordialEssenceEngine::EstablishGround(const std::string& primordialId, float amount) {
    std::lock_guard<std::mutex> lock(s_primordialMutex);
    auto it = s_primordialStructures.find(primordialId);
    if (it == s_primordialStructures.end()) return false;
    
    it->second.ground = std::min(1.0f, it->second.ground + amount);
    it->second.updatedAt = GetCurrentTimestamp();
    
    if (it->second.ground >= 1.0f) {
        it->second.isPrimordial = true;
    }
    return true;
}

// Origin operations
bool PrimordialEssenceEngine::CommenceBeginning(const std::string& originId, float amount) {
    std::lock_guard<std::mutex> lock(s_originMutex);
    auto it = s_originAbsolutes.find(originId);
    if (it == s_originAbsolutes.end()) return false;
    
    it->second.beginning = std::min(1.0f, it->second.beginning + amount);
    it->second.updatedAt = GetCurrentTimestamp();
    return true;
}

bool PrimordialEssenceEngine::MarkInception(const std::string& originId, float amount) {
    std::lock_guard<std::mutex> lock(s_originMutex);
    auto it = s_originAbsolutes.find(originId);
    if (it == s_originAbsolutes.end()) return false;
    
    it->second.inception = std::min(1.0f, it->second.inception + amount);
    it->second.updatedAt = GetCurrentTimestamp();
    return true;
}

bool PrimordialEssenceEngine::DeclareOriginated(const std::string& originId) {
    std::lock_guard<std::mutex> lock(s_originMutex);
    auto it = s_originAbsolutes.find(originId);
    if (it == s_originAbsolutes.end()) return false;
    
    it->second.isOriginated = true;
    it->second.origin = 1.0f;
    it->second.updatedAt = GetCurrentTimestamp();
    return true;
}

// Source operations
bool PrimordialEssenceEngine::OpenWellspring(const std::string& sourceId, float amount) {
    std::lock_guard<std::mutex> lock(s_sourceMutex);
    auto it = s_sourceAbsolutes.find(sourceId);
    if (it == s_sourceAbsolutes.end()) return false;
    
    it->second.wellspring = std::min(1.0f, it->second.wellspring + amount);
    it->second.updatedAt = GetCurrentTimestamp();
    return true;
}

bool PrimordialEssenceEngine::ActivateFountain(const std::string& sourceId, float amount) {
    std::lock_guard<std::mutex> lock(s_sourceMutex);
    auto it = s_sourceAbsolutes.find(sourceId);
    if (it == s_sourceAbsolutes.end()) return false;
    
    it->second.fountain = std::min(1.0f, it->second.fountain + amount);
    it->second.updatedAt = GetCurrentTimestamp();
    return true;
}

bool PrimordialEssenceEngine::DeclareSourced(const std::string& sourceId) {
    std::lock_guard<std::mutex> lock(s_sourceMutex);
    auto it = s_sourceAbsolutes.find(sourceId);
    if (it == s_sourceAbsolutes.end()) return false;
    
    it->second.isSourced = true;
    it->second.source = 1.0f;
    it->second.updatedAt = GetCurrentTimestamp();
    return true;
}

// Root operations
bool PrimordialEssenceEngine::StrengthenBasis(const std::string& rootId, float amount) {
    std::lock_guard<std::mutex> lock(s_rootMutex);
    auto it = s_rootAbsolutes.find(rootId);
    if (it == s_rootAbsolutes.end()) return false;
    
    it->second.basis = std::min(1.0f, it->second.basis + amount);
    it->second.updatedAt = GetCurrentTimestamp();
    return true;
}

bool PrimordialEssenceEngine::FortifyCore(const std::string& rootId, float amount) {
    std::lock_guard<std::mutex> lock(s_rootMutex);
    auto it = s_rootAbsolutes.find(rootId);
    if (it == s_rootAbsolutes.end()) return false;
    
    it->second.core = std::min(1.0f, it->second.core + amount);
    it->second.updatedAt = GetCurrentTimestamp();
    return true;
}

bool PrimordialEssenceEngine::DeclareRooted(const std::string& rootId) {
    std::lock_guard<std::mutex> lock(s_rootMutex);
    auto it = s_rootAbsolutes.find(rootId);
    if (it == s_rootAbsolutes.end()) return false;
    
    it->second.isRooted = true;
    it->second.root = 1.0f;
    it->second.updatedAt = GetCurrentTimestamp();
    return true;
}

// Foundation operations
bool PrimordialEssenceEngine::PrepareGroundwork(const std::string& foundationId, float amount) {
    std::lock_guard<std::mutex> lock(s_foundationMutex);
    auto it = s_foundationAbsolutes.find(foundationId);
    if (it == s_foundationAbsolutes.end()) return false;
    
    it->second.groundwork = std::min(1.0f, it->second.groundwork + amount);
    it->second.updatedAt = GetCurrentTimestamp();
    return true;
}

bool PrimordialEssenceEngine::SecureUnderpinning(const std::string& foundationId, float amount) {
    std::lock_guard<std::mutex> lock(s_foundationMutex);
    auto it = s_foundationAbsolutes.find(foundationId);
    if (it == s_foundationAbsolutes.end()) return false;
    
    it->second.underpinning = std::min(1.0f, it->second.underpinning + amount);
    it->second.updatedAt = GetCurrentTimestamp();
    return true;
}

bool PrimordialEssenceEngine::DeclareFounded(const std::string& foundationId) {
    std::lock_guard<std::mutex> lock(s_foundationMutex);
    auto it = s_foundationAbsolutes.find(foundationId);
    if (it == s_foundationAbsolutes.end()) return false;
    
    it->second.isFounded = true;
    it->second.foundation = 1.0f;
    it->second.updatedAt = GetCurrentTimestamp();
    return true;
}

// Ground operations
bool PrimordialEssenceEngine::CultivateSoil(const std::string& groundId, float amount) {
    std::lock_guard<std::mutex> lock(s_groundMutex);
    auto it = s_groundAbsolutes.find(groundId);
    if (it == s_groundAbsolutes.end()) return false;
    
    it->second.soil = std::min(1.0f, it->second.soil + amount);
    it->second.updatedAt = GetCurrentTimestamp();
    return true;
}

bool PrimordialEssenceEngine::ExposeBedrock(const std::string& groundId, float amount) {
    std::lock_guard<std::mutex> lock(s_groundMutex);
    auto it = s_groundAbsolutes.find(groundId);
    if (it == s_groundAbsolutes.end()) return false;
    
    it->second.bedrock = std::min(1.0f, it->second.bedrock + amount);
    it->second.updatedAt = GetCurrentTimestamp();
    return true;
}

bool PrimordialEssenceEngine::DeclareGrounded(const std::string& groundId) {
    std::lock_guard<std::mutex> lock(s_groundMutex);
    auto it = s_groundAbsolutes.find(groundId);
    if (it == s_groundAbsolutes.end()) return false;
    
    it->second.isGrounded = true;
    it->second.ground = 1.0f;
    it->second.updatedAt = GetCurrentTimestamp();
    return true;
}

nlohmann::json PrimordialEssenceEngine::GetPrimordialEssenceMetrics() {
    std::lock_guard<std::mutex> lock1(s_primordialMutex);
    std::lock_guard<std::mutex> lock2(s_originMutex);
    std::lock_guard<std::mutex> lock3(s_sourceMutex);
    std::lock_guard<std::mutex> lock4(s_rootMutex);
    std::lock_guard<std::mutex> lock5(s_foundationMutex);
    std::lock_guard<std::mutex> lock6(s_groundMutex);
    
    nlohmann::json metrics;
    metrics["primordialStructureCount"] = s_primordialStructures.size();
    metrics["originAbsoluteCount"] = s_originAbsolutes.size();
    metrics["sourceAbsoluteCount"] = s_sourceAbsolutes.size();
    metrics["rootAbsoluteCount"] = s_rootAbsolutes.size();
    metrics["foundationAbsoluteCount"] = s_foundationAbsolutes.size();
    metrics["groundAbsoluteCount"] = s_groundAbsolutes.size();
    
    float totalPrimordiality = 0.0f, totalOrigin = 0.0f, totalSource = 0.0f;
    float totalRoot = 0.0f, totalFoundation = 0.0f, totalGround = 0.0f;
    int primordialCount = 0;
    
    for (auto& pair : s_primordialStructures) {
        totalPrimordiality += pair.second.primordiality;
        totalOrigin += pair.second.origin;
        totalSource += pair.second.source;
        totalRoot += pair.second.root;
        totalFoundation += pair.second.foundation;
        totalGround += pair.second.ground;
        if (pair.second.isPrimordial) primordialCount++;
    }
    
    metrics["totalPrimordiality"] = totalPrimordiality;
    metrics["totalOrigin"] = totalOrigin;
    metrics["totalSource"] = totalSource;
    metrics["totalRoot"] = totalRoot;
    metrics["totalFoundation"] = totalFoundation;
    metrics["totalGround"] = totalGround;
    metrics["primordialCount"] = primordialCount;
    
    if (!s_primordialStructures.empty()) {
        metrics["averagePrimordiality"] = totalPrimordiality / s_primordialStructures.size();
        metrics["averageOrigin"] = totalOrigin / s_primordialStructures.size();
        metrics["averageSource"] = totalSource / s_primordialStructures.size();
        metrics["averageRoot"] = totalRoot / s_primordialStructures.size();
        metrics["averageFoundation"] = totalFoundation / s_primordialStructures.size();
        metrics["averageGround"] = totalGround / s_primordialStructures.size();
    }
    
    return metrics;
}

void PrimordialEssenceEngine::RegisterEventCallback(PrimordialEventCallback callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_eventCallbacks.push_back(callback);
}

void PrimordialEssenceEngine::UnregisterEventCallback(PrimordialEventCallback callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_eventCallbacks.erase(
        std::remove_if(s_eventCallbacks.begin(), s_eventCallbacks.end(),
            [&callback](const PrimordialEventCallback& cb) {
                return cb.target_type() == callback.target_type();
            }), s_eventCallbacks.end());
}

void PrimordialEssenceEngine::EmitEvent(const std::string& eventType, const nlohmann::json& data) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    for (auto& callback : s_eventCallbacks) {
        callback(eventType, data);
    }
}

std::string PrimordialEssenceEngine::GenerateId() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    ss << "prim_";
    for (int i = 0; i < 16; i++) {
        ss << std::hex << dis(gen);
    }
    return ss.str();
}

std::string PrimordialEssenceEngine::GetCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%dT%H:%M:%S");
    return ss.str();
}

} // namespace PrimordialEssence
