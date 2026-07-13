#include "CosmicSynthesisEngine.hpp"
#include <chrono>
#include <algorithm>

namespace CosmicSynthesis {

// Static member definitions
bool CosmicSynthesisEngine::s_initialized = false;
std::mutex CosmicSynthesisEngine::s_cosmicMutex;
std::mutex CosmicSynthesisEngine::s_synthesisMutex;
std::mutex CosmicSynthesisEngine::s_harmonyMutex;
std::mutex CosmicSynthesisEngine::s_balanceMutex;
std::mutex CosmicSynthesisEngine::s_unityMutex;

std::vector<std::shared_ptr<CosmicSynthesisStructure>> CosmicSynthesisEngine::s_cosmicStructures;
std::vector<std::shared_ptr<SynthesisCosmic>> CosmicSynthesisEngine::s_synthesisCosmics;
std::vector<std::shared_ptr<HarmonyCosmic>> CosmicSynthesisEngine::s_harmonyCosmics;
std::vector<std::shared_ptr<BalanceCosmic>> CosmicSynthesisEngine::s_balanceCosmics;
std::vector<std::shared_ptr<UnityCosmic>> CosmicSynthesisEngine::s_unityCosmics;

std::atomic<int64_t> CosmicSynthesisEngine::s_cosmicCounter{0};
std::atomic<int64_t> CosmicSynthesisEngine::s_synthesisCounter{0};
std::atomic<int64_t> CosmicSynthesisEngine::s_harmonyCounter{0};
std::atomic<int64_t> CosmicSynthesisEngine::s_balanceCounter{0};
std::atomic<int64_t> CosmicSynthesisEngine::s_unityCounter{0};

// JSON serialization implementations
nlohmann::json CosmicSynthesisStructure::ToJson() const {
    return {
        {"cosmicId", cosmicId},
        {"name", name},
        {"cosmicness", cosmicness},
        {"synthesis", synthesis},
        {"harmony", harmony},
        {"balance", balance},
        {"unity", unity},
        {"createdAt", createdAt},
        {"lastModified", lastModified},
        {"isActive", isActive}
    };
}

CosmicSynthesisStructure CosmicSynthesisStructure::FromJson(const nlohmann::json& j) {
    CosmicSynthesisStructure s;
    s.cosmicId = j.value("cosmicId", "");
    s.name = j.value("name", "");
    s.cosmicness = j.value("cosmicness", 0.0f);
    s.synthesis = j.value("synthesis", 0.0f);
    s.harmony = j.value("harmony", 0.0f);
    s.balance = j.value("balance", 0.0f);
    s.unity = j.value("unity", 0.0f);
    s.createdAt = j.value("createdAt", 0);
    s.lastModified = j.value("lastModified", 0);
    s.isActive = j.value("isActive", true);
    return s;
}

nlohmann::json SynthesisCosmic::ToJson() const {
    return {
        {"synthesisId", synthesisId},
        {"name", name},
        {"synthesis", synthesis},
        {"cosmicness", cosmicness},
        {"integration", integration},
        {"fusion", fusion},
        {"isSynthesized", isSynthesized},
        {"createdAt", createdAt}
    };
}

SynthesisCosmic SynthesisCosmic::FromJson(const nlohmann::json& j) {
    SynthesisCosmic s;
    s.synthesisId = j.value("synthesisId", "");
    s.name = j.value("name", "");
    s.synthesis = j.value("synthesis", 0.0f);
    s.cosmicness = j.value("cosmicness", 0.0f);
    s.integration = j.value("integration", 0.0f);
    s.fusion = j.value("fusion", 0.0f);
    s.isSynthesized = j.value("isSynthesized", false);
    s.createdAt = j.value("createdAt", 0);
    return s;
}

nlohmann::json HarmonyCosmic::ToJson() const {
    return {
        {"harmonyId", harmonyId},
        {"name", name},
        {"harmony", harmony},
        {"cosmicness", cosmicness},
        {"resonance", resonance},
        {"alignment", alignment},
        {"createdAt", createdAt}
    };
}

HarmonyCosmic HarmonyCosmic::FromJson(const nlohmann::json& j) {
    HarmonyCosmic h;
    h.harmonyId = j.value("harmonyId", "");
    h.name = j.value("name", "");
    h.harmony = j.value("harmony", 0.0f);
    h.cosmicness = j.value("cosmicness", 0.0f);
    h.resonance = j.value("resonance", 0.0f);
    h.alignment = j.value("alignment", 0.0f);
    h.createdAt = j.value("createdAt", 0);
    return h;
}

nlohmann::json BalanceCosmic::ToJson() const {
    return {
        {"balanceId", balanceId},
        {"name", name},
        {"balance", balance},
        {"cosmicness", cosmicness},
        {"equilibrium", equilibrium},
        {"stability", stability},
        {"isBalanced", isBalanced},
        {"createdAt", createdAt}
    };
}

BalanceCosmic BalanceCosmic::FromJson(const nlohmann::json& j) {
    BalanceCosmic b;
    b.balanceId = j.value("balanceId", "");
    b.name = j.value("name", "");
    b.balance = j.value("balance", 0.0f);
    b.cosmicness = j.value("cosmicness", 0.0f);
    b.equilibrium = j.value("equilibrium", 0.0f);
    b.stability = j.value("stability", 0.0f);
    b.isBalanced = j.value("isBalanced", false);
    b.createdAt = j.value("createdAt", 0);
    return b;
}

nlohmann::json UnityCosmic::ToJson() const {
    return {
        {"unityId", unityId},
        {"name", name},
        {"unity", unity},
        {"cosmicness", cosmicness},
        {"cohesion", cohesion},
        {"oneness", oneness},
        {"createdAt", createdAt}
    };
}

UnityCosmic UnityCosmic::FromJson(const nlohmann::json& j) {
    UnityCosmic u;
    u.unityId = j.value("unityId", "");
    u.name = j.value("name", "");
    u.unity = j.value("unity", 0.0f);
    u.cosmicness = j.value("cosmicness", 0.0f);
    u.cohesion = j.value("cohesion", 0.0f);
    u.oneness = j.value("oneness", 0.0f);
    u.createdAt = j.value("createdAt", 0);
    return u;
}

// Engine implementation
void CosmicSynthesisEngine::Init() {
    if (s_initialized) return;
    s_initialized = true;
}

void CosmicSynthesisEngine::Shutdown() {
    if (!s_initialized) return;
    
    std::lock_guard<std::mutex> lock1(s_cosmicMutex);
    std::lock_guard<std::mutex> lock2(s_synthesisMutex);
    std::lock_guard<std::mutex> lock3(s_harmonyMutex);
    std::lock_guard<std::mutex> lock4(s_balanceMutex);
    std::lock_guard<std::mutex> lock5(s_unityMutex);
    
    s_cosmicStructures.clear();
    s_synthesisCosmics.clear();
    s_harmonyCosmics.clear();
    s_balanceCosmics.clear();
    s_unityCosmics.clear();
    
    s_initialized = false;
}

bool CosmicSynthesisEngine::IsInitialized() {
    return s_initialized;
}

// Cosmic Synthesis Structure operations
std::string CosmicSynthesisEngine::CreateCosmicSynthesisStructure(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_cosmicMutex);
    
    auto structure = std::make_shared<CosmicSynthesisStructure>();
    structure->cosmicId = "cosmic_" + std::to_string(s_cosmicCounter++);
    structure->name = name;
    structure->cosmicness = 0.0f;
    structure->synthesis = 0.0f;
    structure->harmony = 0.0f;
    structure->balance = 0.0f;
    structure->unity = 0.0f;
    structure->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    structure->lastModified = structure->createdAt;
    structure->isActive = true;
    
    s_cosmicStructures.push_back(structure);
    return structure->cosmicId;
}

bool CosmicSynthesisEngine::DestroyCosmicSynthesisStructure(const std::string& cosmicId) {
    std::lock_guard<std::mutex> lock(s_cosmicMutex);
    
    auto it = std::remove_if(s_cosmicStructures.begin(), s_cosmicStructures.end(),
        [&cosmicId](const auto& s) { return s->cosmicId == cosmicId; });
    
    if (it != s_cosmicStructures.end()) {
        s_cosmicStructures.erase(it, s_cosmicStructures.end());
        return true;
    }
    return false;
}

std::shared_ptr<CosmicSynthesisStructure> CosmicSynthesisEngine::GetCosmicSynthesisStructure(const std::string& cosmicId) {
    std::lock_guard<std::mutex> lock(s_cosmicMutex);
    
    for (auto& s : s_cosmicStructures) {
        if (s->cosmicId == cosmicId) {
            return s;
        }
    }
    return nullptr;
}

std::vector<CosmicSynthesisStructure> CosmicSynthesisEngine::GetAllCosmicSynthesisStructures() {
    std::lock_guard<std::mutex> lock(s_cosmicMutex);
    
    std::vector<CosmicSynthesisStructure> result;
    for (auto& s : s_cosmicStructures) {
        result.push_back(*s);
    }
    return result;
}

bool CosmicSynthesisEngine::ExpandCosmicness(const std::string& cosmicId, float amount) {
    std::lock_guard<std::mutex> lock(s_cosmicMutex);
    
    for (auto& s : s_cosmicStructures) {
        if (s->cosmicId == cosmicId) {
            s->cosmicness = std::min(1.0f, s->cosmicness + amount);
            s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return true;
        }
    }
    return false;
}

bool CosmicSynthesisEngine::CatalyzeSynthesis(const std::string& cosmicId, float amount) {
    std::lock_guard<std::mutex> lock(s_cosmicMutex);
    
    for (auto& s : s_cosmicStructures) {
        if (s->cosmicId == cosmicId) {
            s->synthesis = std::min(1.0f, s->synthesis + amount);
            s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return true;
        }
    }
    return false;
}

bool CosmicSynthesisEngine::AttuneHarmony(const std::string& cosmicId, float amount) {
    std::lock_guard<std::mutex> lock(s_cosmicMutex);
    
    for (auto& s : s_cosmicStructures) {
        if (s->cosmicId == cosmicId) {
            s->harmony = std::min(1.0f, s->harmony + amount);
            s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return true;
        }
    }
    return false;
}

bool CosmicSynthesisEngine::EstablishBalance(const std::string& cosmicId, float amount) {
    std::lock_guard<std::mutex> lock(s_cosmicMutex);
    
    for (auto& s : s_cosmicStructures) {
        if (s->cosmicId == cosmicId) {
            s->balance = std::min(1.0f, s->balance + amount);
            s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return true;
        }
    }
    return false;
}

bool CosmicSynthesisEngine::ForgeUnity(const std::string& cosmicId, float amount) {
    std::lock_guard<std::mutex> lock(s_cosmicMutex);
    
    for (auto& s : s_cosmicStructures) {
        if (s->cosmicId == cosmicId) {
            s->unity = std::min(1.0f, s->unity + amount);
            s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return true;
        }
    }
    return false;
}

// Synthesis Cosmic operations
std::string CosmicSynthesisEngine::CreateSynthesisCosmic(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_synthesisMutex);
    
    auto synthesis = std::make_shared<SynthesisCosmic>();
    synthesis->synthesisId = "synthesis_" + std::to_string(s_synthesisCounter++);
    synthesis->name = name;
    synthesis->synthesis = 0.0f;
    synthesis->cosmicness = 0.0f;
    synthesis->integration = 0.0f;
    synthesis->fusion = 0.0f;
    synthesis->isSynthesized = false;
    synthesis->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_synthesisCosmics.push_back(synthesis);
    return synthesis->synthesisId;
}

bool CosmicSynthesisEngine::DestroySynthesisCosmic(const std::string& synthesisId) {
    std::lock_guard<std::mutex> lock(s_synthesisMutex);
    
    auto it = std::remove_if(s_synthesisCosmics.begin(), s_synthesisCosmics.end(),
        [&synthesisId](const auto& s) { return s->synthesisId == synthesisId; });
    
    if (it != s_synthesisCosmics.end()) {
        s_synthesisCosmics.erase(it, s_synthesisCosmics.end());
        return true;
    }
    return false;
}

std::shared_ptr<SynthesisCosmic> CosmicSynthesisEngine::GetSynthesisCosmic(const std::string& synthesisId) {
    std::lock_guard<std::mutex> lock(s_synthesisMutex);
    
    for (auto& s : s_synthesisCosmics) {
        if (s->synthesisId == synthesisId) {
            return s;
        }
    }
    return nullptr;
}

std::vector<SynthesisCosmic> CosmicSynthesisEngine::GetAllSynthesisCosmics() {
    std::lock_guard<std::mutex> lock(s_synthesisMutex);
    
    std::vector<SynthesisCosmic> result;
    for (auto& s : s_synthesisCosmics) {
        result.push_back(*s);
    }
    return result;
}

bool CosmicSynthesisEngine::DeepenIntegration(const std::string& synthesisId, float amount) {
    std::lock_guard<std::mutex> lock(s_synthesisMutex);
    
    for (auto& s : s_synthesisCosmics) {
        if (s->synthesisId == synthesisId) {
            s->integration = std::min(1.0f, s->integration + amount);
            return true;
        }
    }
    return false;
}

bool CosmicSynthesisEngine::CatalyzeFusion(const std::string& synthesisId, float amount) {
    std::lock_guard<std::mutex> lock(s_synthesisMutex);
    
    for (auto& s : s_synthesisCosmics) {
        if (s->synthesisId == synthesisId) {
            s->fusion = std::min(1.0f, s->fusion + amount);
            return true;
        }
    }
    return false;
}

bool CosmicSynthesisEngine::DeclareSynthesized(const std::string& synthesisId) {
    std::lock_guard<std::mutex> lock(s_synthesisMutex);
    
    for (auto& s : s_synthesisCosmics) {
        if (s->synthesisId == synthesisId) {
            s->isSynthesized = true;
            s->synthesis = 1.0f;
            return true;
        }
    }
    return false;
}

// Harmony Cosmic operations
std::string CosmicSynthesisEngine::CreateHarmonyCosmic(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_harmonyMutex);
    
    auto harmony = std::make_shared<HarmonyCosmic>();
    harmony->harmonyId = "harmony_" + std::to_string(s_harmonyCounter++);
    harmony->name = name;
    harmony->harmony = 0.0f;
    harmony->cosmicness = 0.0f;
    harmony->resonance = 0.0f;
    harmony->alignment = 0.0f;
    harmony->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_harmonyCosmics.push_back(harmony);
    return harmony->harmonyId;
}

bool CosmicSynthesisEngine::DestroyHarmonyCosmic(const std::string& harmonyId) {
    std::lock_guard<std::mutex> lock(s_harmonyMutex);
    
    auto it = std::remove_if(s_harmonyCosmics.begin(), s_harmonyCosmics.end(),
        [&harmonyId](const auto& h) { return h->harmonyId == harmonyId; });
    
    if (it != s_harmonyCosmics.end()) {
        s_harmonyCosmics.erase(it, s_harmonyCosmics.end());
        return true;
    }
    return false;
}

std::shared_ptr<HarmonyCosmic> CosmicSynthesisEngine::GetHarmonyCosmic(const std::string& harmonyId) {
    std::lock_guard<std::mutex> lock(s_harmonyMutex);
    
    for (auto& h : s_harmonyCosmics) {
        if (h->harmonyId == harmonyId) {
            return h;
        }
    }
    return nullptr;
}

std::vector<HarmonyCosmic> CosmicSynthesisEngine::GetAllHarmonyCosmics() {
    std::lock_guard<std::mutex> lock(s_harmonyMutex);
    
    std::vector<HarmonyCosmic> result;
    for (auto& h : s_harmonyCosmics) {
        result.push_back(*h);
    }
    return result;
}

bool CosmicSynthesisEngine::AmplifyResonance(const std::string& harmonyId, float amount) {
    std::lock_guard<std::mutex> lock(s_harmonyMutex);
    
    for (auto& h : s_harmonyCosmics) {
        if (h->harmonyId == harmonyId) {
            h->resonance = std::min(1.0f, h->resonance + amount);
            return true;
        }
    }
    return false;
}

bool CosmicSynthesisEngine::PerfectAlignment(const std::string& harmonyId, float amount) {
    std::lock_guard<std::mutex> lock(s_harmonyMutex);
    
    for (auto& h : s_harmonyCosmics) {
        if (h->harmonyId == harmonyId) {
            h->alignment = std::min(1.0f, h->alignment + amount);
            return true;
        }
    }
    return false;
}

// Balance Cosmic operations
std::string CosmicSynthesisEngine::CreateBalanceCosmic(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_balanceMutex);
    
    auto balance = std::make_shared<BalanceCosmic>();
    balance->balanceId = "balance_" + std::to_string(s_balanceCounter++);
    balance->name = name;
    balance->balance = 0.0f;
    balance->cosmicness = 0.0f;
    balance->equilibrium = 0.0f;
    balance->stability = 0.0f;
    balance->isBalanced = false;
    balance->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_balanceCosmics.push_back(balance);
    return balance->balanceId;
}

bool CosmicSynthesisEngine::DestroyBalanceCosmic(const std::string& balanceId) {
    std::lock_guard<std::mutex> lock(s_balanceMutex);
    
    auto it = std::remove_if(s_balanceCosmics.begin(), s_balanceCosmics.end(),
        [&balanceId](const auto& b) { return b->balanceId == balanceId; });
    
    if (it != s_balanceCosmics.end()) {
        s_balanceCosmics.erase(it, s_balanceCosmics.end());
        return true;
    }
    return false;
}

std::shared_ptr<BalanceCosmic> CosmicSynthesisEngine::GetBalanceCosmic(const std::string& balanceId) {
    std::lock_guard<std::mutex> lock(s_balanceMutex);
    
    for (auto& b : s_balanceCosmics) {
        if (b->balanceId == balanceId) {
            return b;
        }
    }
    return nullptr;
}

std::vector<BalanceCosmic> CosmicSynthesisEngine::GetAllBalanceCosmics() {
    std::lock_guard<std::mutex> lock(s_balanceMutex);
    
    std::vector<BalanceCosmic> result;
    for (auto& b : s_balanceCosmics) {
        result.push_back(*b);
    }
    return result;
}

bool CosmicSynthesisEngine::RestoreEquilibrium(const std::string& balanceId, float amount) {
    std::lock_guard<std::mutex> lock(s_balanceMutex);
    
    for (auto& b : s_balanceCosmics) {
        if (b->balanceId == balanceId) {
            b->equilibrium = std::min(1.0f, b->equilibrium + amount);
            return true;
        }
    }
    return false;
}

bool CosmicSynthesisEngine::EnsureStability(const std::string& balanceId, float amount) {
    std::lock_guard<std::mutex> lock(s_balanceMutex);
    
    for (auto& b : s_balanceCosmics) {
        if (b->balanceId == balanceId) {
            b->stability = std::min(1.0f, b->stability + amount);
            return true;
        }
    }
    return false;
}

bool CosmicSynthesisEngine::DeclareBalanced(const std::string& balanceId) {
    std::lock_guard<std::mutex> lock(s_balanceMutex);
    
    for (auto& b : s_balanceCosmics) {
        if (b->balanceId == balanceId) {
            b->isBalanced = true;
            b->balance = 1.0f;
            return true;
        }
    }
    return false;
}

// Unity Cosmic operations
std::string CosmicSynthesisEngine::CreateUnityCosmic(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_unityMutex);
    
    auto unity = std::make_shared<UnityCosmic>();
    unity->unityId = "unity_" + std::to_string(s_unityCounter++);
    unity->name = name;
    unity->unity = 0.0f;
    unity->cosmicness = 0.0f;
    unity->cohesion = 0.0f;
    unity->oneness = 0.0f;
    unity->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_unityCosmics.push_back(unity);
    return unity->unityId;
}

bool CosmicSynthesisEngine::DestroyUnityCosmic(const std::string& unityId) {
    std::lock_guard<std::mutex> lock(s_unityMutex);
    
    auto it = std::remove_if(s_unityCosmics.begin(), s_unityCosmics.end(),
        [&unityId](const auto& u) { return u->unityId == unityId; });
    
    if (it != s_unityCosmics.end()) {
        s_unityCosmics.erase(it, s_unityCosmics.end());
        return true;
    }
    return false;
}

std::shared_ptr<UnityCosmic> CosmicSynthesisEngine::GetUnityCosmic(const std::string& unityId) {
    std::lock_guard<std::mutex> lock(s_unityMutex);
    
    for (auto& u : s_unityCosmics) {
        if (u->unityId == unityId) {
            return u;
        }
    }
    return nullptr;
}

std::vector<UnityCosmic> CosmicSynthesisEngine::GetAllUnityCosmics() {
    std::lock_guard<std::mutex> lock(s_unityMutex);
    
    std::vector<UnityCosmic> result;
    for (auto& u : s_unityCosmics) {
        result.push_back(*u);
    }
    return result;
}

bool CosmicSynthesisEngine::StrengthenCohesion(const std::string& unityId, float amount) {
    std::lock_guard<std::mutex> lock(s_unityMutex);
    
    for (auto& u : s_unityCosmics) {
        if (u->unityId == unityId) {
            u->cohesion = std::min(1.0f, u->cohesion + amount);
            return true;
        }
    }
    return false;
}

bool CosmicSynthesisEngine::RealizeOneness(const std::string& unityId, float amount) {
    std::lock_guard<std::mutex> lock(s_unityMutex);
    
    for (auto& u : s_unityCosmics) {
        if (u->unityId == unityId) {
            u->oneness = std::min(1.0f, u->oneness + amount);
            return true;
        }
    }
    return false;
}

// Metrics and reporting
nlohmann::json CosmicSynthesisEngine::GetCosmicSynthesisMetrics() {
    std::lock_guard<std::mutex> lock1(s_cosmicMutex);
    std::lock_guard<std::mutex> lock2(s_synthesisMutex);
    std::lock_guard<std::mutex> lock3(s_harmonyMutex);
    std::lock_guard<std::mutex> lock4(s_balanceMutex);
    std::lock_guard<std::mutex> lock5(s_unityMutex);
    
    float totalCosmicness = 0.0f, totalSynthesis = 0.0f, totalHarmony = 0.0f, totalBalance = 0.0f, totalUnity = 0.0f;
    
    for (auto& s : s_cosmicStructures) {
        totalCosmicness += s->cosmicness;
        totalSynthesis += s->synthesis;
        totalHarmony += s->harmony;
        totalBalance += s->balance;
        totalUnity += s->unity;
    }
    
    int synthesizedCount = 0;
    for (auto& s : s_synthesisCosmics) {
        if (s->isSynthesized) synthesizedCount++;
    }
    
    int balancedCount = 0;
    for (auto& b : s_balanceCosmics) {
        if (b->isBalanced) balancedCount++;
    }
    
    return {
        {"cosmicStructureCount", s_cosmicStructures.size()},
        {"synthesisCosmicCount", s_synthesisCosmics.size()},
        {"harmonyCosmicCount", s_harmonyCosmics.size()},
        {"balanceCosmicCount", s_balanceCosmics.size()},
        {"unityCosmicCount", s_unityCosmics.size()},
        {"totalCosmicness", totalCosmicness},
        {"totalSynthesis", totalSynthesis},
        {"totalHarmony", totalHarmony},
        {"totalBalance", totalBalance},
        {"totalUnity", totalUnity},
        {"synthesizedCount", synthesizedCount},
        {"balancedCount", balancedCount}
    };
}

nlohmann::json CosmicSynthesisEngine::GenerateCosmicSynthesisReport() {
    auto report = GetCosmicSynthesisMetrics();
    
    std::lock_guard<std::mutex> lock(s_cosmicMutex);
    nlohmann::json structures = nlohmann::json::array();
    for (auto& s : s_cosmicStructures) {
        structures.push_back(s->ToJson());
    }
    report["structures"] = structures;
    
    return report;
}

} // namespace CosmicSynthesis
