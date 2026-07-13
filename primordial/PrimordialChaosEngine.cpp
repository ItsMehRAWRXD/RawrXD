#include "PrimordialChaosEngine.hpp"
#include <chrono>
#include <algorithm>

namespace PrimordialChaos {

// Static member definitions
bool PrimordialChaosEngine::s_initialized = false;
std::mutex PrimordialChaosEngine::s_primordialMutex;
std::mutex PrimordialChaosEngine::s_chaosMutex;
std::mutex PrimordialChaosEngine::s_voidMutex;
std::mutex PrimordialChaosEngine::s_abyssMutex;
std::mutex PrimordialChaosEngine::s_fluxMutex;

std::vector<std::shared_ptr<PrimordialChaosStructure>> PrimordialChaosEngine::s_primordialStructures;
std::vector<std::shared_ptr<ChaosPrimordial>> PrimordialChaosEngine::s_chaosPrimordials;
std::vector<std::shared_ptr<VoidPrimordial>> PrimordialChaosEngine::s_voidPrimordials;
std::vector<std::shared_ptr<AbyssPrimordial>> PrimordialChaosEngine::s_abyssPrimordials;
std::vector<std::shared_ptr<FluxPrimordial>> PrimordialChaosEngine::s_fluxPrimordials;

std::atomic<int64_t> PrimordialChaosEngine::s_primordialCounter{0};
std::atomic<int64_t> PrimordialChaosEngine::s_chaosCounter{0};
std::atomic<int64_t> PrimordialChaosEngine::s_voidCounter{0};
std::atomic<int64_t> PrimordialChaosEngine::s_abyssCounter{0};
std::atomic<int64_t> PrimordialChaosEngine::s_fluxCounter{0};

// JSON serialization implementations
nlohmann::json PrimordialChaosStructure::ToJson() const {
    return {
        {"primordialId", primordialId},
        {"name", name},
        {"primordiality", primordiality},
        {"chaos", chaos},
        {"voidness", voidness},
        {"abyss", abyss},
        {"flux", flux},
        {"createdAt", createdAt},
        {"lastModified", lastModified},
        {"isActive", isActive}
    };
}

PrimordialChaosStructure PrimordialChaosStructure::FromJson(const nlohmann::json& j) {
    PrimordialChaosStructure s;
    s.primordialId = j.value("primordialId", "");
    s.name = j.value("name", "");
    s.primordiality = j.value("primordiality", 0.0f);
    s.chaos = j.value("chaos", 0.0f);
    s.voidness = j.value("voidness", 0.0f);
    s.abyss = j.value("abyss", 0.0f);
    s.flux = j.value("flux", 0.0f);
    s.createdAt = j.value("createdAt", 0);
    s.lastModified = j.value("lastModified", 0);
    s.isActive = j.value("isActive", true);
    return s;
}

nlohmann::json ChaosPrimordial::ToJson() const {
    return {
        {"chaosId", chaosId},
        {"name", name},
        {"chaos", chaos},
        {"primordiality", primordiality},
        {"disorder", disorder},
        {"turbulence", turbulence},
        {"isChaotic", isChaotic},
        {"createdAt", createdAt}
    };
}

ChaosPrimordial ChaosPrimordial::FromJson(const nlohmann::json& j) {
    ChaosPrimordial c;
    c.chaosId = j.value("chaosId", "");
    c.name = j.value("name", "");
    c.chaos = j.value("chaos", 0.0f);
    c.primordiality = j.value("primordiality", 0.0f);
    c.disorder = j.value("disorder", 0.0f);
    c.turbulence = j.value("turbulence", 0.0f);
    c.isChaotic = j.value("isChaotic", false);
    c.createdAt = j.value("createdAt", 0);
    return c;
}

nlohmann::json VoidPrimordial::ToJson() const {
    return {
        {"voidId", voidId},
        {"name", name},
        {"voidness", voidness},
        {"primordiality", primordiality},
        {"emptiness", emptiness},
        {"nullity", nullity},
        {"createdAt", createdAt}
    };
}

VoidPrimordial VoidPrimordial::FromJson(const nlohmann::json& j) {
    VoidPrimordial v;
    v.voidId = j.value("voidId", "");
    v.name = j.value("name", "");
    v.voidness = j.value("voidness", 0.0f);
    v.primordiality = j.value("primordiality", 0.0f);
    v.emptiness = j.value("emptiness", 0.0f);
    v.nullity = j.value("nullity", 0.0f);
    v.createdAt = j.value("createdAt", 0);
    return v;
}

nlohmann::json AbyssPrimordial::ToJson() const {
    return {
        {"abyssId", abyssId},
        {"name", name},
        {"abyss", abyss},
        {"primordiality", primordiality},
        {"depth", depth},
        {"darkness", darkness},
        {"isAbyssal", isAbyssal},
        {"createdAt", createdAt}
    };
}

AbyssPrimordial AbyssPrimordial::FromJson(const nlohmann::json& j) {
    AbyssPrimordial a;
    a.abyssId = j.value("abyssId", "");
    a.name = j.value("name", "");
    a.abyss = j.value("abyss", 0.0f);
    a.primordiality = j.value("primordiality", 0.0f);
    a.depth = j.value("depth", 0.0f);
    a.darkness = j.value("darkness", 0.0f);
    a.isAbyssal = j.value("isAbyssal", false);
    a.createdAt = j.value("createdAt", 0);
    return a;
}

nlohmann::json FluxPrimordial::ToJson() const {
    return {
        {"fluxId", fluxId},
        {"name", name},
        {"flux", flux},
        {"primordiality", primordiality},
        {"change", change},
        {"flow", flow},
        {"createdAt", createdAt}
    };
}

FluxPrimordial FluxPrimordial::FromJson(const nlohmann::json& j) {
    FluxPrimordial f;
    f.fluxId = j.value("fluxId", "");
    f.name = j.value("name", "");
    f.flux = j.value("flux", 0.0f);
    f.primordiality = j.value("primordiality", 0.0f);
    f.change = j.value("change", 0.0f);
    f.flow = j.value("flow", 0.0f);
    f.createdAt = j.value("createdAt", 0);
    return f;
}

// Engine implementation
void PrimordialChaosEngine::Init() {
    if (s_initialized) return;
    s_initialized = true;
}

void PrimordialChaosEngine::Shutdown() {
    if (!s_initialized) return;
    
    std::lock_guard<std::mutex> lock1(s_primordialMutex);
    std::lock_guard<std::mutex> lock2(s_chaosMutex);
    std::lock_guard<std::mutex> lock3(s_voidMutex);
    std::lock_guard<std::mutex> lock4(s_abyssMutex);
    std::lock_guard<std::mutex> lock5(s_fluxMutex);
    
    s_primordialStructures.clear();
    s_chaosPrimordials.clear();
    s_voidPrimordials.clear();
    s_abyssPrimordials.clear();
    s_fluxPrimordials.clear();
    
    s_initialized = false;
}

bool PrimordialChaosEngine::IsInitialized() {
    return s_initialized;
}

// Primordial Chaos Structure operations
std::string PrimordialChaosEngine::CreatePrimordialChaosStructure(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_primordialMutex);
    
    auto structure = std::make_shared<PrimordialChaosStructure>();
    structure->primordialId = "primordial_" + std::to_string(s_primordialCounter++);
    structure->name = name;
    structure->primordiality = 0.0f;
    structure->chaos = 0.0f;
    structure->voidness = 0.0f;
    structure->abyss = 0.0f;
    structure->flux = 0.0f;
    structure->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    structure->lastModified = structure->createdAt;
    structure->isActive = true;
    
    s_primordialStructures.push_back(structure);
    return structure->primordialId;
}

bool PrimordialChaosEngine::DestroyPrimordialChaosStructure(const std::string& primordialId) {
    std::lock_guard<std::mutex> lock(s_primordialMutex);
    
    auto it = std::remove_if(s_primordialStructures.begin(), s_primordialStructures.end(),
        [&primordialId](const auto& s) { return s->primordialId == primordialId; });
    
    if (it != s_primordialStructures.end()) {
        s_primordialStructures.erase(it, s_primordialStructures.end());
        return true;
    }
    return false;
}

std::shared_ptr<PrimordialChaosStructure> PrimordialChaosEngine::GetPrimordialChaosStructure(const std::string& primordialId) {
    std::lock_guard<std::mutex> lock(s_primordialMutex);
    
    for (auto& s : s_primordialStructures) {
        if (s->primordialId == primordialId) {
            return s;
        }
    }
    return nullptr;
}

std::vector<PrimordialChaosStructure> PrimordialChaosEngine::GetAllPrimordialChaosStructures() {
    std::lock_guard<std::mutex> lock(s_primordialMutex);
    
    std::vector<PrimordialChaosStructure> result;
    for (auto& s : s_primordialStructures) {
        result.push_back(*s);
    }
    return result;
}

bool PrimordialChaosEngine::AwakenPrimordiality(const std::string& primordialId, float amount) {
    std::lock_guard<std::mutex> lock(s_primordialMutex);
    
    for (auto& s : s_primordialStructures) {
        if (s->primordialId == primordialId) {
            s->primordiality = std::min(1.0f, s->primordiality + amount);
            s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return true;
        }
    }
    return false;
}

bool PrimordialChaosEngine::UnleashChaos(const std::string& primordialId, float amount) {
    std::lock_guard<std::mutex> lock(s_primordialMutex);
    
    for (auto& s : s_primordialStructures) {
        if (s->primordialId == primordialId) {
            s->chaos = std::min(1.0f, s->chaos + amount);
            s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return true;
        }
    }
    return false;
}

bool PrimordialChaosEngine::EmbraceVoid(const std::string& primordialId, float amount) {
    std::lock_guard<std::mutex> lock(s_primordialMutex);
    
    for (auto& s : s_primordialStructures) {
        if (s->primordialId == primordialId) {
            s->voidness = std::min(1.0f, s->voidness + amount);
            s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return true;
        }
    }
    return false;
}

bool PrimordialChaosEngine::PlumbAbyss(const std::string& primordialId, float amount) {
    std::lock_guard<std::mutex> lock(s_primordialMutex);
    
    for (auto& s : s_primordialStructures) {
        if (s->primordialId == primordialId) {
            s->abyss = std::min(1.0f, s->abyss + amount);
            s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return true;
        }
    }
    return false;
}

bool PrimordialChaosEngine::ChannelFlux(const std::string& primordialId, float amount) {
    std::lock_guard<std::mutex> lock(s_primordialMutex);
    
    for (auto& s : s_primordialStructures) {
        if (s->primordialId == primordialId) {
            s->flux = std::min(1.0f, s->flux + amount);
            s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return true;
        }
    }
    return false;
}

// Chaos Primordial operations
std::string PrimordialChaosEngine::CreateChaosPrimordial(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_chaosMutex);
    
    auto chaos = std::make_shared<ChaosPrimordial>();
    chaos->chaosId = "chaos_" + std::to_string(s_chaosCounter++);
    chaos->name = name;
    chaos->chaos = 0.0f;
    chaos->primordiality = 0.0f;
    chaos->disorder = 0.0f;
    chaos->turbulence = 0.0f;
    chaos->isChaotic = false;
    chaos->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_chaosPrimordials.push_back(chaos);
    return chaos->chaosId;
}

bool PrimordialChaosEngine::DestroyChaosPrimordial(const std::string& chaosId) {
    std::lock_guard<std::mutex> lock(s_chaosMutex);
    
    auto it = std::remove_if(s_chaosPrimordials.begin(), s_chaosPrimordials.end(),
        [&chaosId](const auto& c) { return c->chaosId == chaosId; });
    
    if (it != s_chaosPrimordials.end()) {
        s_chaosPrimordials.erase(it, s_chaosPrimordials.end());
        return true;
    }
    return false;
}

std::shared_ptr<ChaosPrimordial> PrimordialChaosEngine::GetChaosPrimordial(const std::string& chaosId) {
    std::lock_guard<std::mutex> lock(s_chaosMutex);
    
    for (auto& c : s_chaosPrimordials) {
        if (c->chaosId == chaosId) {
            return c;
        }
    }
    return nullptr;
}

std::vector<ChaosPrimordial> PrimordialChaosEngine::GetAllChaosPrimordials() {
    std::lock_guard<std::mutex> lock(s_chaosMutex);
    
    std::vector<ChaosPrimordial> result;
    for (auto& c : s_chaosPrimordials) {
        result.push_back(*c);
    }
    return result;
}

bool PrimordialChaosEngine::SowDisorder(const std::string& chaosId, float amount) {
    std::lock_guard<std::mutex> lock(s_chaosMutex);
    
    for (auto& c : s_chaosPrimordials) {
        if (c->chaosId == chaosId) {
            c->disorder = std::min(1.0f, c->disorder + amount);
            return true;
        }
    }
    return false;
}

bool PrimordialChaosEngine::StirTurbulence(const std::string& chaosId, float amount) {
    std::lock_guard<std::mutex> lock(s_chaosMutex);
    
    for (auto& c : s_chaosPrimordials) {
        if (c->chaosId == chaosId) {
            c->turbulence = std::min(1.0f, c->turbulence + amount);
            return true;
        }
    }
    return false;
}

bool PrimordialChaosEngine::DeclareChaotic(const std::string& chaosId) {
    std::lock_guard<std::mutex> lock(s_chaosMutex);
    
    for (auto& c : s_chaosPrimordials) {
        if (c->chaosId == chaosId) {
            c->isChaotic = true;
            c->chaos = 1.0f;
            return true;
        }
    }
    return false;
}

// Void Primordial operations
std::string PrimordialChaosEngine::CreateVoidPrimordial(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_voidMutex);
    
    auto voidp = std::make_shared<VoidPrimordial>();
    voidp->voidId = "void_" + std::to_string(s_voidCounter++);
    voidp->name = name;
    voidp->voidness = 0.0f;
    voidp->primordiality = 0.0f;
    voidp->emptiness = 0.0f;
    voidp->nullity = 0.0f;
    voidp->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_voidPrimordials.push_back(voidp);
    return voidp->voidId;
}

bool PrimordialChaosEngine::DestroyVoidPrimordial(const std::string& voidId) {
    std::lock_guard<std::mutex> lock(s_voidMutex);
    
    auto it = std::remove_if(s_voidPrimordials.begin(), s_voidPrimordials.end(),
        [&voidId](const auto& v) { return v->voidId == voidId; });
    
    if (it != s_voidPrimordials.end()) {
        s_voidPrimordials.erase(it, s_voidPrimordials.end());
        return true;
    }
    return false;
}

std::shared_ptr<VoidPrimordial> PrimordialChaosEngine::GetVoidPrimordial(const std::string& voidId) {
    std::lock_guard<std::mutex> lock(s_voidMutex);
    
    for (auto& v : s_voidPrimordials) {
        if (v->voidId == voidId) {
            return v;
        }
    }
    return nullptr;
}

std::vector<VoidPrimordial> PrimordialChaosEngine::GetAllVoidPrimordials() {
    std::lock_guard<std::mutex> lock(s_voidMutex);
    
    std::vector<VoidPrimordial> result;
    for (auto& v : s_voidPrimordials) {
        result.push_back(*v);
    }
    return result;
}

bool PrimordialChaosEngine::DeepenEmptiness(const std::string& voidId, float amount) {
    std::lock_guard<std::mutex> lock(s_voidMutex);
    
    for (auto& v : s_voidPrimordials) {
        if (v->voidId == voidId) {
            v->emptiness = std::min(1.0f, v->emptiness + amount);
            return true;
        }
    }
    return false;
}

bool PrimordialChaosEngine::EmbraceNullity(const std::string& voidId, float amount) {
    std::lock_guard<std::mutex> lock(s_voidMutex);
    
    for (auto& v : s_voidPrimordials) {
        if (v->voidId == voidId) {
            v->nullity = std::min(1.0f, v->nullity + amount);
            return true;
        }
    }
    return false;
}

// Abyss Primordial operations
std::string PrimordialChaosEngine::CreateAbyssPrimordial(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_abyssMutex);
    
    auto abyss = std::make_shared<AbyssPrimordial>();
    abyss->abyssId = "abyss_" + std::to_string(s_abyssCounter++);
    abyss->name = name;
    abyss->abyss = 0.0f;
    abyss->primordiality = 0.0f;
    abyss->depth = 0.0f;
    abyss->darkness = 0.0f;
    abyss->isAbyssal = false;
    abyss->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_abyssPrimordials.push_back(abyss);
    return abyss->abyssId;
}

bool PrimordialChaosEngine::DestroyAbyssPrimordial(const std::string& abyssId) {
    std::lock_guard<std::mutex> lock(s_abyssMutex);
    
    auto it = std::remove_if(s_abyssPrimordials.begin(), s_abyssPrimordials.end(),
        [&abyssId](const auto& a) { return a->abyssId == abyssId; });
    
    if (it != s_abyssPrimordials.end()) {
        s_abyssPrimordials.erase(it, s_abyssPrimordials.end());
        return true;
    }
    return false;
}

std::shared_ptr<AbyssPrimordial> PrimordialChaosEngine::GetAbyssPrimordial(const std::string& abyssId) {
    std::lock_guard<std::mutex> lock(s_abyssMutex);
    
    for (auto& a : s_abyssPrimordials) {
        if (a->abyssId == abyssId) {
            return a;
        }
    }
    return nullptr;
}

std::vector<AbyssPrimordial> PrimordialChaosEngine::GetAllAbyssPrimordials() {
    std::lock_guard<std::mutex> lock(s_abyssMutex);
    
    std::vector<AbyssPrimordial> result;
    for (auto& a : s_abyssPrimordials) {
        result.push_back(*a);
    }
    return result;
}

bool PrimordialChaosEngine::FathomDepth(const std::string& abyssId, float amount) {
    std::lock_guard<std::mutex> lock(s_abyssMutex);
    
    for (auto& a : s_abyssPrimordials) {
        if (a->abyssId == abyssId) {
            a->depth = std::min(1.0f, a->depth + amount);
            return true;
        }
    }
    return false;
}

bool PrimordialChaosEngine::ShroudDarkness(const std::string& abyssId, float amount) {
    std::lock_guard<std::mutex> lock(s_abyssMutex);
    
    for (auto& a : s_abyssPrimordials) {
        if (a->abyssId == abyssId) {
            a->darkness = std::min(1.0f, a->darkness + amount);
            return true;
        }
    }
    return false;
}

bool PrimordialChaosEngine::DeclareAbyssal(const std::string& abyssId) {
    std::lock_guard<std::mutex> lock(s_abyssMutex);
    
    for (auto& a : s_abyssPrimordials) {
        if (a->abyssId == abyssId) {
            a->isAbyssal = true;
            a->abyss = 1.0f;
            return true;
        }
    }
    return false;
}

// Flux Primordial operations
std::string PrimordialChaosEngine::CreateFluxPrimordial(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_fluxMutex);
    
    auto flux = std::make_shared<FluxPrimordial>();
    flux->fluxId = "flux_" + std::to_string(s_fluxCounter++);
    flux->name = name;
    flux->flux = 0.0f;
    flux->primordiality = 0.0f;
    flux->change = 0.0f;
    flux->flow = 0.0f;
    flux->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_fluxPrimordials.push_back(flux);
    return flux->fluxId;
}

bool PrimordialChaosEngine::DestroyFluxPrimordial(const std::string& fluxId) {
    std::lock_guard<std::mutex> lock(s_fluxMutex);
    
    auto it = std::remove_if(s_fluxPrimordials.begin(), s_fluxPrimordials.end(),
        [&fluxId](const auto& f) { return f->fluxId == fluxId; });
    
    if (it != s_fluxPrimordials.end()) {
        s_fluxPrimordials.erase(it, s_fluxPrimordials.end());
        return true;
    }
    return false;
}

std::shared_ptr<FluxPrimordial> PrimordialChaosEngine::GetFluxPrimordial(const std::string& fluxId) {
    std::lock_guard<std::mutex> lock(s_fluxMutex);
    
    for (auto& f : s_fluxPrimordials) {
        if (f->fluxId == fluxId) {
            return f;
        }
    }
    return nullptr;
}

std::vector<FluxPrimordial> PrimordialChaosEngine::GetAllFluxPrimordials() {
    std::lock_guard<std::mutex> lock(s_fluxMutex);
    
    std::vector<FluxPrimordial> result;
    for (auto& f : s_fluxPrimordials) {
        result.push_back(*f);
    }
    return result;
}

bool PrimordialChaosEngine::AccelerateChange(const std::string& fluxId, float amount) {
    std::lock_guard<std::mutex> lock(s_fluxMutex);
    
    for (auto& f : s_fluxPrimordials) {
        if (f->fluxId == fluxId) {
            f->change = std::min(1.0f, f->change + amount);
            return true;
        }
    }
    return false;
}

bool PrimordialChaosEngine::DirectFlow(const std::string& fluxId, float amount) {
    std::lock_guard<std::mutex> lock(s_fluxMutex);
    
    for (auto& f : s_fluxPrimordials) {
        if (f->fluxId == fluxId) {
            f->flow = std::min(1.0f, f->flow + amount);
            return true;
        }
    }
    return false;
}

// Metrics and reporting
nlohmann::json PrimordialChaosEngine::GetPrimordialChaosMetrics() {
    std::lock_guard<std::mutex> lock1(s_primordialMutex);
    std::lock_guard<std::mutex> lock2(s_chaosMutex);
    std::lock_guard<std::mutex> lock3(s_voidMutex);
    std::lock_guard<std::mutex> lock4(s_abyssMutex);
    std::lock_guard<std::mutex> lock5(s_fluxMutex);
    
    float totalPrimordiality = 0.0f, totalChaos = 0.0f, totalVoidness = 0.0f, totalAbyss = 0.0f, totalFlux = 0.0f;
    
    for (auto& s : s_primordialStructures) {
        totalPrimordiality += s->primordiality;
        totalChaos += s->chaos;
        totalVoidness += s->voidness;
        totalAbyss += s->abyss;
        totalFlux += s->flux;
    }
    
    int chaoticCount = 0;
    for (auto& c : s_chaosPrimordials) {
        if (c->isChaotic) chaoticCount++;
    }
    
    int abyssalCount = 0;
    for (auto& a : s_abyssPrimordials) {
        if (a->isAbyssal) abyssalCount++;
    }
    
    return {
        {"primordialStructureCount", s_primordialStructures.size()},
        {"chaosPrimordialCount", s_chaosPrimordials.size()},
        {"voidPrimordialCount", s_voidPrimordials.size()},
        {"abyssPrimordialCount", s_abyssPrimordials.size()},
        {"fluxPrimordialCount", s_fluxPrimordials.size()},
        {"totalPrimordiality", totalPrimordiality},
        {"totalChaos", totalChaos},
        {"totalVoidness", totalVoidness},
        {"totalAbyss", totalAbyss},
        {"totalFlux", totalFlux},
        {"chaoticCount", chaoticCount},
        {"abyssalCount", abyssalCount}
    };
}

nlohmann::json PrimordialChaosEngine::GeneratePrimordialChaosReport() {
    auto report = GetPrimordialChaosMetrics();
    
    std::lock_guard<std::mutex> lock(s_primordialMutex);
    nlohmann::json structures = nlohmann::json::array();
    for (auto& s : s_primordialStructures) {
        structures.push_back(s->ToJson());
    }
    report["structures"] = structures;
    
    return report;
}

} // namespace PrimordialChaos
