#include "InfiniteSynthesisEngine.hpp"
#include <chrono>
#include <random>
#include <iomanip>
#include <sstream>

namespace InfiniteSynthesis {

json InfiniteSynthesis::ToJson() const {
    return json{
        {"id", id}, {"name", name}, {"synthesis", synthesis},
        {"integration", integration}, {"continuity", continuity}, {"omnipresence", omnipresence},
        {"harmony", harmony}, {"coherence", coherence}, {"clarity", clarity},
        {"createdAt", createdAt}, {"lastUpdated", lastUpdated}, {"isActive", isActive}, {"metadata", metadata}
    };
}

InfiniteSynthesis InfiniteSynthesis::FromJson(const json& j) {
    InfiniteSynthesis inf;
    inf.id = j.value("id", "");
    inf.name = j.value("name", "");
    inf.synthesis = j.value("synthesis", 0.0);
    inf.integration = j.value("integration", 0.0);
    inf.continuity = j.value("continuity", 0.0);
    inf.omnipresence = j.value("omnipresence", 0.0);
    inf.harmony = j.value("harmony", 0.0);
    inf.coherence = j.value("coherence", 0.0);
    inf.clarity = j.value("clarity", 0.0);
    inf.createdAt = j.value("createdAt", 0);
    inf.lastUpdated = j.value("lastUpdated", 0);
    inf.isActive = j.value("isActive", false);
    if (j.contains("metadata")) inf.metadata = j["metadata"].get<std::map<std::string, std::string>>();
    return inf;
}

json SynthesisNode::ToJson() const {
    return json{
        {"id", id}, {"infiniteId", infiniteId}, {"localSynthesis", localSynthesis},
        {"globalSynthesis", globalSynthesis}, {"harmonyFactor", harmonyFactor}, {"coherenceLevel", coherenceLevel},
        {"clarityIndex", clarityIndex}, {"integrationStrength", integrationStrength},
        {"isUnified", isUnified}, {"isActive", isActive}, {"createdAt", createdAt}, {"metadata", metadata}
    };
}

SynthesisNode SynthesisNode::FromJson(const json& j) {
    SynthesisNode node;
    node.id = j.value("id", "");
    node.infiniteId = j.value("infiniteId", "");
    node.localSynthesis = j.value("localSynthesis", 0.0);
    node.globalSynthesis = j.value("globalSynthesis", 0.0);
    node.harmonyFactor = j.value("harmonyFactor", 0.0);
    node.coherenceLevel = j.value("coherenceLevel", 0.0);
    node.clarityIndex = j.value("clarityIndex", 0.0);
    node.integrationStrength = j.value("integrationStrength", 0.0);
    node.isUnified = j.value("isUnified", false);
    node.isActive = j.value("isActive", false);
    node.createdAt = j.value("createdAt", 0);
    if (j.contains("metadata")) node.metadata = j["metadata"].get<std::map<std::string, std::string>>();
    return node;
}

void SynthesisNode::MergeSynthesis(double otherSynthesis) {
    globalSynthesis = (globalSynthesis + otherSynthesis) / 2.0;
    localSynthesis = std::max(localSynthesis, otherSynthesis);
    harmonyFactor = std::min(1.0, harmonyFactor + 0.1);
}

void SynthesisNode::UnifyNodes(SynthesisNode& other) {
    MergeSynthesis(other.localSynthesis);
    other.globalSynthesis = globalSynthesis;
    isUnified = other.isUnified = true;
    coherenceLevel = std::min(1.0, coherenceLevel + other.coherenceLevel);
}

json InfiniteStream::ToJson() const {
    return json{
        {"id", id}, {"name", name}, {"streamFlow", streamFlow}, {"density", density},
        {"clarity", clarity}, {"harmony", harmony}, {"continuity", continuity},
        {"omnipresence", omnipresence}, {"integration", integration}, {"isActive", isActive}, {"createdAt", createdAt}
    };
}

InfiniteStream InfiniteStream::FromJson(const json& j) {
    InfiniteStream s;
    s.id = j.value("id", "");
    s.name = j.value("name", "");
    s.streamFlow = j.value("streamFlow", 0.0);
    s.density = j.value("density", 0.0);
    s.clarity = j.value("clarity", 0.0);
    s.harmony = j.value("harmony", 0.0);
    s.continuity = j.value("continuity", 0.0);
    s.omnipresence = j.value("omnipresence", 0.0);
    s.integration = j.value("integration", 0.0);
    s.isActive = j.value("isActive", false);
    s.createdAt = j.value("createdAt", 0);
    return s;
}

json SynthesisWave::ToJson() const {
    return json{
        {"id", id}, {"name", name}, {"amplitude", amplitude}, {"frequency", frequency},
        {"clarity", clarity}, {"harmony", harmony}, {"omnipresence", omnipresence},
        {"continuity", continuity}, {"coherence", coherence}, {"integration", integration}, {"isActive", isActive}, {"createdAt", createdAt}
    };
}

SynthesisWave SynthesisWave::FromJson(const json& j) {
    SynthesisWave w;
    w.id = j.value("id", "");
    w.name = j.value("name", "");
    w.amplitude = j.value("amplitude", 0.0);
    w.frequency = j.value("frequency", 0.0);
    w.clarity = j.value("clarity", 0.0);
    w.harmony = j.value("harmony", 0.0);
    w.omnipresence = j.value("omnipresence", 0.0);
    w.continuity = j.value("continuity", 0.0);
    w.coherence = j.value("coherence", 0.0);
    w.integration = j.value("integration", 0.0);
    w.isActive = j.value("isActive", false);
    w.createdAt = j.value("createdAt", 0);
    return w;
}

json IntegrationMatrix::ToJson() const {
    json m = json::array();
    for (int i = 0; i < 10; ++i) {
        json row = json::array();
        for (int j = 0; j < 10; ++j) row.push_back(matrix[i][j]);
        m.push_back(row);
    }
    return json{
        {"id", id}, {"name", name}, {"matrix", m}, {"coherence", coherence}, {"clarity", clarity},
        {"harmony", harmony}, {"continuity", continuity}, {"omnipresence", omnipresence},
        {"integration", integration}, {"stability", stability}, {"createdAt", createdAt}
    };
}

IntegrationMatrix IntegrationMatrix::FromJson(const json& j) {
    IntegrationMatrix m;
    m.id = j.value("id", "");
    m.name = j.value("name", "");
    m.coherence = j.value("coherence", 0.0);
    m.clarity = j.value("clarity", 0.0);
    m.harmony = j.value("harmony", 0.0);
    m.continuity = j.value("continuity", 0.0);
    m.omnipresence = j.value("omnipresence", 0.0);
    m.integration = j.value("integration", 0.0);
    m.stability = j.value("stability", 0.0);
    m.createdAt = j.value("createdAt", 0);
    if (j.contains("matrix") && j["matrix"].is_array()) {
        for (size_t i = 0; i < std::min(size_t(10), j["matrix"].size()); ++i) {
            if (j["matrix"][i].is_array()) {
                for (size_t k = 0; k < std::min(size_t(10), j["matrix"][i].size()); ++k) {
                    m.matrix[i][k] = j["matrix"][i][k].get<double>();
                }
            }
        }
    }
    return m;
}

void IntegrationMatrix::StabilizeField() {
    double total = 0.0;
    for (int i = 0; i < 10; ++i) for (int j = 0; j < 10; ++j) total += matrix[i][j];
    stability = total / 100.0;
    coherence = std::min(1.0, coherence + stability * 0.1);
    clarity = std::min(1.0, clarity + stability * 0.05);
}

json ConvergenceTensor::ToJson() const {
    json t = json::array();
    for (int i = 0; i < 7; ++i) {
        json plane = json::array();
        for (int j = 0; j < 7; ++j) {
            json row = json::array();
            for (int k = 0; k < 7; ++k) row.push_back(tensor[i][j][k]);
            plane.push_back(row);
        }
        t.push_back(plane);
    }
    return json{
        {"id", id}, {"name", name}, {"tensor", t}, {"convergence", convergence}, {"clarity", clarity},
        {"harmony", harmony}, {"omnipresence", omnipresence}, {"integration", integration}, {"density", density}, {"createdAt", createdAt}
    };
}

ConvergenceTensor ConvergenceTensor::FromJson(const json& j) {
    ConvergenceTensor t;
    t.id = j.value("id", "");
    t.name = j.value("name", "");
    t.convergence = j.value("convergence", 0.0);
    t.clarity = j.value("clarity", 0.0);
    t.harmony = j.value("harmony", 0.0);
    t.omnipresence = j.value("omnipresence", 0.0);
    t.integration = j.value("integration", 0.0);
    t.density = j.value("density", 0.0);
    t.createdAt = j.value("createdAt", 0);
    if (j.contains("tensor") && j["tensor"].is_array()) {
        for (size_t i = 0; i < std::min(size_t(7), j["tensor"].size()); ++i) {
            if (j["tensor"][i].is_array()) {
                for (size_t m = 0; m < std::min(size_t(7), j["tensor"][i].size()); ++m) {
                    if (j["tensor"][i][m].is_array()) {
                        for (size_t n = 0; n < std::min(size_t(7), j["tensor"][i][m].size()); ++n) {
                            t.tensor[i][m][n] = j["tensor"][i][m][n].get<double>();
                        }
                    }
                }
            }
        }
    }
    return t;
}

json InfiniteClarity::ToJson() const {
    return json{
        {"id", id}, {"name", name}, {"clarity", clarity}, {"purity", purity}, {"harmony", harmony},
        {"continuity", continuity}, {"omnipresence", omnipresence}, {"coherence", coherence},
        {"integration", integration}, {"density", density}, {"createdAt", createdAt}
    };
}

InfiniteClarity InfiniteClarity::FromJson(const json& j) {
    InfiniteClarity c;
    c.id = j.value("id", "");
    c.name = j.value("name", "");
    c.clarity = j.value("clarity", 0.0);
    c.purity = j.value("purity", 0.0);
    c.harmony = j.value("harmony", 0.0);
    c.continuity = j.value("continuity", 0.0);
    c.omnipresence = j.value("omnipresence", 0.0);
    c.coherence = j.value("coherence", 0.0);
    c.integration = j.value("integration", 0.0);
    c.density = j.value("density", 0.0);
    c.createdAt = j.value("createdAt", 0);
    return c;
}

InfiniteSynthesisEngine& InfiniteSynthesisEngine::GetInstance() {
    static InfiniteSynthesisEngine instance;
    return instance;
}

void InfiniteSynthesisEngine::Initialize() {}

void InfiniteSynthesisEngine::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    infiniteSyntheses_.clear(); nodes_.clear(); streams_.clear(); waves_.clear(); matrices_.clear(); tensors_.clear(); clarities_.clear();
}

std::string InfiniteSynthesisEngine::GenerateId() const {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis;
    std::stringstream ss;
    ss << std::hex << dis(gen);
    return ss.str();
}

std::string InfiniteSynthesisEngine::CreateInfiniteSynthesis(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto inf = std::make_shared<InfiniteSynthesis>();
    inf->id = GenerateId(); inf->name = name;
    inf->synthesis = inf->integration = inf->continuity = inf->omnipresence = inf->harmony = inf->coherence = inf->clarity = 0.5;
    inf->isActive = true;
    inf->createdAt = inf->lastUpdated = std::chrono::system_clock::now().time_since_epoch().count();
    infiniteSyntheses_[inf->id] = inf;
    return inf->id;
}

std::shared_ptr<InfiniteSynthesis> InfiniteSynthesisEngine::GetInfiniteSynthesis(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = infiniteSyntheses_.find(id);
    return (it != infiniteSyntheses_.end()) ? it->second : nullptr;
}

std::vector<std::shared_ptr<InfiniteSynthesis>> InfiniteSynthesisEngine::GetAllInfiniteSyntheses() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<InfiniteSynthesis>> result;
    for (const auto& [id, inf] : infiniteSyntheses_) result.push_back(inf);
    return result;
}

void InfiniteSynthesisEngine::UpdateInfiniteSynthesis(const std::string& id, const InfiniteSynthesis& inf) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = infiniteSyntheses_.find(id);
    if (it != infiniteSyntheses_.end()) { *it->second = inf; it->second->lastUpdated = std::chrono::system_clock::now().time_since_epoch().count(); }
}

void InfiniteSynthesisEngine::DeleteInfiniteSynthesis(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    infiniteSyntheses_.erase(id);
}

std::string InfiniteSynthesisEngine::CreateSynthesisNode(const std::string& infiniteId, const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto node = std::make_shared<SynthesisNode>();
    node->id = GenerateId(); node->infiniteId = infiniteId;
    node->localSynthesis = node->globalSynthesis = node->harmonyFactor = node->coherenceLevel = node->clarityIndex = node->integrationStrength = 0.5;
    node->isUnified = false; node->isActive = true;
    node->createdAt = std::chrono::system_clock::now().time_since_epoch().count();
    nodes_[node->id] = node;
    return node->id;
}

std::shared_ptr<SynthesisNode> InfiniteSynthesisEngine::GetSynthesisNode(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = nodes_.find(id);
    return (it != nodes_.end()) ? it->second : nullptr;
}

std::vector<std::shared_ptr<SynthesisNode>> InfiniteSynthesisEngine::GetSynthesisNodesForInfinite(const std::string& infiniteId) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<SynthesisNode>> result;
    for (const auto& [id, node] : nodes_) if (node->infiniteId == infiniteId) result.push_back(node);
    return result;
}

void InfiniteSynthesisEngine::UpdateSynthesisNode(const std::string& id, const SynthesisNode& node) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = nodes_.find(id);
    if (it != nodes_.end()) *it->second = node;
}

void InfiniteSynthesisEngine::DeleteSynthesisNode(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    nodes_.erase(id);
}

std::string InfiniteSynthesisEngine::CreateInfiniteStream(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto s = std::make_shared<InfiniteStream>();
    s->id = GenerateId(); s->name = name;
    s->streamFlow = s->density = s->clarity = s->harmony = s->continuity = s->omnipresence = s->integration = 0.5;
    s->isActive = true;
    s->createdAt = std::chrono::system_clock::now().time_since_epoch().count();
    streams_[s->id] = s;
    return s->id;
}

std::shared_ptr<InfiniteStream> InfiniteSynthesisEngine::GetInfiniteStream(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = streams_.find(id);
    return (it != streams_.end()) ? it->second : nullptr;
}

std::vector<std::shared_ptr<InfiniteStream>> InfiniteSynthesisEngine::GetAllInfiniteStreams() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<InfiniteStream>> result;
    for (const auto& [id, s] : streams_) result.push_back(s);
    return result;
}

void InfiniteSynthesisEngine::UpdateInfiniteStream(const std::string& id, const InfiniteStream& stream) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = streams_.find(id);
    if (it != streams_.end()) *it->second = stream;
}

void InfiniteSynthesisEngine::DeleteInfiniteStream(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    streams_.erase(id);
}

std::string InfiniteSynthesisEngine::CreateSynthesisWave(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto w = std::make_shared<SynthesisWave>();
    w->id = GenerateId(); w->name = name;
    w->amplitude = w->frequency = w->clarity = w->harmony = w->omnipresence = w->continuity = w->coherence = w->integration = 0.5;
    w->isActive = true;
    w->createdAt = std::chrono::system_clock::now().time_since_epoch().count();
    waves_[w->id] = w;
    return w->id;
}

std::shared_ptr<SynthesisWave> InfiniteSynthesisEngine::GetSynthesisWave(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = waves_.find(id);
    return (it != waves_.end()) ? it->second : nullptr;
}

std::vector<std::shared_ptr<SynthesisWave>> InfiniteSynthesisEngine::GetAllSynthesisWaves() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<SynthesisWave>> result;
    for (const auto& [id, w] : waves_) result.push_back(w);
    return result;
}

void InfiniteSynthesisEngine::UpdateSynthesisWave(const std::string& id, const SynthesisWave& wave) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = waves_.find(id);
    if (it != waves_.end()) *it->second = wave;
}

void InfiniteSynthesisEngine::DeleteSynthesisWave(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    waves_.erase(id);
}

std::string InfiniteSynthesisEngine::CreateIntegrationMatrix(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto m = std::make_shared<IntegrationMatrix>();
    m->id = GenerateId(); m->name = name;
    m->coherence = m->clarity = m->harmony = m->continuity = m->omnipresence = m->integration = m->stability = 0.5;
    m->createdAt = std::chrono::system_clock::now().time_since_epoch().count();
    std::random_device rd; std::mt19937 gen(rd()); std::uniform_real_distribution<double> dis(0.0, 1.0);
    for (int i = 0; i < 10; ++i) for (int j = 0; j < 10; ++j) m->matrix[i][j] = dis(gen);
    matrices_[m->id] = m;
    return m->id;
}

std::shared_ptr<IntegrationMatrix> InfiniteSynthesisEngine::GetIntegrationMatrix(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = matrices_.find(id);
    return (it != matrices_.end()) ? it->second : nullptr;
}

std::vector<std::shared_ptr<IntegrationMatrix>> InfiniteSynthesisEngine::GetAllIntegrationMatrices() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<IntegrationMatrix>> result;
    for (const auto& [id, m] : matrices_) result.push_back(m);
    return result;
}

void InfiniteSynthesisEngine::UpdateIntegrationMatrix(const std::string& id, const IntegrationMatrix& matrix) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = matrices_.find(id);
    if (it != matrices_.end()) *it->second = matrix;
}

void InfiniteSynthesisEngine::DeleteIntegrationMatrix(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    matrices_.erase(id);
}

std::string InfiniteSynthesisEngine::CreateConvergenceTensor(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto t = std::make_shared<ConvergenceTensor>();
    t->id = GenerateId(); t->name = name;
    t->convergence = t->clarity = t->harmony = t->omnipresence = t->integration = t->density = 0.5;
    t->createdAt = std::chrono::system_clock::now().time_since_epoch().count();
    std::random_device rd; std::mt19937 gen(rd()); std::uniform_real_distribution<double> dis(0.0, 1.0);
    for (int i = 0; i < 7; ++i) for (int j = 0; j < 7; ++j) for (int k = 0; k < 7; ++k) t->tensor[i][j][k] = dis(gen);
    tensors_[t->id] = t;
    return t->id;
}

std::shared_ptr<ConvergenceTensor> InfiniteSynthesisEngine::GetConvergenceTensor(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tensors_.find(id);
    return (it != tensors_.end()) ? it->second : nullptr;
}

std::vector<std::shared_ptr<ConvergenceTensor>> InfiniteSynthesisEngine::GetAllConvergenceTensors() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<ConvergenceTensor>> result;
    for (const auto& [id, t] : tensors_) result.push_back(t);
    return result;
}

void InfiniteSynthesisEngine::UpdateConvergenceTensor(const std::string& id, const ConvergenceTensor& tensor) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tensors_.find(id);
    if (it != tensors_.end()) *it->second = tensor;
}

void InfiniteSynthesisEngine::DeleteConvergenceTensor(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    tensors_.erase(id);
}

std::string InfiniteSynthesisEngine::CreateInfiniteClarity(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto c = std::make_shared<InfiniteClarity>();
    c->id = GenerateId(); c->name = name;
    c->clarity = c->purity = c->harmony = c->continuity = c->omnipresence = c->coherence = c->integration = c->density = 0.5;
    c->createdAt = std::chrono::system_clock::now().time_since_epoch().count();
    clarities_[c->id] = c;
    return c->id;
}

std::shared_ptr<InfiniteClarity> InfiniteSynthesisEngine::GetInfiniteClarity(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = clarities_.find(id);
    return (it != clarities_.end()) ? it->second : nullptr;
}

std::vector<std::shared_ptr<InfiniteClarity>> InfiniteSynthesisEngine::GetAllInfiniteClarities() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<InfiniteClarity>> result;
    for (const auto& [id, c] : clarities_) result.push_back(c);
    return result;
}

void InfiniteSynthesisEngine::UpdateInfiniteClarity(const std::string& id, const InfiniteClarity& clarity) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = clarities_.find(id);
    if (it != clarities_.end()) *it->second = clarity;
}

void InfiniteSynthesisEngine::DeleteInfiniteClarity(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    clarities_.erase(id);
}

void InfiniteSynthesisEngine::ExpandInfinite(const std::string& infiniteId) {
    auto inf = GetInfiniteSynthesis(infiniteId);
    if (inf) { inf->omnipresence = std::min(1.0, inf->omnipresence + 0.1); inf->integration = std::min(1.0, inf->integration + 0.05); UpdateInfiniteSynthesis(infiniteId, *inf); }
}

void InfiniteSynthesisEngine::AmplifyHarmony(const std::string& infiniteId) {
    auto inf = GetInfiniteSynthesis(infiniteId);
    if (inf) { inf->harmony = std::min(1.0, inf->harmony + 0.1); inf->coherence = std::min(1.0, inf->coherence + 0.05); UpdateInfiniteSynthesis(infiniteId, *inf); }
}

void InfiniteSynthesisEngine::StrengthenContinuity(const std::string& infiniteId) {
    auto inf = GetInfiniteSynthesis(infiniteId);
    if (inf) { inf->continuity = std::min(1.0, inf->continuity + 0.1); inf->coherence = std::min(1.0, inf->coherence + 0.05); UpdateInfiniteSynthesis(infiniteId, *inf); }
}

void InfiniteSynthesisEngine::ClarifyInfinite(const std::string& infiniteId) {
    auto inf = GetInfiniteSynthesis(infiniteId);
    if (inf) { inf->clarity = std::min(1.0, inf->clarity + 0.1); inf->synthesis = std::min(1.0, inf->synthesis + 0.05); UpdateInfiniteSynthesis(infiniteId, *inf); }
}

json InfiniteSynthesisEngine::SerializeAll() const {
    std::lock_guard<std::mutex> lock(mutex_);
    json result;
    result["infiniteSyntheses"] = json::array();
    for (const auto& [id, inf] : infiniteSyntheses_) result["infiniteSyntheses"].push_back(inf->ToJson());
    result["nodes"] = json::array();
    for (const auto& [id, node] : nodes_) result["nodes"].push_back(node->ToJson());
    result["streams"] = json::array();
    for (const auto& [id, s] : streams_) result["streams"].push_back(s->ToJson());
    result["waves"] = json::array();
    for (const auto& [id, w] : waves_) result["waves"].push_back(w->ToJson());
    result["matrices"] = json::array();
    for (const auto& [id, m] : matrices_) result["matrices"].push_back(m->ToJson());
    result["tensors"] = json::array();
    for (const auto& [id, t] : tensors_) result["tensors"].push_back(t->ToJson());
    result["clarities"] = json::array();
    for (const auto& [id, c] : clarities_) result["clarities"].push_back(c->ToJson());
    return result;
}

void InfiniteSynthesisEngine::DeserializeAll(const json& j) {
    std::lock_guard<std::mutex> lock(mutex_);
    infiniteSyntheses_.clear(); nodes_.clear(); streams_.clear(); waves_.clear(); matrices_.clear(); tensors_.clear(); clarities_.clear();
    if (j.contains("infiniteSyntheses")) for (const auto& infJson : j["infiniteSyntheses"]) { auto inf = std::make_shared<InfiniteSynthesis>(InfiniteSynthesis::FromJson(infJson)); infiniteSyntheses_[inf->id] = inf; }
    if (j.contains("nodes")) for (const auto& nodeJson : j["nodes"]) { auto node = std::make_shared<SynthesisNode>(SynthesisNode::FromJson(nodeJson)); nodes_[node->id] = node; }
    if (j.contains("streams")) for (const auto& sJson : j["streams"]) { auto s = std::make_shared<InfiniteStream>(InfiniteStream::FromJson(sJson)); streams_[s->id] = s; }
    if (j.contains("waves")) for (const auto& wJson : j["waves"]) { auto w = std::make_shared<SynthesisWave>(SynthesisWave::FromJson(wJson)); waves_[w->id] = w; }
    if (j.contains("matrices")) for (const auto& mJson : j["matrices"]) { auto m = std::make_shared<IntegrationMatrix>(IntegrationMatrix::FromJson(mJson)); matrices_[m->id] = m; }
    if (j.contains("tensors")) for (const auto& tJson : j["tensors"]) { auto t = std::make_shared<ConvergenceTensor>(ConvergenceTensor::FromJson(tJson)); tensors_[t->id] = t; }
    if (j.contains("clarities")) for (const auto& cJson : j["clarities"]) { auto c = std::make_shared<InfiniteClarity>(InfiniteClarity::FromJson(cJson)); clarities_[c->id] = c; }
}

} // namespace InfiniteSynthesis
