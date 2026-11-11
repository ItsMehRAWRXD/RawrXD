#include "EternalConvergenceEngine.hpp"
#include <chrono>
#include <random>
#include <iomanip>
#include <sstream>

namespace EternalConvergence {

json EternalConvergence::ToJson() const {
    return json{
        {"id", id}, {"name", name}, {"convergence", convergence}, {"unity", unity},
        {"continuity", continuity}, {"omnipresence", omnipresence}, {"harmony", harmony},
        {"coherence", coherence}, {"clarity", clarity}, {"createdAt", createdAt},
        {"lastUpdated", lastUpdated}, {"isActive", isActive}, {"metadata", metadata}
    };
}

EternalConvergence EternalConvergence::FromJson(const json& j) {
    EternalConvergence e;
    e.id = j.value("id", "");
    e.name = j.value("name", "");
    e.convergence = j.value("convergence", 0.0);
    e.unity = j.value("unity", 0.0);
    e.continuity = j.value("continuity", 0.0);
    e.omnipresence = j.value("omnipresence", 0.0);
    e.harmony = j.value("harmony", 0.0);
    e.coherence = j.value("coherence", 0.0);
    e.clarity = j.value("clarity", 0.0);
    e.createdAt = j.value("createdAt", 0);
    e.lastUpdated = j.value("lastUpdated", 0);
    e.isActive = j.value("isActive", false);
    if (j.contains("metadata")) e.metadata = j["metadata"].get<std::map<std::string, std::string>>();
    return e;
}

json ConvergenceNode::ToJson() const {
    return json{
        {"id", id}, {"eternalId", eternalId}, {"localConvergence", localConvergence},
        {"globalConvergence", globalConvergence}, {"harmonyFactor", harmonyFactor},
        {"coherenceLevel", coherenceLevel}, {"clarityIndex", clarityIndex},
        {"unityStrength", unityStrength}, {"isUnified", isUnified},
        {"isActive", isActive}, {"createdAt", createdAt}, {"metadata", metadata}
    };
}

ConvergenceNode ConvergenceNode::FromJson(const json& j) {
    ConvergenceNode node;
    node.id = j.value("id", "");
    node.eternalId = j.value("eternalId", "");
    node.localConvergence = j.value("localConvergence", 0.0);
    node.globalConvergence = j.value("globalConvergence", 0.0);
    node.harmonyFactor = j.value("harmonyFactor", 0.0);
    node.coherenceLevel = j.value("coherenceLevel", 0.0);
    node.clarityIndex = j.value("clarityIndex", 0.0);
    node.unityStrength = j.value("unityStrength", 0.0);
    node.isUnified = j.value("isUnified", false);
    node.isActive = j.value("isActive", false);
    node.createdAt = j.value("createdAt", 0);
    if (j.contains("metadata")) node.metadata = j["metadata"].get<std::map<std::string, std::string>>();
    return node;
}

void ConvergenceNode::MergeConvergence(double otherConvergence) {
    globalConvergence = (globalConvergence + otherConvergence) / 2.0;
    localConvergence = std::max(localConvergence, otherConvergence);
    harmonyFactor = std::min(1.0, harmonyFactor + 0.1);
}

void ConvergenceNode::UnifyNodes(ConvergenceNode& other) {
    MergeConvergence(other.localConvergence);
    other.globalConvergence = globalConvergence;
    isUnified = other.isUnified = true;
    coherenceLevel = std::min(1.0, coherenceLevel + other.coherenceLevel);
}

json EternalStream::ToJson() const {
    return json{
        {"id", id}, {"name", name}, {"streamFlow", streamFlow}, {"density", density},
        {"clarity", clarity}, {"harmony", harmony}, {"continuity", continuity},
        {"omnipresence", omnipresence}, {"unity", unity}, {"isActive", isActive}, {"createdAt", createdAt}
    };
}

EternalStream EternalStream::FromJson(const json& j) {
    EternalStream s;
    s.id = j.value("id", "");
    s.name = j.value("name", "");
    s.streamFlow = j.value("streamFlow", 0.0);
    s.density = j.value("density", 0.0);
    s.clarity = j.value("clarity", 0.0);
    s.harmony = j.value("harmony", 0.0);
    s.continuity = j.value("continuity", 0.0);
    s.omnipresence = j.value("omnipresence", 0.0);
    s.unity = j.value("unity", 0.0);
    s.isActive = j.value("isActive", false);
    s.createdAt = j.value("createdAt", 0);
    return s;
}

json ConvergenceWave::ToJson() const {
    return json{
        {"id", id}, {"name", name}, {"amplitude", amplitude}, {"frequency", frequency},
        {"clarity", clarity}, {"harmony", harmony}, {"omnipresence", omnipresence},
        {"continuity", continuity}, {"coherence", coherence}, {"unity", unity},
        {"isActive", isActive}, {"createdAt", createdAt}
    };
}

ConvergenceWave ConvergenceWave::FromJson(const json& j) {
    ConvergenceWave w;
    w.id = j.value("id", "");
    w.name = j.value("name", "");
    w.amplitude = j.value("amplitude", 0.0);
    w.frequency = j.value("frequency", 0.0);
    w.clarity = j.value("clarity", 0.0);
    w.harmony = j.value("harmony", 0.0);
    w.omnipresence = j.value("omnipresence", 0.0);
    w.continuity = j.value("continuity", 0.0);
    w.coherence = j.value("coherence", 0.0);
    w.unity = j.value("unity", 0.0);
    w.isActive = j.value("isActive", false);
    w.createdAt = j.value("createdAt", 0);
    return w;
}

json UnityMatrix::ToJson() const {
    json m = json::array();
    for (int i = 0; i < 11; ++i) {
        json row = json::array();
        for (int j = 0; j < 11; ++j) row.push_back(matrix[i][j]);
        m.push_back(row);
    }
    return json{
        {"id", id}, {"name", name}, {"matrix", m}, {"coherence", coherence}, {"clarity", clarity},
        {"harmony", harmony}, {"continuity", continuity}, {"omnipresence", omnipresence},
        {"unity", unity}, {"stability", stability}, {"createdAt", createdAt}
    };
}

UnityMatrix UnityMatrix::FromJson(const json& j) {
    UnityMatrix m;
    m.id = j.value("id", "");
    m.name = j.value("name", "");
    m.coherence = j.value("coherence", 0.0);
    m.clarity = j.value("clarity", 0.0);
    m.harmony = j.value("harmony", 0.0);
    m.continuity = j.value("continuity", 0.0);
    m.omnipresence = j.value("omnipresence", 0.0);
    m.unity = j.value("unity", 0.0);
    m.stability = j.value("stability", 0.0);
    m.createdAt = j.value("createdAt", 0);
    if (j.contains("matrix") && j["matrix"].is_array()) {
        for (size_t i = 0; i < std::min(size_t(11), j["matrix"].size()); ++i) {
            if (j["matrix"][i].is_array()) {
                for (size_t k = 0; k < std::min(size_t(11), j["matrix"][i].size()); ++k) {
                    m.matrix[i][k] = j["matrix"][i][k].get<double>();
                }
            }
        }
    }
    return m;
}

void UnityMatrix::StabilizeField() {
    double total = 0.0;
    for (int i = 0; i < 11; ++i) for (int j = 0; j < 11; ++j) total += matrix[i][j];
    stability = total / 121.0;
    coherence = std::min(1.0, coherence + stability * 0.1);
    clarity = std::min(1.0, clarity + stability * 0.05);
}

json EternalTensor::ToJson() const {
    json t = json::array();
    for (int i = 0; i < 8; ++i) {
        json plane = json::array();
        for (int j = 0; j < 8; ++j) {
            json row = json::array();
            for (int k = 0; k < 8; ++k) row.push_back(tensor[i][j][k]);
            plane.push_back(row);
        }
        t.push_back(plane);
    }
    return json{
        {"id", id}, {"name", name}, {"tensor", t}, {"eternity", eternity}, {"clarity", clarity},
        {"harmony", harmony}, {"omnipresence", omnipresence}, {"unity", unity}, {"density", density}, {"createdAt", createdAt}
    };
}

EternalTensor EternalTensor::FromJson(const json& j) {
    EternalTensor t;
    t.id = j.value("id", "");
    t.name = j.value("name", "");
    t.eternity = j.value("eternity", 0.0);
    t.clarity = j.value("clarity", 0.0);
    t.harmony = j.value("harmony", 0.0);
    t.omnipresence = j.value("omnipresence", 0.0);
    t.unity = j.value("unity", 0.0);
    t.density = j.value("density", 0.0);
    t.createdAt = j.value("createdAt", 0);
    if (j.contains("tensor") && j["tensor"].is_array()) {
        for (size_t i = 0; i < std::min(size_t(8), j["tensor"].size()); ++i) {
            if (j["tensor"][i].is_array()) {
                for (size_t m = 0; m < std::min(size_t(8), j["tensor"][i].size()); ++m) {
                    if (j["tensor"][i][m].is_array()) {
                        for (size_t n = 0; n < std::min(size_t(8), j["tensor"][i][m].size()); ++n) {
                            t.tensor[i][m][n] = j["tensor"][i][m][n].get<double>();
                        }
                    }
                }
            }
        }
    }
    return t;
}

json EternalClarity::ToJson() const {
    return json{
        {"id", id}, {"name", name}, {"clarity", clarity}, {"purity", purity}, {"harmony", harmony},
        {"continuity", continuity}, {"omnipresence", omnipresence}, {"coherence", coherence},
        {"unity", unity}, {"density", density}, {"createdAt", createdAt}
    };
}

EternalClarity EternalClarity::FromJson(const json& j) {
    EternalClarity c;
    c.id = j.value("id", "");
    c.name = j.value("name", "");
    c.clarity = j.value("clarity", 0.0);
    c.purity = j.value("purity", 0.0);
    c.harmony = j.value("harmony", 0.0);
    c.continuity = j.value("continuity", 0.0);
    c.omnipresence = j.value("omnipresence", 0.0);
    c.coherence = j.value("coherence", 0.0);
    c.unity = j.value("unity", 0.0);
    c.density = j.value("density", 0.0);
    c.createdAt = j.value("createdAt", 0);
    return c;
}

EternalConvergenceEngine& EternalConvergenceEngine::GetInstance() {
    static EternalConvergenceEngine instance;
    return instance;
}

void EternalConvergenceEngine::Initialize() {}

void EternalConvergenceEngine::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    eternalConvergences_.clear(); nodes_.clear(); streams_.clear(); waves_.clear(); matrices_.clear(); tensors_.clear(); clarities_.clear();
}

std::string EternalConvergenceEngine::GenerateId() const {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis;
    std::stringstream ss;
    ss << std::hex << dis(gen);
    return ss.str();
}

std::string EternalConvergenceEngine::CreateEternalConvergence(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto e = std::make_shared<EternalConvergence>();
    e->id = GenerateId(); e->name = name;
    e->convergence = e->unity = e->continuity = e->omnipresence = e->harmony = e->coherence = e->clarity = 0.5;
    e->isActive = true;
    e->createdAt = e->lastUpdated = std::chrono::system_clock::now().time_since_epoch().count();
    eternalConvergences_[e->id] = e;
    return e->id;
}

std::shared_ptr<EternalConvergence> EternalConvergenceEngine::GetEternalConvergence(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = eternalConvergences_.find(id);
    return (it != eternalConvergences_.end()) ? it->second : nullptr;
}

std::vector<std::shared_ptr<EternalConvergence>> EternalConvergenceEngine::GetAllEternalConvergences() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<EternalConvergence>> result;
    for (const auto& [id, e] : eternalConvergences_) result.push_back(e);
    return result;
}

void EternalConvergenceEngine::UpdateEternalConvergence(const std::string& id, const EternalConvergence& e) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = eternalConvergences_.find(id);
    if (it != eternalConvergences_.end()) { *it->second = e; it->second->lastUpdated = std::chrono::system_clock::now().time_since_epoch().count(); }
}

void EternalConvergenceEngine::DeleteEternalConvergence(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    eternalConvergences_.erase(id);
}

std::string EternalConvergenceEngine::CreateConvergenceNode(const std::string& eternalId, const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto node = std::make_shared<ConvergenceNode>();
    node->id = GenerateId(); node->eternalId = eternalId;
    node->localConvergence = node->globalConvergence = node->harmonyFactor = node->coherenceLevel = node->clarityIndex = node->unityStrength = 0.5;
    node->isUnified = false; node->isActive = true;
    node->createdAt = std::chrono::system_clock::now().time_since_epoch().count();
    nodes_[node->id] = node;
    return node->id;
}

std::shared_ptr<ConvergenceNode> EternalConvergenceEngine::GetConvergenceNode(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = nodes_.find(id);
    return (it != nodes_.end()) ? it->second : nullptr;
}

std::vector<std::shared_ptr<ConvergenceNode>> EternalConvergenceEngine::GetConvergenceNodesForEternal(const std::string& eternalId) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<ConvergenceNode>> result;
    for (const auto& [id, node] : nodes_) if (node->eternalId == eternalId) result.push_back(node);
    return result;
}

void EternalConvergenceEngine::UpdateConvergenceNode(const std::string& id, const ConvergenceNode& node) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = nodes_.find(id);
    if (it != nodes_.end()) *it->second = node;
}

void EternalConvergenceEngine::DeleteConvergenceNode(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    nodes_.erase(id);
}

std::string EternalConvergenceEngine::CreateEternalStream(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto s = std::make_shared<EternalStream>();
    s->id = GenerateId(); s->name = name;
    s->streamFlow = s->density = s->clarity = s->harmony = s->continuity = s->omnipresence = s->unity = 0.5;
    s->isActive = true;
    s->createdAt = std::chrono::system_clock::now().time_since_epoch().count();
    streams_[s->id] = s;
    return s->id;
}

std::shared_ptr<EternalStream> EternalConvergenceEngine::GetEternalStream(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = streams_.find(id);
    return (it != streams_.end()) ? it->second : nullptr;
}

std::vector<std::shared_ptr<EternalStream>> EternalConvergenceEngine::GetAllEternalStreams() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<EternalStream>> result;
    for (const auto& [id, s] : streams_) result.push_back(s);
    return result;
}

void EternalConvergenceEngine::UpdateEternalStream(const std::string& id, const EternalStream& stream) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = streams_.find(id);
    if (it != streams_.end()) *it->second = stream;
}

void EternalConvergenceEngine::DeleteEternalStream(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    streams_.erase(id);
}

std::string EternalConvergenceEngine::CreateConvergenceWave(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto w = std::make_shared<ConvergenceWave>();
    w->id = GenerateId(); w->name = name;
    w->amplitude = w->frequency = w->clarity = w->harmony = w->omnipresence = w->continuity = w->coherence = w->unity = 0.5;
    w->isActive = true;
    w->createdAt = std::chrono::system_clock::now().time_since_epoch().count();
    waves_[w->id] = w;
    return w->id;
}

std::shared_ptr<ConvergenceWave> EternalConvergenceEngine::GetConvergenceWave(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = waves_.find(id);
    return (it != waves_.end()) ? it->second : nullptr;
}

std::vector<std::shared_ptr<ConvergenceWave>> EternalConvergenceEngine::GetAllConvergenceWaves() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<ConvergenceWave>> result;
    for (const auto& [id, w] : waves_) result.push_back(w);
    return result;
}

void EternalConvergenceEngine::UpdateConvergenceWave(const std::string& id, const ConvergenceWave& wave) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = waves_.find(id);
    if (it != waves_.end()) *it->second = wave;
}

void EternalConvergenceEngine::DeleteConvergenceWave(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    waves_.erase(id);
}

std::string EternalConvergenceEngine::CreateUnityMatrix(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto m = std::make_shared<UnityMatrix>();
    m->id = GenerateId(); m->name = name;
    m->coherence = m->clarity = m->harmony = m->continuity = m->omnipresence = m->unity = m->stability = 0.5;
    m->createdAt = std::chrono::system_clock::now().time_since_epoch().count();
    std::random_device rd; std::mt19937 gen(rd()); std::uniform_real_distribution<double> dis(0.0, 1.0);
    for (int i = 0; i < 11; ++i) for (int j = 0; j < 11; ++j) m->matrix[i][j] = dis(gen);
    matrices_[m->id] = m;
    return m->id;
}

std::shared_ptr<UnityMatrix> EternalConvergenceEngine::GetUnityMatrix(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = matrices_.find(id);
    return (it != matrices_.end()) ? it->second : nullptr;
}

std::vector<std::shared_ptr<UnityMatrix>> EternalConvergenceEngine::GetAllUnityMatrices() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<UnityMatrix>> result;
    for (const auto& [id, m] : matrices_) result.push_back(m);
    return result;
}

void EternalConvergenceEngine::UpdateUnityMatrix(const std::string& id, const UnityMatrix& matrix) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = matrices_.find(id);
    if (it != matrices_.end()) *it->second = matrix;
}

void EternalConvergenceEngine::DeleteUnityMatrix(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    matrices_.erase(id);
}

std::string EternalConvergenceEngine::CreateEternalTensor(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto t = std::make_shared<EternalTensor>();
    t->id = GenerateId(); t->name = name;
    t->eternity = t->clarity = t->harmony = t->omnipresence = t->unity = t->density = 0.5;
    t->createdAt = std::chrono::system_clock::now().time_since_epoch().count();
    std::random_device rd; std::mt19937 gen(rd()); std::uniform_real_distribution<double> dis(0.0, 1.0);
    for (int i = 0; i < 8; ++i) for (int j = 0; j < 8; ++j) for (int k = 0; k < 8; ++k) t->tensor[i][j][k] = dis(gen);
    tensors_[t->id] = t;
    return t->id;
}

std::shared_ptr<EternalTensor> EternalConvergenceEngine::GetEternalTensor(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tensors_.find(id);
    return (it != tensors_.end()) ? it->second : nullptr;
}

std::vector<std::shared_ptr<EternalTensor>> EternalConvergenceEngine::GetAllEternalTensors() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<EternalTensor>> result;
    for (const auto& [id, t] : tensors_) result.push_back(t);
    return result;
}

void EternalConvergenceEngine::UpdateEternalTensor(const std::string& id, const EternalTensor& tensor) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tensors_.find(id);
    if (it != tensors_.end()) *it->second = tensor;
}

void EternalConvergenceEngine::DeleteEternalTensor(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    tensors_.erase(id);
}

std::string EternalConvergenceEngine::CreateEternalClarity(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto c = std::make_shared<EternalClarity>();
    c->id = GenerateId(); c->name = name;
    c->clarity = c->purity = c->harmony = c->continuity = c->omnipresence = c->coherence = c->unity = c->density = 0.5;
    c->createdAt = std::chrono::system_clock::now().time_since_epoch().count();
    clarities_[c->id] = c;
    return c->id;
}

std::shared_ptr<EternalClarity> EternalConvergenceEngine::GetEternalClarity(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = clarities_.find(id);
    return (it != clarities_.end()) ? it->second : nullptr;
}

std::vector<std::shared_ptr<EternalClarity>> EternalConvergenceEngine::GetAllEternalClarities() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<EternalClarity>> result;
    for (const auto& [id, c] : clarities_) result.push_back(c);
    return result;
}

void EternalConvergenceEngine::UpdateEternalClarity(const std::string& id, const EternalClarity& clarity) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = clarities_.find(id);
    if (it != clarities_.end()) *it->second = clarity;
}

void EternalConvergenceEngine::DeleteEternalClarity(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    clarities_.erase(id);
}

void EternalConvergenceEngine::ExpandEternal(const std::string& eternalId) {
    auto e = GetEternalConvergence(eternalId);
    if (e) { e->omnipresence = std::min(1.0, e->omnipresence + 0.1); e->unity = std::min(1.0, e->unity + 0.05); UpdateEternalConvergence(eternalId, *e); }
}

void EternalConvergenceEngine::AmplifyHarmony(const std::string& eternalId) {
    auto e = GetEternalConvergence(eternalId);
    if (e) { e->harmony = std::min(1.0, e->harmony + 0.1); e->coherence = std::min(1.0, e->coherence + 0.05); UpdateEternalConvergence(eternalId, *e); }
}

void EternalConvergenceEngine::StrengthenContinuity(const std::string& eternalId) {
    auto e = GetEternalConvergence(eternalId);
    if (e) { e->continuity = std::min(1.0, e->continuity + 0.1); e->coherence = std::min(1.0, e->coherence + 0.05); UpdateEternalConvergence(eternalId, *e); }
}

void EternalConvergenceEngine::ClarifyEternal(const std::string& eternalId) {
    auto e = GetEternalConvergence(eternalId);
    if (e) { e->clarity = std::min(1.0, e->clarity + 0.1); e->convergence = std::min(1.0, e->convergence + 0.05); UpdateEternalConvergence(eternalId, *e); }
}

json EternalConvergenceEngine::SerializeAll() const {
    std::lock_guard<std::mutex> lock(mutex_);
    json result;
    result["eternalConvergences"] = json::array();
    for (const auto& [id, e] : eternalConvergences_) result["eternalConvergences"].push_back(e->ToJson());
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

void EternalConvergenceEngine::DeserializeAll(const json& j) {
    std::lock_guard<std::mutex> lock(mutex_);
    eternalConvergences_.clear(); nodes_.clear(); streams_.clear(); waves_.clear(); matrices_.clear(); tensors_.clear(); clarities_.clear();
    if (j.contains("eternalConvergences")) for (const auto& eJson : j["eternalConvergences"]) { auto e = std::make_shared<EternalConvergence>(EternalConvergence::FromJson(eJson)); eternalConvergences_[e->id] = e; }
    if (j.contains("nodes")) for (const auto& nodeJson : j["nodes"]) { auto node = std::make_shared<ConvergenceNode>(ConvergenceNode::FromJson(nodeJson)); nodes_[node->id] = node; }
    if (j.contains("streams")) for (const auto& sJson : j["streams"]) { auto s = std::make_shared<EternalStream>(EternalStream::FromJson(sJson)); streams_[s->id] = s; }
    if (j.contains("waves")) for (const auto& wJson : j["waves"]) { auto w = std::make_shared<ConvergenceWave>(ConvergenceWave::FromJson(wJson)); waves_[w->id] = w; }
    if (j.contains("matrices")) for (const auto& mJson : j["matrices"]) { auto m = std::make_shared<UnityMatrix>(UnityMatrix::FromJson(mJson)); matrices_[m->id] = m; }
    if (j.contains("tensors")) for (const auto& tJson : j["tensors"]) { auto t = std::make_shared<EternalTensor>(EternalTensor::FromJson(tJson)); tensors_[t->id] = t; }
    if (j.contains("clarities")) for (const auto& cJson : j["clarities"]) { auto c = std::make_shared<EternalClarity>(EternalClarity::FromJson(cJson)); clarities_[c->id] = c; }
}

} // namespace EternalConvergence
