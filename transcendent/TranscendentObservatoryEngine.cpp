#include "transcendent/TranscendentObservatoryEngine.hpp"
#include <chrono>
#include <algorithm>

namespace Transcendent {

std::mutex TranscendentObservatoryEngine::s_mutex;
bool TranscendentObservatoryEngine::s_initialized = false;
std::map<std::string, UniversalTelescope> TranscendentObservatoryEngine::s_telescopes;
std::map<std::string, CosmicSensor> TranscendentObservatoryEngine::s_sensors;
std::map<std::string, MultiversalScanner> TranscendentObservatoryEngine::s_scanners;
std::map<std::string, TranscendentDetectionArray> TranscendentObservatoryEngine::s_arrays;
std::map<std::string, CosmicObservation> TranscendentObservatoryEngine::s_observations;
int64_t TranscendentObservatoryEngine::s_tickCount = 0;

void TranscendentObservatoryEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_initialized) return;
    s_initialized = true;
    s_tickCount = 0;
}

void TranscendentObservatoryEngine::Shutdown() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_initialized = false;
    s_telescopes.clear();
    s_sensors.clear();
    s_scanners.clear();
    s_arrays.clear();
    s_observations.clear();
}

std::string TranscendentObservatoryEngine::CommissionUniversalTelescope(const std::string& name,
                                                                        const std::string& observationType,
                                                                        float sensitivity,
                                                                        float range) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int telescopeCounter = 0;
    std::string telescopeId = "universal_telescope_" + std::to_string(++telescopeCounter);
    
    UniversalTelescope telescope;
    telescope.telescopeId = telescopeId;
    telescope.name = name;
    telescope.observationType = observationType;
    telescope.sensitivity = sensitivity;
    telescope.range = range;
    telescope.active = false;
    telescope.commissionedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_telescopes[telescopeId] = telescope;
    return telescopeId;
}

bool TranscendentObservatoryEngine::ActivateTelescope(const std::string& telescopeId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_telescopes.find(telescopeId);
    if (it == s_telescopes.end()) return false;
    it->second.active = true;
    return true;
}

bool TranscendentObservatoryEngine::DeactivateTelescope(const std::string& telescopeId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_telescopes.find(telescopeId);
    if (it == s_telescopes.end()) return false;
    it->second.active = false;
    return true;
}

bool TranscendentObservatoryEngine::PointTelescope(const std::string& telescopeId, const std::string& universeId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_telescopes.find(telescopeId);
    if (it == s_telescopes.end()) return false;
    it->second.targetUniverses.push_back(universeId);
    return true;
}

UniversalTelescope TranscendentObservatoryEngine::GetTelescope(const std::string& telescopeId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_telescopes.find(telescopeId);
    if (it != s_telescopes.end()) return it->second;
    return UniversalTelescope{};
}

std::vector<UniversalTelescope> TranscendentObservatoryEngine::GetAllTelescopes() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<UniversalTelescope> result;
    for (const auto& [id, telescope] : s_telescopes) {
        result.push_back(telescope);
    }
    return result;
}

std::vector<UniversalTelescope> TranscendentObservatoryEngine::GetActiveTelescopes() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<UniversalTelescope> result;
    for (const auto& [id, telescope] : s_telescopes) {
        if (telescope.active) result.push_back(telescope);
    }
    return result;
}

std::string TranscendentObservatoryEngine::DeployCosmicSensor(const std::string& name,
                                                               const std::string& sensorType,
                                                               float detectionThreshold) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int sensorCounter = 0;
    std::string sensorId = "cosmic_sensor_" + std::to_string(++sensorCounter);
    
    CosmicSensor sensor;
    sensor.sensorId = sensorId;
    sensor.name = name;
    sensor.sensorType = sensorType;
    sensor.detectionThreshold = detectionThreshold;
    sensor.accuracy = 1.0f;
    sensor.lastReadingTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_sensors[sensorId] = sensor;
    return sensorId;
}

bool TranscendentObservatoryEngine::CalibrateSensor(const std::string& sensorId, float newThreshold) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_sensors.find(sensorId);
    if (it == s_sensors.end()) return false;
    it->second.detectionThreshold = newThreshold;
    return true;
}

bool TranscendentObservatoryEngine::RecordSensorReading(const std::string& sensorId, 
                                                         const std::string& metric,
                                                         float value) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_sensors.find(sensorId);
    if (it == s_sensors.end()) return false;
    it->second.readings[metric] = value;
    it->second.lastReadingTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

CosmicSensor TranscendentObservatoryEngine::GetSensor(const std::string& sensorId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_sensors.find(sensorId);
    if (it != s_sensors.end()) return it->second;
    return CosmicSensor{};
}

std::vector<CosmicSensor> TranscendentObservatoryEngine::GetAllSensors() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CosmicSensor> result;
    for (const auto& [id, sensor] : s_sensors) {
        result.push_back(sensor);
    }
    return result;
}

std::vector<CosmicSensor> TranscendentObservatoryEngine::GetSensorsByType(const std::string& sensorType) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CosmicSensor> result;
    for (const auto& [id, sensor] : s_sensors) {
        if (sensor.sensorType == sensorType) result.push_back(sensor);
    }
    return result;
}

std::string TranscendentObservatoryEngine::InitializeMultiversalScanner(const std::string& name,
                                                                         const std::string& scanMode) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int scannerCounter = 0;
    std::string scannerId = "multiversal_scanner_" + std::to_string(++scannerCounter);
    
    MultiversalScanner scanner;
    scanner.scannerId = scannerId;
    scanner.name = name;
    scanner.scanMode = scanMode;
    scanner.coveragePercent = 0.0f;
    scanner.lastScanTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_scanners[scannerId] = scanner;
    return scannerId;
}

bool TranscendentObservatoryEngine::StartScan(const std::string& scannerId, const std::vector<std::string>& targetUniverses) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_scanners.find(scannerId);
    if (it == s_scanners.end()) return false;
    it->second.scannedUniverses = targetUniverses;
    it->second.coveragePercent = 0.0f;
    return true;
}

bool TranscendentObservatoryEngine::StopScan(const std::string& scannerId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_scanners.find(scannerId);
    if (it == s_scanners.end()) return false;
    it->second.scannedUniverses.clear();
    return true;
}

MultiversalScanner TranscendentObservatoryEngine::GetScanner(const std::string& scannerId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_scanners.find(scannerId);
    if (it != s_scanners.end()) return it->second;
    return MultiversalScanner{};
}

std::vector<MultiversalScanner> TranscendentObservatoryEngine::GetAllScanners() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<MultiversalScanner> result;
    for (const auto& [id, scanner] : s_scanners) {
        result.push_back(scanner);
    }
    return result;
}

std::string TranscendentObservatoryEngine::EstablishDetectionArray(const std::string& name,
                                                                      const std::string& arrayType,
                                                                      const std::vector<std::string>& sensors) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int arrayCounter = 0;
    std::string arrayId = "detection_array_" + std::to_string(++arrayCounter);
    
    TranscendentDetectionArray array;
    array.arrayId = arrayId;
    array.name = name;
    array.arrayType = arrayType;
    array.componentSensors = sensors;
    array.detectionRate = 0.0f;
    array.establishedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_arrays[arrayId] = array;
    return arrayId;
}

bool TranscendentObservatoryEngine::RegisterDetection(const std::string& arrayId, 
                                                         const std::string& detectionId,
                                                         const nlohmann::json& detectionData) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_arrays.find(arrayId);
    if (it == s_arrays.end()) return false;
    it->second.detections[detectionId] = detectionData;
    return true;
}

TranscendentDetectionArray TranscendentObservatoryEngine::GetDetectionArray(const std::string& arrayId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_arrays.find(arrayId);
    if (it != s_arrays.end()) return it->second;
    return TranscendentDetectionArray{};
}

std::vector<TranscendentDetectionArray> TranscendentObservatoryEngine::GetAllDetectionArrays() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<TranscendentDetectionArray> result;
    for (const auto& [id, array] : s_arrays) {
        result.push_back(array);
    }
    return result;
}

std::string TranscendentObservatoryEngine::RecordObservation(const std::string& sourceId,
                                                              const std::string& observationType,
                                                              const nlohmann::json& data,
                                                              float confidence) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int observationCounter = 0;
    std::string observationId = "observation_" + std::to_string(++observationCounter);
    
    CosmicObservation observation;
    observation.observationId = observationId;
    observation.sourceId = sourceId;
    observation.observationType = observationType;
    observation.data = data;
    observation.confidence = confidence;
    observation.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_observations[observationId] = observation;
    return observationId;
}

std::vector<CosmicObservation> TranscendentObservatoryEngine::GetObservationsBySource(const std::string& sourceId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CosmicObservation> result;
    for (const auto& [id, observation] : s_observations) {
        if (observation.sourceId == sourceId) result.push_back(observation);
    }
    return result;
}

std::vector<CosmicObservation> TranscendentObservatoryEngine::GetAllObservations() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CosmicObservation> result;
    for (const auto& [id, observation] : s_observations) {
        result.push_back(observation);
    }
    return result;
}

float TranscendentObservatoryEngine::CalculateObservationCoverage() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_telescopes.empty()) return 1.0f;
    int activeCount = 0;
    for (const auto& [id, telescope] : s_telescopes) {
        if (telescope.active) activeCount++;
    }
    return static_cast<float>(activeCount) / s_telescopes.size();
}

float TranscendentObservatoryEngine::CalculateDetectionAccuracy() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_sensors.empty()) return 1.0f;
    float totalAccuracy = 0.0f;
    for (const auto& [id, sensor] : s_sensors) {
        totalAccuracy += sensor.accuracy;
    }
    return totalAccuracy / s_sensors.size();
}

nlohmann::json TranscendentObservatoryEngine::GetObservatoryMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json metrics;
    metrics["telescopeCount"] = s_telescopes.size();
    metrics["activeTelescopeCount"] = GetActiveTelescopes().size();
    metrics["sensorCount"] = s_sensors.size();
    metrics["scannerCount"] = s_scanners.size();
    metrics["arrayCount"] = s_arrays.size();
    metrics["observationCount"] = s_observations.size();
    metrics["observationCoverage"] = CalculateObservationCoverage();
    metrics["detectionAccuracy"] = CalculateDetectionAccuracy();
    metrics["tickCount"] = s_tickCount;
    return metrics;
}

nlohmann::json TranscendentObservatoryEngine::GenerateObservatoryReport() {
    nlohmann::json report;
    report["metrics"] = GetObservatoryMetrics();
    report["activeTelescopes"] = nlohmann::json::array();
    report["recentObservations"] = nlohmann::json::array();
    report["sensorSummary"] = nlohmann::json::array();
    
    for (const auto& telescope : GetActiveTelescopes()) {
        nlohmann::json t;
        t["id"] = telescope.telescopeId;
        t["name"] = telescope.name;
        t["type"] = telescope.observationType;
        t["sensitivity"] = telescope.sensitivity;
        report["activeTelescopes"].push_back(t);
    }
    
    for (const auto& observation : GetAllObservations()) {
        nlohmann::json o;
        o["id"] = observation.observationId;
        o["type"] = observation.observationType;
        o["confidence"] = observation.confidence;
        report["recentObservations"].push_back(o);
    }
    
    return report;
}

void TranscendentObservatoryEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_tickCount++;
    
    for (auto& [id, telescope] : s_telescopes) {
        if (telescope.active) {
            telescope.sensitivity *= 0.9999f;
            telescope.sensitivity += 0.0001f;
        }
    }
    
    for (auto& [id, sensor] : s_sensors) {
        sensor.accuracy *= 0.9999f;
        sensor.accuracy += 0.0001f;
    }
    
    for (auto& [id, scanner] : s_scanners) {
        if (!scanner.scannedUniverses.empty()) {
            scanner.coveragePercent = std::min(100.0f, scanner.coveragePercent + 0.1f);
        }
    }
}

bool TranscendentObservatoryEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

} // namespace Transcendent
