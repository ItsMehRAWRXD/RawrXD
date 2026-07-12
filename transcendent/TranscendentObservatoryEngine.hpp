#pragma once
#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>

namespace Transcendent {

struct UniversalTelescope {
    std::string telescopeId;
    std::string name;
    std::string observationType; // "optical", "radio", "gravitational", "quantum"
    float sensitivity;
    float range;
    std::vector<std::string> targetUniverses;
    bool active;
    int64_t commissionedTimestamp;
};

struct CosmicSensor {
    std::string sensorId;
    std::string name;
    std::string sensorType; // "energy", "matter", "dark_energy", "dark_matter"
    float detectionThreshold;
    float accuracy;
    std::map<std::string, float> readings;
    int64_t lastReadingTimestamp;
};

struct MultiversalScanner {
    std::string scannerId;
    std::string name;
    std::string scanMode; // "passive", "active", "deep", "survey"
    std::vector<std::string> scannedUniverses;
    nlohmann::json scanData;
    float coveragePercent;
    int64_t lastScanTimestamp;
};

struct TranscendentDetectionArray {
    std::string arrayId;
    std::string name;
    std::string arrayType; // "pulsar", "black_hole", "neutron_star", "exoplanet"
    std::vector<std::string> componentSensors;
    nlohmann::json detections;
    float detectionRate;
    int64_t establishedTimestamp;
};

struct CosmicObservation {
    std::string observationId;
    std::string sourceId;
    std::string observationType;
    nlohmann::json data;
    float confidence;
    int64_t timestamp;
};

class TranscendentObservatoryEngine {
public:
    static void Init();
    static void Shutdown();
    
    static std::string CommissionUniversalTelescope(const std::string& name,
                                                    const std::string& observationType,
                                                    float sensitivity,
                                                    float range);
    static bool ActivateTelescope(const std::string& telescopeId);
    static bool DeactivateTelescope(const std::string& telescopeId);
    static bool PointTelescope(const std::string& telescopeId, const std::string& universeId);
    static UniversalTelescope GetTelescope(const std::string& telescopeId);
    static std::vector<UniversalTelescope> GetAllTelescopes();
    static std::vector<UniversalTelescope> GetActiveTelescopes();
    
    static std::string DeployCosmicSensor(const std::string& name,
                                          const std::string& sensorType,
                                          float detectionThreshold);
    static bool CalibrateSensor(const std::string& sensorId, float newThreshold);
    static bool RecordSensorReading(const std::string& sensorId, 
                                    const std::string& metric,
                                    float value);
    static CosmicSensor GetSensor(const std::string& sensorId);
    static std::vector<CosmicSensor> GetAllSensors();
    static std::vector<CosmicSensor> GetSensorsByType(const std::string& sensorType);
    
    static std::string InitializeMultiversalScanner(const std::string& name,
                                                    const std::string& scanMode);
    static bool StartScan(const std::string& scannerId, const std::vector<std::string>& targetUniverses);
    static bool StopScan(const std::string& scannerId);
    static MultiversalScanner GetScanner(const std::string& scannerId);
    static std::vector<MultiversalScanner> GetAllScanners();
    
    static std::string EstablishDetectionArray(const std::string& name,
                                               const std::string& arrayType,
                                               const std::vector<std::string>& sensors);
    static bool RegisterDetection(const std::string& arrayId, 
                                  const std::string& detectionId,
                                  const nlohmann::json& detectionData);
    static TranscendentDetectionArray GetDetectionArray(const std::string& arrayId);
    static std::vector<TranscendentDetectionArray> GetAllDetectionArrays();
    
    static std::string RecordObservation(const std::string& sourceId,
                                         const std::string& observationType,
                                         const nlohmann::json& data,
                                         float confidence);
    static std::vector<CosmicObservation> GetObservationsBySource(const std::string& sourceId);
    static std::vector<CosmicObservation> GetAllObservations();
    
    static float CalculateObservationCoverage();
    static float CalculateDetectionAccuracy();
    static nlohmann::json GetObservatoryMetrics();
    static nlohmann::json GenerateObservatoryReport();
    
    static void OnTick();
    static bool IsAlive();

private:
    static std::mutex s_mutex;
    static bool s_initialized;
    static std::map<std::string, UniversalTelescope> s_telescopes;
    static std::map<std::string, CosmicSensor> s_sensors;
    static std::map<std::string, MultiversalScanner> s_scanners;
    static std::map<std::string, TranscendentDetectionArray> s_arrays;
    static std::map<std::string, CosmicObservation> s_observations;
    static int64_t s_tickCount;
};

} // namespace Transcendent
