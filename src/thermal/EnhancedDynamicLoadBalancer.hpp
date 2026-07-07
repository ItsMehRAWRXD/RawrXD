/**
 * @file EnhancedDynamicLoadBalancer.hpp
 * @brief Health-Aware Dynamic Load Balancer
 */

#pragma once

#include <vector>
#include <string>
#include <chrono>
#include <map>

namespace rawrxd::thermal {

struct SMARTData {
    int rawReadErrorRate = 0;
    int reallocatedSectorCount = 0;
    int seekErrorRate = 0;
    int powerOnHours = 0;
    int spinRetryCount = 0;
    int reallocatedEventCount = 0;
    int currentPendingSectorCount = 0;
    int uncorrectableSectorCount = 0;
    int availableSpare = 100;
    int availableSpareThreshold = 10;
    int percentageUsed = 0;
    int64_t dataUnitsWritten = 0;
    int64_t dataUnitsRead = 0;
};

struct DriveHealthProfile {
    std::string driveLetter;
    SMARTData smartData;
    double healthScore = 100.0;
    int64_t totalBytesWritten = 0;
    int64_t estimatedTBWRemaining = 0;
    std::chrono::system_clock::time_point lastUpdated;
};

struct ThermalZone {
    int zoneId = 0;
    std::string name;
    double currentTemp = 0.0;
    double criticalTemp = 85.0;
    double warningTemp = 75.0;
    bool throttling = false;
};

class EnhancedDynamicLoadBalancer
{

public:
    enum class OperationType {
        Read,
        Write,
        Sequential,
        Random,
        LargeFile,
        SmallFiles
    };

    explicit EnhancedDynamicLoadBalancer(void* parent = nullptr);
    ~EnhancedDynamicLoadBalancer();

    void setWindowTitle(const std::string& title);
    void setMinimumSize(int w, int h);
    void setModal(bool modal);

    void updateDriveHealth(const std::string& driveLetter, const DriveHealthProfile& profile);
    void updateThermalZone(const ThermalZone& zone);
    
    std::string selectOptimalDrive(OperationType opType);
    std::vector<std::string> getAvailableDrives() const;
    DriveHealthProfile getDriveHealth(const std::string& driveLetter) const;
    
    void setLoadWeight(double weight);
    void setHealthWeight(double weight);
    void setThermalWeight(double weight);

private:
    void* m_parent;
    std::map<std::string, DriveHealthProfile> m_driveHealth;
    std::map<int, ThermalZone> m_thermalZones;
    double m_loadWeight = 0.4;
    double m_healthWeight = 0.4;
    double m_thermalWeight = 0.2;
};

} // namespace rawrxd::thermal

#endif
