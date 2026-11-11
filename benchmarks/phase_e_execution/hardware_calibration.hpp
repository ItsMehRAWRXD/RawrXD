#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>

namespace rawrxd {
namespace benchmarks {

/**
 * Phase E.1 Batch 1/5: Hardware Calibration
 * 
 * Ensures reproducible benchmark conditions by:
 * - Capturing complete system configuration
 * - Validating thermal stability
 * - Checking for background interference
 * - Locking CPU/GPU states
 */

// CPU information
struct CPUInfo {
    std::string vendor;
    std::string model;
    int physical_cores;
    int logical_cores;
    double base_clock_ghz;
    double max_clock_ghz;
    std::vector<double> core_clocks_ghz;
    double temperature_c;
    std::string power_profile;
};

// GPU information (AMD RX 7800 XT specific)
struct GPUInfo {
    std::string vendor = "AMD";
    std::string model = "RX 7800 XT";
    int compute_units;
    int vram_mb;
    double gpu_clock_mhz;
    double vram_clock_mhz;
    double temperature_c;
    double power_draw_w;
    double utilization_percent;
    std::string driver_version;
    bool thermal_throttling;
    bool power_throttling;
};

// Memory information
struct MemoryInfo {
    int total_ram_mb;
    int available_ram_mb;
    double ram_bandwidth_gbps;
    std::string ram_type;  // DDR4, DDR5, etc.
    int ram_speed_mhz;
};

// PCIe topology
struct PCIeInfo {
    int link_width;  // x16, x8, etc.
    std::string link_speed;  // PCIe 4.0, 5.0, etc.
    double bandwidth_gbps;
};

// System environment
struct SystemEnvironment {
    std::string os_name;
    std::string os_version;
    std::string kernel_version;
    std::string compiler;
    std::string compiler_version;
    std::vector<std::string> loaded_modules;
    std::vector<std::string> running_processes;
    double system_load_average;
    int background_tasks;
};

// Complete hardware profile
struct HardwareProfile {
    CPUInfo cpu;
    GPUInfo gpu;
    MemoryInfo memory;
    PCIeInfo pcie;
    SystemEnvironment system;
    std::chrono::system_clock::time_point timestamp;
    std::string profile_id;  // SHA256 hash of configuration
    
    // Validation results
    bool thermal_stable;
    bool clocks_stable;
    bool background_clean;
    bool overall_valid;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
};

// Calibration configuration
struct CalibrationConfig {
    // Thermal thresholds
    double max_gpu_temp_c = 85.0;
    double max_cpu_temp_c = 80.0;
    double thermal_stability_duration_s = 60.0;
    double thermal_variance_threshold_c = 2.0;
    
    // Clock stability
    double clock_variance_threshold_percent = 1.0;
    int clock_stability_samples = 10;
    
    // Background process limits
    int max_background_tasks = 5;
    double max_system_load = 2.0;
    std::vector<std::string> forbidden_processes = {
        "chrome", "firefox", "spotify", "discord", "steam"
    };
    
    // Power profile
    std::string required_power_profile = "high_performance";
    bool disable_turbo_boost = true;
    bool lock_cpu_affinity = true;
    bool isolate_gpu = true;
    
    // Sampling
    double sample_interval_ms = 1000.0;
    int stabilization_samples = 30;
};

// Hardware calibrator
class HardwareCalibrator {
public:
    explicit HardwareCalibrator(const CalibrationConfig& config);
    
    // Main calibration routine
    HardwareProfile Calibrate();
    
    // Individual checks
    CPUInfo CaptureCPUInfo();
    GPUInfo CaptureGPUInfo();
    MemoryInfo CaptureMemoryInfo();
    PCIeInfo CapturePCIeInfo();
    SystemEnvironment CaptureSystemEnvironment();
    
    // Validation
    bool ValidateThermalStability();
    bool ValidateClockStability();
    bool ValidateBackgroundCleanliness();
    bool ValidatePowerProfile();
    
    // System preparation
    void DisableTurboBoost();
    void EnableTurboBoost();
    void LockCPUAffinity();
    void UnlockCPUAffinity();
    void SetHighPerformancePowerProfile();
    void IsolateGPU();
    void RestoreSystemState();
    
    // Export
    std::string ExportToJson(const HardwareProfile& profile);
    std::string ExportToMarkdown(const HardwareProfile& profile);
    
    // Comparison
    bool IsReproducibleEnvironment(const HardwareProfile& a, const HardwareProfile& b);

private:
    CalibrationConfig config_;
    HardwareProfile baseline_;
    
    // Platform-specific implementations
    CPUInfo CaptureCPUInfoWindows();
    CPUInfo CaptureCPUInfoLinux();
    GPUInfo CaptureGPUInfoAMD();
    void SetPowerProfileWindows(const std::string& profile);
    void SetPowerProfileLinux(const std::string& profile);
};

// Factory
std::unique_ptr<HardwareCalibrator> CreateHardwareCalibrator(
    const CalibrationConfig& config = CalibrationConfig());

// Predefined configs for different validation scenarios
CalibrationConfig GetStrictCalibrationConfig();  // Maximum reproducibility
CalibrationConfig GetFastCalibrationConfig();      // Quick validation
CalibrationConfig GetCIConfig();                   // CI/CD automation

// Validation report
struct CalibrationReport {
    HardwareProfile profile;
    bool passed;
    std::vector<std::string> checks_passed;
    std::vector<std::string> checks_failed;
    std::vector<std::string> recommendations;
    std::string summary;
    
    std::string ToMarkdown() const;
    std::string ToJson() const;
};

CalibrationReport ValidateHardware(const CalibrationConfig& config);

} // namespace benchmarks
} // namespace rawrxd
