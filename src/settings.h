#pragma once
// Stub settings.h for CLI-only builds

struct AppState {
    bool enable_overclock_governor = false;
    int target_all_core_mhz = 0;
    int applied_core_offset_mhz = 0;
    int applied_gpu_offset_mhz = 0;
    int boost_step_mhz = 25;
    std::string governor_status;
    uint32_t current_cpu_temp_c = 0;
    uint32_t current_gpu_hotspot_c = 0;
};

class Settings {
public:
    static void LoadCompute(AppState&) {}
    static void LoadOverclock(AppState&) {}
    static void SaveCompute(const AppState&) {}
    static void SaveOverclock(const AppState&) {}
};
