// Live GPU junction sample via ADL (R9700 / atiadlxx)
#include "PlasmaGovernor.hpp"
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
#include <cstdlib>
#include <cstdint>
#include <chrono>

namespace Deep2 {
namespace {

#ifdef _WIN32
struct AdlTemp { int iSize; int iTemperature; };
using AdlAlloc = void* (*)(int);
using AdlCreate = int (*)(AdlAlloc, int);
using AdlTempGet = int (*)(int, int, AdlTemp*);
void* AdlMalloc(int n) { return std::malloc((size_t)n); }

bool SampleAdl(float* outC) {
    static HMODULE dll = nullptr;
    static AdlTempGet getTemp = nullptr;
    static bool inited = false;
    if (!inited) {
        inited = true;
        dll = LoadLibraryA("atiadlxx.dll");
        if (!dll) dll = LoadLibraryA("atiadlxy.dll");
        if (!dll) return false;
        auto create = reinterpret_cast<AdlCreate>(
            GetProcAddress(dll, "ADL_Main_Control_Create"));
        getTemp = reinterpret_cast<AdlTempGet>(
            GetProcAddress(dll, "ADL_Overdrive5_Temperature_Get"));
        if (!create || !getTemp || create(&AdlMalloc, 1) != 0) {
            getTemp = nullptr;
            return false;
        }
    }
    if (!getTemp) return false;
    AdlTemp t{};
    t.iSize = (int)sizeof(t);
    if (getTemp(0, 0, &t) != 0) return false;
    *outC = (float)t.iTemperature / 1000.f;
    return *outC > 0.f && *outC < 130.f;
}
#endif

} // namespace

bool LivePath_SampleThermal(rawrxd::PlasmaGovernor* plasma) {
    if (!plasma) return false;
    rawrxd::ThermalState st{};
    st.timestamp_us = (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
#ifdef _WIN32
    if (!SampleAdl(&st.junction_temp_c)) return false;
    st.hotspot_temp_c = st.junction_temp_c;
    plasma->updateThermalState(st);
    return true;
#else
    (void)st;
    return false;
#endif
}

} // namespace Deep2
