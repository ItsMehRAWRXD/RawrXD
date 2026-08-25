#pragma once
#include "sovereign/HealthReport.hpp"

namespace Sovereign {

struct SovereignHealth {
    SubsystemHealth kv;
    SubsystemHealth experts;
    SubsystemHealth attention;
    SubsystemHealth moe;
    SubsystemHealth nvme;
    SubsystemHealth vulkan;
    SubsystemHealth model;
    SubsystemHealth quant;
    SubsystemHealth telemetry;
    SubsystemHealth replay;
};

}
