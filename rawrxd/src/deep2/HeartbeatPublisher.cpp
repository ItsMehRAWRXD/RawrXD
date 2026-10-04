// HeartbeatPublisher.cpp — RAWRXD_REVERSE_001
//
// The INSIDE -> OUTSIDE direction.
//
// It exports execution reality as FACTS. It exports no pointer, no address, no
// handle. The one field that could accidentally become a locator
// (freeBytesOnDevice) is a byte count.
//
// CPU half is read from the SAME ProbeCPU() that the kernel dispatcher already
// depends on, so the heartbeat cannot advertise an instruction set the
// dispatcher will refuse to use, nor one the dispatcher assumed was present.
//
// Device half is REGISTERED, not guessed. Deep2Engine publishes a device only
// after Vulkan has actually reported it, and withdraws it when the device is
// lost. An unregistered machine publishes ZERO devices, which makes every GPU
// form unreachable — the fail-closed direction.

#include "ReverseLayer.hpp"
#include "QuantKernelRegistry.hpp"

#include <algorithm>
#include <chrono>
#include <mutex>

namespace Deep2 {
namespace {

struct DeviceRegistry {
    std::mutex mtx;
    std::vector<DeviceBeacon> devices;
    uint64_t generation = 1;
};

DeviceRegistry& registry() {
    static DeviceRegistry r;
    return r;
}

} // namespace

// ---------------------------------------------------------------------------
// Registration API, called from the engine at real residency transitions.
// ---------------------------------------------------------------------------
void publishDevice(const DeviceBeacon& b) {
    auto& r = registry();
    std::lock_guard<std::mutex> g(r.mtx);
    bool replaced = false;
    for (auto& d : r.devices) {
        if (d.deviceId == b.deviceId) {
            // A device that was already published keeps its identity; only its
            // measured facts move. Identity of a device is its slot.
            d.name           = b.name;
            d.totalBytes     = b.totalBytes;
            d.freeBytes      = b.freeBytes;
            d.peerReachable  = b.peerReachable;
            d.generation     = b.generation ? b.generation : r.generation;
            replaced = true;
            break;
        }
    }
    if (!replaced) r.devices.push_back(b);
    ++r.generation;
}

void withdrawDevice(uint32_t deviceId) {
    auto& r = registry();
    std::lock_guard<std::mutex> g(r.mtx);
    const size_t before = r.devices.size();
    r.devices.erase(std::remove_if(r.devices.begin(), r.devices.end(),
                                   [deviceId](const DeviceBeacon& d) {
                                       return d.deviceId == deviceId;
                                   }),
                    r.devices.end());
    if (r.devices.size() != before) ++r.generation;
}

void withdrawAllDevices() {
    auto& r = registry();
    std::lock_guard<std::mutex> g(r.mtx);
    if (!r.devices.empty()) {
        r.devices.clear();
        ++r.generation;
    }
}

// ---------------------------------------------------------------------------
// publishHeartbeat — the export. Facts only.
// ---------------------------------------------------------------------------
Heartbeat publishHeartbeat() {
    Heartbeat hb;

    // --- CPU: the flags the dispatcher itself uses ---
    auto& reg = QuantKernelRegistry::Instance();
    reg.ProbeCPU();
    const CPUFeatures& cf = reg.cpuFeatures();
    hb.cpu.avx2    = cf.avx2;
    hb.cpu.avx512f = cf.avx512f;
    hb.cpu.fma     = cf.fma;
    hb.cpu.f16c    = cf.f16c;

    // --- devices: only what was really published ---
    auto& r = registry();
    {
        std::lock_guard<std::mutex> g(r.mtx);
        hb.devices      = r.devices;
        hb.generation   = r.generation;
    }
    hb.cpu.generation = hb.generation;

    // A residency-relevant change invalidates every generated form bound to
    // the previous generation. Bumping here is what makes a stale form
    // detectable rather than silently reused.
    if (hb.generation != BackingDirectory::Instance().generation()) {
        BackingDirectory::Instance().bumpGeneration();
    }
    return hb;
}

} // namespace Deep2
