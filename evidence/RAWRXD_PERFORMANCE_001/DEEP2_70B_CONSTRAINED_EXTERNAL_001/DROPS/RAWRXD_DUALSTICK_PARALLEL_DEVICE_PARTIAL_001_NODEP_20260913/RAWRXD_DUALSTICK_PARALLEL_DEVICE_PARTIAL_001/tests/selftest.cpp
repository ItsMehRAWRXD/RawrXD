#include "ds_parallel_device_partial.hpp"

#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

using namespace rawrxd::deep2::dsdp;

class SimBackend final : public Backend {
public:
    explicit SimBackend(bool attest = false) : attest_(attest) {}

    bool BeginLayer(uint32_t hidden, DevicePartial out[2], std::string&) override {
        hidden_ = hidden;
        p_[0].assign(hidden, 0.0f);
        p_[1].assign(hidden, 0.0f);
        out[0] = DevicePartial{101, hidden};
        out[1] = DevicePartial{202, hidden};
        return true;
    }

    bool ExecWeightedExpert(unsigned stick, const WorkItem& item,
                            DevicePartial&, std::string& error) override {
        if (failExpert_ == item.expertId) {
            error = "SIM_FAIL";
            return false;
        }
        // Force simultaneous residency in both worker bodies when both are used.
        const unsigned s = stick & 1u;
        entered_[s].store(true, std::memory_order_release);
        const unsigned other = s ^ 1u;
        for (int spin = 0; spin < 2000 && !entered_[other].load(std::memory_order_acquire); ++spin)
            std::this_thread::yield();
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
        for (uint32_t i = 0; i < hidden_; ++i)
            p_[s][i] += item.weight * float(item.expertId + 1);
        return true;
    }

    bool DownloadPartial(unsigned stick, const DevicePartial&, float* host,
                         uint32_t hidden, std::string&) override {
        ++downloads_;
        for (uint32_t i = 0; i < hidden; ++i) host[i] = p_[stick & 1u][i];
        return true;
    }

    void AbortLayer(DevicePartial[2]) noexcept override { ++aborts_; }
    void EndLayer(DevicePartial[2]) noexcept override { ++ends_; }
    bool ProductBackendAttested() const noexcept override { return attest_; }

    int failExpert_ = -1;
    std::atomic<uint32_t> downloads_{0};
    std::atomic<uint32_t> aborts_{0};
    std::atomic<uint32_t> ends_{0};

private:
    bool attest_ = false;
    uint32_t hidden_ = 0;
    std::vector<float> p_[2];
    std::atomic<bool> entered_[2]{{false}, {false}};
};

static bool Near(float a, float b) { return std::fabs(a - b) < 1e-5f; }

int main() {
    constexpr uint32_t H = 32;
    std::vector<WorkItem> a{{0, .10f, 11}, {2, .20f, 12}, {4, .30f, 13}, {6, .40f, 14}};
    std::vector<WorkItem> b{{1, .15f, 21}, {3, .25f, 22}, {5, .35f, 23}, {7, .45f, 24}};
    std::vector<float> accum(H, 0.0f);

    SimBackend mock(false);
    Result r = RunLayer(mock, a, b, H, accum.data());
    const float want = .10f*1 + .20f*3 + .30f*5 + .40f*7 +
                       .15f*2 + .25f*4 + .35f*6 + .45f*8;
    bool ok = r.ok && r.counters.selected == 8 && r.counters.executed == 8 &&
              r.counters.maxConcurrentWorkers >= 2 &&
              r.counters.deviceDownVectors == 8 &&
              r.counters.devicePartialAccums == 8 &&
              r.counters.d2hPartialVectors == 2 &&
              r.counters.hostExpertDownVectors == 0 &&
              r.counters.layerJoins == 1 &&
              !r.productAuthorityEligible && mock.downloads_ == 2 &&
              mock.ends_ == 1 && mock.aborts_ == 0;
    for (float x : accum) ok = ok && Near(x, want);
    std::printf("TRUE_PARALLEL_STICKS=%s max_concurrent=%llu\n", ok ? "PASS" : "FAIL",
                (unsigned long long)r.counters.maxConcurrentWorkers);
    std::printf("DEVICE_PARTIAL_D2H_2VEC=%s d2h=%llu down=%llu accum=%llu\n",
                (r.counters.d2hPartialVectors == 2 && r.counters.deviceDownVectors == 8) ? "PASS" : "FAIL",
                (unsigned long long)r.counters.d2hPartialVectors,
                (unsigned long long)r.counters.deviceDownVectors,
                (unsigned long long)r.counters.devicePartialAccums);
    std::printf("MOCK_AUTHORITY_BLOCK=%s\n", !r.productAuthorityEligible ? "PASS" : "FAIL");

    SimBackend fail(false);
    fail.failExpert_ = 5;
    std::fill(accum.begin(), accum.end(), 0.0f);
    Result rf = RunLayer(fail, a, b, H, accum.data());
    const bool failClosed = !rf.ok && fail.aborts_ == 1 && fail.ends_ == 0 &&
                            rf.counters.layerJoins == 0 && fail.downloads_ == 0;
    std::printf("WORKER_FAIL_CLOSED=%s\n", failClosed ? "PASS" : "FAIL");
    ok = ok && failClosed;

    SimBackend attested(true);
    std::fill(accum.begin(), accum.end(), 0.0f);
    Result ra = RunLayer(attested, a, b, H, accum.data());
    const bool authEligible = ra.ok && ra.productAuthorityEligible;
    std::printf("ATTESTED_ELIGIBILITY_LOGIC=%s\n", authEligible ? "PASS" : "FAIL");
    ok = ok && authEligible;

    std::printf("DSDP_SELFTEST=%s\n", ok ? "PASS" : "FAIL");
    std::printf("TPS_PERFORMANCE_AUTHORITY=0\nTARGET_35_50_TPS=UNMINTED\nPROMOTE=0\n");
    return ok ? 0 : 1;
}
