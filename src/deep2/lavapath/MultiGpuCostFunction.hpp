#pragma once
/* MultiGpuCostFunction — weighted readiness/locality vs transfer/queue/VRAM.
   GATE=G3_DEEP2_SCOREBOARD_SCHEDULER_LAW_001 LIVE=0. ≤99. */
#include "ScoreboardTypes.hpp"
#include <cmath>
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

struct MetricWeights {
    double readiness = 100.0;
    double locality = 50.0;
    double transfer = 35.0;
    double queue = 25.0;
    double headroom = 40.0;
};

struct DeviceMetrics {
    DeviceId deviceId = -1;
    uint64_t totalVram = 0;
    uint64_t freeVram = 0;
    double pcieGBps = 16.0;
    double peerGBps = 32.0;
    uint32_t queuedKernels = 0;
    double queuedFlops = 0.0;
    double tflops = 1.0;
};

struct DispatchDecision {
    DeviceId deviceId = -1;
    double score = -1e300;
    int peerXfer = 0;
    int dmaUpload = 0;
    double latencyMs = 0.0;
};

struct MultiGpuCostFunction {
    MetricWeights w{};

    DispatchDecision evaluate(const TensorScore& t, int curExec,
                              const DeviceMetrics* devs, uint32_t nDev) const {
        DispatchDecision best{};
        if (!devs || !nDev)
            return best;
        const uint32_t st = t.state.load(std::memory_order_acquire);
        for (uint32_t i = 0; i < nDev; ++i) {
            const DeviceMetrics& d = devs[i];
            double ready = 0, loc = 0, xferMs = 0, qPen = 0, head = 0;
            int peer = 0, dma = 0;
            if (st == (uint32_t)ResidencyState::GpuReady &&
                t.currentDevice == d.deviceId) {
                ready = 1.0;
                loc = 1.0;
            } else if (st == (uint32_t)ResidencyState::GpuReady) {
                ready = 0.7;
                loc = 0.2;
                peer = 1;
            } else if (st == (uint32_t)ResidencyState::RamReady) {
                ready = 0.5;
                loc = 0.5;
                dma = 1;
            } else {
                dma = 1;
            }
            const double bytes = (double)t.backingBytes;
            if (peer) {
                const double bw = d.peerGBps > 0.0 ? d.peerGBps : d.pcieGBps;
                xferMs = bw > 0.0 ? (bytes / (bw * 1e9)) * 1000.0 : 1e6;
            } else if (dma) {
                xferMs = d.pcieGBps > 0.0 ? (bytes / (d.pcieGBps * 1e9)) * 1000.0
                                          : 1e6;
            }
            double computeMs = 0.0;
            if (d.tflops > 0.0)
                computeMs = (d.queuedFlops / (d.tflops * 1e12)) * 1000.0;
            qPen = computeMs + d.queuedKernels * 0.005;
            if (d.freeVram < t.backingBytes)
                head = 1e6;
            else {
                const double rem = (double)(d.freeVram - t.backingBytes);
                const double fill =
                    1.0 - rem / (d.totalVram ? (double)d.totalVram : 1.0);
                head = std::exp(fill * 5.0);
            }
            double score = w.readiness * ready + w.locality * loc -
                           w.transfer * xferMs - w.queue * qPen -
                           w.headroom * head;
            if (curExec >= 0 && d.deviceId != curExec)
                score -= 15.0;
            if (score > best.score) {
                best.deviceId = d.deviceId;
                best.score = score;
                best.peerXfer = peer;
                best.dmaUpload = dma;
                best.latencyMs = xferMs + computeMs;
            }
        }
        return best;
    }
};

} /* namespace scoreboard */
} /* namespace Deep2 */
