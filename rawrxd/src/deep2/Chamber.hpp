#pragma once
/* Chamber — SM0-DSP anomaly detector */
#include <cstdint>
#include <cstddef>
#include <vector>
#include <cmath>
namespace Deep2 {

struct ChamberResult {
    int status = 0;          // 0=ok, 1=anomaly detected
    uint32_t flags = 0;      // bitfield of anomaly types
    float severity = 0.0f;   // 0.0–1.0 composite severity score
};

struct FormulaRoute {
    int route = 0;           // selected routing decision
    float confidence = 0.0f; // confidence in route selection
};

class Chamber {
public:
    Chamber() = default;

    ChamberResult evaluate(const float* hidden_state, size_t dim);
    FormulaRoute routePrimitive(uint64_t context_hash) const;

    void setDeadNeuronThreshold(float threshold) { deadNeuronThreshold_ = threshold; }
    void setOutlierZ(float z) { outlierZ_ = z; }
    void setEntropyMin(float min) { entropyMin_ = min; }

    uint64_t evaluationsTotal() const { return evaluationsTotal_; }
    uint64_t evaluationsAnomalous() const { return evaluationsAnomalous_; }
    void resetCounters() { evaluationsTotal_ = 0; evaluationsAnomalous_ = 0; }

private:
    float deadNeuronThreshold_ = 1e-6f; // variance below this = dead
    float outlierZ_ = 4.0f;             // z-score threshold for outliers
    float entropyMin_ = 0.01f;          // min expected normalized entropy

    uint64_t evaluationsTotal_ = 0;
    uint64_t evaluationsAnomalous_ = 0;
};

} // namespace Deep2
