#pragma once
/* Deep2MachineExperience — no third-party deps, fixed-capacity persistent experience. */
#include <cstdint>
#include <cstddef>

namespace Deep2 { namespace mx {

enum Feature : uint32_t {
    F_KERNEL=1u<<0, F_H2D=1u<<1, F_D2H=1u<<2, F_QUEUE=1u<<3,
    F_RESIDENCY=1u<<4, F_SYNC=1u<<5, F_CONTEND=1u<<6, F_AFFINITY=1u<<7
};
enum CellFlag : uint32_t { C_VALID=1u, C_QUARANTINE=2u, C_LIVE=4u, C_TRUTH=8u };
enum Source : uint8_t { SRC_DEFAULT=0, SRC_HISTORY=1, SRC_LIVE=2, SRC_NEAREST=3 };

struct Epoch {
    uint64_t hardware, driver, runtime, kernelAbi, modelLayout, topology;
};
struct Regime {
    uint16_t clock0, clock1, queue0, queue1, vram0, vram1;
    uint16_t contention, transferMode;
};
struct Key {
    uint16_t layer, expert, inBucket, outBucket;
    uint8_t gpu, quant, residency, kernel;
    uint32_t featureMask;
};
struct Cell {
    Key key;
    uint64_t epochHash, regimeHash, meanNs, devNs, lastTick;
    uint32_t samples, flags, generation, driftPpm;
};
struct Store {
    static const uint32_t CAP=512;
    Cell cells[CAP];
    uint32_t used, generation;
    uint64_t epochHash, regimeHash;
    uint32_t invalidMask;
};
struct Prediction {
    uint64_t ns;
    uint32_t confidencePpm, staleRiskPpm;
    uint8_t source;
    uint8_t quarantined;
};

uint64_t HashEpoch(const Epoch& e);
uint64_t HashRegime(const Regime& r);
uint32_t RegimeDistancePpm(const Regime& a, const Regime& b);
void Init(Store& s, const Epoch& e, const Regime& r);
void BeginGeneration(Store& s, const Epoch& e, const Regime& r, uint32_t changedMask);
void Observe(Store& s, const Key& k, uint64_t actualNs, uint64_t predictedNs,
             uint64_t tick, bool truthValidated);
Prediction Predict(const Store& s, const Key& k, uint64_t tick, uint64_t fallbackNs);
void QuarantineDrift(Store& s, uint32_t tripPpm);
void Revalidate(Store& s, const Key& k, uint64_t actualNs, uint32_t tolerancePpm);
bool Save(const Store& s, const char* path);
bool Load(Store& s, const char* path, const Epoch& e, const Regime& r);
uint32_t Checksum(const void* p, size_t n);

}} // namespace Deep2::mx
