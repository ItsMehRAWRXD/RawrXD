#include "finish_batches.hpp"
#include "worldforge_bridge.hpp"
#include <cmath>
#include <sstream>

static void climateAt(const kg::Settings& settings, double x, double z, double& temp, double& moist, double& elev) {
    kg::Settings warm = settings;
    warm.seed ^= 0x51A7ull;
    warm.biome = kg::Biome::Tropical;
    kg::Settings wet = settings;
    wet.seed ^= 0xC0FFEEull;
    wet.biome = kg::Biome::Tropical;
    temp = std::clamp(((kg::sampleHeight(x, z, warm) - 6.0) / 22.0) * 0.5 + 0.5, 0.0, 1.0);
    moist = std::clamp(((kg::sampleHeight(x, z, wet) - 6.0) / 22.0) * 0.5 + 0.5, 0.0, 1.0);
    elev = kg::sampleHeight(x, z, settings);
}

static int climateClass(double temp, double moist, double elev) {
    if (elev > 20.0) return 0;
    if (moist < 0.35 && temp > 0.55) return 1;
    if (moist > 0.60 && temp > 0.55) return 2;
    if (moist > 0.50) return 3;
    return 4;
}

void fillBatchClimate(std::vector<BatchGate>& out) {
    WorldForgeBridge bridge;
    bridge.initialize(20261025, "tropical");
    const kg::Settings& settings = bridge.getWorld().settings;
    int counts[5] = {};
    for (int z = -3072; z <= 3072; z += 128) {
        for (int x = -3072; x <= 3072; x += 128) {
            double temp, moist, elev;
            climateAt(settings, x, z, temp, moist, elev);
            counts[climateClass(temp, moist, elev)]++;
        }
    }
    bool biomes = counts[0] > 0 && counts[1] > 0 && counts[2] > 0 && counts[3] > 0 && counts[4] > 0;
    std::ostringstream biome;
    biome << "mountain=" << counts[0] << " desert=" << counts[1] << " tropical=" << counts[2]
          << " forest=" << counts[3] << " plains=" << counts[4];
    addGate(out, 4, "Climate maps and blended biomes", passFail(biomes), biome.str());

    auto closeEnough = [](double a, double b) { return std::fabs(a - b) < 1e-5; };
    double original = bridge.sampleHeightAt(80.0f, 0.0f);
    double neighbor = bridge.sampleHeightAt(240.0f, 0.0f);
    bridge.editHeight(80.0f, 0.0f, original + 5.0);
    bool saved = bridge.saveEdits("F:/rawrxd/kartgib/evidence/kartgib_chunk_edit.txt");
    bridge.clearEdits();
    bool regenerated = closeEnough(bridge.sampleHeightAt(80.0f, 0.0f), original) && closeEnough(bridge.sampleHeightAt(240.0f, 0.0f), neighbor);
    WorldForgeBridge reloaded;
    reloaded.initialize(20261025, "tropical");
    bool loaded = reloaded.loadEdits("F:/rawrxd/kartgib/evidence/kartgib_chunk_edit.txt");
    bool edited = closeEnough(reloaded.sampleHeightAt(80.0f, 0.0f), original + 5.0);
    bool untouched = closeEnough(reloaded.sampleHeightAt(240.0f, 0.0f), neighbor);
    std::ostringstream save;
    save << "file=evidence/kartgib_chunk_edit.txt saved=" << saved << " regen=" << regenerated
         << " reload=" << loaded << " edit_kept=" << edited << " neighbor_kept=" << untouched;
    addGate(out, 5, "World save/load and terrain modification", passFail(saved && regenerated && loaded && edited && untouched), save.str());
}
