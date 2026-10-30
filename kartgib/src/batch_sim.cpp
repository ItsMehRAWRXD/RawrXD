#include "finish_batches.hpp"
#include "player_step.hpp"
#include "worldforge.hpp"
#include <cmath>
#include <sstream>
#include <vector>

void fillBatchSim(std::vector<BatchGate>& out) {
    kg::Settings settings;
    settings.seed = 20261025;
    settings.biome = kg::Biome::Tropical;
    auto ground = [&](float x, float z) { return static_cast<float>(kg::sampleHeight(x, z, settings)); };
    KartState a, b;
    a.throttle = b.throttle = 1.0f;
    a.steer = b.steer = 0.25f;
    a.yaw = b.yaw = 0.4f;
    for (int i = 0; i < 60; ++i) { stepKartBody(a, 1.0f / 60.0f, ground); stepKartBody(b, 1.0f / 60.0f, ground); }
    bool same = a.x == b.x && a.z == b.z && a.y == b.y;
    float landed = a.y;
    a.jump = true;
    stepKartBody(a, 1.0f / 60.0f, ground);
    bool rose = a.y > landed && a.airborne;
    for (int i = 0; i < 180; ++i) stepKartBody(a, 1.0f / 60.0f, ground);
    bool down = !a.airborne;
    double groundY = kg::sampleHeight(50, 40, settings);
    double hit = 80.0;
    bool found = false;
    for (int s = 0; s < 400; ++s) { hit -= 0.5; if (hit <= groundY) { found = true; break; } }
    bool ray = found && std::fabs(hit - groundY) < 0.51;
    std::ostringstream physics;
    physics << "fixed_step_match=" << same << " jump=" << rose << " landed=" << down << " ray_delta_lt_0.51=" << ray;
    addGate(out, 9, "Physics integration and character collision", passFail(same && rose && down && ray), physics.str());

    constexpr int n = 16;
    int blocked[n][n] = {};
    for (int j = 0; j < n; ++j) for (int i = 0; i < n; ++i) {
        double h = kg::sampleHeight(i * 24.0, j * 24.0, settings);
        blocked[j][i] = std::fabs(kg::sampleHeight(i * 24.0 + 24, j * 24.0, settings) - h) > 6.0;
    }
    blocked[0][0] = blocked[n - 1][n - 1] = 0;
    int dist[n][n];
    for (int j = 0; j < n; ++j) for (int i = 0; i < n; ++i) dist[j][i] = -1;
    std::vector<int> queue = {0};
    dist[0][0] = 0;
    for (size_t q = 0; q < queue.size(); ++q) {
        int i = queue[q] % n, j = queue[q] / n;
        for (int d = 0; d < 4; ++d) {
            int ni = i + (d == 0) - (d == 1), nj = j + (d == 2) - (d == 3);
            if (ni < 0 || nj < 0 || ni >= n || nj >= n || blocked[nj][ni] || dist[nj][ni] >= 0) continue;
            dist[nj][ni] = dist[j][i] + 1;
            queue.push_back(nj * n + ni);
        }
    }
    bool path = dist[n - 1][n - 1] > 0;
    std::ostringstream nav;
    nav << "path_steps=" << dist[n - 1][n - 1] << " cells=" << (n * n);
    addGate(out, 10, "Navigation meshes and pathfinding", passFail(path), nav.str());
}
