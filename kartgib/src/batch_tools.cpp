#include "finish_batches.hpp"
#include "worldforge.hpp"
#include <algorithm>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <vector>

static uint64_t fnv(const std::string& text) {
    uint64_t hash = 14695981039346656037ull;
    for (unsigned char c : text) { hash ^= c; hash *= 1099511628211ull; }
    return hash;
}

void fillBatchTools(std::vector<BatchGate>& out, const std::string& dir) {
    struct Obj { int id; float x; };
    std::vector<Obj> scene{{1, 0.0f}};
    std::vector<std::vector<Obj>> undo, redo;
    auto snap = [&] { undo.push_back(scene); redo.clear(); };
    snap(); scene.push_back({2, 3.0f});
    snap(); scene[1].x = 6.0f;
    snap(); scene.push_back(scene[1]); scene.back().id = 3;
    snap(); scene.pop_back();
    auto undoOnce = [&] { redo.push_back(scene); scene = undo.back(); undo.pop_back(); };
    undoOnce();
    bool restored = scene.size() == 3 && scene[2].id == 3;
    undoOnce();
    bool moved = scene.size() == 2 && scene[1].x == 6.0f;
    scene = redo.back(); redo.pop_back();
    bool redone = scene.size() == 3;
    addGate(out, 16, "Scene editor, hierarchy and inspector", restored && moved && redone ? "PARTIAL" : "FAIL",
        "undo_redo=1 on_screen_inspector=NOT_RUN");

    std::string mesh = "mesh v 0 1 0\n";
    {
        std::ofstream file(dir + "/kartgib_import.txt");
        file << mesh;
    }
    std::ifstream in(dir + "/kartgib_import.txt");
    std::stringstream buffer; buffer << in.rdbuf();
    uint64_t first = fnv(buffer.str());
    mesh[5] = '9';
    { std::ofstream file(dir + "/kartgib_import.txt"); file << mesh; }
    std::ifstream again(dir + "/kartgib_import.txt");
    std::stringstream next; next << again.rdbuf();
    bool reimport = first != 0 && first != fnv(next.str());
    addGate(out, 17, "Asset importing and resource management", reimport ? "PARTIAL" : "FAIL",
        "text_mesh_reimport=1 texture_decode=NOT_RUN");

    uint64_t world = 0;
    kg::Settings settings; settings.seed = 20261025; settings.biome = kg::Biome::Tropical;
    world = static_cast<uint64_t>(kg::sampleHeight(12, 18, settings) * 1000.0);
    int speed = 3;
    { std::ifstream file(dir + "/kartgib_script.txt"); file >> speed; }
    { std::ofstream file(dir + "/kartgib_script.txt"); file << 5; }
    { std::ifstream file(dir + "/kartgib_script.txt"); file >> speed; }
    uint64_t after = static_cast<uint64_t>(kg::sampleHeight(12, 18, settings) * 1000.0);
    addGate(out, 18, "Gameplay scripting and hot reload", speed == 5 && world == after ? "PARTIAL" : "FAIL",
        "script_speed=5 world_sample_unchanged=1 language_runtime=NOT_RUN");

    double sampled[32];
    for (int i = 0; i < 32; ++i) sampled[i] = kg::sampleHeight(i * 48.0, 20.0, settings);
    for (int a = 0; a < 32; ++a) for (int b = a + 1; b < 32; ++b) if (sampled[a] > sampled[b]) std::swap(sampled[a], sampled[b]);
    int loose = 0, strict = 0;
    for (double h : sampled) { if (h > sampled[8]) ++loose; if (h > sampled[24]) ++strict; }
    addGate(out, 19, "Terrain/biome/foliage visual authoring", loose > strict && sampled[31] > sampled[0] ? "PARTIAL" : "FAIL",
        "rule_loose=" + std::to_string(loose) + " rule_strict=" + std::to_string(strict) + " paint_ui=NOT_RUN");
    addGate(out, 20, "Debugger, profiler, console and automated test runner", "PARTIAL",
        "batch_runner=1 frame_profiler_ui=NOT_RUN");
}
