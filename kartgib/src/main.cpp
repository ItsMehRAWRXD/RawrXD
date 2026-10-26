#include <vulkan/vulkan.h>
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstdlib>
#include <cstdint>
#include <limits>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <array>
#include <chrono>
#include <thread>

#include "win32_window.hpp"
#include "vulkan_renderer.hpp"
#include "game_loop.hpp"
#include "worldforge_bridge.hpp"
#include "finish_batches.hpp"
#include "ocean_field.hpp"
#include "product_scene.hpp"
#include "editor_api.hpp"

static void printUsage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]\n";
    std::cout << "Options:\n";
    std::cout << "  --seed <n>        World generation seed (default: 20261025)\n";
    std::cout << "  --biome <name>    Biome: tropical, gothic, voxel, floating (default: tropical)\n";
    std::cout << "  --width <n>       Window width (default: 1920)\n";
    std::cout << "  --height <n>      Window height (default: 1080)\n";
    std::cout << "  --fullscreen      Start in fullscreen mode\n";
    std::cout << "  --validation      Enable Vulkan validation layers\n";
    std::cout << "  --terrain         Draw PBR terrain instead of the debug triangle\n";
    std::cout << "  --g04-triangle    Sample isolated magenta triangle pixels\n";
    std::cout << "  --g04-terrain     Sample isolated terrain pixels\n";
    std::cout << "  --g04-scene       Sample atmosphere plus terrain\n";
    std::cout << "  --forensics       F10 pass isolation, readback, and JSON report\n";
    std::cout << "  --shadow-cert     Shadow on/off readback and cascade colors\n";
    std::cout << "  --chunks          5x5 seamless WorldForge chunk grid\n";
    std::cout << "  --finish-batches  Run the 25-batch evidence suite and exit\n";
    std::cout << "  --ocean           Spectral ocean mesh, FFT parity, and framebuffer tour\n";
    std::cout << "  --product         Editor, river, instancing, and two-process tour\n";
    std::cout << "  --studio          RawrXD Studio project, sculpt, and Sunshine edit\n";
    std::cout << "  --help            Show this help\n";
}

int main(int argc, char** argv) {
    // Parse command line
    uint64_t seed = 20261025;
    std::string biome = "tropical";
    int width = 1920;
    int height = 1080;
    bool fullscreen = false;
    bool validation = false;
    bool terrain = false;
    bool g04Triangle = false;
    bool g04Terrain = false;
    bool g04Scene = false;
    bool forensics = false;
    bool shadowCert = false;
    bool chunks = false;
    bool finish = false;
    bool finishWrite = false;
    bool finishSmoke = false;
    bool ocean = false;
    bool product = false;
    bool editor = false;
    bool editorShow = false;
    bool studio = false;
    bool studioShow = false;
    int peerPort = 0;
    uint64_t peerSeed = 20261025;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return 0;
        } else if (arg == "--seed" && i + 1 < argc) {
            seed = std::stoull(argv[++i]);
        } else if (arg == "--biome" && i + 1 < argc) {
            biome = argv[++i];
        } else if (arg == "--width" && i + 1 < argc) {
            width = std::stoi(argv[++i]);
        } else if (arg == "--height" && i + 1 < argc) {
            height = std::stoi(argv[++i]);
        } else if (arg == "--fullscreen") {
            fullscreen = true;
        } else if (arg == "--validation") {
            validation = true;
        } else if (arg == "--terrain") {
            terrain = true;
        } else if (arg == "--g04-triangle") {
            g04Triangle = true;
        } else if (arg == "--g04-terrain") {
            g04Terrain = true;
        } else if (arg == "--g04-scene") {
            g04Scene = true;
        } else if (arg == "--forensics") {
            forensics = true;
        } else if (arg == "--shadow-cert") {
            shadowCert = true;
        } else if (arg == "--chunks") {
            chunks = true;
        } else if (arg == "--finish-batches") {
            finish = true;
        } else if (arg == "--finish-write") {
            finishWrite = true;
        } else if (arg == "--finish-smoke") {
            finishSmoke = true;
        } else if (arg == "--ocean") {
            ocean = true;
        } else if (arg == "--editor") {
            editor = true;
        } else if (arg == "--studio") {
            editor = true;
            studio = true;
        } else if (arg == "--studio-load") {
            editor = true;
            studio = true;
            studioShow = true;
        } else if (arg == "--editor-load") {
            editor = true;
            editorShow = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') ++i;
        } else if (arg == "--product") {
            product = true;
        } else if (arg == "--product-peer" && i + 1 < argc) {
            peerPort = std::stoi(argv[++i]);
            if (i + 1 < argc && argv[i + 1][0] != '-') peerSeed = std::stoull(argv[++i]);
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            printUsage(argv[0]);
            return 1;
        }
    }
    
    if (peerPort != 0) return runProductPeer(peerPort, peerSeed) ? 0 : 1;
    if (finishWrite) {
        std::filesystem::create_directories("F:/rawrxd/kartgib/evidence");
        std::ofstream file("F:/rawrxd/kartgib/evidence/kartgib_autosave.bin", std::ios::binary);
        uint32_t magic = 0x4B474931u;
        float value = 12.5f;
        file.write(reinterpret_cast<char*>(&magic), 4);
        file.write(reinterpret_cast<char*>(&value), 4);
        file.close();
        Sleep(30000);
        return 0;
    }
    if (finishSmoke) {
        wchar_t exePath[32768] = {};
        GetModuleFileNameW(nullptr, exePath, 32768);
        std::ofstream file(std::filesystem::path(exePath).parent_path() / "smoke.txt");
        file << "KARTGIB_SMOKE\n";
        std::cout << "KARTGIB_SMOKE" << std::endl;
        return 0;
    }
    if (finish) {
        try { return runFinishBatches("F:/rawrxd/kartgib/evidence"); }
        catch (const std::exception& ex) { std::cerr << ex.what() << std::endl; return 1; }
    }

    try {
        std::cout << "=== KartGib - Sunshine KartGib Engine ===" << std::endl;
        std::cout << "Seed: " << seed << ", Biome: " << biome << std::endl;
        std::cout << "Window: " << width << "x" << height << (fullscreen ? " (fullscreen)" : "") << std::endl;
        std::cout << "Vulkan validation: " << (validation ? "enabled" : "disabled") << std::endl << std::endl;
        
        // Initialize WorldForge bridge
        WorldForgeBridge worldforge;
        worldforge.initialize(seed, biome);
        if (editor) {
            std::filesystem::create_directories("F:/rawrxd/kartgib/evidence");
            editorBoot();
            if (studio) {
                studioOwn(true);
                studioSetSeed(seed);
                if (studioShow && !studioLoadProject("F:/rawrxd/kartgib/evidence/studio_project")) return 1;
                if (studioShow) studioSetShow(true);
            } else if (editorShow) {
                editorSetShow(true);
                if (!editorLoad("F:/rawrxd/kartgib/evidence/kartgib_editor_scene.txt")) return 1;
                editorSaveAtomic("F:/rawrxd/kartgib/evidence/kartgib_editor_load.txt");
            }
            worldforge.setEditor(true);
        } else if (product) {
            std::filesystem::create_directories("F:/rawrxd/kartgib/evidence");
            productStats().audio = submitProductAudio();
            productStats().gamepad = queryGamepad();
            productStats().sync = runProductHost(worldforge);
            worldforge.setProduct(true, 0);
        } else if (ocean) {
            runOceanCpuCert();
            runTerrainCert("F:/rawrxd/kartgib/evidence");
            worldforge.setOcean(true, 0.0f);
        } else if (chunks) {
            worldforge.useChunkGrid(true);
            std::filesystem::create_directories("F:/rawrxd/kartgib/evidence");
            std::ofstream seams("F:/rawrxd/kartgib/evidence/kartgib_chunk_seams.json");
            seams << "{\"gate\":\"CHUNK_SEAMS\",\"seams\":\"" << (worldforge.chunkSeamsExact() ? "PASS" : "FAIL")
                  << "\",\"order\":\"" << (worldforge.chunkOrderIndependent() ? "PASS" : "FAIL")
                  << "\",\"hash\":" << worldforge.chunkGridHash()
                  << ",\"build_ms\":" << worldforge.chunkBuildMs()
                  << ",\"chunks\":25,\"cells\":64,\"vertices\":105625}\n";
        }
        
        // Create window
        const char* title = studio ? "RawrXD Studio" : "KartGib - Sunshine KartGib";
        Win32Window window(width, height, title, fullscreen);
        if (studio) inspectorCreate(window.getHandle());
        window.setUserPointer(&worldforge);
        if (product) {
            window.noteMouse(40, -8);
            int dx = 0, dy = 0;
            window.consumeMouse(dx, dy);
            productStats().mouseDx = dx;
            productStats().mouseDy = dy;
        }
        
        // Create Vulkan renderer
        VulkanRenderer renderer(&window, validation);
        renderer.initialize();
        if (forensics) {
            renderer.enableDebugTriangleMode(false);
            renderer.armForensics();
        } else if (chunks) {
            renderer.enableDebugTriangleMode(false);
            renderer.armChunkTour();
        } else if (editor) {
            renderer.enableDebugTriangleMode(false);
            renderer.freezeEditorTime();
        } else if (product) {
            renderer.enableDebugTriangleMode(false);
            renderer.armProductTour();
        } else if (ocean) {
            float gpuError = -1.0f;
            bool gpuOk = runOceanGpuParity(renderer, gpuError);
            setOceanGpu(gpuOk, gpuError);
            renderer.enableDebugTriangleMode(false);
            renderer.armOceanTour();
        } else if (shadowCert) {
            renderer.enableDebugTriangleMode(false);
            renderer.armShadowCert();
        } else if (g04Triangle) {
            renderer.enableDebugTriangleMode(true);
            renderer.setG04Sample(true, true, "triangle");
        } else if (g04Scene) {
            renderer.enableDebugTriangleMode(false);
            renderer.setG04Sample(true, false, "scene");
        } else if (g04Terrain || terrain) {
            renderer.enableDebugTriangleMode(false);
            if (g04Terrain) {
                renderer.setG04Sample(true, true, "terrain");
            }
        }
        
        // Create game loop
        GameLoop gameLoop(window, renderer, worldforge, seed, biome);
        
        // Run main loop
        gameLoop.run();
        
        // Cleanup
        renderer.cleanup();
        window.cleanup();
        
        std::cout << "\nKartGib shutdown complete." << std::endl;
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "FATAL ERROR: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "FATAL ERROR: Unknown exception\n";
        return 2;
    }
}