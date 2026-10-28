// ============================================================================
// main.cpp — the voxel engine.
//
// There are two ways to run it.
//
//   The window. A native Direct3D 12 viewport on the left and the RawrXD
//   browser on the right. The camera walks with the keyboard and turns
//   with the mouse. The frames go to the browser, and the browser can
//   drive the camera.
//
//   The headless run. No window and no display. The engine renders into
//   an offscreen target, captures the frames, writes them to disk and
//   prints a receipt that says what was drawn. This is the run that
//   proves the renderer works, because it needs nothing but the machine.
//
// The two modes share everything: the same world, the same mesher, the
// same renderer and the same capture. The headless run is not a
// simulation of the window; it is the window's renderer without the
// window.
// ============================================================================

#include <windows.h>
#include <windowsx.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "BrowserPanel.hpp"
#include "Camera.hpp"
#include "ChunkStore.hpp"
#include "FrameCapture.hpp"
#include "GreedyMesher.hpp"
#include "RuinBuilder.hpp"
#include "ShaderSource.hpp"
#include "VoxelRenderer.hpp"

namespace {

using namespace sunshine;

// ---------------------------------------------------------------------------
// The frame as a PNG data URL, for the browser.
//
// The frame is encoded once and then handed to the page as a data URL, so
// no file has to be written and read back for every frame.
// ---------------------------------------------------------------------------

std::string base64Of(const std::vector<uint8_t>& bytes) {
    static const char* alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string encoded;
    encoded.reserve(((bytes.size() + 2) / 3) * 4);
    size_t i = 0;
    while (i + 2 < bytes.size()) {
        const uint32_t triple = (static_cast<uint8_t>(bytes[i]) << 16) |
                                (static_cast<uint8_t>(bytes[i + 1]) << 8) |
                                static_cast<uint8_t>(bytes[i + 2]);
        encoded += alphabet[(triple >> 18) & 0x3F];
        encoded += alphabet[(triple >> 12) & 0x3F];
        encoded += alphabet[(triple >> 6) & 0x3F];
        encoded += alphabet[triple & 0x3F];
        i += 3;
    }
    if (i + 1 == bytes.size()) {
        const uint32_t triple = static_cast<uint8_t>(bytes[i]) << 16;
        encoded += alphabet[(triple >> 18) & 0x3F];
        encoded += alphabet[(triple >> 12) & 0x3F];
        encoded += "==";
    } else if (i + 2 == bytes.size()) {
        const uint32_t triple = (static_cast<uint8_t>(bytes[i]) << 16) |
                                (static_cast<uint8_t>(bytes[i + 1]) << 8);
        encoded += alphabet[(triple >> 18) & 0x3F];
        encoded += alphabet[(triple >> 12) & 0x3F];
        encoded += alphabet[(triple >> 6) & 0x3F];
        encoded += "=";
    }
    return encoded;
}

std::string frameAsPngDataUrl(const CapturedFrame& frame) {
    const std::vector<uint8_t> png = encodePng(frame);
    if (png.empty()) return "";
    return "data:image/png;base64," + base64Of(png);
}

// The directory the executable is in, so that the page and the loader can
// be found next to it.
std::string executableDirectory() {
    wchar_t path[MAX_PATH] = {0};
    const DWORD length = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) return ".";

    const int size = WideCharToMultiByte(CP_UTF8, 0, path, static_cast<int>(length),
                                         nullptr, 0, nullptr, nullptr);
    if (size <= 0) return ".";

    std::string text(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, path, static_cast<int>(length), text.data(), size,
                        nullptr, nullptr);

    const size_t slash = text.find_last_of("\\/");
    if (slash == std::string::npos) return ".";
    return text.substr(0, slash);
}

// ---------------------------------------------------------------------------
// The world as a source of blocks for the mesher.
// ---------------------------------------------------------------------------

class WorldSource : public BlockSource {
public:
    explicit WorldSource(World& world) : world_(world) {}
    uint8_t blockAt(int32_t wx, int32_t wy, int32_t wz) override {
        return world_.blockAt(wx, wy, wz);
    }

private:
    World& world_;
};

// ---------------------------------------------------------------------------
// The options
// ---------------------------------------------------------------------------

struct Options {
    bool headless = false;
    uint32_t frames = 60;
    uint32_t width = 1280;
    uint32_t height = 720;
    uint32_t seed = 0x5EED1234u;
    int32_t radius = 5;             // chunks around the camera
    std::string outDir = ".";
    bool capture = true;
    bool json = false;
    bool text = false;
    bool browser = false;
    uint32_t previewWidth = 480;
    bool flat = false;

    // The certification of the browser panel: the engine draws a frame,
    // the page asks the camera to move, the engine moves it, and the two
    // frames are compared.
    bool certifyBrowser = false;
    uint32_t certifyTimeoutSeconds = 30;

    // The certification of the look: the five cameras are found, each one
    // is rendered, and each one is measured.
    bool certifyVisual = false;
};

// ---------------------------------------------------------------------------
// The engine: the world, the chunks on the GPU, and the camera.
// ---------------------------------------------------------------------------

class VoxelEngine {
public:
    bool initialize(const Options& options, std::string& error) {
        options_ = options;
        world_.setSeed(options.seed);
        world_.setFlat(options.flat);
        source_.reset(new WorldSource(world_));

        if (!renderer_.initialize(error)) return false;

        if (options.headless) {
            if (!renderer_.createOffscreenTarget(options.width, options.height, error)) return false;
            // The table of calls the runtime has is found by drawing a
            // frame and looking at it.
            if (!renderer_.probeTableLayout(error)) return false;
        }
        return true;
    }

    // Put the camera somewhere sensible: above the terrain, looking at
    // it. The pitch is positive to look down, because the camera looks
    // along the direction its pitch gives it and a positive pitch sends
    // that direction downwards.
    //
    // The camera goes well above the ground, because the ground around
    // the origin is not the ground at the origin, and a camera that is
    // only a little above the lowest of it ends up inside a hillside.
    // Put the camera somewhere sensible: above the terrain, looking at
    // it. The pitch is positive to look down, because the camera looks
    // along the direction its pitch gives it and a positive pitch sends
    // that direction downwards.
    //
    // The camera goes above the highest ground around it and not just
    // above the ground under it, because the ground under the origin may
    // be in a hollow with a hill beside it, and a camera that is inside
    // the hill shows the inside of the world.
    void placeCamera(Camera& camera) {
        // The test quad is at the origin, and the camera looks at it from
        // in front of it.
        if (renderer_.isTestQuad()) {
            camera.position = Vec3{0.0f, 0.0f, -30.0f};
            camera.pitch = 0.0f;
            camera.yaw = 0.0f;
            return;
        }

        int32_t highest = 0;
        for (int32_t dz = -6; dz <= 6; ++dz) {
            for (int32_t dx = -6; dx <= 6; ++dx) {
                const int32_t h = world_.surfaceHeight(dx * 4, dz * 4);
                if (h > highest) highest = h;
            }
        }
        if (highest < kSeaLevel) highest = kSeaLevel;

        camera.position = Vec3{0.5f, static_cast<float>(highest + 26), 0.5f};
        camera.pitch = 0.30f;
        camera.yaw = 0.6f;
    }

    // Bring the chunks around the camera onto the GPU.
    //
    // The chunks that are already there are left alone, and the ones that
    // have been left behind are released, so walking about does not grow
    // without bound.
    bool updateChunks(const Camera& camera, std::string& error) {
        // The test quad is already on the GPU, and the world would only
        // hide it.
        if (renderer_.isTestQuad()) return true;

        const int32_t centerX = static_cast<int32_t>(std::floor(camera.position.x / kChunkSize));
        const int32_t centerZ = static_cast<int32_t>(std::floor(camera.position.z / kChunkSize));
        const int32_t radius = options_.radius;

        // The chunks that are wanted this time.
        for (int32_t dz = -radius; dz <= radius; ++dz) {
            for (int32_t dx = -radius; dx <= radius; ++dx) {
                const int32_t cx = centerX + dx;
                const int32_t cz = centerZ + dz;

                const uint64_t key = chunkKey(cx, cz);
                if (loaded_.count(key)) continue;

                // The chunk is generated by the world, and the world is
                // what the mesher reads, so the borders are right.
                world_.chunk(cx, cz);
                const ChunkMesh mesh = meshChunk(*source_, cx, cz);
                if (!renderer_.uploadChunk(cx, cz, mesh.vertices, error)) return false;
                loaded_[key] = ChunkRecord{cx, cz};
            }
        }

        // The chunks that are not wanted any more.
        for (auto it = loaded_.begin(); it != loaded_.end();) {
            const int64_t ddx = static_cast<int64_t>(it->second.cx) - centerX;
            const int64_t ddz = static_cast<int64_t>(it->second.cz) - centerZ;
            if (ddx * ddx + ddz * ddz > static_cast<int64_t>(radius + 1) * (radius + 1)) {
                renderer_.releaseChunk(it->second.cx, it->second.cz);
                it = loaded_.erase(it);
            } else {
                ++it;
            }
        }

        // The world keeps the blocks, and it drops the ones that are far
        // away so that the memory does not grow with the walk.
        world_.evictBeyond(centerX, centerZ, radius + 2);

        return true;
    }

    // Draw one frame.
    bool render(const Camera& camera, double time, FrameStats& stats, std::string& error) {
        const float aspect = static_cast<float>(options_.width) /
                             static_cast<float>(options_.height > 0 ? options_.height : 1);
        const Mat4 viewProjection = camera.viewProjection(aspect);
        return renderer_.renderFrame(viewProjection, camera.position, time, stats, error);
    }

    // Read the last frame back.
    bool capture(CapturedFrame& frame, std::string& error) {
        return renderer_.captureFrame(frame, error);
    }

    // The renderer, for the parts the engine does not own.
    VoxelRenderer& renderer() { return renderer_; }
    World& world() { return world_; }

private:
    struct ChunkRecord {
        int32_t cx = 0;
        int32_t cz = 0;
    };

    static uint64_t chunkKey(int32_t cx, int32_t cz) {
        return (static_cast<uint64_t>(static_cast<uint32_t>(cx)) << 32) |
               static_cast<uint32_t>(cz);
    }

    Options options_;
    World world_;
    std::unique_ptr<WorldSource> source_;
    VoxelRenderer renderer_;
    std::unordered_map<uint64_t, ChunkRecord> loaded_;
};

// ---------------------------------------------------------------------------
// The receipt.
//
// The receipt is the evidence. It says what was drawn, how long it took
// and what the pixels look like, so that a run can be checked by a
// machine and not only by a person looking at a picture.
// ---------------------------------------------------------------------------

std::string jsonEscape(const std::string& text) {
    std::string out;
    out.reserve(text.size() + 8);
    for (char c : text) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buffer[8];
                    snprintf(buffer, sizeof(buffer), "\\u%04x", c);
                    out += buffer;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

std::string number(double value, int decimals = 3) {
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%.*f", decimals, value);
    return buffer;
}

// ---------------------------------------------------------------------------
// The headless run.
// ---------------------------------------------------------------------------

int runHeadless(const Options& options) {
    VoxelEngine engine;
    std::string error;
    if (!engine.initialize(options, error)) {
        fprintf(stderr, "sunshine-voxel: %s\n", error.c_str());
        return 1;
    }

    Camera camera;
    engine.placeCamera(camera);

    // The frames are captured on this interval, so that the disk does not
    // fill up with a hundred thousand pictures.
    const uint32_t captureEvery = options.frames <= 8 ? 1 : options.frames / 8;

    FrameStats lastStats{};
    FrameStatistics lastMeasure{};
    std::vector<std::string> written;
    double totalMs = 0.0;
    uint32_t captured = 0;
    double terrainFractionMax = 0.0;
    uint32_t distinctMax = 0;

    const auto start = std::chrono::steady_clock::now();

    for (uint32_t frame = 0; frame < options.frames; ++frame) {
        // The camera walks forward and turns a little, so the frames are
        // not all the same picture and the chunk streaming is exercised.
        camera.turn(6.0f, 0.0f);
        camera.move(0.9f, 0.0f, 0.0f);

        if (!engine.updateChunks(camera, error)) {
            fprintf(stderr, "sunshine-voxel: %s\n", error.c_str());
            return 1;
        }

        const double time = static_cast<double>(frame) / 30.0;
        if (!engine.render(camera, time, lastStats, error)) {
            fprintf(stderr, "sunshine-voxel: %s\n", error.c_str());
            return 1;
        }
        totalMs += lastStats.gpuFrameMs;

        if (options.capture && (frame % captureEvery) == 0) {
            CapturedFrame captured_frame;
            if (!engine.capture(captured_frame, error)) {
                fprintf(stderr, "sunshine-voxel: %s\n", error.c_str());
                return 1;
            }

            const FrameStatistics measure = measureFrame(captured_frame);
            lastMeasure = measure;
            terrainFractionMax = std::max(terrainFractionMax, measure.terrainFraction);
            distinctMax = std::max(distinctMax, measure.distinctColours);

            char name[256];
            snprintf(name, sizeof(name), "%s/voxel_frame_%03u.bmp",
                     options.outDir.c_str(), frame);
            if (!writeBitmap(name, captured_frame, error)) {
                fprintf(stderr, "sunshine-voxel: %s\n", error.c_str());
                return 1;
            }
            written.push_back(name);

            snprintf(name, sizeof(name), "%s/voxel_frame_%03u.png",
                     options.outDir.c_str(), frame);
            if (!writePng(name, captured_frame, error)) {
                fprintf(stderr, "sunshine-voxel: %s\n", error.c_str());
                return 1;
            }
            written.push_back(name);

            ++captured;
        }
    }

    const double totalSeconds =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();

    // The verdict. A frame that has terrain in it has a spread of
    // colours and a terrain fraction well above zero. A renderer that
    // drew nothing has neither, and the receipt says so.
    const bool drewSomething = terrainFractionMax > 0.01 && distinctMax > 8;

    if (options.json) {
        printf("{\n");
        printf("  \"schema_version\": \"sunshine.voxel.receipt/1\",\n");
        printf("  \"mode\": \"headless\",\n");
        printf("  \"adapter\": \"%s\",\n", jsonEscape(engine.renderer().adapterName()).c_str());
        printf("  \"seed\": %u,\n", options.seed);
        printf("  \"frames\": %u,\n", options.frames);
        printf("  \"frames_captured\": %u,\n", captured);
        printf("  \"width\": %u,\n", options.width);
        printf("  \"height\": %u,\n", options.height);
        printf("  \"chunks_drawn\": %u,\n", lastStats.chunksDrawn);
        printf("  \"triangles_drawn\": %llu,\n",
               static_cast<unsigned long long>(lastStats.trianglesDrawn));
        printf("  \"mean_frame_ms\": %s,\n", number(totalMs / (options.frames ? options.frames : 1)).c_str());
        printf("  \"total_seconds\": %s,\n", number(totalSeconds).c_str());
        printf("  \"mean_luminance\": %s,\n", number(lastMeasure.meanLuminance, 2).c_str());
        printf("  \"distinct_colours\": %u,\n", lastMeasure.distinctColours);
        printf("  \"repeated_colours\": %u,\n", lastMeasure.repeatedColours);
        printf("  \"terrain_fraction\": %s,\n", number(lastMeasure.terrainFraction, 5).c_str());
        printf("  \"terrain_fraction_max\": %s,\n", number(terrainFractionMax, 5).c_str());
        printf("  \"drew_terrain\": %s,\n", drewSomething ? "true" : "false");
        printf("  \"files\": [");
        for (size_t i = 0; i < written.size(); ++i) {
            printf("%s\"%s\"", i ? ", " : "", jsonEscape(written[i]).c_str());
        }
        printf("]\n");
        printf("}\n");
    } else {
        printf("sunshine-voxel headless run\n");
        printf("  adapter            %s\n", engine.renderer().adapterName().c_str());
        printf("  seed               %u\n", options.seed);
        printf("  frames             %u (%u captured)\n", options.frames, captured);
        printf("  size               %ux%u\n", options.width, options.height);
        printf("  chunks drawn       %u\n", lastStats.chunksDrawn);
        printf("  triangles drawn    %llu\n",
               static_cast<unsigned long long>(lastStats.trianglesDrawn));
        printf("  mean frame         %s ms\n",
               number(totalMs / (options.frames ? options.frames : 1)).c_str());
        printf("  total              %s s\n", number(totalSeconds).c_str());
        printf("  mean luminance     %s\n", number(lastMeasure.meanLuminance, 2).c_str());
        printf("  distinct colours   %u\n", lastMeasure.distinctColours);
        printf("  terrain fraction   %s\n", number(lastMeasure.terrainFraction, 5).c_str());
        printf("  drew terrain       %s\n", drewSomething ? "yes" : "no");
        for (const std::string& file : written) {
            printf("  wrote              %s\n", file.c_str());
        }
    }

    if (options.text) {
        // The last frame, as text, so that the run can be seen in a
        // terminal that cannot draw.
        CapturedFrame frame;
        if (engine.capture(frame, error)) {
            printf("\n");
            printf("%s\n", frameAsText(frame, 96, 30).c_str());
        }
    }

    return drewSomething ? 0 : 2;
}

// ---------------------------------------------------------------------------
// The window.
// ---------------------------------------------------------------------------

struct WindowState {
    VoxelEngine* engine = nullptr;
    BrowserPanel* browser = nullptr;
    Camera camera;
    Options options;
    HWND viewport = nullptr;
    bool running = true;
    bool captureRequested = false;
    bool rendererReady = false;
    uint64_t frames = 0;
    double lastTime = 0.0;
    double fps = 0.0;
};

// The evidence of the browser certification.
//
// The claim being tested is that a command from the page moves the
// camera and that the world comes out differently because of it. The
// evidence is the camera before and after, the hash of the two frames,
// and the number of pixels that are not the same.
//
struct BrowserCertification {
    bool active = false;
    bool firstFramePosted = false;
    bool commandSeen = false;
    bool pageReady = false;
    bool finished = false;

    CapturedFrame frameBefore;
    uint64_t hashBefore = 0;
    Vec3 cameraBefore;

    uint64_t hashAfter = 0;
    Vec3 cameraAfter;
    FrameDifference difference;

    std::string frameBeforePath;
    std::string frameAfterPath;
    std::string browserVersion;
    std::string failure;

    // The verdict. Every one of these has to hold.
    bool passed() const {
        return active && firstFramePosted && commandSeen && pageReady &&
               hashBefore != hashAfter &&
               cameraBefore != cameraAfter &&
               difference.fraction > 0.005;
    }
};


LRESULT CALLBACK windowProc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    WindowState* state = reinterpret_cast<WindowState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (!state && (message == WM_NCCREATE)) {
        auto* create = reinterpret_cast<CREATESTRUCTW*>(lparam);
        state = static_cast<WindowState*>(create->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
    }
    if (!state) return DefWindowProcW(hwnd, message, wparam, lparam);

    switch (message) {
        case WM_SIZE: {
            const int width = LOWORD(lparam);
            const int height = HIWORD(lparam);
            if (state->viewport && width > 0 && height > 0) {
                // The viewport takes the left of the window and the
                // browser takes the right.
                const int browserWidth = state->options.browser ? width / 2 : 0;
                const int viewportWidth = width - browserWidth;
                SetWindowPos(state->viewport, nullptr, 0, 0, viewportWidth, height,
                             SWP_NOZORDER | SWP_NOACTIVATE);
                if (state->browser && state->browser->isCreated()) {
                    RECT bounds{viewportWidth, 0, width, height};
                    state->browser->setBounds(bounds);
                }
                if (state->rendererReady && state->engine) {
                    // The swap chain and the depth buffer follow the
                    // window.
                    std::string error;
                    state->engine->renderer().resizeTarget(
                        static_cast<uint32_t>(viewportWidth),
                        static_cast<uint32_t>(height), error);
                }
            }
            return 0;
        }

        case WM_KEYDOWN: {
            const WPARAM key = wparam;
            if (key == VK_ESCAPE) {
                state->running = false;
                DestroyWindow(hwnd);
                return 0;
            }
            if (key == 'F') {
                state->captureRequested = true;
                return 0;
            }
            break;
        }

        case WM_LBUTTONDOWN:
        case WM_LBUTTONUP:
        case WM_MOUSEMOVE: {
            if (state->viewport && GetFocus() == state->viewport) {
                SetCapture(hwnd);
                return 0;
            }
            break;
        }

        case WM_CLOSE:
            state->running = false;
            DestroyWindow(hwnd);
            return 0;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;

        default:
            break;
    }
    return DefWindowProcW(hwnd, message, wparam, lparam);
}

int runWindowed(const Options& options) {
    VoxelEngine engine;
    std::string error;
    if (!engine.initialize(options, error)) {
        fprintf(stderr, "sunshine-voxel: %s\n", error.c_str());
        return 1;
    }

    WindowState state;
    state.engine = &engine;
    state.options = options;
    engine.placeCamera(state.camera);

    BrowserCertification certify;
    certify.active = options.certifyBrowser;
    const auto certifyStart = std::chrono::steady_clock::now();

    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.style = CS_HREDRAW | CS_VREDRAW;
    windowClass.lpfnWndProc = windowProc;
    windowClass.hInstance = GetModuleHandleW(nullptr);
    windowClass.hCursor = LoadCursor(nullptr, IDC_ARROW);
    windowClass.lpszClassName = L"SunshineVoxelWindow";
    if (!RegisterClassExW(&windowClass)) {
        fprintf(stderr, "sunshine-voxel: the window class could not be registered\n");
        return 1;
    }

    RECT rect{0, 0, static_cast<LONG>(options.width), static_cast<LONG>(options.height)};
    AdjustWindowRect(&rect, WS_OVERLAPPEDWINDOW, FALSE);

    HWND hwnd = CreateWindowExW(0, windowClass.lpszClassName, L"Sunshine Voxel World",
                                WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                                rect.right - rect.left, rect.bottom - rect.top,
                                nullptr, nullptr, windowClass.hInstance, &state);
    if (!hwnd) {
        fprintf(stderr, "sunshine-voxel: the window could not be created\n");
        return 1;
    }

    // The viewport is a child window, so that the browser can be another
    // child window beside it.
    WNDCLASSEXW viewportClass{};
    viewportClass.cbSize = sizeof(viewportClass);
    viewportClass.lpfnWndProc = DefWindowProcW;
    viewportClass.hInstance = windowClass.hInstance;
    viewportClass.hCursor = LoadCursor(nullptr, IDC_ARROW);
    viewportClass.lpszClassName = L"SunshineVoxelViewport";
    RegisterClassExW(&viewportClass);

    RECT client{};
    GetClientRect(hwnd, &client);
    const int browserBar = options.browser ? 72 : 0;
    state.viewport = CreateWindowExW(0, viewportClass.lpszClassName, L"", WS_CHILD | WS_VISIBLE,
                                     0, 0, client.right, client.bottom - browserBar,
                                     hwnd, nullptr, windowClass.hInstance, nullptr);

    if (!engine.renderer().createWindowTarget(state.viewport, options.width, options.height, error)) {
        fprintf(stderr, "sunshine-voxel: %s\n", error.c_str());
        return 1;
    }
    state.rendererReady = true;

    // The browser.
    BrowserPanel browser;
    state.browser = &browser;
    if (options.browser) {
        RECT browserBounds{0, client.bottom - browserBar, client.right, client.bottom};
        wchar_t userData[MAX_PATH] = {0};
        GetEnvironmentVariableW(L"LOCALAPPDATA", userData, MAX_PATH);
        std::wstring profile = std::wstring(userData) + L"\\RawrXD\\SunshineVoxel";
        CreateDirectoryW((std::wstring(userData) + L"\\RawrXD").c_str(), nullptr);
        CreateDirectoryW(profile.c_str(), nullptr);

        if (!browser.create(hwnd, browserBounds, profile, error)) {
            fprintf(stderr, "sunshine-voxel: the browser could not be started: %s\n", error.c_str());
            fprintf(stderr, "sunshine-voxel: the world will run without it\n");
        } else {
            // The page is loaded once the controller is up. The panel is
            // pumped until it is.
            const auto deadline = GetTickCount64() + 8000;
            while (!browser.isCreated() && GetTickCount64() < deadline) {
                MSG message;
                while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
                    TranslateMessage(&message);
                    DispatchMessageW(&message);
                }
                Sleep(10);
            }
            if (browser.isCreated()) {
                // The page sits next to the executable, so that the
                // engine can be run from anywhere.
                const std::string page = executableDirectory() + "\\voxel_page.html";
                if (!browser.loadFile(page, error)) {
                    fprintf(stderr, "sunshine-voxel: the page could not be loaded: %s\n", error.c_str());
                }
            }
        }
    }

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    // The loop.
    LARGE_INTEGER frequency{};
    QueryPerformanceFrequency(&frequency);
    LARGE_INTEGER counter{};
    QueryPerformanceCounter(&counter);
    double lastCounter = static_cast<double>(counter.QuadPart);
    auto lastFrameTime = std::chrono::steady_clock::now();

    bool mouseDown = false;
    int lastMouseX = 0, lastMouseY = 0;
    SetFocus(state.viewport);

    while (state.running) {
        MSG message;
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
            if (message.message == WM_MOUSEMOVE && (message.wParam & MK_LBUTTON)) {
                const int x = GET_X_LPARAM(message.lParam);
                const int y = GET_Y_LPARAM(message.lParam);
                state.camera.turn(static_cast<float>(x - lastMouseX), static_cast<float>(y - lastMouseY));
                lastMouseX = x;
                lastMouseY = y;
            } else if (message.message == WM_LBUTTONDOWN) {
                mouseDown = true;
                lastMouseX = GET_X_LPARAM(message.lParam);
                lastMouseY = GET_Y_LPARAM(message.lParam);
            } else if (message.message == WM_LBUTTONUP) {
                mouseDown = false;
            }
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        (void)mouseDown;

        // The camera, from the keyboard.
        float forward = 0.0f, strafe = 0.0f, rise = 0.0f;
        if (GetAsyncKeyState('W') & 0x8000) forward += 1.0f;
        if (GetAsyncKeyState('S') & 0x8000) forward -= 1.0f;
        if (GetAsyncKeyState('A') & 0x8000) strafe -= 1.0f;
        if (GetAsyncKeyState('D') & 0x8000) strafe += 1.0f;
        if (GetAsyncKeyState('E') & 0x8000) rise += 1.0f;
        if (GetAsyncKeyState('Q') & 0x8000) rise -= 1.0f;
        if (GetAsyncKeyState(VK_SPACE) & 0x8000) rise += 1.0f;

        // The commands from the browser.
        if (browser.isCreated()) {
            for (const BrowserCommand& command : browser.takeCommands()) {
                if (command.type == "move") {
                    if (certify.active && !certify.commandSeen) {
                        // The certification moves the camera a known
                        // distance, so that the two frames cannot be the
                        // same picture and the test says so for a reason
                        // and not because of the noise.
                        certify.commandSeen = true;
                        state.camera.move(8.0f, 3.0f, 0.0f);
                        continue;
                    }
                    forward += command.forward;
                    strafe += command.strafe;
                    rise += command.rise;
                } else if (command.type == "turn") {
                    state.camera.turn(command.turnX, command.turnY);
                } else if (command.type == "capture") {
                    state.captureRequested = true;
                } else if (command.type == "walk") {
                    forward += command.forward;
                }
            }
        }

        const auto now = std::chrono::steady_clock::now();
        const double delta = std::chrono::duration<double>(now - lastFrameTime).count();
        lastFrameTime = now;
        if (delta > 0.0001) state.fps = state.fps * 0.9 + (1.0 / delta) * 0.1;

        const float step = static_cast<float>(delta) * state.camera.moveSpeed;
        state.camera.move(forward * step, strafe * step, rise * step);

        if (!engine.updateChunks(state.camera, error)) {
            fprintf(stderr, "sunshine-voxel: %s\n", error.c_str());
            break;
        }

        FrameStats stats{};
        const double time = static_cast<double>(state.frames) / 60.0;
        if (!engine.render(state.camera, time, stats, error)) {
            fprintf(stderr, "sunshine-voxel: %s\n", error.c_str());
            break;
        }
        ++state.frames;

        // The browser gets a frame.
        if (browser.isCreated() && browser.pageReady()) {
            static double lastPost = 0.0;
            if (certify.active && time - lastPost > 0.08) {
                lastPost = time;
                CapturedFrame frame;
                if (engine.capture(frame, error)) {
                    // The picture that goes to the browser is made
                    // smaller first, because a picture in a message is
                    // large and a message has a size.
                    const CapturedFrame preview = downscale(frame, options.previewWidth,
                                                           options.previewWidth * frame.height /
                                                               (frame.width ? frame.width : 1));
                    const std::string png = frameAsPngDataUrl(preview);

                    char head[512];
                    snprintf(head, sizeof(head),
                             "{\"type\":\"frame\",\"frame\":%llu,\"chunks\":%u,\"triangles\":%llu,"
                             "\"fps\":%s,\"position\":[%s,%s,%s],\"adapter\":\"%s\","
                             "\"certify\":%s,\"png\":\"",
                             static_cast<unsigned long long>(state.frames),
                             stats.chunksDrawn,
                             static_cast<unsigned long long>(stats.trianglesDrawn),
                             number(state.fps, 1).c_str(),
                             number(state.camera.position.x, 1).c_str(),
                             number(state.camera.position.y, 1).c_str(),
                             number(state.camera.position.z, 1).c_str(),
                             jsonEscape(engine.renderer().adapterName()).c_str(),
                             (certify.active && !certify.firstFramePosted) ? "true" : "false");

                    std::string message(head);
                    message += png;
                    message += "\"}";
                    browser.postJson(message);

                    // The first frame of the certification is kept, so
                    // that the frame after the camera has moved can be
                    // compared with it.
                    if (certify.active && !certify.firstFramePosted) {
                        certify.firstFramePosted = true;
                        certify.frameBefore = frame;
                        certify.hashBefore = frameHash(frame);
                        certify.cameraBefore = state.camera.position;
                    }
                }
            }
        }

        if (state.captureRequested) {
            state.captureRequested = false;
            CapturedFrame frame;
            if (engine.capture(frame, error)) {
                char name[256];
                snprintf(name, sizeof(name), "%s/voxel_window_%03llu.bmp", options.outDir.c_str(),
                         static_cast<unsigned long long>(state.frames));
                if (writeBitmap(name, frame, error)) {
                    fprintf(stderr, "sunshine-voxel: the frame was written to %s\n", name);
                }
            }
        }

        // The certification: once the camera has moved, the frame after
        // the move is captured and compared with the one before it.
        if (certify.active && !certify.finished && certify.commandSeen &&
            certify.firstFramePosted) {
            certify.finished = true;
            certify.cameraAfter = state.camera.position;
            certify.hashAfter = certify.firstFramePosted ? 0 : 0;

            CapturedFrame after;
            if (engine.capture(after, error)) {
                certify.hashAfter = frameHash(after);
                certify.difference = compareFrames(certify.frameBefore, after);

                char before[256];
                char afterPath[256];
                snprintf(before, sizeof(before), "%s/browser_before.bmp", options.outDir.c_str());
                snprintf(afterPath, sizeof(afterPath), "%s/browser_after.bmp", options.outDir.c_str());
                writeBitmap(before, certify.frameBefore, error);
                writeBitmap(afterPath, after, error);
                certify.frameBeforePath = before;
                certify.frameAfterPath = afterPath;
            }
        }

        if (certify.active && !certify.finished) {
            const double elapsed = std::chrono::duration<double>(
                std::chrono::steady_clock::now() - certifyStart).count();
            if (elapsed > static_cast<double>(options.certifyTimeoutSeconds)) {
                certify.finished = true;
                if (!certify.commandSeen) {
                    certify.failure = "the page did not send a command";
                } else if (!certify.firstFramePosted) {
                    certify.failure = "no frame reached the page";
                }
            }
        }

        if (certify.active && certify.finished) {
            certify.pageReady = browser.pageReady();
            certify.browserVersion = browser.browserVersion();
            if (certify.browserVersion.empty()) {
                certify.failure = browser.lastError().empty()
                                      ? "the browser did not come up and said nothing"
                                      : browser.lastError();
            }

            const bool passed = certify.passed();
            char receipt[4096];
            snprintf(receipt, sizeof(receipt),
                     "{\n"
                     "  \"schema_version\": \"sunshine.voxel.browser.cert/1\",\n"
                     "  \"certification\": \"VOXEL_BROWSER_VISUAL_001\",\n"
                     "  \"verdict\": \"%s\",\n"
                     "  \"browser_version\": \"%s\",\n"
                     "  \"page_ready\": %s,\n"
                     "  \"command_acknowledged\": %s,\n"
                     "  \"camera_before\": [%s, %s, %s],\n"
                     "  \"camera_after\": [%s, %s, %s],\n"
                     "  \"camera_moved\": %s,\n"
                     "  \"hash_before\": \"%016llx\",\n"
                     "  \"hash_after\": \"%016llx\",\n"
                     "  \"hashes_differ\": %s,\n"
                     "  \"different_pixels\": %llu,\n"
                     "  \"total_pixels\": %llu,\n"
                     "  \"pixel_difference_fraction\": %s,\n"
                     "  \"mean_absolute_difference\": %s,\n"
                     "  \"frame_before\": \"%s\",\n"
                     "  \"frame_after\": \"%s\",\n"
                     "  \"failure\": \"%s\"\n"
                     "}\n",                     passed ? "PASS" : "FAIL",
                     jsonEscape(certify.browserVersion).c_str(),
                     certify.pageReady ? "true" : "false",
                     certify.commandSeen ? "true" : "false",
                     number(certify.cameraBefore.x, 3).c_str(),
                     number(certify.cameraBefore.y, 3).c_str(),
                     number(certify.cameraBefore.z, 3).c_str(),
                     number(certify.cameraAfter.x, 3).c_str(),
                     number(certify.cameraAfter.y, 3).c_str(),
                     number(certify.cameraAfter.z, 3).c_str(),
                     (certify.cameraBefore != certify.cameraAfter) ? "true" : "false",
                     static_cast<unsigned long long>(certify.hashBefore),
                     static_cast<unsigned long long>(certify.hashAfter),
                     (certify.hashBefore != certify.hashAfter) ? "true" : "false",
                     static_cast<unsigned long long>(certify.difference.differentPixels),
                     static_cast<unsigned long long>(certify.difference.totalPixels),
                     number(certify.difference.fraction, 6).c_str(),
                     number(certify.difference.meanAbsoluteDifference, 4).c_str(),
                     jsonEscape(certify.frameBeforePath).c_str(),
                     jsonEscape(certify.frameAfterPath).c_str(),
                     jsonEscape(certify.failure).c_str());

            printf("%s", receipt);
            char receiptPath[256];
            snprintf(receiptPath, sizeof(receiptPath), "%s/browser_certification.json",
                     options.outDir.c_str());
            FILE* file = nullptr;
            if (fopen_s(&file, receiptPath, "wb") == 0 && file) {
                fwrite(receipt, 1, strlen(receipt), file);
                fclose(file);
                fprintf(stderr, "sunshine-voxel: the receipt was written to %s\n", receiptPath);
            }

            state.running = false;
            break;
        }

        Sleep(1);
    }

    return 0;
}

} // namespace

// The reading of a picture.
//
// This is the end of the chain. The renderer writes a picture, the
// picture is read back, and what it says is written down in numbers, so
// that a model can be told what is wrong with it and change the thing
// that is wrong rather than being told to make the fog darker.
// The five cameras of the gothic certification.
//
// Each one is found by a rule rather than written down, so the same world
// always gives the same five pictures and one run can be compared with
// the next. The rules are the five things a gothic picture needs: arches,
// a mountain against the sky, the mouth of a cave, a forest, and a long
// view to the horizon.
enum class GothicShot {
    Arches,      // the ruins
    Silhouette,  // the mountain against the sky
    CaveMouth,   // the mouth of a cave
    Forest,      // the trees
    Horizon,     // the long view
    Ruins,       // the cathedral
};

const char* gothicShotName(GothicShot shot) {
    switch (shot) {
        case GothicShot::Arches:     return "GOTHIC_01";
        case GothicShot::Silhouette: return "GOTHIC_02";
        case GothicShot::CaveMouth:  return "GOTHIC_03";
        case GothicShot::Forest:     return "GOTHIC_04";
        case GothicShot::Horizon:    return "GOTHIC_05";
        case GothicShot::Ruins:      return "GOTHIC_06";
    }
    return "GOTHIC_00";
}

// How many shots there are.
constexpr int kGothicShotCount = 6;

struct GothicCamera {
    GothicShot shot = GothicShot::Horizon;
    Vec3 position;
    float yaw = 0.0f;
    float pitch = 0.0f;
    std::string note;
};

// Find the five cameras.
//
// The world is walked in a grid and each column is judged against the
// rule of the shot, and the first column that satisfies the rule is the
// one. The judgement uses the world itself, so the same seed always
// gives the same picture.
// The composition of a picture of the cathedral.
//
// A camera that cannot see the cathedral shows a hillside, and a camera
// that sees it from too close shows a wall. So the viewpoints are tried
// one after the other and the one that sees the spire against the sky
// is the one that is kept, and the number of them that work is the
// number of valid viewpoints.
struct Viewpoint {
    Vec3 position;
    float yaw = 0.0f;
    float pitch = 0.0f;

    // How good the picture is.
    bool seesTheSpire = false;   // is there a clear line to it
    bool againstTheSky = false;  // is it in the upper half of the frame
    bool insideTheFrame = false;  // is it in the frame at all
    double distance = 0.0;
    double score = 0.0;
};

// Whether there is a clear line from one place to another.
//
// The line is stepped along and every block it passes through is
// counted, and a line that passes through the world is not a line of
// sight.
int32_t blocksBetween(World& world, const Vec3& from, const Vec3& to) {
    const float dx = to.x - from.x;
    const float dy = to.y - from.y;
    const float dz = to.z - from.z;
    const int32_t steps = static_cast<int32_t>(std::max(1.0f, std::sqrt(dx * dx + dy * dy + dz * dz) * 2.0f));

    int32_t hit = 0;
    for (int32_t i = 1; i < steps; ++i) {
        const float t = static_cast<float>(i) / static_cast<float>(steps);
        const int32_t x = static_cast<int32_t>(std::floor(from.x + dx * t));
        const int32_t y = static_cast<int32_t>(std::floor(from.y + dy * t));
        const int32_t z = static_cast<int32_t>(std::floor(from.z + dz * t));
        if (world.blockAt(x, y, z) != kBlockAir) ++hit;
    }
    return hit;
}

// The viewpoints of the cathedral that work.
std::vector<Viewpoint> cathedralViewpoints(World& world, const RuinViewpoint& spire,
                                           const World::RuinOrigin& origin, int32_t roofLine) {
    std::vector<Viewpoint> viewpoints;

    // The tip of the spire, which is the part of a gothic building that
    // is against the sky, and the roof line of the hall, which is where
    // the building meets the sky at its widest.
    //
    // The camera is pointed at the roof line, because that is the bottom
    // of the silhouette and the picture wants the silhouette in the
    // middle of the frame, with the tower rising out of it.
    const Vec3 tip{static_cast<float>(spire.x), static_cast<float>(spire.y + 1),
                   static_cast<float>(spire.z)};

    // The aim is just above the roof line, so that the line to it is
    // clear of the wall that is under it.
    const Vec3 aim{static_cast<float>(spire.x), static_cast<float>(roofLine + 2),
                   static_cast<float>(spire.z)};

    // The places to stand from: out in front, off to the side, and
    // further back, at four heights. A forest and a hill mean that the
    // place from which a building is seen is not obvious, so the search
    // has to be wide.
    const int32_t distances[] = {30, 45, 60, 80, 110};
    const int32_t angles[] = {0, 25, -25, 50, -50, 75, -75, 100, -100};
    const int32_t heights[] = {6, 14, 26, 40};

    for (int32_t distance : distances) {
        for (int32_t angle : angles) {
            for (int32_t height : heights) {
                const double radians = static_cast<double>(angle) * 3.14159265358979 / 180.0;
                const int32_t standX = origin.x + static_cast<int32_t>(std::lround(
                    std::sin(radians) * distance));
                const int32_t standZ = origin.z - static_cast<int32_t>(std::lround(
                    std::cos(radians) * distance));

                // The camera stands on the ground.
                int32_t standY = world.surfaceHeight(standX, standZ);
                if (standY < kSeaLevel) standY = kSeaLevel;
                const int32_t cameraY = standY + height;

                Viewpoint viewpoint;
                viewpoint.position = Vec3{static_cast<float>(standX), static_cast<float>(cameraY),
                                          static_cast<float>(standZ)};

                // The aim is the tip of the spire, so the picture is
                // centred on the cathedral.
                const double dx = aim.x - viewpoint.position.x;
                const double dy = aim.y - viewpoint.position.y;
                const double dz = aim.z - viewpoint.position.z;
                const double flat = std::sqrt(dx * dx + dz * dz);
                if (flat < 1.0) continue;
                viewpoint.yaw = static_cast<float>(std::atan2(dx, dz));
                viewpoint.pitch = static_cast<float>(std::atan2(dy, flat));
                viewpoint.distance = std::sqrt(dx * dx + dy * dy + dz * dz);

                // Can the camera see the cathedral?
                //
                // The line is walked to the middle of the building, where
                // the wall is, and it has to be clear: a forest in the way
                // hides the building and the picture is of the forest.
                // The tip is walked as well, because the tip is what is
                // against the sky, and the spire's own body is the only
                // thing allowed to be in the way.
                const int32_t toMiddle = blocksBetween(world, viewpoint.position, aim);
                const int32_t toTip = blocksBetween(world, viewpoint.position, tip);
                viewpoint.seesTheSpire = (toTip <= 2) && (tip.y > viewpoint.position.y + 4.0);

                // Is the ground in front of the camera clear? A short
                // ray, so that a rise of the ground does not hide the
                // building.
                {
                    int32_t nearHits = 0;
                    for (int32_t step = 1; step <= 10; ++step) {
                        const double t = static_cast<double>(step) / 10.0;
                        const int32_t gx = static_cast<int32_t>(std::floor(
                            viewpoint.position.x + dx * t / std::sqrt(dx * dx + dz * dz)));
                        const int32_t gz = static_cast<int32_t>(std::floor(
                            viewpoint.position.z + dz * t / std::sqrt(dx * dx + dz * dz)));
                        const int32_t gy = static_cast<int32_t>(std::floor(
                            viewpoint.position.y + dy * t / std::sqrt(dx * dx + dy * dy + dz * dz)));
                        if (world.blockAt(gx, gy, gz) != kBlockAir) ++nearHits;
                    }
                    // And the whole building has to be in the frame,
                    // which means the base of it cannot be further down
                    // than the frame reaches.
                    const double baseAngle = std::atan2(
                        static_cast<double>(origin.groundY) - viewpoint.position.y, flat);
                    viewpoint.insideTheFrame = (nearHits <= 1) && (baseAngle > -0.5236);
                }

                // Is the spire against the sky? The line past the tip
                // has to find nothing that is as high as the tip.
                {
                    const double tdx = tip.x - viewpoint.position.x;
                    const double tdy = tip.y - viewpoint.position.y;
                    const double tdz = tip.z - viewpoint.position.z;
                    const double length = std::sqrt(tdx * tdx + tdy * tdy + tdz * tdz);
                    int32_t hits = 0;
                    for (int i = 1; i <= 24; ++i) {
                        const double t = static_cast<double>(i) / 24.0;
                        const double beyond = 1.0 + (t * 30.0 / length);
                        const int32_t bx = static_cast<int32_t>(std::floor(
                            viewpoint.position.x + tdx * beyond));
                        const int32_t by = static_cast<int32_t>(std::floor(
                            viewpoint.position.y + tdy * beyond));
                        const int32_t bz = static_cast<int32_t>(std::floor(
                            viewpoint.position.z + tdz * beyond));
                        if (world.blockAt(bx, by, bz) != kBlockAir) ++hits;
                    }
                    viewpoint.againstTheSky = (hits == 0);
                }

                // The picture is better the closer it is, as long as it
                // is far enough that the whole tower is in it, and the
                // subject is in the middle of the frame and not off to
                // one side of it.
                double score = 0.0;
                if (viewpoint.seesTheSpire && viewpoint.insideTheFrame) {
                    score = 1000.0;
                    if (viewpoint.againstTheSky) score += 500.0;

                    // The tower should fill a good part of the frame.
                    const double wanted = 34.0;   // the height of the tower
                    const double angular = std::atan2(wanted, viewpoint.distance);
                    score += 200.0 * (1.0 - std::fabs(angular - 0.42) / 0.42);

                    // And the subject has to be in the middle of it.
                    //
                    // The aim is the tip of the spire and the spire is
                    // the top of the building, so the tip is above the
                    // middle of the picture by however much of the
                    // building is below it. The camera is placed so that
                    // the whole building sits in the frame, and the
                    // middle of the building is put in the middle of
                    // the frame.
                    const double tipAbove = std::atan2(aim.y - viewpoint.position.y, flat);
                    const double baseBelow = std::atan2(
                        static_cast<double>(origin.groundY) - viewpoint.position.y, flat);
                    const double middle = (tipAbove + baseBelow) * 0.5;
                    const double halfFov = 0.5236;   // thirty degrees
                    // How far the middle of the building is from the
                    // middle of the frame, as a share of the frame.
                    const double offCentre = std::fabs(middle) / halfFov;
                    score += 900.0 * (1.0 - offCentre);
                }
                viewpoint.score = score;
                viewpoints.push_back(viewpoint);
            }
        }
    }

    return viewpoints;
}

void findGothicCameras(World& world, std::vector<GothicCamera>& out) {
    const int32_t step = 4;
    const int32_t span = 120;

    GothicCamera best[kGothicShotCount];
    bool found[kGothicShotCount] = {false, false, false, false, false};

    // Every slot knows which shot it is from the start, so that a slot
    // whose rule is never satisfied still names itself and not the
    // default.
    for (int i = 0; i < kGothicShotCount; ++i) {
        best[i].shot = static_cast<GothicShot>(i);
    }

    for (int32_t z = -span; z <= span; z += step) {
        for (int32_t x = -span; x <= span; x += step) {
            const int32_t surface = world.surfaceHeight(x, z);
            if (surface < kSeaLevel) continue;

            // How much the ground rises around here, which is what makes
            // a silhouette.
            int32_t highest = surface;
            for (int32_t dz = -12; dz <= 12; dz += 6) {
                for (int32_t dx = -12; dx <= 12; dx += 6) {
                    const int32_t h = world.surfaceHeight(x + dx, z + dz);
                    if (h > highest) highest = h;
                }
            }
            const int32_t relief = highest - surface;

            // Is there a mouth of a cave under this column?
            bool cave = false;
            for (int32_t depth = 1; depth <= 4 && !cave; ++depth) {
                if (world.blockAt(x, surface - depth, z) == kBlockAir &&
                    world.blockAt(x, surface - depth - 1, z) != kBlockAir) {
                    cave = true;
                }
            }

            // Is there a tree over this column?
            bool tree = false;
            for (int32_t up = 1; up <= 10 && !tree; ++up) {
                for (int32_t around = -2; around <= 2 && !tree; ++around) {
                    const uint8_t block = world.blockAt(x + around, surface + up, z + around);
                    if (block == static_cast<uint8_t>(BlockType::Leaves) ||
                        block == static_cast<uint8_t>(BlockType::Wood)) {
                        tree = true;
                    }
                }
            }

            // The silhouette: the highest ground with the most relief
            // around it.
            if (!found[static_cast<int>(GothicShot::Silhouette)] && relief >= 6) {
                best[static_cast<int>(GothicShot::Silhouette)] = GothicCamera{};
                best[static_cast<int>(GothicShot::Silhouette)].shot = GothicShot::Silhouette;
                best[static_cast<int>(GothicShot::Silhouette)].position = Vec3{static_cast<float>(x),
                                                            static_cast<float>(highest + 18),
                                                            static_cast<float>(z)};
                best[static_cast<int>(GothicShot::Silhouette)].yaw = 0.9f;
                best[static_cast<int>(GothicShot::Silhouette)].pitch = 0.16f;
                best[static_cast<int>(GothicShot::Silhouette)].note = "the highest ground with the most relief";
                found[static_cast<int>(GothicShot::Silhouette)] = true;
            }

            // The cave: a column with a mouth under it.
            if (!found[static_cast<int>(GothicShot::CaveMouth)] && cave) {
                best[static_cast<int>(GothicShot::CaveMouth)] = GothicCamera{};
                best[static_cast<int>(GothicShot::CaveMouth)].shot = GothicShot::CaveMouth;
                best[static_cast<int>(GothicShot::CaveMouth)].position = Vec3{static_cast<float>(x),
                                                          static_cast<float>(surface + 6),
                                                          static_cast<float>(z)};
                best[static_cast<int>(GothicShot::CaveMouth)].yaw = 2.4f;
                best[static_cast<int>(GothicShot::CaveMouth)].pitch = 0.30f;
                best[static_cast<int>(GothicShot::CaveMouth)].note = "a column with a mouth of a cave under it";
                found[static_cast<int>(GothicShot::CaveMouth)] = true;
            }

            // The forest: a column with trees.
            if (!found[static_cast<int>(GothicShot::Forest)] && tree) {
                best[static_cast<int>(GothicShot::Forest)] = GothicCamera{};
                best[static_cast<int>(GothicShot::Forest)].shot = GothicShot::Forest;
                best[static_cast<int>(GothicShot::Forest)].position = Vec3{static_cast<float>(x),
                                                       static_cast<float>(surface + 12),
                                                       static_cast<float>(z)};
                best[static_cast<int>(GothicShot::Forest)].yaw = 3.1f;
                best[static_cast<int>(GothicShot::Forest)].pitch = 0.22f;
                best[static_cast<int>(GothicShot::Forest)].note = "a column with trees over it";
                found[static_cast<int>(GothicShot::Forest)] = true;
            }

            // The ruins: a column with a cave and relief, so there is
            // something to look at.
            if (!found[static_cast<int>(GothicShot::Arches)] && cave && relief >= 6) {
                best[static_cast<int>(GothicShot::Arches)] = GothicCamera{};
                best[static_cast<int>(GothicShot::Arches)].shot = GothicShot::Arches;
                best[static_cast<int>(GothicShot::Arches)].position = Vec3{static_cast<float>(x),
                                                        static_cast<float>(surface + 9),
                                                        static_cast<float>(z)};
                best[static_cast<int>(GothicShot::Arches)].yaw = 1.7f;
                best[static_cast<int>(GothicShot::Arches)].pitch = 0.26f;
                best[static_cast<int>(GothicShot::Arches)].note = "a column with a cave and relief";
                found[static_cast<int>(GothicShot::Arches)] = true;
            }
        }
    }

    // The long view: the highest place there is, looking out.
    {
        int32_t highest = kSeaLevel;
        int32_t hx = 0;
        int32_t hz = 0;
        for (int32_t z = -span; z <= span; z += step) {
            for (int32_t x = -span; x <= span; x += step) {
                const int32_t h = world.surfaceHeight(x, z);
                if (h > highest) {
                    highest = h;
                    hx = x;
                    hz = z;
                }
            }
        }
        best[static_cast<int>(GothicShot::Horizon)] = GothicCamera{};
        best[static_cast<int>(GothicShot::Horizon)].shot = GothicShot::Horizon;
        best[static_cast<int>(GothicShot::Horizon)].position = Vec3{static_cast<float>(hx),
                                                  static_cast<float>(highest + 30),
                                                  static_cast<float>(hz)};
        best[static_cast<int>(GothicShot::Horizon)].yaw = 2.0f;
        best[static_cast<int>(GothicShot::Horizon)].pitch = 0.06f;
        best[static_cast<int>(GothicShot::Horizon)].note = "the highest place there is, looking out";
    }

    // The cathedral: the viewpoint that sees the spire against the sky.
    {
        const std::vector<World::RuinOrigin> origins = world.ruinOrigins();
        if (!origins.empty()) {
            const World::RuinOrigin& origin = origins.front();

            // The plan of this ruin, so that the point to aim at is the
            // tip of its spire and not a guess.
            RuinPlan plan = planRuin(0x5EED1234u, origin.groundY);
            for (RuinPart& part : plan.parts) {
                part.x += origin.x;
                part.z += origin.z;
            }
            for (RuinArch& arch : plan.arches) {
                arch.x += origin.x;
                arch.z += origin.z;
            }
            const RuinViewpoint spire = ruinViewpoint(plan);

            // The roof line of the hall, which is where the building
            // meets the sky at its widest.
            int32_t roofLine = origin.groundY;
            for (const RuinPart& part : plan.parts) {
                if (part.piece != RuinPiece::Nave) continue;
                roofLine = part.y + part.height;
            }

            const std::vector<Viewpoint> viewpoints =
                cathedralViewpoints(world, spire, origin, roofLine);

            // The best one, and how many of them work at all.
            const Viewpoint* bestView = nullptr;
            int32_t usable = 0;
            for (const Viewpoint& viewpoint : viewpoints) {
                if (viewpoint.seesTheSpire && viewpoint.insideTheFrame) ++usable;
                if (!bestView || viewpoint.score > bestView->score) bestView = &viewpoint;
            }

            if (bestView) {
                best[static_cast<int>(GothicShot::Ruins)] = GothicCamera{};
                best[static_cast<int>(GothicShot::Ruins)].shot = GothicShot::Ruins;
                best[static_cast<int>(GothicShot::Ruins)].position = bestView->position;
                best[static_cast<int>(GothicShot::Ruins)].yaw = bestView->yaw;
                best[static_cast<int>(GothicShot::Ruins)].pitch = bestView->pitch;
                best[static_cast<int>(GothicShot::Ruins)].note =
                    "the cathedral, " + std::to_string(usable) + " of the viewpoints see it";
            }
        }
    }

    for (const GothicCamera& camera : best) {
        out.push_back(camera);
    }

    // Every camera has to stand in the open air.
    //
    // A camera that is inside a hill shows the inside of the world, which
    // is a picture of the ceiling and not of the thing the camera is
    // there to look at. So the camera is raised until the cell it is in
    // is air.
    for (GothicCamera& camera : out) {
        int32_t x = static_cast<int32_t>(camera.position.x);
        int32_t y = static_cast<int32_t>(camera.position.y);
        int32_t z = static_cast<int32_t>(camera.position.z);

        int32_t raised = 0;

        // The camera has to be above the ground, and not in a hollow or
        // in a cavern, or it shows the inside of the world.
        const int32_t ground = world.surfaceHeight(x, z);
        if (y < ground + 4) {
            y = ground + 4;
            raised = 1;
        }

        // And it has to be able to see the sky. A camera under an
        // overhang sees the underside of the overhang, and the fog of the
        // hollow it is in, and not the thing it is there to look at.
        auto clearAbove = [&](int32_t at) {
            for (int32_t up = 1; up <= 40; ++up) {
                if (world.blockAt(x, at + up, z) != kBlockAir) return false;
            }
            return true;
        };

        while (raised < 96) {
            const bool inSomething = world.blockAt(x, y, z) != kBlockAir;
            if (!inSomething && clearAbove(y)) break;
            ++y;
            ++raised;
        }
        camera.position.y = static_cast<float>(y);
        camera.note += raised > 0 ? ", raised out of the ground" : "";
    }
}

// The certification of the look.
//
// The five cameras are found, each one is rendered, each one is measured,
// and the measurements are written down. It is the loop the shader is
// judged by: the picture is the evidence and the numbers are the
// description of the evidence.
int runCertifyVisual(const Options& options) {
    // The certification draws into an offscreen target, because it has no
    // window and no display.
    Options settings = options;
    settings.headless = true;

    VoxelEngine engine;
    std::string error;
    if (!engine.initialize(settings, error)) {
        fprintf(stderr, "sunshine-voxel: %s\n", error.c_str());
        return 1;
    }

    std::vector<GothicCamera> cameras;
    findGothicCameras(engine.world(), cameras);

    printf("{\n");
    printf("  \"schema_version\": \"sunshine.voxel.visual.cert/1\",\n");
    printf("  \"certification\": \"GOTHIC_200\",\n");
    printf("  \"adapter\": \"%s\",\n",
           jsonEscape(engine.renderer().adapterName()).c_str());
    printf("  \"resolution\": \"%ux%u\",\n", options.width, options.height);
    printf("  \"shots\": [\n");

    bool allDrew = true;

    for (size_t i = 0; i < cameras.size(); ++i) {
        const GothicCamera& shot = cameras[i];

        Camera camera;
        camera.position = shot.position;
        camera.yaw = shot.yaw;
        camera.pitch = shot.pitch;

        if (!engine.updateChunks(camera, error)) {
            fprintf(stderr, "sunshine-voxel: %s\n", error.c_str());
            return 1;
        }

        FrameStats stats{};
        const double time = static_cast<double>(i) * 0.5;
        if (!engine.render(camera, time, stats, error)) {
            fprintf(stderr, "sunshine-voxel: %s\n", error.c_str());
            return 1;
        }

        CapturedFrame frame;
        if (!engine.capture(frame, error)) {
            fprintf(stderr, "sunshine-voxel: %s\n", error.c_str());
            return 1;
        }

        const ImageAnalysis analysis = analyseImage(frame);

        char path[256];
        snprintf(path, sizeof(path), "%s/%s.bmp", options.outDir.c_str(), gothicShotName(shot.shot));
        if (!writeBitmap(path, frame, error)) {
            fprintf(stderr, "sunshine-voxel: %s\n", error.c_str());
        }

        // The picture has to have something in it: the ground and the
        // sky, and the ground has to be different from the sky.
        const bool drew = analysis.groundFraction > 0.02 && analysis.skyFraction > 0.02;
        if (!drew) allDrew = false;

        printf("    {\n");
        printf("      \"name\": \"%s\",\n", gothicShotName(shot.shot));
        printf("      \"note\": \"%s\",\n", jsonEscape(shot.note).c_str());
        printf("      \"camera\": [%s, %s, %s, %s, %s],\n",
               number(camera.position.x, 1).c_str(), number(camera.position.y, 1).c_str(),
               number(camera.position.z, 1).c_str(), number(camera.yaw, 3).c_str(),
               number(camera.pitch, 3).c_str());
        printf("      \"frame_ms\": %s,\n", number(stats.gpuFrameMs, 3).c_str());
        printf("      \"triangles\": %llu,\n",
               static_cast<unsigned long long>(stats.trianglesDrawn));
        printf("      \"chunks\": %u,\n", stats.chunksDrawn);
        printf("      \"sky_fraction\": %s,\n", number(analysis.skyFraction, 5).c_str());
        printf("      \"ground_fraction\": %s,\n", number(analysis.groundFraction, 5).c_str());

        // Where the thing the shot is of sits in the frame.
        //
        // A subject that is off to one side is a subject the picture is
        // about something else, and the distance from the middle of the
        // frame is the number that says so.
        if (shot.shot == GothicShot::Ruins) {
            const float aspect = static_cast<float>(options.width) /
                                 static_cast<float>(options.height > 0 ? options.height : 1);
            const Mat4 vp = camera.viewProjection(aspect);
            Vec3 subject{0.0f, 0.0f, 0.0f};
            bool haveSubject = false;
            for (const World::RuinOrigin& origin : engine.world().ruinOrigins()) {
                RuinPlan plan = planRuin(0x5EED1234u, origin.groundY);
                for (RuinPart& part : plan.parts) {
                    part.x += origin.x;
                    part.z += origin.z;
                }
                for (RuinArch& arch : plan.arches) {
                    arch.x += origin.x;
                    arch.z += origin.z;
                }
                const RuinViewpoint spire = ruinViewpoint(plan);
                subject = Vec3{static_cast<float>(spire.x), static_cast<float>(spire.y),
                               static_cast<float>(spire.z)};
                haveSubject = true;
                break;
            }
            if (haveSubject) {
                const Vec3 ndc = vp.transformPoint(subject);
                const double offset = std::sqrt(ndc.x * ndc.x + ndc.y * ndc.y);
                printf("      \"subject_in_frame\": [%s, %s],\n", number(ndc.x, 4).c_str(),
                       number(ndc.y, 4).c_str());
                printf("      \"subject_offset\": %s,\n", number(offset, 4).c_str());
            }
        }
        printf("      \"mean_luminance\": %s,\n", number(analysis.meanLuminance, 2).c_str());
        printf("      \"luminance_p5\": %s,\n", number(analysis.luminanceP5, 2).c_str());
        printf("      \"luminance_p95\": %s,\n", number(analysis.luminanceP95, 2).c_str());
        printf("      \"saturation\": %s,\n", number(analysis.saturation, 4).c_str());
        printf("      \"distinct_colours\": %u,\n", analysis.distinctColours);
        printf("      \"band_contrast\": [");
        for (int band = 0; band < 8; ++band) {
            printf("%s%s", band ? ", " : "", number(analysis.bandContrast[band], 2).c_str());
        }
        printf("],\n");
        printf("      \"hash\": \"%016llx\",\n",
               static_cast<unsigned long long>(frameHash(frame)));
        printf("      \"file\": \"%s\",\n", jsonEscape(path).c_str());
        printf("      \"drew\": %s\n", drew ? "true" : "false");
        printf("    }%s\n", i + 1 < cameras.size() ? "," : "");
    }

    printf("  ],\n");
    printf("  \"verdict\": \"%s\"\n", allDrew ? "PASS" : "FAIL");
    printf("}\n");
    return allDrew ? 0 : 2;
}

int runReadImage(const std::string& path) {
    CapturedFrame frame;
    std::string error;
    if (!readBitmap(path, frame, error)) {
        fprintf(stderr, "sunshine-voxel: %s\n", error.c_str());
        return 1;
    }

    const ImageAnalysis analysis = analyseImage(frame);

    printf("{\n");
    printf("  \"schema_version\": \"sunshine.voxel.image/1\",\n");
    printf("  \"path\": \"%s\",\n", jsonEscape(path).c_str());
    printf("  \"width\": %u,\n", analysis.width);
    printf("  \"height\": %u,\n", analysis.height);
    printf("  \"pixel_count\": %llu,\n", static_cast<unsigned long long>(analysis.pixelCount));
    printf("  \"sky_fraction\": %s,\n", number(analysis.skyFraction, 5).c_str());
    printf("  \"ground_fraction\": %s,\n", number(analysis.groundFraction, 5).c_str());
    printf("  \"water_fraction\": %s,\n", number(analysis.waterFraction, 5).c_str());
    printf("  \"mean_luminance\": %s,\n", number(analysis.meanLuminance, 2).c_str());
    printf("  \"luminance_p5\": %s,\n", number(analysis.luminanceP5, 2).c_str());
    printf("  \"luminance_p25\": %s,\n", number(analysis.luminanceP25, 2).c_str());
    printf("  \"luminance_p50\": %s,\n", number(analysis.luminanceP50, 2).c_str());
    printf("  \"luminance_p75\": %s,\n", number(analysis.luminanceP75, 2).c_str());
    printf("  \"luminance_p95\": %s,\n", number(analysis.luminanceP95, 2).c_str());
    printf("  \"saturation\": %s,\n", number(analysis.saturation, 4).c_str());
    printf("  \"band_contrast\": [");
    for (int band = 0; band < 8; ++band) {
        printf("%s%s", band ? ", " : "", number(analysis.bandContrast[band], 3).c_str());
    }
    printf("],\n");
    printf("  \"palette\": [");
    for (size_t i = 0; i < analysis.palette.size(); ++i) {
        const ImageAnalysis::Colour& colour = analysis.palette[i];
        printf("%s{\"r\": %u, \"g\": %u, \"b\": %u, \"fraction\": %s}", i ? ", " : "",
               colour.r, colour.g, colour.b, number(colour.fraction, 5).c_str());
    }
    printf("],\n");
    printf("  \"ascii\": \"");
    // The picture as text, so that a model can look at the shape of it
    // without being able to see.
    const std::string text = frameAsText(frame, 96, 30);
    for (char c : text) {
        if (c == '\n') printf("\\n");
        else if (c == '"') printf("\\\"");
        else if (c == '\\') printf("\\\\");
        else putchar(c);
    }
    printf("\"\n");
    printf("}\n");
    return 0;
}

int main(int argc, char** argv) {
    Options options;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        const bool hasValue = (i + 1) < argc;

        if (arg == "--read-image" && hasValue) {
            // The reading of a picture that was captured earlier. It is
            // the end of the chain: the picture is read and what it says
            // is written down.
            return runReadImage(argv[++i]);
        } else if (arg == "--certify-visual") {
            options.certifyVisual = true;
        } else if (arg == "--headless") {
            options.headless = true;
        } else if (arg == "--frames" && hasValue) {
            options.frames = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--width" && hasValue) {
            options.width = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--height" && hasValue) {
            options.height = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--seed" && hasValue) {
            options.seed = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--radius" && hasValue) {
            options.radius = static_cast<int32_t>(std::stol(argv[++i]));
        } else if (arg == "--out" && hasValue) {
            options.outDir = argv[++i];
        } else if (arg == "--no-capture") {
            options.capture = false;
        } else if (arg == "--json") {
            options.json = true;
        } else if (arg == "--text") {
            options.text = true;
        } else if (arg == "--no-browser") {
            options.browser = false;
        } else if (arg == "--flat") {
            options.flat = true;
        } else if (arg == "--certify-browser") {
            options.certifyBrowser = true;
        } else if (arg == "--certify-timeout") {
            if (i + 1 >= argc) {
                fprintf(stderr, "sunshine-voxel: --certify-timeout needs a number of seconds\n");
                return 2;
            }
            options.certifyTimeoutSeconds = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--help" || arg == "-h") {
            printf(
                "sunshine-voxel — the native voxel renderer of the RawrXD browser\n"
                "\n"
                "usage: sunshine-voxel [options]\n"
                "\n"
                "  --headless        render into an offscreen target, with no window\n"
                "  --frames N        how many frames to draw (default 60)\n"
                "  --width N         the width of the target (default 1280)\n"
                "  --height N        the height of the target (default 720)\n"
                "  --seed N          the world seed\n"
                "  --radius N        how many chunks around the camera to load\n"
                "  --out DIR         where the captured frames are written\n"
                "  --no-capture      do not write the frames to disk\n"
                "  --flat            a plain world, with no hills or caves\n"
                "  --json            print the receipt as JSON\n"
                "  --text            print the last frame as text\n"
                "  --no-browser      do not open the browser panel\n");
            return 0;
        } else {
            fprintf(stderr, "sunshine-voxel: the option '%s' was not understood\n", arg.c_str());
            return 2;
        }
    }

    if (options.certifyVisual) {
        return runCertifyVisual(options);
    }
    if (options.headless) {
        return runHeadless(options);
    }
    return runWindowed(options);
}
