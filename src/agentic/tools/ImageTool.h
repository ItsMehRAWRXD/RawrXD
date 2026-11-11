// ============================================================================
// ImageTool.h - the agent's ability to SEE an image.
//
// The text models RawrXD runs (Nemotron, Qwen, Llama) have no vision tower
// and no image tokens. What they can consume is a description of the pixels
// that is dense enough to reason about. This tool provides that, from the
// real pixels, with no hashing, no placeholders and no "image attached"
// fiction.
//
// Decoding uses WIC, the Windows Imaging Component: a platform decoder that
// handles PNG, BMP, JPEG, TIFF and GIF. It is the same class of platform
// boundary as DirectX, not a third-party library, and it is the only decoder
// the F: tree would otherwise have to hand-roll.
//
// The output is two grids plus a legend:
//
//   * a luminance map (the classic ASCII ramp), which gives the model the
//     spatial structure of the scene, and
//   * a colour map, where every cell is classified by hue and brightness
//     against a small named palette, which gives the model the content.
//
// Together they let a text model answer questions about a frame: is there
// terrain, where is the horizon, what colour dominates, how much of the
// frame is covered.
//
// The tool is READ ONLY and is workspace scoped, exactly like readFile.
// ============================================================================
#pragma once

#include "tool_core.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
# ifndef NOMINMAX
#  define NOMINMAX
# endif
# include <windows.h>
# include <wincodec.h>
# include <wrl/client.h>
#endif

namespace rawrxd::tools {
namespace image_detail {

using Microsoft::WRL::ComPtr;

struct DecodedImage {
    uint32_t width = 0;
    uint32_t height = 0;
    std::vector<uint8_t> bgra;  // 4 bytes per pixel, B G R A
};

// Decodes an image file with WIC. Returns false and fills `error` on
// failure. WIC handles PNG, BMP, JPEG, TIFF and GIF.
//
// Every WIC interface is held in a ComPtr inside an inner scope, and the
// COM apartment is torn down AFTER that scope ends. Releasing a WIC object
// after CoUninitialize() tears the apartment down under it, which is an
// access violation, not an exception: the inner scope is what makes this
// correct.
inline bool DecodeImage(const fs::path& path, DecodedImage& out, std::string& error) {
#ifdef _WIN32
    const HRESULT init = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool needCoUninit = SUCCEEDED(init);
    if (FAILED(init) && init != RPC_E_CHANGED_MODE) {
        error = "COM initialization failed for the image decoder";
        return false;
    }

    bool ok = false;
    {
        // Each WIC interface is created as a raw pointer with a +1 reference
        // and then Adopted by a ComPtr, so the reference is released exactly
        // once.
        IWICImagingFactory* factoryRaw = nullptr;
        HRESULT hr = CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                                      IID_PPV_ARGS(&factoryRaw));
        if (FAILED(hr) || factoryRaw == nullptr) {
            error = "the Windows Imaging Component is unavailable";
        } else {
            ComPtr<IWICImagingFactory> factory;
            factory.Attach(factoryRaw);

            IWICBitmapDecoder* decoderRaw = nullptr;
            hr = factory->CreateDecoderFromFilename(path.c_str(), nullptr, GENERIC_READ,
                                                    WICDecodeMetadataCacheOnDemand, &decoderRaw);
            if (FAILED(hr) || decoderRaw == nullptr) {
                error = "the file is not an image WIC can decode";
            } else {
                ComPtr<IWICBitmapDecoder> decoder;
                decoder.Attach(decoderRaw);

                IWICBitmapFrameDecode* frameRaw = nullptr;
                hr = decoder->GetFrame(0, &frameRaw);
                if (FAILED(hr) || frameRaw == nullptr) {
                    error = "the image has no decodable frame";
                } else {
                    ComPtr<IWICBitmapFrameDecode> frame;
                    frame.Attach(frameRaw);

                    IWICFormatConverter* converterRaw = nullptr;
                    hr = factory->CreateFormatConverter(&converterRaw);
                    if (FAILED(hr) || converterRaw == nullptr) {
                        error = "the image converter could not be created";
                    } else {
                        ComPtr<IWICFormatConverter> converter;
                        converter.Attach(converterRaw);

                        hr = converter->Initialize(frame.Get(), GUID_WICPixelFormat32bppBGR,
                                                   WICBitmapDitherTypeNone, nullptr, 0.0,
                                                   WICBitmapPaletteTypeCustom);
                        if (FAILED(hr)) {
                            error = "the image could not be converted to a 32bpp format";
                        } else {
                            UINT width = 0;
                            UINT height = 0;
                            converter->GetSize(&width, &height);
                            if (width == 0 || height == 0) {
                                error = "the image has zero extent";
                            } else {
                                out.width = width;
                                out.height = height;
                                out.bgra.resize(static_cast<size_t>(width) * height * 4u);
                                const UINT stride = width * 4u;
                                hr = converter->CopyPixels(nullptr, stride,
                                                           static_cast<UINT>(out.bgra.size()),
                                                           out.bgra.data());
                                if (FAILED(hr)) {
                                    error = "the image pixels could not be copied";
                                } else {
                                    ok = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }  // every WIC interface is released here, before CoUninitialize

    if (needCoUninit) CoUninitialize();
    return ok;
#else
    (void)path;
    (void)out;
    error = "image decoding is only available on Windows";
    return false;
#endif
}

// A named colour class for the colour map.
struct ColorClass {
    char symbol;
    const char* name;
    uint32_t r;
    uint32_t g;
    uint32_t b;
};

inline const ColorClass* ColorClasses(size_t& count) {
    static const ColorClass kClasses[] = {
        {'.', "black",          0, 0, 0},
        {'K', "dark grey",      64, 64, 64},
        {'W', "white",         240, 240, 240},
        {'S', "snow",          226, 236, 245},
        {'R', "red",           200, 60, 55},
        {'O', "orange",        225, 140, 50},
        {'Y', "yellow",        225, 205, 90},
        {'T', "tan",           200, 180, 130},
        {'G', "grass green",   80, 155, 70},
        {'D', "dark green",    40, 95, 45},
        {'B', "blue",          60, 110, 200},
        {'C', "cyan",          80, 190, 200},
        {'M', "magenta",       190, 90, 180},
        {'N', "brown",         120, 85, 60},
    };
    count = sizeof(kClasses) / sizeof(kClasses[0]);
    return kClasses;
}

inline char ClassifyColor(uint32_t r, uint32_t g, uint32_t b) {
    const float rf = static_cast<float>(r) / 255.0f;
    const float gf = static_cast<float>(g) / 255.0f;
    const float bf = static_cast<float>(b) / 255.0f;
    const float maxC = std::max({rf, gf, bf});
    const float minC = std::min({rf, gf, bf});
    const float delta = maxC - minC;
    const float value = maxC;
    const float saturation = (maxC <= 0.0f) ? 0.0f : (delta / maxC);

    float hue = 0.0f;
    if (delta > 1e-6f) {
        if (maxC == rf) hue = 60.0f * std::fmod((gf - bf) / delta, 6.0f);
        else if (maxC == gf) hue = 60.0f * ((bf - rf) / delta + 2.0f);
        else hue = 60.0f * ((rf - gf) / delta + 4.0f);
        if (hue < 0.0f) hue += 360.0f;
    }

    if (value < 0.10f) return '.';
    if (saturation < 0.12f) {
        if (value > 0.86f) return 'W';
        if (value > 0.62f) return 'S';
        if (value > 0.34f) return 'K';
        return '.';
    }
    if (hue >= 0.0f && hue < 20.0f) return 'R';
    if (hue >= 20.0f && hue < 45.0f) return 'O';
    if (hue >= 45.0f && hue < 70.0f) return 'Y';
    if (hue >= 70.0f && hue < 160.0f) return (value < 0.45f) ? 'D' : 'G';
    if (hue >= 160.0f && hue < 200.0f) return 'C';
    if (hue >= 200.0f && hue < 255.0f) return 'B';
    if (hue >= 255.0f && hue < 300.0f) return 'M';
    return 'N';
}

// The text the model receives. This is the whole point of the tool.
inline std::string RenderForModel(const DecodedImage& img, uint32_t requestedCols) {
    if (img.width == 0 || img.height == 0 || img.bgra.empty()) return "the image is empty";

    const uint32_t cols = std::max(16u, std::min(160u, requestedCols));
    // Keep the cell roughly square, and never taller than 48 rows.
    uint32_t rows = static_cast<uint32_t>(
        (static_cast<double>(cols) * img.height / img.width) / 2.0 + 0.5);
    rows = std::max(8u, std::min(48u, rows));

    // Average each cell.
    struct Cell {
        double sumR = 0.0;
        double sumG = 0.0;
        double sumB = 0.0;
        uint32_t count = 0;
    };
    std::vector<Cell> cells(static_cast<size_t>(cols) * rows);
    for (uint32_t y = 0; y < img.height; ++y) {
        const uint32_t cy = std::min(rows - 1, (y * rows) / img.height);
        for (uint32_t x = 0; x < img.width; ++x) {
            const uint32_t cx = std::min(cols - 1, (x * cols) / img.width);
            const size_t p = (static_cast<size_t>(y) * img.width + x) * 4u;
            Cell& cell = cells[static_cast<size_t>(cy) * cols + cx];
            cell.sumB += img.bgra[p + 0];
            cell.sumG += img.bgra[p + 1];
            cell.sumR += img.bgra[p + 2];
            cell.count += 1;
        }
    }

    // Luminance ramp, and the dominant colour classes with their coverage.
    static const char kRamp[] = " .:-=+*#%@";
    size_t classCount = 0;
    const ColorClass* classes = ColorClasses(classCount);
    std::vector<uint32_t> classPixels(classCount, 0);

    std::ostringstream luminance;
    std::ostringstream colour;
    std::ostringstream legend;

    for (uint32_t row = 0; row < rows; ++row) {
        for (uint32_t col = 0; col < cols; ++col) {
            const Cell& cell = cells[static_cast<size_t>(row) * cols + col];
            const double r = cell.count ? cell.sumR / cell.count : 0.0;
            const double g = cell.count ? cell.sumG / cell.count : 0.0;
            const double b = cell.count ? cell.sumB / cell.count : 0.0;
            const double lum = (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255.0;
            const int level = std::min<int>(9, static_cast<int>(lum * 10.0));
            luminance << kRamp[level];

            const char symbol = ClassifyColor(static_cast<uint32_t>(r), static_cast<uint32_t>(g),
                                              static_cast<uint32_t>(b));
            colour << symbol;
            for (size_t i = 0; i < classCount; ++i) {
                if (classes[i].symbol == symbol) { classPixels[i] += 1; break; }
            }
        }
        luminance << '\n';
        colour << '\n';
    }

    const double totalCells = static_cast<double>(cols) * rows;
    legend << "colour legend (symbol = name, share of the frame):\n";
    for (size_t i = 0; i < classCount; ++i) {
        if (classPixels[i] == 0) continue;
        const double share = 100.0 * static_cast<double>(classPixels[i]) / totalCells;
        legend << "  " << classes[i].symbol << " = " << classes[i].name << "  " << share
               << "%\n";
    }

    std::ostringstream out;
    out << "image " << img.width << "x" << img.height << " decoded, rendered at " << cols
        << "x" << rows << " cells\n";
    out << "\nluminance map (darker is less light, '@' is brightest):\n" << luminance.str();
    out << "\ncolour map:\n" << colour.str();
    out << "\n" << legend.str();
    return out.str();
}

} // namespace image_detail

// Registers the image tool on the registry. The path is workspace scoped,
// exactly like readFile.
inline void register_image_tools(Registry& reg, fs::path root) {
    root = canonical_root(root);
    reg.add({"readImage",
             "Look at an image file in the workspace and return a rendering of its "
             "pixels (a luminance map and a colour map) so the model can reason "
             "about what the image shows",
             Risk::ReadOnly,
             {"path"},
             [root](const Request& r) -> Result {
                 const fs::path p = scoped(root, arg(r, "path"));
                 if (!fs::is_regular_file(p)) throw std::runtime_error("not a file");
                 image_detail::DecodedImage img;
                 std::string error;
                 if (!image_detail::DecodeImage(p, img, error)) {
                     throw std::runtime_error(error);
                 }
                 uint32_t cols = 64;
                 auto colsIt = r.args.find("cols");
                 if (colsIt != r.args.end()) {
                     cols = static_cast<uint32_t>(std::max(16, std::min(160, std::atoi(colsIt->second.c_str()))));
                 }
                 return {true, image_detail::RenderForModel(img, cols), ""};
             }});
}

} // namespace rawrxd::tools
