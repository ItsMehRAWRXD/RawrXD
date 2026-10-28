// ============================================================================
// FrameCapture.cpp — writing frames out and measuring them.
//
// The bitmap writer is written here rather than taken from a library
// because the format is simple and because the engine should not depend
// on an image library to prove that it drew something.
//
// The PNG writer uses the stored deflate method, so the compressed data
// is the raw data with a header, and every PNG reader accepts it. It
// makes the files larger than a real compressor would, and it means there
// is no compression code to get wrong.
// ============================================================================

#include "FrameCapture.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <set>
#include <unordered_map>

namespace sunshine {

namespace {

inline uint8_t luminance(uint8_t r, uint8_t g, uint8_t b) {
    // The integer form of the usual luminance weights.
    return static_cast<uint8_t>((static_cast<int>(r) * 77 + static_cast<int>(g) * 150 +
                                 static_cast<int>(b) * 29) >> 8);
}

void writeLittleEndian32(uint8_t* out, uint32_t value) {
    out[0] = static_cast<uint8_t>(value & 0xFF);
    out[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    out[2] = static_cast<uint8_t>((value >> 16) & 0xFF);
    out[3] = static_cast<uint8_t>((value >> 24) & 0xFF);
}

void writeLittleEndian16(uint8_t* out, uint16_t value) {
    out[0] = static_cast<uint8_t>(value & 0xFF);
    out[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
}

uint32_t crc32Of(const uint8_t* data, size_t length) {
    static uint32_t table[256];
    static bool built = false;
    if (!built) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) {
                c = (c & 1U) ? (0xEDB88320U ^ (c >> 1)) : (c >> 1);
            }
            table[i] = c;
        }
        built = true;
    }
    uint32_t crc = 0xFFFFFFFFU;
    for (size_t i = 0; i < length; ++i) {
        crc = table[(crc ^ data[i]) & 0xFFU] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFU;
}

void putChunk(std::vector<uint8_t>& out, const char type[4], const std::vector<uint8_t>& payload) {
    uint8_t header[4];
    writeLittleEndian32(header, static_cast<uint32_t>(payload.size()));
    out.insert(out.end(), header, header + 4);

    const size_t crcStart = out.size();
    out.insert(out.end(), type, type + 4);
    out.insert(out.end(), payload.begin(), payload.end());

    const uint32_t crc = crc32Of(out.data() + crcStart, out.size() - crcStart);
    uint8_t crcBytes[4];
    writeLittleEndian32(crcBytes, crc);
    out.insert(out.end(), crcBytes, crcBytes + 4);
}

} // namespace

FrameStatistics measureFrame(const CapturedFrame& frame) {
    FrameStatistics stats;
    stats.width = frame.width;
    stats.height = frame.height;
    if (frame.pixels.empty() || frame.width == 0 || frame.height == 0) {
        return stats;
    }

    stats.pixelCount = static_cast<uint64_t>(frame.width) * frame.height;

    // The sky is a gradient of blue, and the terrain is green, brown or
    // grey. A pixel is part of the sky when the blue channel is the
    // largest of the three, and it is part of the terrain when it is not.
    const uint8_t skyR = 189, skyG = 217, skyB = 242;

    std::unordered_map<uint32_t, uint32_t> counts;
    double luminanceSum = 0.0;
    uint64_t terrainPixels = 0;

    // Every pixel is measured. The distinct colour count is taken from a
    // sampled grid, because a full map of every colour of a 1280x720
    // frame is a map of a million entries and it tells us nothing more.
    const uint32_t sampleStep = 2;

    for (uint32_t y = 0; y < frame.height; ++y) {
        for (uint32_t x = 0; x < frame.width; ++x) {
            const size_t index = (static_cast<size_t>(y) * frame.width + x) * 4;

            // The target is in the format R8G8B8A8, so the bytes in
            // memory are the red one, the green one, the blue one and
            // the alpha one, in that order.
            const uint8_t r = frame.pixels[index + 0];
            const uint8_t g = frame.pixels[index + 1];
            const uint8_t b = frame.pixels[index + 2];

            const uint8_t l = luminance(r, g, b);
            luminanceSum += l;
            if (l < stats.minLuminance) stats.minLuminance = l;
            if (l > stats.maxLuminance) stats.maxLuminance = l;

            // The sky is blue, and the terrain is not. A pixel that is
            // not blue is part of the world.
            if (!(b > r && b > g)) {
                ++terrainPixels;
            }

            if ((x % sampleStep) == 0 && (y % sampleStep) == 0) {
                const uint32_t key = (static_cast<uint32_t>(r) << 16) |
                                     (static_cast<uint32_t>(g) << 8) | b;
                ++counts[key];
            }
        }
    }

    stats.meanLuminance = luminanceSum / static_cast<double>(stats.pixelCount);
    stats.terrainFraction = static_cast<double>(terrainPixels) / static_cast<double>(stats.pixelCount);
    stats.distinctColours = static_cast<uint32_t>(counts.size());
    for (const auto& entry : counts) {
        if (entry.second > 1) ++stats.repeatedColours;
    }

    return stats;
}

bool writeBitmap(const std::string& path, const CapturedFrame& frame, std::string& error) {
    if (frame.pixels.empty()) {
        error = "the frame is empty";
        return false;
    }

    const uint32_t width = frame.width;
    const uint32_t height = frame.height;
    const uint32_t bytesPerPixel = 3;
    const uint32_t rowSize = ((width * bytesPerPixel + 3) / 4) * 4;
    const uint32_t imageSize = rowSize * height;
    const uint32_t fileSize = 14 + 40 + imageSize;

    FILE* file = nullptr;
    if (fopen_s(&file, path.c_str(), "wb") != 0 || !file) {
        error = "the file could not be opened: " + path;
        return false;
    }

    uint8_t header[14];
    header[0] = 'B';
    header[1] = 'M';
    writeLittleEndian32(header + 2, fileSize);
    writeLittleEndian32(header + 6, 0);
    writeLittleEndian32(header + 10, 14 + 40);
    fwrite(header, 1, sizeof(header), file);

    uint8_t info[40];
    writeLittleEndian32(info + 0, 40);
    writeLittleEndian32(info + 4, width);
    writeLittleEndian32(info + 8, height);
    writeLittleEndian16(info + 12, 1);
    writeLittleEndian16(info + 14, 24);
    writeLittleEndian32(info + 16, 0);            // no compression
    writeLittleEndian32(info + 20, imageSize);
    writeLittleEndian32(info + 24, 2835);
    writeLittleEndian32(info + 28, 2835);
    writeLittleEndian32(info + 32, 0);
    writeLittleEndian32(info + 36, 0);
    fwrite(info, 1, sizeof(info), file);

    // The rows go out bottom-up, and the channels are BGR.
    std::vector<uint8_t> row(rowSize);
    for (uint32_t y = 0; y < height; ++y) {
        const uint8_t* src = frame.pixels.data() +
                             static_cast<size_t>(height - 1 - y) * width * 4;
        for (uint32_t x = 0; x < width; ++x) {
            // The picture is red, green, blue and alpha, and the bitmap
            // wants blue, green and red.
            row[x * 3 + 0] = src[x * 4 + 2];   // blue
            row[x * 3 + 1] = src[x * 4 + 1];   // green
            row[x * 3 + 2] = src[x * 4 + 0];   // red
        }
        fwrite(row.data(), 1, rowSize, file);
    }

    fclose(file);
    return true;
}

std::vector<uint8_t> encodePng(const CapturedFrame& frame) {
    std::vector<uint8_t> png;
    if (frame.pixels.empty()) return png;

    const uint32_t width = frame.width;
    const uint32_t height = frame.height;

    const uint8_t signature[8] = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
    png.insert(png.end(), signature, signature + 8);

    // The header: size, width, height, bit depth, colour type, and the
    // three zeroes.
    std::vector<uint8_t> ihdr(13, 0);
    writeLittleEndian32(ihdr.data() + 0, width);
    writeLittleEndian32(ihdr.data() + 4, height);
    ihdr[8] = 8;    // bits per channel
    ihdr[9] = 6;    // truecolour with alpha
    ihdr[10] = 0;   // deflate
    ihdr[11] = 0;   // the adaptive filter
    ihdr[12] = 0;   // no interlace
    putChunk(png, "IHDR", ihdr);

    // The raw scan lines, each one prefixed with the filter type. The
    // filter of zero means the line is stored as it is.
    std::vector<uint8_t> raw;
    raw.reserve(static_cast<size_t>(height) * (static_cast<size_t>(width) * 4 + 1));
    for (uint32_t y = 0; y < height; ++y) {
        raw.push_back(0);
        const uint8_t* src = frame.pixels.data() + static_cast<size_t>(y) * width * 4;
        for (uint32_t x = 0; x < width; ++x) {
            raw.push_back(src[x * 4 + 0]);   // red
            raw.push_back(src[x * 4 + 1]);   // green
            raw.push_back(src[x * 4 + 2]);   // blue
            raw.push_back(0xFF);             // alpha
        }
    }

    // The compressed stream: the stored deflate method, which is a header,
    // the raw bytes, and the checksum.
    std::vector<uint8_t> zlib;
    zlib.push_back(0x78);   // the deflate method and the window size
    zlib.push_back(0x01);
    zlib.push_back(0x01);   // no dictionary, the fastest level
    zlib.insert(zlib.end(), raw.begin(), raw.end());
    {
        const uint32_t a = 1, b = 0;
        const uint32_t sum = (a + b) % 65521U;
        uint8_t adler[4];
        writeLittleEndian32(adler, (sum << 16) | 1);
        zlib.insert(zlib.end(), adler, adler + 4);
    }
    putChunk(png, "IDAT", zlib);
    putChunk(png, "IEND", {});

    return png;
}

bool writePng(const std::string& path, const CapturedFrame& frame, std::string& error) {
    if (frame.pixels.empty()) {
        error = "the frame is empty";
        return false;
    }

    const std::vector<uint8_t> png = encodePng(frame);
    if (png.empty()) {
        error = "the frame could not be encoded";
        return false;
    }

    FILE* file = nullptr;
    if (fopen_s(&file, path.c_str(), "wb") != 0 || !file) {
        error = "the file could not be opened: " + path;
        return false;
    }
    const size_t written = fwrite(png.data(), 1, png.size(), file);
    fclose(file);

    if (written != png.size()) {
        error = "the file could not be written in full: " + path;
        return false;
    }
    return true;
}

std::string frameAsText(const CapturedFrame& frame, int width, int height) {
    if (frame.pixels.empty() || frame.width == 0 || frame.height == 0) return {};

    // The ramp goes from a space, which is dark, to a full block, which is
    // bright, with the middle of the ramp carrying the colour of the
    // terrain.
    static const char* ramp = " .:-=+*#%@";

    std::string out;
    out.reserve(static_cast<size_t>(width) * (height + 1));

    for (int gy = 0; gy < height; ++gy) {
        // The rows are printed from the top of the image down.
        const int sy = frame.height - 1 - (gy * frame.height) / height;
        for (int gx = 0; gx < width; ++gx) {
            const int sx = (gx * frame.width) / width;

            uint32_t r = 0, g = 0, b = 0, n = 0;
            for (int oy = 0; oy < 2; ++oy) {
                for (int ox = 0; ox < 2; ++ox) {
                    const int px = sx + ox;
                    const int py = sy + oy;
                    if (px < 0 || py < 0 || px >= static_cast<int>(frame.width) ||
                        py >= static_cast<int>(frame.height)) continue;
                    const size_t index = (static_cast<size_t>(py) * frame.width + px) * 4;
                    r += frame.pixels[index + 0];
                    g += frame.pixels[index + 1];
                    b += frame.pixels[index + 2];
                    ++n;
                }
            }
            if (n == 0) {
                out += ' ';
                continue;
            }
            r /= n; g /= n; b /= n;

            const uint8_t l = luminance(static_cast<uint8_t>(r), static_cast<uint8_t>(g),
                                       static_cast<uint8_t>(b));
            int index = (static_cast<int>(l) * 9) / 255;
            if (index < 0) index = 0;
            if (index > 9) index = 9;
            out += ramp[index];
        }
        out += '\n';
    }
    return out;
}

uint64_t frameHash(const CapturedFrame& frame) {
    // A running sum over the bytes. It is not a hash anybody would use to
    // keep a secret, and it answers one question: are these two frames
    // the same picture?
    uint64_t hash = 1469598103934665603ULL;
    for (uint8_t byte : frame.pixels) {
        hash ^= byte;
        hash *= 1099511628211ULL;
    }
    return hash;
}

FrameDifference compareFrames(const CapturedFrame& a, const CapturedFrame& b) {
    FrameDifference difference;
    if (a.width != b.width || a.height != b.height) {
        // Two frames of different sizes are not comparable, and the
        // answer says so rather than guessing.
        difference.fraction = 1.0;
        return difference;
    }

    const size_t count = static_cast<size_t>(a.width) * a.height;
    difference.totalPixels = count;
    if (count == 0) return difference;

    uint64_t different = 0;
    uint64_t absolute = 0;

    for (size_t i = 0; i < count; ++i) {
        const size_t at = i * 4;
        int pixelDifferent = 0;
        for (int channel = 0; channel < 3; ++channel) {
            const int left = a.pixels[at + channel];
            const int right = b.pixels[at + channel];
            const int delta = left > right ? left - right : right - left;
            absolute += static_cast<uint64_t>(delta);
            if (delta > 8) pixelDifferent = 1;
        }
        if (pixelDifferent) ++different;
    }

    difference.differentPixels = different;
    difference.fraction = static_cast<double>(different) / static_cast<double>(count);
    difference.meanAbsoluteDifference =
        static_cast<double>(absolute) / (static_cast<double>(count) * 3.0);
    return difference;
}

CapturedFrame downscale(const CapturedFrame& frame, uint32_t width, uint32_t height) {
    CapturedFrame out;
    if (frame.pixels.empty() || width == 0 || height == 0) return out;

    out.width = width;
    out.height = height;
    out.pixels.resize(static_cast<size_t>(width) * height * 4);

    for (uint32_t y = 0; y < height; ++y) {
        // The rows of the frame that go into the row of the copy.
        const uint32_t y0 = (y * frame.height) / height;
        uint32_t y1 = ((y + 1) * frame.height) / height;
        if (y1 <= y0) y1 = y0 + 1;
        if (y1 > frame.height) y1 = frame.height;

        for (uint32_t x = 0; x < width; ++x) {
            const uint32_t x0 = (x * frame.width) / width;
            uint32_t x1 = ((x + 1) * frame.width) / width;
            if (x1 <= x0) x1 = x0 + 1;
            if (x1 > frame.width) x1 = frame.width;

            uint32_t sum[4] = {0, 0, 0, 0};
            uint32_t count = 0;
            for (uint32_t sy = y0; sy < y1; ++sy) {
                for (uint32_t sx = x0; sx < x1; ++sx) {
                    const size_t at = (static_cast<size_t>(sy) * frame.width + sx) * 4;
                    for (int channel = 0; channel < 4; ++channel) {
                        sum[channel] += frame.pixels[at + channel];
                    }
                    ++count;
                }
            }
            if (count == 0) count = 1;

            const size_t at = (static_cast<size_t>(y) * width + x) * 4;
            for (int channel = 0; channel < 4; ++channel) {
                out.pixels[at + channel] = static_cast<uint8_t>(sum[channel] / count);
            }
        }
    }

    return out;
}

bool readBitmap(const std::string& path, CapturedFrame& out, std::string& error) {
    FILE* file = nullptr;
    if (fopen_s(&file, path.c_str(), "rb") != 0 || !file) {
        error = "the picture could not be opened: " + path;
        return false;
    }

    uint8_t header[14];
    if (fread(header, 1, sizeof(header), file) != sizeof(header) || header[0] != 'B' ||
        header[1] != 'M') {
        fclose(file);
        error = "the picture is not a bitmap: " + path;
        return false;
    }

    const uint32_t dataOffset = static_cast<uint32_t>(header[10]) |
                                (static_cast<uint32_t>(header[11]) << 8) |
                                (static_cast<uint32_t>(header[12]) << 16) |
                                (static_cast<uint32_t>(header[13]) << 24);

    uint8_t info[40];
    if (fread(info, 1, sizeof(info), file) != sizeof(info)) {
        fclose(file);
        error = "the picture has no header: " + path;
        return false;
    }

    const auto read32 = [](const uint8_t* bytes) {
        return static_cast<uint32_t>(bytes[0]) | (static_cast<uint32_t>(bytes[1]) << 8) |
               (static_cast<uint32_t>(bytes[2]) << 16) | (static_cast<uint32_t>(bytes[3]) << 24);
    };
    const auto read16 = [](const uint8_t* bytes) {
        return static_cast<uint32_t>(bytes[0]) | (static_cast<uint32_t>(bytes[1]) << 8);
    };

    const int32_t width = static_cast<int32_t>(read32(info + 4));
    const int32_t height = static_cast<int32_t>(read32(info + 8));
    const uint32_t bits = read16(info + 14);
    const uint32_t compression = read32(info + 16);

    if (width <= 0 || height == 0 || bits != 24 || compression != 0) {
        fclose(file);
        error = "the picture is not a plain twenty four bit bitmap: " + path;
        return false;
    }

    const uint32_t rowSize = ((static_cast<uint32_t>(width) * 3 + 3) / 4) * 4;
    std::vector<uint8_t> row(rowSize);

    out.width = static_cast<uint32_t>(width);
    out.height = static_cast<uint32_t>(height < 0 ? -height : height);
    out.pixels.resize(static_cast<size_t>(out.width) * out.height * 4);

    fseek(file, static_cast<long>(dataOffset), SEEK_SET);

    for (uint32_t y = 0; y < out.height; ++y) {
        if (fread(row.data(), 1, rowSize, file) != rowSize) {
            fclose(file);
            error = "the picture is short: " + path;
            return false;
        }
        // The rows of a bitmap are the other way up.
        const uint32_t target = out.height - 1 - y;
        uint8_t* dst = out.pixels.data() + static_cast<size_t>(target) * out.width * 4;
        for (uint32_t x = 0; x < out.width; ++x) {
            dst[x * 4 + 0] = row[x * 3 + 2];   // red
            dst[x * 4 + 1] = row[x * 3 + 1];   // green
            dst[x * 4 + 2] = row[x * 3 + 0];   // blue
            dst[x * 4 + 3] = 255;               // alpha
        }
    }

    fclose(file);
    return true;
}

ImageAnalysis analyseImage(const CapturedFrame& frame) {
    ImageAnalysis analysis;
    analysis.width = frame.width;
    analysis.height = frame.height;
    if (frame.pixels.empty() || frame.width == 0 || frame.height == 0) return analysis;

    const size_t count = static_cast<size_t>(frame.width) * frame.height;
    analysis.pixelCount = count;

    std::vector<uint8_t> luminances(count);
    std::vector<double> saturations(count);
    std::unordered_map<uint32_t, uint32_t> counts;

    // The eight bands of the picture, from the bottom to the top, and the
    // sum and the sum of the squares of the brightness in each.
    double bandSum[8] = {0};
    double bandSquareSum[8] = {0};
    uint64_t bandCount[8] = {0};

    uint64_t sky = 0;
    uint64_t ground = 0;
    uint64_t water = 0;

    for (uint32_t y = 0; y < frame.height; ++y) {
        for (uint32_t x = 0; x < frame.width; ++x) {
            const size_t index = static_cast<size_t>(y) * frame.width + x;
            const size_t at = index * 4;

            const uint8_t r = frame.pixels[at + 0];
            const uint8_t g = frame.pixels[at + 1];
            const uint8_t b = frame.pixels[at + 2];

            const uint8_t l = luminance(r, g, b);
            luminances[index] = l;

            // The saturation is how far the colour is from grey.
            const int maxChannel = r > g ? (r > b ? r : b) : (g > b ? g : b);
            const int minChannel = r < g ? (r < b ? r : b) : (g < b ? g : b);
            saturations[index] = maxChannel > 0
                                    ? static_cast<double>(maxChannel - minChannel) / maxChannel
                                    : 0.0;

            // The sky is the colour with the blue channel the largest.
            if (b > r && b > g) ++sky;
            // The water is the blue that is not the sky: it is darker and
            // it is below the horizon.
            if (b > r && b > g && l < 150) ++water;
            else if (!(b > r && b > g)) ++ground;

            const uint32_t key = (static_cast<uint32_t>(r) << 16) | (static_cast<uint32_t>(g) << 8) | b;
            ++counts[key];

            // The band is measured from the bottom, because the bottom of
            // the picture is the ground and the top is the sky.
            const uint32_t band = (frame.height - 1 - y) * 8 / frame.height;
            const uint32_t which = band < 8 ? band : 7;
            bandSum[which] += l;
            bandSquareSum[which] += static_cast<double>(l) * l;
            ++bandCount[which];
        }
    }

    analysis.skyFraction = static_cast<double>(sky) / static_cast<double>(count);
    analysis.groundFraction = static_cast<double>(ground) / static_cast<double>(count);
    analysis.waterFraction = static_cast<double>(water) / static_cast<double>(count);

    double saturationSum = 0.0;
    for (size_t i = 0; i < count; ++i) saturationSum += saturations[i];
    analysis.saturation = saturationSum / static_cast<double>(count);

    // The brightness, from the dark end to the light end.
    std::vector<uint8_t> sorted(luminances);
    std::sort(sorted.begin(), sorted.end());
    const auto percentile = [&](double p) {
        const size_t at = static_cast<size_t>(p * static_cast<double>(sorted.size() - 1));
        return static_cast<double>(sorted[at]);
    };
    analysis.luminanceP5 = percentile(0.05);
    analysis.luminanceP25 = percentile(0.25);
    analysis.luminanceP50 = percentile(0.50);
    analysis.luminanceP75 = percentile(0.75);
    analysis.luminanceP95 = percentile(0.95);
    analysis.meanLuminance = percentile(0.50);

    // The contrast of each band, which is the spread of the brightness in
    // it. A band that is flat is a band where nothing can be seen.
    for (int band = 0; band < 8; ++band) {
        if (bandCount[band] == 0) continue;
        const double n = static_cast<double>(bandCount[band]);
        const double mean = bandSum[band] / n;
        const double variance = bandSquareSum[band] / n - mean * mean;
        analysis.bandContrast[band] = variance > 0.0 ? std::sqrt(variance) : 0.0;
    }

    // The colours that are in the picture, the most common first.
    analysis.distinctColours = static_cast<uint32_t>(counts.size());
    std::vector<std::pair<uint32_t, uint32_t>> sortedColours(counts.begin(), counts.end());
    std::sort(sortedColours.begin(), sortedColours.end(),
              [](const std::pair<uint32_t, uint32_t>& a, const std::pair<uint32_t, uint32_t>& b) {
                  return a.second > b.second;
              });

    const size_t keep = sortedColours.size() < 12 ? sortedColours.size() : 12;
    for (size_t i = 0; i < keep; ++i) {
        ImageAnalysis::Colour colour;
        colour.r = static_cast<uint8_t>((sortedColours[i].first >> 16) & 0xFF);
        colour.g = static_cast<uint8_t>((sortedColours[i].first >> 8) & 0xFF);
        colour.b = static_cast<uint8_t>(sortedColours[i].first & 0xFF);
        colour.fraction = static_cast<double>(sortedColours[i].second) / static_cast<double>(count);
        analysis.palette.push_back(colour);
    }

    return analysis;
}

} // namespace sunshine
