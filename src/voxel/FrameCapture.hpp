// ============================================================================
// FrameCapture.hpp — turning a rendered frame into a file and into numbers.
//
// The capture has two jobs. It writes the frame to a file, so that the
// image can be looked at, and it measures the frame, so that a claim about
// what was drawn can be checked without looking at it.
//
// The measurements are the important part. A renderer that draws nothing
// still produces a frame, and the frame still has a file. The statistics
// are what tell the two apart: a frame with terrain in it has a spread of
// colours, a frame that is only sky has one.
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "VoxelRenderer.hpp"

namespace sunshine {

// What a frame actually contains.
struct FrameStatistics {
    uint32_t width = 0;
    uint32_t height = 0;
    uint64_t pixelCount = 0;

    // The number of distinct colours, counted over a sampled grid.
    uint32_t distinctColours = 0;

    // The mean luminance, 0 to 255.
    double meanLuminance = 0.0;

    // The largest and the smallest luminance.
    uint8_t minLuminance = 255;
    uint8_t maxLuminance = 0;

    // The fraction of the frame that is not the sky. A frame with terrain
    // in it has a value well above zero; a frame that is only sky has a
    // value of zero.
    double terrainFraction = 0.0;

    // The number of colours that appear more than once. A blank frame has
    // one; a frame with terrain has many.
    uint32_t repeatedColours = 0;
};

// Measure a frame.
FrameStatistics measureFrame(const CapturedFrame& frame);

// Write a frame as a 24 bit Windows bitmap.
//
// The bitmap is written so that the row order is the normal bottom-up
// order that every bitmap reader expects, and the pixels arrive in BGRA
// from the GPU, so the blue and the red channels are swapped on the way
// out.
bool writeBitmap(const std::string& path, const CapturedFrame& frame, std::string& error);

// Write a frame as a PNG.
//
// The PNG is written with the stored (uncompressed) deflate method, which
// needs no compression library and produces a file every reader accepts.
bool writePng(const std::string& path, const CapturedFrame& frame, std::string& error);

// The bytes of a PNG.
//
// This is what the browser panel needs: the frame is encoded once and
// then handed to the page as a data URL, so no file has to be written
// and read back for every frame.
std::vector<uint8_t> encodePng(const CapturedFrame& frame);

// A coarse picture of the frame, as text.
//
// The frame is reduced to a grid of cells and each cell is mapped to a
// character by its brightness and its colour. It is a way to see a frame
// in a terminal without a terminal that can draw.
std::string frameAsText(const CapturedFrame& frame, int width = 64, int height = 24);

// The hash of a frame.
//
// It is a running sum over the bytes, which is not a hash anybody would
// use to keep a secret, and it is here because it answers one question:
// are these two frames the same picture? Two frames that are the same
// picture have the same hash, and two that are not do not.
uint64_t frameHash(const CapturedFrame& frame);

// How much of one frame is not the other.
//
// The answer is the number of pixels whose colour is different by more
// than a little, which is the measure that says "the camera moved and
// the world came out differently" rather than "the frame is the same
// with a little noise in it".
struct FrameDifference {
    uint64_t differentPixels = 0;
    uint64_t totalPixels = 0;
    double fraction = 0.0;
    double meanAbsoluteDifference = 0.0;
};

FrameDifference compareFrames(const CapturedFrame& a, const CapturedFrame& b);

// A smaller copy of a frame.
//
// The browser panel is given the frame as a picture in a message, and a
// message has a size, so the picture that goes to the browser is made
// smaller first. The reduction is a box filter, so it does not throw the
// detail away the way that taking every other pixel does.
CapturedFrame downscale(const CapturedFrame& frame, uint32_t width, uint32_t height);

// Read a picture that was written by writeBitmap.
//
// The bitmap is the format the vision path of the tree reads, so a
// capture can be handed straight to it.
bool readBitmap(const std::string& path, CapturedFrame& out, std::string& error);

// What a picture says, in numbers.
//
// This is the measure the renderer is judged by. It is not a score, it
// is a description: how much of the picture is sky, how much is ground,
// how bright the picture is from end to end, and how much the picture
// changes as it goes into the distance. That last one is the measure of
// whether the distance is being hidden or is being drawn.
//
struct ImageAnalysis {
    uint32_t width = 0;
    uint32_t height = 0;
    uint64_t pixelCount = 0;

    // The share of the picture that is sky, and the share that is ground.
    double skyFraction = 0.0;
    double groundFraction = 0.0;
    double waterFraction = 0.0;

    // The brightness of the picture, from the dark end to the light end.
    double luminanceP5 = 0.0;
    double luminanceP25 = 0.0;
    double luminanceP50 = 0.0;
    double luminanceP75 = 0.0;
    double luminanceP95 = 0.0;
    double meanLuminance = 0.0;
    double saturation = 0.0;

    // The contrast of eight bands of the picture, from the bottom to the
    // top. A band that is flat is a band where nothing can be seen, and
    // the bands that are flat are usually the ones in the distance.
    double bandContrast[8] = {0};

    // The colours that are in the picture, and how much of it each one
    // covers.
    struct Colour {
        uint8_t r = 0;
        uint8_t g = 0;
        uint8_t b = 0;
        double fraction = 0.0;
    };
    std::vector<Colour> palette;

    // How many different colours are in the picture, all of them and not
    // only the common ones.
    uint32_t distinctColours = 0;
};

// Measure a picture.
ImageAnalysis analyseImage(const CapturedFrame& frame);

} // namespace sunshine
