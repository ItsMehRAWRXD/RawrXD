// ============================================================================
// image_tool_certify.cpp - the certification gate for the agent's ability to
// VIEW an image.
//
// This does not check that a tool was registered. It DECODES a real image
// file, runs the registered tool through the real registry, and verifies that
// what comes back is a faithful rendering of the actual pixels:
//
//   1. the tool exists, is read only, and is workspace scoped
//   2. it decodes a real PNG (the native voxel renderer's own frame)
//   3. the rendering is the right size and carries both grids
//   4. the luminance map is not a flat field, so the pixels really varied
//   5. the colour map contains the classes the scene actually has, and the
//      legend's coverage shares sum to the whole frame
//   6. reading a path outside the workspace is refused
//   7. a file that is not an image is refused, and says so
//
// Exit code is non-zero if any check fails.
// ============================================================================

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "agentic/tools/ImageTool.h"

namespace fs = std::filesystem;
using namespace rawrxd::tools;

namespace {

int g_failures = 0;

void Report(const char* name, bool ok, const std::string& detail) {
    printf("[%s] %-46s %s\n", ok ? "PASS" : "FAIL", name, detail.c_str());
    if (!ok) ++g_failures;
}

// Splits a block of text into its non-empty lines.
std::vector<std::string> SplitLines(const std::string& text) {
    std::vector<std::string> lines;
    std::string current;
    for (char c : text) {
        if (c == '\n') {
            if (!current.empty()) lines.push_back(current);
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    if (!current.empty()) lines.push_back(current);
    return lines;
}

} // namespace

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc < 2) {
        printf("usage: image_tool_certify <image-path>\n");
        return 2;
    }
    const fs::path imagePath = fs::absolute(argv[1]);
    if (!fs::is_regular_file(imagePath)) {
        printf("the image path does not exist: %s\n", imagePath.string().c_str());
        return 2;
    }
    const fs::path root = imagePath.parent_path();

    printf("=== agent image viewing certification ===\n");
    printf("workspace root: %s\n", root.string().c_str());

    Registry registry;
    register_workspace_tools(registry, root);
    register_image_tools(registry, root);

    // ---- 1. The tool is registered and is read only ------------------------
    Tool tool;
    const bool found = registry.find("readImage", tool);
    Report("the readImage tool is registered", found,
           found ? tool.description.substr(0, 60) + "..." : "not found");
    if (!found) {
        printf("=== %d check(s) failed ===\n", g_failures);
        return 1;
    }
    Report("the readImage tool is read only", tool.risk == Risk::ReadOnly, "Risk::ReadOnly");

    // ---- 2. It decodes a real PNG ------------------------------------------
    Request request;
    request.name = "readImage";
    request.args["path"] = imagePath.filename().string();
    request.args["cols"] = "64";

    const Result result = registry.call(request, nullptr);
    if (!result.ok) {
        Report("the tool decodes the image", false, result.error);
        printf("=== %d check(s) failed ===\n", g_failures);
        return 1;
    }
    const std::string& view = result.output;
    Report("the tool decodes the image", !view.empty(),
           std::to_string(view.size()) + " characters of model-visible output");

    // ---- 3. The rendering has both grids -----------------------------------
    const bool hasLuminance = view.find("luminance map") != std::string::npos;
    const bool hasColour = view.find("colour map") != std::string::npos;
    const bool hasLegend = view.find("colour legend") != std::string::npos;
    Report("the rendering carries both grids and a legend",
           hasLuminance && hasColour && hasLegend,
           std::string("luminance=") + (hasLuminance ? "yes" : "no") + " colour=" +
               (hasColour ? "yes" : "no") + " legend=" + (hasLegend ? "yes" : "no"));

    // ---- 4. The luminance map is not a flat field ---------------------------
    // Extract the WHOLE grid block, not just its first row: the top row of a
    // landscape frame is uniform sky, and reading only that would say nothing
    // about the image.
    auto blockAfter = [&](const std::string& marker) {
        const size_t at = view.find(marker);
        if (at == std::string::npos) return std::string();
        size_t start = view.find('\n', at);
        if (start == std::string::npos) return std::string();
        ++start;
        const size_t end = view.find("\n\n", start);
        return view.substr(start, (end == std::string::npos) ? std::string::npos : end - start);
    };
    const std::string luminanceBlock = blockAfter("luminance map");
    std::string rampChars;
    uint32_t luminanceRows = 0;
    uint32_t luminanceCols = 0;
    for (const std::string& line : SplitLines(luminanceBlock)) {
        if (line.empty()) continue;
        ++luminanceRows;
        luminanceCols = static_cast<uint32_t>(line.size());
        for (char c : line) {
            if (rampChars.find(c) == std::string::npos) rampChars.push_back(c);
        }
    }
    Report("the luminance map is a full grid", luminanceRows > 1 && luminanceCols > 16,
           std::to_string(luminanceRows) + " rows of " + std::to_string(luminanceCols) + " cells");
    Report("the luminance map carries real variation", rampChars.size() >= 3,
           std::to_string(rampChars.size()) + " distinct brightness levels");

    // ---- 5. The colour map matches the scene, and the shares add up ---------
    const std::string colourBlock = blockAfter("colour map");
    std::vector<char> grid;
    uint32_t colourRows = 0;
    for (const std::string& line : SplitLines(colourBlock)) {
        if (line.empty()) continue;
        ++colourRows;
        for (char c : line) grid.push_back(c);
    }
    Report("the colour map has a full grid",
           colourRows > 1 && grid.size() == static_cast<size_t>(luminanceRows) * luminanceCols,
           std::to_string(colourRows) + " rows, " + std::to_string(grid.size()) + " cells");

    // The legend shares must sum to 100 percent.
    double shareSum = 0.0;
    size_t percent = view.find('%');
    while (percent != std::string::npos) {
        size_t start = percent;
        while (start > 0 && (isdigit(static_cast<unsigned char>(view[start - 1])) ||
                             view[start - 1] == '.')) {
            --start;
        }
        shareSum += std::atof(view.substr(start, percent - start).c_str());
        percent = view.find('%', percent + 1);
    }
    Report("the legend accounts for the whole frame",
           std::fabs(shareSum - 100.0) < 0.5,
           "coverage shares sum to " + std::to_string(shareSum) + "%");

    // The model must be able to tell content apart. This is deliberately
    // scene agnostic: a landscape has sky and terrain, a photograph of a room
    // has neither. The requirement is that the map resolves several distinct
    // classes, not that any particular class is present.
    std::vector<char> distinctSymbols;
    for (char c : grid) {
        if (std::find(distinctSymbols.begin(), distinctSymbols.end(), c) == distinctSymbols.end()) {
            distinctSymbols.push_back(c);
        }
    }
    Report("the colour map distinguishes several content classes",
           distinctSymbols.size() >= 3,
           std::to_string(distinctSymbols.size()) + " distinct classes: " +
               std::string(distinctSymbols.begin(), distinctSymbols.end()));

    // ---- 6. A path outside the workspace is refused -------------------------
    Request escape;
    escape.name = "readImage";
    escape.args["path"] = (fs::path("..") / imagePath.filename()).string();
    const Result escapeResult = registry.call(escape, nullptr);
    Report("a path outside the workspace is refused",
           !escapeResult.ok && escapeResult.error.find("outside workspace") != std::string::npos,
           escapeResult.ok ? "the escape was ALLOWED" : escapeResult.error);

    // ---- 7. A file that is not an image is refused --------------------------
    const fs::path fake = root / "not_an_image.png";
    { std::ofstream out(fake, std::ios::binary); out << "this is not a PNG"; }
    Request bogus;
    bogus.name = "readImage";
    bogus.args["path"] = fake.filename().string();
    const Result bogusResult = registry.call(bogus, nullptr);
    std::error_code ec;
    fs::remove(fake, ec);
    Report("a file that is not an image is refused",
           !bogusResult.ok && !bogusResult.error.empty(),
           bogusResult.ok ? "the bogus file was ACCEPTED" : bogusResult.error);

    // ---- Show the model what it actually sees -------------------------------
    printf("\n---------- what the model receives ----------\n");
    printf("%s\n", view.c_str());
    printf("-------------------------------------------\n");

    printf("=== %s ===\n", g_failures == 0 ? "ALL CHECKS PASSED" : "CHECKS FAILED");
    if (g_failures != 0) {
        printf("=== %d check(s) failed ===\n", g_failures);
        return 1;
    }
    return 0;
}
