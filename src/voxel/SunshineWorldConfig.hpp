// ============================================================================
// SunshineWorldConfig.hpp - the world generation configuration and its
// dependency-free JSON serialization.
//
// The configuration is the exact shape the world designer exports:
//
//   {"seed":1337,"world":"islands","scale":1,"sea":64,"mountains":35,
//    "erosion":55,"caves":40,"trees":85,"temperature":85,"humidity":80,
//    "rivers":40,"structures":35}
//
// The parser and the serializer are hand written. There is no third-party
// JSON library in this module, and the output is byte stable: the same
// configuration always produces the same text, which is what makes a preset
// comparable and diffable.
//
// The percentage fields (sea, mountains, erosion, caves, trees, temperature,
// humidity, rivers, structures) are expressed on a 0..100 scale and are
// mapped onto the engine's fixed world height at generation time.
// ============================================================================

#pragma once

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "sunshine/WorldGen.hpp"

namespace RawrXD {
namespace Voxel {

struct SunshineWorldConfig {
    uint64_t seed = 1337;
    std::string world = "islands";
    double scale = 1.0;
    int sea = 64;
    int mountains = 35;
    int erosion = 55;
    int caves = 40;
    int trees = 85;
    int temperature = 85;
    int humidity = 80;
    int rivers = 40;
    int structures = 35;

    // ---- Serialization ------------------------------------------------------

    // The exact text the world designer exports, in the same key order, with
    // no spaces. Stable across runs.
    std::string ToJson() const {
        std::ostringstream out;
        out << "{\"seed\":" << seed
            << ",\"world\":\"" << world << "\""
            << ",\"scale\":" << FormatScale(scale)
            << ",\"sea\":" << sea
            << ",\"mountains\":" << mountains
            << ",\"erosion\":" << erosion
            << ",\"caves\":" << caves
            << ",\"trees\":" << trees
            << ",\"temperature\":" << temperature
            << ",\"humidity\":" << humidity
            << ",\"rivers\":" << rivers
            << ",\"structures\":" << structures
            << "}";
        return out.str();
    }

    // Parses the flat object form above. Unknown keys are ignored, missing
    // keys keep their default. Returns false and fills `error` on a
    // malformed document.
    bool ParseJson(const std::string& text, std::string* error) {
        std::size_t pos = 0;
        auto skipSpace = [&]() {
            while (pos < text.size() &&
                   (text[pos] == ' ' || text[pos] == '\t' || text[pos] == '\r' || text[pos] == '\n')) {
                ++pos;
            }
        };
        auto fail = [&](const char* what) {
            if (error) {
                std::ostringstream out;
                out << what << " at offset " << pos;
                *error = out.str();
            }
            return false;
        };

        skipSpace();
        if (pos >= text.size() || text[pos] != '{') return fail("expected '{'");
        ++pos;
        skipSpace();

        if (pos < text.size() && text[pos] == '}') {
            ++pos;
            return true;  // an empty object keeps every default
        }

        while (pos < text.size()) {
            skipSpace();
            if (pos >= text.size() || text[pos] != '"') return fail("expected a key");
            ++pos;
            const size_t keyStart = pos;
            while (pos < text.size() && text[pos] != '"') ++pos;
            if (pos >= text.size()) return fail("unterminated key");
            const std::string key = text.substr(keyStart, pos - keyStart);
            ++pos;
            skipSpace();
            if (pos >= text.size() || text[pos] != ':') return fail("expected ':'");
            ++pos;
            skipSpace();
            if (pos >= text.size()) return fail("expected a value");

            if (text[pos] == '"') {
                ++pos;
                const size_t valueStart = pos;
                while (pos < text.size() && text[pos] != '"') ++pos;
                if (pos >= text.size()) return fail("unterminated string");
                const std::string value = text.substr(valueStart, pos - valueStart);
                ++pos;
                if (key == "world") world = value;
            } else if (text[pos] == '{' || text[pos] == '[') {
                return fail("nested values are not part of the world configuration schema");
            } else {
                const size_t valueStart = pos;
                while (pos < text.size() && text[pos] != ',' && text[pos] != '}') ++pos;
                const std::string value = text.substr(valueStart, pos - valueStart);
                const double number = ParseNumber(value);
                if (key == "seed") seed = static_cast<uint64_t>(number);
                else if (key == "scale") scale = number;
                else if (key == "sea") sea = static_cast<int>(number);
                else if (key == "mountains") mountains = static_cast<int>(number);
                else if (key == "erosion") erosion = static_cast<int>(number);
                else if (key == "caves") caves = static_cast<int>(number);
                else if (key == "trees") trees = static_cast<int>(number);
                else if (key == "temperature") temperature = static_cast<int>(number);
                else if (key == "humidity") humidity = static_cast<int>(number);
                else if (key == "rivers") rivers = static_cast<int>(number);
                else if (key == "structures") structures = static_cast<int>(number);
            }

            skipSpace();
            if (pos < text.size() && text[pos] == ',') {
                ++pos;
                continue;
            }
            if (pos < text.size() && text[pos] == '}') {
                ++pos;
                return true;
            }
            return fail("expected ',' or '}'");
        }
        return fail("unterminated object");
    }

    bool LoadFile(const std::string& path, std::string* error) {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            if (error) *error = "cannot open the world configuration file";
            return false;
        }
        std::ostringstream buffer;
        buffer << in.rdbuf();
        return ParseJson(buffer.str(), error);
    }

    bool SaveFile(const std::string& path, std::string* error) const {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            if (error) *error = "cannot write the world configuration file";
            return false;
        }
        out << ToJson() << "\n";
        if (!out) {
            if (error) *error = "the world configuration file could not be written";
            return false;
        }
        return true;
    }

    // Clamps every percentage into range. The scale must be positive.
    void Clamp() {
        if (scale <= 0.0) scale = 1.0;
        sea = ClampPercent(sea);
        mountains = ClampPercent(mountains);
        erosion = ClampPercent(erosion);
        caves = ClampPercent(caves);
        trees = ClampPercent(trees);
        temperature = ClampPercent(temperature);
        humidity = ClampPercent(humidity);
        rivers = ClampPercent(rivers);
        structures = ClampPercent(structures);
    }

    // ---- Mapping onto the generator ----------------------------------------

    // The designer's sea level is a PERCENTAGE of the world height. The
    // generator's configuration carries an absolute block level, so the
    // percentage is resolved here, against the engine's real column height.
    //
    // Every other field is already on the 0..100 scale the generator
    // expects, so it passes through unchanged.
    //
    // The generator's first version generates islands only. A request for
    // another mode is reported through `supported`, and the generator is
    // handed the island mode it can actually run rather than being asked
    // for something it would reject.
    bool ToGeneratorConfig(int32_t worldHeight, sunshine::Config& out, bool* supported = nullptr) const {
        SunshineWorldConfig copy = *this;
        copy.Clamp();

        const std::string requested = copy.world;
        out.seed = copy.seed;
        out.scale = static_cast<int>(copy.scale);
        if (out.scale < 1) out.scale = 1;
        if (out.scale > 64) out.scale = 64;
        out.sea = static_cast<int>((static_cast<double>(copy.sea) / 100.0) *
                                   static_cast<double>(worldHeight) + 0.5);
        out.mountains = copy.mountains;
        out.erosion = copy.erosion;
        out.caves = copy.caves;
        out.trees = copy.trees;
        out.temperature = copy.temperature;
        out.humidity = copy.humidity;
        out.rivers = copy.rivers;
        out.structures = copy.structures;

        const bool modeSupported = (requested == "islands");
        if (supported) *supported = modeSupported;
        out.world = "islands";
        return out.valid();
    }

private:
    static int ClampPercent(int value) {
        if (value < 0) return 0;
        if (value > 100) return 100;
        return value;
    }

    static double ParseNumber(const std::string& text) {
        try {
            size_t used = 0;
            const double value = std::stod(text, &used);
            return used == text.size() ? value : 0.0;
        } catch (...) {
            return 0.0;
        }
    }

    // The scale is written without a trailing ".0" when it is integral, so
    // the serialized form matches the designer's export exactly.
    static std::string FormatScale(double value) {
        std::ostringstream out;
        if (value == static_cast<double>(static_cast<long long>(value))) {
            out << static_cast<long long>(value);
        } else {
            out.precision(6);
            out << value;
        }
        return out.str();
    }
};

} // namespace Voxel
} // namespace RawrXD
