#include "ReverseModelLoader.hpp"
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cctype>

namespace rxd::reverse {

static std::string ReadFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open model file: " + path);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::string ExtractString(const std::string& json, const std::string& key) {
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return {};
    pos = json.find(':', pos);
    if (pos == std::string::npos) return {};
    pos = json.find('"', pos);
    if (pos == std::string::npos) return {};
    size_t end = json.find('"', pos + 1);
    if (end == std::string::npos) return {};
    return json.substr(pos + 1, end - pos - 1);
}

static double ExtractDouble(const std::string& json, const std::string& key, double fallback) {
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return fallback;
    pos = json.find(':', pos);
    if (pos == std::string::npos) return fallback;
    size_t n = json.find_first_of("0123456789.-+", pos + 1);
    if (n == std::string::npos) return fallback;
    size_t e = json.find_first_not_of("0123456789.-+", n);
    try {
        return std::stod(json.substr(n, e == std::string::npos ? std::string::npos : e - n));
    } catch (...) {
        return fallback;
    }
}

static std::vector<uint8_t> ExtractByteArray(const std::string& json, size_t start, size_t end) {
    std::vector<uint8_t> out;
    size_t p = start;
    while (p < end) {
        size_t n = json.find_first_of("0123456789", p);
        if (n >= end) break;
        size_t e = json.find_first_not_of("0123456789", n);
        if (e > end) e = end;
        out.push_back(static_cast<uint8_t>(std::stoi(json.substr(n, e - n))));
        p = e;
    }
    return out;
}

// Find the array that follows a given key, respecting nested braces/brackets.
static bool FindArray(const std::string& json, const std::string& key, size_t& out_start, size_t& out_end) {
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return false;
    pos = json.find('[', pos);
    if (pos == std::string::npos) return false;

    int depth = 1;
    size_t i = pos + 1;
    while (i < json.size() && depth > 0) {
        char c = json[i];
        if (c == '[') ++depth;
        else if (c == ']') --depth;
        else if (c == '"') {
            ++i;
            while (i < json.size() && json[i] != '"') {
                if (json[i] == '\\' && i + 1 < json.size()) ++i;
                ++i;
            }
        }
        ++i;
    }
    if (depth != 0) return false;
    out_start = pos;
    out_end = i - 1;
    return true;
}

static void ParsePatterns(const std::string& json, ReverseModel& model) {
    size_t arr_start, arr_end;
    if (!FindArray(json, "patterns", arr_start, arr_end)) return;

    size_t p = arr_start + 1;
    while (p < arr_end) {
        size_t obj_start = json.find('{', p);
        if (obj_start == std::string::npos || obj_start > arr_end) break;

        int depth = 1;
        size_t i = obj_start + 1;
        while (i < arr_end && depth > 0) {
            char c = json[i];
            if (c == '{') ++depth;
            else if (c == '}') --depth;
            else if (c == '"') {
                ++i;
                while (i < arr_end && json[i] != '"') {
                    if (json[i] == '\\' && i + 1 < json.size()) ++i;
                    ++i;
                }
            }
            ++i;
        }
        if (depth != 0) break;
        size_t obj_end = i - 1;
        std::string obj = json.substr(obj_start, obj_end - obj_start + 1);

        Pattern pat;
        pat.id = ExtractString(obj, "id");
        if (pat.id.empty()) pat.id = ExtractString(obj, "pattern");
        pat.mnemonic = ExtractString(obj, "pattern");
        pat.description = ExtractString(obj, "description");
        pat.weight = ExtractDouble(obj, "base_weight", 1.0);
        if (pat.weight == 0.0) pat.weight = ExtractDouble(obj, "confidence_weight", 1.0);
        pat.priority = static_cast<int>(ExtractDouble(obj, "priority", 0.0));

        size_t bstart = obj.find('[');
        size_t bend = obj.find(']', bstart);
        if (bstart != std::string::npos && bend != std::string::npos) {
            pat.bytes = ExtractByteArray(obj, bstart, bend);
        }

        size_t mstart = obj.find('[', bend != std::string::npos ? bend + 1 : bstart + 1);
        size_t mend = obj.find(']', mstart);
        if (mstart != std::string::npos && mend != std::string::npos && mstart != bstart) {
            pat.mask = ExtractByteArray(obj, mstart, mend);
        }

        model.patterns.push_back(std::move(pat));
        p = obj_end + 1;
    }
}

static void ParseSamples(const std::string& json, ReverseModel& model) {
    size_t arr_start, arr_end;
    if (!FindArray(json, "samples", arr_start, arr_end)) return;

    size_t p = arr_start + 1;
    while (p < arr_end) {
        size_t obj_start = json.find('{', p);
        if (obj_start == std::string::npos || obj_start > arr_end) break;

        int depth = 1;
        size_t i = obj_start + 1;
        while (i < arr_end && depth > 0) {
            char c = json[i];
            if (c == '{') ++depth;
            else if (c == '}') --depth;
            else if (c == '"') {
                ++i;
                while (i < arr_end && json[i] != '"') {
                    if (json[i] == '\\' && i + 1 < json.size()) ++i;
                    ++i;
                }
            }
            ++i;
        }
        if (depth != 0) break;
        size_t obj_end = i - 1;
        std::string obj = json.substr(obj_start, obj_end - obj_start + 1);

        Sample s;
        s.input = ExtractString(obj, "input");
        s.output = static_cast<uint8_t>(ExtractDouble(obj, "output", 0.0));
        s.confidence = ExtractDouble(obj, "confidence", 0.0);
        model.samples.push_back(std::move(s));
        p = obj_end + 1;
    }
}

ReverseModel ReverseModelLoader::LoadFromJson(const std::string& json) {
    ReverseModel model;
    model.name = ExtractString(json, "name");
    model.type = ExtractString(json, "type");
    model.version = ExtractString(json, "version");
    model.description = ExtractString(json, "model_description");
    model.minConfidence = ExtractDouble(json, "min_confidence", 0.65);
    if (model.minConfidence == 0.65) {
        model.minConfidence = ExtractDouble(json, "minConfidence", 0.65);
    }
    model.allowPartial = true;
    model.normalizeBytes = true;
    model.dedupeConsecutive = true;

    // Parse post_processing clip_range
    size_t pp_pos = json.find("\"post_processing\"");
    if (pp_pos != std::string::npos) {
        size_t obj_start = json.find('{', pp_pos);
        size_t obj_end = json.find('}', obj_start);
        if (obj_start != std::string::npos && obj_end != std::string::npos) {
            std::string pp_obj = json.substr(obj_start, obj_end - obj_start + 1);
            model.dedupeConsecutive = ExtractDouble(pp_obj, "dedupe_consecutive", 1.0) >= 0.5;
            model.normalizeBytes = ExtractDouble(pp_obj, "normalize_byte_range", 1.0) >= 0.5;
            size_t clip_start = pp_obj.find('[');
            size_t clip_end = pp_obj.find(']', clip_start);
            if (clip_start != std::string::npos && clip_end != std::string::npos) {
                auto clip = ExtractByteArray(pp_obj, clip_start, clip_end);
                if (clip.size() >= 2) {
                    model.clipMin = clip[0];
                    model.clipMax = clip[1];
                }
            }
        }
    }

    // Parse export.compatible_with
    size_t ex_pos = json.find("\"export\"");
    if (ex_pos != std::string::npos) {
        size_t arr_start, arr_end;
        if (FindArray(json, "compatible_with", arr_start, arr_end)) {
            size_t p = arr_start + 1;
            while (p < arr_end) {
                size_t str_start = json.find('"', p);
                if (str_start == std::string::npos || str_start >= arr_end) break;
                size_t str_end = json.find('"', str_start + 1);
                if (str_end == std::string::npos || str_end >= arr_end) break;
                model.compatibleWith.push_back(json.substr(str_start + 1, str_end - str_start - 1));
                p = str_end + 1;
            }
        }
    }

    ParsePatterns(json, model);
    ParseSamples(json, model);
    return model;
}

ReverseModel ReverseModelLoader::LoadFromFile(const std::string& path) {
    return LoadFromJson(ReadFile(path));
}

} // namespace rxd::reverse
