#pragma once

// Strict adapter for the native Deep2 text-tool protocol.  Ollama exposes
// structured tool_calls, while a local GGUF may only be able to emit text.
// This parser is deliberately small and fail-closed: prose, partial commands,
// unknown verbs, and trailing model chatter are never dispatchable.

#include <cctype>
#include <string>
#include <string_view>

namespace rawrxd::agentic {

struct NativeToolCommand {
    bool valid = false;
    bool finish = false;
    std::string tool;
    std::string path;
    std::string content;
    std::string command;
    std::string error;
};

inline std::string NativeToolTrim(std::string_view value) {
    size_t first = 0;
    while (first < value.size() &&
           std::isspace(static_cast<unsigned char>(value[first]))) {
        ++first;
    }
    size_t last = value.size();
    while (last > first &&
           std::isspace(static_cast<unsigned char>(value[last - 1]))) {
        --last;
    }
    return std::string(value.substr(first, last - first));
}

inline std::string NativeToolRemoveEndMarkers(std::string value) {
    // Models commonly emit one of these control tokens after a complete
    // command.  They are terminators, not command payload, and are accepted
    // only at the end of the response.
    constexpr std::string_view markers[] = {
        "<|eot_id|>", "<|end_of_text|>", "<|im_end|>", "<|eom_id|>"
    };
    for (;;) {
        value = NativeToolTrim(value);
        bool removed = false;
        for (const auto marker : markers) {
            if (value.size() >= marker.size() &&
                value.compare(value.size() - marker.size(), marker.size(), marker) == 0) {
                value.resize(value.size() - marker.size());
                removed = true;
                break;
            }
        }
        if (!removed) return NativeToolTrim(value);
    }
}

inline NativeToolCommand ParseNativeToolCommand(std::string_view response) {
    NativeToolCommand out;
    const std::string text = NativeToolRemoveEndMarkers(std::string(response));
    if (text.empty()) {
        out.error = "empty native tool response";
        return out;
    }
    if (text.rfind("TOOL ", 0) != 0) {
        out.error = "response must start with TOOL";
        return out;
    }

    if (text == "TOOL finish") {
        out.valid = true;
        out.finish = true;
        out.tool = "finish";
        out.command = text;
        return out;
    }

    constexpr std::string_view readPrefix = "TOOL read ";
    if (text.rfind(readPrefix, 0) == 0) {
        const std::string path = NativeToolTrim(text.substr(readPrefix.size()));
        if (path.empty() || path.find_first_of("\r\n\t ") != std::string::npos) {
            out.error = "read requires one relative path";
            return out;
        }
        out.valid = true;
        out.tool = "readFile";
        out.path = path;
        out.command = text;
        return out;
    }

    constexpr std::string_view writePrefix = "TOOL write ";
    if (text.rfind(writePrefix, 0) == 0) {
        const size_t pathEnd = text.find_first_of(" \t\r\n", writePrefix.size());
        if (pathEnd == std::string::npos) {
            out.error = "write requires a path and @@ payload";
            return out;
        }
        const std::string path = std::string(text.substr(writePrefix.size(),
                                                          pathEnd - writePrefix.size()));
        const size_t open = text.find("@@", pathEnd);
        const size_t close = open == std::string::npos
            ? std::string::npos : text.rfind("@@");
        if (path.empty() || path.find_first_of("\r\n\t ") != std::string::npos ||
            open == std::string::npos || close <= open + 1 ||
            close + 2 != text.size()) {
            out.error = "write requires one path and a complete @@...@@ payload";
            return out;
        }
        out.valid = true;
        out.tool = "writeFile";
        out.path = path;
        out.content = text.substr(open + 2, close - open - 2);
        out.command = text;
        return out;
    }

    // These commands are bounded host operations.  They are not arbitrary
    // shell text, so the native model cannot smuggle a second command through
    // this adapter.
    if (text == "TOOL build" || text == "TOOL test") {
        out.valid = true;
        out.tool = "runInTerminal";
        out.command = text == "TOOL build"
            ? "cmake --build build_ide --config Release"
            : "ctest --test-dir build_ide --output-on-failure";
        return out;
    }

    out.error = "unsupported native tool command";
    return out;
}

} // namespace rawrxd::agentic
