// ============================================================================
// feature_handlers_model_load.cpp — file.loadModel / !model_load (headless-safe)
// ============================================================================
// Split from feature_handlers.cpp so tests and minimal links can pull GGUF
// validation without Win32IDE, Ollama, hotpatch, and debugger dependencies.
// ============================================================================

#include "feature_handlers.h"
#include "../inference/rxqf_converter.h"

#include <windows.h>

#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

CommandResult handleFileLoadModel(const CommandContext& ctx)
{
    if (!ctx.args || !ctx.args[0])
    {
        ctx.output("Usage: !model_load <path-to-gguf>\n");
        return CommandResult::error("file.loadModel: missing path");
    }
    HANDLE h =
        CreateFileA(ctx.args, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        std::string msg = "[Model] File not found: " + std::string(ctx.args) + "\n";
        ctx.output(msg.c_str());
        return CommandResult::error("file.loadModel: not found");
    }
    uint32_t magic = 0;
    DWORD bytesRead = 0;
    ReadFile(h, &magic, sizeof(magic), &bytesRead, nullptr);
    LARGE_INTEGER fileSize;
    GetFileSizeEx(h, &fileSize);
    CloseHandle(h);
    if (magic != 0x46475547u)
    {
        ctx.output("[Model] Invalid GGUF magic bytes. Not a valid model file.\n");
        return CommandResult::error("file.loadModel: invalid GGUF");
    }
    std::ostringstream oss;
    oss << "[Model] Valid GGUF: " << ctx.args << " (" << (fileSize.QuadPart / (1024 * 1024)) << " MB)\n";
    oss << "[Model] Dispatching to GGUFLoader...\n";
    ctx.output(oss.str().c_str());
    return CommandResult::ok("file.loadModel");
}

CommandResult handleFileConvertToRxqf(const CommandContext& ctx)
{
    if (!ctx.args || !ctx.args[0])
    {
        ctx.output("Usage: !model_to_rxqf <input-model> <output.rxqf> [--no-names] [--align N]\n");
        return CommandResult::error("file.convertToRxqf: missing arguments");
    }

    std::istringstream iss(ctx.args);
    std::vector<std::string> parts;
    std::string tok;
    while (iss >> tok)
    {
        parts.push_back(tok);
    }

    if (parts.size() < 2)
    {
        ctx.output("Usage: !model_to_rxqf <input-model> <output.rxqf> [--no-names] [--align N]\n");
        return CommandResult::error("file.convertToRxqf: missing input/output");
    }

    bool emitNames = true;
    uint64_t alignment = 64;

    for (size_t i = 2; i < parts.size(); ++i)
    {
        if (parts[i] == "--no-names")
        {
            emitNames = false;
            continue;
        }
        if (parts[i] == "--align" && (i + 1) < parts.size())
        {
            try
            {
                alignment = static_cast<uint64_t>(std::stoull(parts[i + 1]));
            }
            catch (...)
            {
                return CommandResult::error("file.convertToRxqf: invalid --align value");
            }
            ++i;
            continue;
        }
    }

    std::ostringstream pre;
    pre << "[RXQF] Converting: " << parts[0] << " -> " << parts[1] << "\n";
    pre << "[RXQF] Options: names=" << (emitNames ? "on" : "off")
        << ", align=" << alignment << "\n";
    ctx.output(pre.str().c_str());

    PatchResult r = RawrXD::Inference::ConvertModelToRXQF(parts[0], parts[1], emitNames, alignment);
    if (!r.success)
    {
        std::string msg = "[RXQF] Conversion failed: " + r.detail + "\n";
        ctx.output(msg.c_str());
        return CommandResult::error("file.convertToRxqf: failed", r.errorCode);
    }

    std::string ok = "[RXQF] Conversion complete: " + parts[1] + "\n";
    ctx.output(ok.c_str());
    return CommandResult::ok("file.convertToRxqf");
}
