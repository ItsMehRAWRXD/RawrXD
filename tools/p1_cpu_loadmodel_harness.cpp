// P1 Scenario 2 localization harness — smallest CPUInferenceEngine::LoadModel call.
// Modes:
//   default / --native-only : LoadModel alone (baseline)
//   --after-streaming       : StreamingGGUF Open→Parse→Index→LoadZone then LoadModel
//                             (matches IDE S2 product order without UI pump)
#include "cpu_inference_engine.h"
#include "streaming_gguf_loader.h"
#include "win32app/p1_load_checkpoint.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <windows.h>

static void onInvalidParam(const wchar_t*, const wchar_t*, const wchar_t*, unsigned int, uintptr_t)
{
    RawrXD::P1LoadCkpt::emit("CRT_INVALID_PARAMETER", "aborting");
}

static void onPurecall()
{
    RawrXD::P1LoadCkpt::emit("CRT_PURECALL", "aborting");
}

static bool runStreamingPrefix(const char* path)
{
    RawrXD::P1LoadCkpt::emit("STREAM_PREFIX", "enter");
    // Keep open for process lifetime — product path keeps m_ggufLoader mapped.
    static RawrXD::StreamingGGUFLoader* s_keep = new RawrXD::StreamingGGUFLoader();
    RawrXD::StreamingGGUFLoader& loader = *s_keep;
    if (!loader.Open(path))
    {
        RawrXD::P1LoadCkpt::emit("STREAM_PREFIX", "Open_FAIL");
        return false;
    }
    RawrXD::P1LoadCkpt::emit("STREAM_PREFIX", "Open_ok");
    if (!loader.ParseHeader())
    {
        RawrXD::P1LoadCkpt::emit("STREAM_PREFIX", "ParseHeader_FAIL");
        return false;
    }
    RawrXD::P1LoadCkpt::emit("STREAM_PREFIX", "ParseHeader_ok");
    if (!loader.ParseMetadata())
    {
        RawrXD::P1LoadCkpt::emit("STREAM_PREFIX", "ParseMetadata_FAIL");
        return false;
    }
    RawrXD::P1LoadCkpt::emit("STREAM_PREFIX", "ParseMetadata_ok");
    if (!loader.BuildTensorIndex())
    {
        RawrXD::P1LoadCkpt::emit("STREAM_PREFIX", "BuildTensorIndex_FAIL");
        return false;
    }
    RawrXD::P1LoadCkpt::emit("STREAM_PREFIX", "BuildTensorIndex_ok");
    (void)loader.LoadZone("embedding");
    RawrXD::P1LoadCkpt::emit("STREAM_PREFIX", "done_keep_open");
    return true;
}

int main(int argc, char** argv)
{
    _set_invalid_parameter_handler(onInvalidParam);
    _set_purecall_handler(onPurecall);

    bool afterStreaming = false;
    const char* path = "F:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    for (int i = 1; i < argc; ++i)
    {
        if (!argv[i])
            continue;
        if (strcmp(argv[i], "--after-streaming") == 0)
            afterStreaming = true;
        else if (strcmp(argv[i], "--native-only") == 0)
            afterStreaming = false;
        else if (argv[i][0] != '-')
            path = argv[i];
    }

    RawrXD::P1LoadCkpt::reset();
    RawrXD::P1LoadCkpt::emit("HARNESS_ENTER", path);
    RawrXD::P1LoadCkpt::emit("HARNESS_MODE", afterStreaming ? "after_streaming" : "native_only");
    RawrXD::P1LoadCkpt::emit("THREAD", "main");

    DWORD attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY))
    {
        RawrXD::P1LoadCkpt::emit("MODEL_FILE", "MISSING");
        return 3;
    }
    RawrXD::P1LoadCkpt::emit("MODEL_FILE", "OK");

    if (afterStreaming)
    {
        if (!runStreamingPrefix(path))
            return 5;
    }

    RawrXD::P1LoadCkpt::emit("GET_SHARED_INSTANCE", "before");
    auto eng = RawrXD::CPUInferenceEngine::GetSharedInstance();
    if (!eng)
    {
        RawrXD::P1LoadCkpt::emit("GET_SHARED_INSTANCE", "NULL");
        return 4;
    }
    RawrXD::P1LoadCkpt::emit("GET_SHARED_INSTANCE", "ok");

    RawrXD::P1LoadCkpt::emit("LOADMODEL", "before");
    const bool ok = eng->LoadModel(path);
    RawrXD::P1LoadCkpt::emit("LOADMODEL", ok ? "ok" : "fail");
    if (!ok)
    {
        const std::string err = eng->GetLastLoadErrorMessage();
        RawrXD::P1LoadCkpt::emit("LOAD_ERROR", err.empty() ? "(empty)" : err.c_str());
        return 2;
    }

    RawrXD::P1LoadCkpt::emit("MODEL_LOADED", eng->IsModelLoaded() ? "true" : "false");
    RawrXD::P1LoadCkpt::emit("HARNESS_PASS", path);
    return 0;
}
