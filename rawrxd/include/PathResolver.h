#pragma once
#include <string>

// RAWRXD_GOLD_LINK_BLOCKER_003
// This header calls GetEnvironmentVariableA and uses MAX_PATH without declaring
// either. Both come from <windows.h>, which nothing above this header provides,
// so every translation unit that included it failed at the use site rather than
// at the include:
//
//     include\PathResolver.h(9,18):  error C2065: 'MAX_PATH': undeclared identifier
//     include\PathResolver.h(10,13): error C3861: 'GetEnvironmentVariableA': identifier not found
//     include\PathResolver.h(10,59): error C2065: 'MAX_PATH': undeclared identifier
//     include\PathResolver.h(13,13): error C3861: 'GetEnvironmentVariableA': identifier not found
//     include\PathResolver.h(13,57): error C2065: 'MAX_PATH': undeclared identifier
//
// The include belongs HERE, not at a call site: this is a header, and depending
// on the includer to have already pulled in <windows.h> is what made the failure
// depend on include order rather than on this file's own contents. The guards
// below match the rest of the tree's convention, because <windows.h> defines
// min/max macros that collide with <algorithm>.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

// Minimal stub — pre-existing dependency gap in repo.
// Full implementation should resolve canonical model paths from env/registry.
class PathResolver {
public:
    static std::string getModelsPath() {
        char buf[MAX_PATH]{};
        if (GetEnvironmentVariableA("OLLAMA_MODELS", buf, MAX_PATH) > 0) {
            return std::string(buf);
        }
        if (GetEnvironmentVariableA("USERPROFILE", buf, MAX_PATH) > 0) {
            return std::string(buf) + "\\.ollama\\models";
        }
        return std::string("C:\\.ollama\\models");
    }

    // RAWRXD_GOLD_LINK_BLOCKER_008 -- getPluginsPath, restored.
    //
    // src/core/ssot_handlers_ext.cpp calls PathResolver::getPluginsPath() at
    // lines 6800 and 6902 while probing for RawrXD_UnrealBridge.dll and
    // RawrXD_UnityBridge.dll, and the member did not exist:
    //     ssot_handlers_ext.cpp(6800,43): error C2039: 'getPluginsPath': is not a
    //         member of 'PathResolver'
    // (the same line also produced C3861 'identifier not found', which is the
    // same fact reported a second way -- the compiler names the qualified and
    // the unqualified lookup separately).
    //
    // CONTRACT, taken from how the two callers use the return value rather than
    // invented: both do
    //     if (!pluginDir.empty())
    //         candidates.insert(candidates.begin(), pluginDir + "\\" + <dll>);
    // so an empty result is a meaningful state meaning "no plugins directory
    // is configured", and a non-empty result names the one directory to try
    // first. That is why this returns EMPTY when nothing is configured instead of
    // a hardcoded fallback the way getModelsPath does.
    //
    // The two differ deliberately. getModelsPath can fall back because Ollama
    // model locations are genuinely well known -- the code uses the same default
    // at its own last line. A plugins directory has no such convention: returning
    // a guessed path would make both callers probe a directory that has never
    // existed, which is a claim this function cannot support.
    //
    // Resolution order: RAWRXD_PLUGINS if set, else RAWRXD_HOME + "\plugins" if
    // set, else %USERPROFILE%\.rawrxd\plugins if USERPROFILE is set, else "".
    static std::string getPluginsPath() {
        char buf[MAX_PATH]{};

        if (GetEnvironmentVariableA("RAWRXD_PLUGINS", buf, MAX_PATH) > 0 && buf[0]) {
            return std::string(buf);
        }

        if (GetEnvironmentVariableA("RAWRXD_HOME", buf, MAX_PATH) > 0 && buf[0]) {
            return std::string(buf) + "\\plugins";
        }

        if (GetEnvironmentVariableA("USERPROFILE", buf, MAX_PATH) > 0 && buf[0]) {
            return std::string(buf) + "\\.rawrxd\\plugins";
        }

        // No configuration and no user profile: report nothing rather than guess.
        return std::string();
    }
};
