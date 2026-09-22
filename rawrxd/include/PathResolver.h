#pragma once
#include <string>

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
};
