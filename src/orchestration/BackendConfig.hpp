#pragma once
#include <string>

enum class BackendType : int {
    PowerShell   = 1,
    BareMetal    = 2,
    RemoteAgent  = 3,
    Sandbox      = 4
};

struct ConfigurationSession {
    BackendType activeBackend;
    BackendType fallbackBackend;
    int timeoutMs;
    bool allowScripts;
};

class BackendConfig {
public:
    static std::string ResolveAppDataPath();
    static bool SaveToDisk(const ConfigurationSession& session);
    static ConfigurationSession LoadFromDisk();
};
