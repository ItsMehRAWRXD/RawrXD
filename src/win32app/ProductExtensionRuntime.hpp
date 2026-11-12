// ProductExtensionRuntime — real LocalServer /api/extensions product path.
// Replaces product_thin invent-empty. Fail-closed: no fake host_pid.
// PROMOTE=0 TIP_CLIMB=HOLD ABSORB=NOT_AUTHORIZED tip748B=1
#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <cstdint>
#include <windows.h>

namespace ProductExtensionRuntime {

struct ExtRecord {
    std::string id;
    std::string name;
    std::string version;
    std::string path;
    std::string publisher;
    bool enabled = true;
    bool active = false;
    DWORD processId = 0;
};

struct HostState {
    DWORD hostPid = 0;
    HANDLE hostProcess = nullptr;
    ULONGLONG startTick = 0;
    int extensionsLoaded = 0;
};

void SetRoots(const std::string& projectRoot, const std::string& exeDir);
int Scan();
std::string ListJson();
std::vector<ExtRecord> ListRecords();
std::string LoadManifestPath(const std::string& pathOrVsix);
std::string Activate(const std::string& id);
std::string Enable(const std::string& id, bool enabled);
std::string HostStatusJson();
std::string KillHost();
std::string HandleRoute(const std::string& method, const std::string& path,
                        const std::string& body);
bool ToolActivate(const std::string& id, std::string& outJson);

// Tip probes (WM_COMMAND) — write TOP25_C43_EXTHOST / TOP25_MASM_TOOLING logs.
void ProbeExtHostRuntime();
void ProbeMasmTooling();

} // namespace ProductExtensionRuntime

