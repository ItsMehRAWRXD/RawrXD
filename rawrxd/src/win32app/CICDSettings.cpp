// CICDSettings.cpp — CI/CD pipeline configuration with build/test/deploy stages
#include <windows.h>
#include <cstring>
#include <vector>
#include <functional>
#include <cstdio>
#include <fstream>
#include <sstream>

namespace RawrXD::IDE {

// External settings API
std::string Settings_Get(const std::string& key, const std::string& def);
void Settings_Set(const std::string& key, const std::string& value);
void Settings_Save();

// External build runner
bool BuildRunner_Run(const std::string& cmd, const std::string& dir);
bool BuildRunner_IsRunning();
void BuildRunner_SetOutputCallback(std::function<void(const std::string&)> cb);
void BuildRunner_SetDoneCallback(std::function<void(bool, int, int)> cb);

// ── Pipeline stage ───────────────────────────────────────────────────────────
enum class StageType { Build, Test, Deploy, Custom };

struct PipelineStage {
    std::string name;
    StageType   type;
    std::string command;
    std::string workingDir;
    bool        enabled = true;
    bool        stopOnFailure = true;
    int         timeoutSec = 300;
};

struct CICDState {
    std::vector<PipelineStage> stages;
    std::string pipelineName = "Default";
    bool        running = false;
    int         currentStage = -1;
    std::function<void(const std::string& stage, bool success)> onStageComplete;
    std::function<void(bool allSuccess)> onPipelineComplete;
};

static CICDState g_cicd;

// ── Default pipeline ─────────────────────────────────────────────────────────
static void InitDefaultPipeline()
{
    if (!g_cicd.stages.empty()) return;
    g_cicd.stages = {
        {"CMake Configure", StageType::Build, "cmake -B build -S .", "", true, true, 120},
        {"Build",           StageType::Build, "cmake --build build --config Release", "", true, true, 600},
        {"Unit Tests",      StageType::Test,  "ctest --test-dir build -C Release --output-on-failure", "", true, true, 300},
        {"Package",         StageType::Custom,"cpack -C Release -B build", "", true, false, 120},
    };
}

// ── Stage execution ──────────────────────────────────────────────────────────
static void RunNextStage();

static void OnStageDone(bool success, int errors, int warnings)
{
    if (g_cicd.currentStage < 0 || g_cicd.currentStage >= (int)g_cicd.stages.size()) {
        g_cicd.running = false;
        if (g_cicd.onPipelineComplete) g_cicd.onPipelineComplete(success);
        return;
    }

    auto& stage = g_cicd.stages[g_cicd.currentStage];
    bool stageOk = success && errors == 0;
    if (g_cicd.onStageComplete) g_cicd.onStageComplete(stage.name, stageOk);

    if (!stageOk && stage.stopOnFailure) {
        g_cicd.running = false;
        if (g_cicd.onPipelineComplete) g_cicd.onPipelineComplete(false);
        return;
    }

    ++g_cicd.currentStage;
    if (g_cicd.currentStage >= (int)g_cicd.stages.size()) {
        g_cicd.running = false;
        if (g_cicd.onPipelineComplete) g_cicd.onPipelineComplete(true);
        return;
    }

    RunNextStage();
}

static void RunNextStage()
{
    if (g_cicd.currentStage < 0 || g_cicd.currentStage >= (int)g_cicd.stages.size()) return;
    auto& stage = g_cicd.stages[g_cicd.currentStage];
    if (!stage.enabled) {
        ++g_cicd.currentStage;
        RunNextStage();
        return;
    }
    BuildRunner_SetDoneCallback(OnStageDone);
    BuildRunner_Run(stage.command, stage.workingDir);
}

// ── Public API ────────────────────────────────────────────────────────────────
void CICD_LoadPipeline()
{
    InitDefaultPipeline();
    g_cicd.pipelineName = Settings_Get("cicd.pipelineName", "Default");
    int stageCount = Settings_GetInt("cicd.stageCount", 0);
    if (stageCount > 0) {
        g_cicd.stages.clear();
        for (int i = 0; i < stageCount; ++i) {
            std::string prefix = "cicd.stage" + std::to_string(i) + ".";
            PipelineStage s;
            s.name = Settings_Get(prefix + "name", "Stage " + std::to_string(i));
            std::string t = Settings_Get(prefix + "type", "Build");
            if (t == "Build") s.type = StageType::Build;
            else if (t == "Test") s.type = StageType::Test;
            else if (t == "Deploy") s.type = StageType::Deploy;
            else s.type = StageType::Custom;
            s.command = Settings_Get(prefix + "command", "");
            s.workingDir = Settings_Get(prefix + "workingDir", "");
            s.enabled = Settings_GetBool(prefix + "enabled", true);
            s.stopOnFailure = Settings_GetBool(prefix + "stopOnFailure", true);
            s.timeoutSec = Settings_GetInt(prefix + "timeout", 300);
            g_cicd.stages.push_back(s);
        }
    }
}

void CICD_SavePipeline()
{
    Settings_Set("cicd.pipelineName", g_cicd.pipelineName);
    Settings_SetInt("cicd.stageCount", (int)g_cicd.stages.size());
    for (size_t i = 0; i < g_cicd.stages.size(); ++i) {
        std::string prefix = "cicd.stage" + std::to_string(i) + ".";
        auto& s = g_cicd.stages[i];
        Settings_Set(prefix + "name", s.name);
        std::string t = "Custom";
        if (s.type == StageType::Build) t = "Build";
        else if (s.type == StageType::Test) t = "Test";
        else if (s.type == StageType::Deploy) t = "Deploy";
        Settings_Set(prefix + "type", t);
        Settings_Set(prefix + "command", s.command);
        Settings_Set(prefix + "workingDir", s.workingDir);
        Settings_SetBool(prefix + "enabled", s.enabled);
        Settings_SetBool(prefix + "stopOnFailure", s.stopOnFailure);
        Settings_SetInt(prefix + "timeout", s.timeoutSec);
    }
    Settings_Save();
}

bool CICD_RunPipeline()
{
    if (g_cicd.running) return false;
    if (g_cicd.stages.empty()) InitDefaultPipeline();
    g_cicd.running = true;
    g_cicd.currentStage = 0;
    RunNextStage();
    return true;
}

bool CICD_IsRunning() { return g_cicd.running; }
std::string CICD_GetCurrentStageName()
{
    if (!g_cicd.running || g_cicd.currentStage < 0 || g_cicd.currentStage >= (int)g_cicd.stages.size())
        return "";
    return g_cicd.stages[g_cicd.currentStage].name;
}

void CICD_SetStageCompleteCallback(std::function<void(const std::string&, bool)> cb)
{
    g_cicd.onStageComplete = std::move(cb);
}

void CICD_SetPipelineCompleteCallback(std::function<void(bool)> cb)
{
    g_cicd.onPipelineComplete = std::move(cb);
}

std::vector<PipelineStage>& CICD_GetStages() { return g_cicd.stages; }

void CICD_AddStage(const PipelineStage& stage) { g_cicd.stages.push_back(stage); }
void CICD_ClearStages() { g_cicd.stages.clear(); }
void CICD_RemoveStage(int idx)
{
    if (idx >= 0 && idx < (int)g_cicd.stages.size())
        g_cicd.stages.erase(g_cicd.stages.begin() + idx);
}

void CICD_SetPipelineName(const std::string& name) { g_cicd.pipelineName = name; }
std::string CICD_GetPipelineName() { return g_cicd.pipelineName; }

} // namespace RawrXD::IDE
