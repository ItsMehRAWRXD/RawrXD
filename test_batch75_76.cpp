// test_batch75_76.cpp — Compilation test for Batch 75 (Workspace) and Batch 76 (Tasks)
#include "../workspace/workspace_manager.hpp"
#include "../tasks/task_runner.hpp"

int main() {
    // Test Batch 75: Workspace Intelligence
    RawrXD::Workspace::WorkspaceManager ws;
    ws.Initialize();
    ws.AddFolder("d:\\rawrxd");
    ws.IndexAllProjects();
    auto projects = ws.GetProjects();
    auto graph = ws.BuildGraph();
    auto depOrder = ws.GetDependencyOrder();
    ws.SetSetting("editor.fontSize", "14");
    auto fontSize = ws.GetSetting("editor.fontSize");
    ws.SaveWorkspaceFile("d:\\rawrxd\\test.rawrxd-workspace");
    ws.Shutdown();

    // Test Batch 76: Task Automation
    RawrXD::Tasks::TaskRunner runner;
    runner.Initialize();

    RawrXD::Tasks::TaskDefinition buildTask;
    buildTask.label = "Build";
    buildTask.command = "ninja -C build_ninja RawrXD-Win32IDE.exe";
    buildTask.type = RawrXD::Tasks::TaskType::Shell;
    buildTask.options.group = "build";
    buildTask.options.isDefault = true;
    runner.RegisterTask(buildTask);

    RawrXD::Tasks::TaskDefinition testTask;
    testTask.label = "Test";
    testTask.command = "ctest --test-dir build_ninja";
    testTask.type = RawrXD::Tasks::TaskType::Shell;
    testTask.options.group = "test";
    testTask.options.dependsOn = {"Build"};
    runner.RegisterTask(testTask);

    runner.LoadTasksFile("d:\\rawrxd\\.vscode\\tasks.json");
    runner.SaveTasksFile("d:\\rawrxd\\tasks.json");

    auto* buildResult = runner.RunDefaultBuildTask();
    auto* testResult = runner.RunDefaultTestTask();
    runner.CancelAll();
    runner.Shutdown();

    return 0;
}
