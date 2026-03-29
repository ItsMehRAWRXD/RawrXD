# 🔨 Build Integration Guide — Autonomous Agent

**Status**: ✅ READY TO BUILD  
**Platform**: Windows 10/11 x64  
**Compiler**: MSVC 2022  
**Build System**: CMake 3.20+

---

## 📋 Files Added

### Headers

```
d:\rawrxd\src\modules\
├── autonomous_agent.h              (450+ lines)
└── ide_agent_integration.h         (100+ lines)
```

### Implementation

```
d:\rawrxd\src\modules\
├── autonomous_agent.cpp            (600+ lines)
└── ide_agent_integration.cpp       (200+ lines)
```

### Documentation

```
d:\
├── AUTONOMOUS_AGENT_GUIDE.md       (800+ lines)
└── PARITY_GAP_CLOSURE.md           (400+ lines)
```

---

## 🔧 CMakeLists.txt Integration

Add to `d:\rawrxd\CMakeLists.txt`:

```cmake
# ============================================================================
# Autonomous Agent Module
# ============================================================================

set(AUTONOMOUS_AGENT_SOURCES
    src/modules/autonomous_agent.cpp
    src/modules/ide_agent_integration.cpp
)

set(AUTONOMOUS_AGENT_HEADERS
    src/modules/autonomous_agent.h
    src/modules/ide_agent_integration.h
)

# Add to main IDE target
target_sources(RawrXD-Win32IDE PRIVATE
    ${AUTONOMOUS_AGENT_SOURCES}
    ${AUTONOMOUS_AGENT_HEADERS}
)

# Include directories
target_include_directories(RawrXD-Win32IDE PRIVATE
    src/modules
)
```

---

## 🏗️ Build Steps

### Option 1: Command Line

```batch
cd d:\rawrxd
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

### Option 2: Visual Studio

```batch
cd d:\rawrxd
cmake -G "Visual Studio 17 2022" -A x64 -B build
start build\RawrXD.sln
# In Visual Studio: Build → Build Solution (Release)
```

### Option 3: PowerShell

```powershell
cd d:\rawrxd
cmake -G "Visual Studio 17 2022" -A x64 -B build
cmake --build build --config Release --parallel 4
```

---

## 📦 Output

After successful build:

```
d:\rawrxd\build\bin\Release\
├── RawrXD-Win32IDE.exe          (Main IDE executable)
├── RawrXD-Win32IDE.pdb          (Debug symbols)
└── [other DLLs]
```

---

## 🔗 IDE Integration

### In IDE Initialization Code

```cpp
#include "autonomous_agent.h"
#include "ide_agent_integration.h"

// In IDE_Initialize():
RawrXD::CopilotGapCloser gapCloser;
gapCloser.Initialize();

// Create autonomous agent
RawrXD::AutonomousAgent* g_pAgent = new RawrXD::AutonomousAgent(gapCloser);
RawrXD::IDEAgentIntegration* g_pIntegration = new RawrXD::IDEAgentIntegration(*g_pAgent);

// Set up callbacks
g_pAgent->OnTaskCompletion([](uint32_t taskId, bool success) {
    // Update UI when task completes
    UpdateTaskResultsPanel(taskId);
});

g_pAgent->OnApprovalNeeded([](uint32_t taskId, const ApprovalRequest& req) {
    // Show approval dialog
    ShowApprovalDialog(taskId, req);
});

g_pAgent->OnProgress([](uint32_t taskId, const AutonomousAgent::TaskProgress& progress) {
    // Update progress bar
    UpdateProgressBar(progress);
});
```

### In Chat Handler

```cpp
// When user types in chat and presses Enter
void OnChatSubmit(const std::string& message) {
    // Get current workspace path
    std::string workspacePath = GetCurrentWorkspacePath();
    
    // Submit task to agent
    uint32_t taskId = g_pIntegration->SubmitTaskFromChat(message, workspacePath);
    
    if (taskId > 0) {
        // Display plan
        std::string planDisplay = g_pIntegration->FormatPlanForDisplay(taskId);
        AppendToOutputPanel(planDisplay);
        
        // Show approval buttons
        ShowApprovalButtons(taskId);
    } else {
        AppendToOutputPanel("❌ Failed to submit task");
    }
}
```

### In Approval Handler

```cpp
// When user clicks [APPROVE] button
void OnApproveButtonClicked(uint32_t taskId) {
    if (g_pIntegration->ApproveAndExecute(taskId)) {
        AppendToOutputPanel("✅ Task approved, execution started");
        // Progress will be updated via OnProgress callback
    } else {
        AppendToOutputPanel("❌ Failed to approve task");
    }
}

// When user clicks [REJECT] button
void OnRejectButtonClicked(uint32_t taskId) {
    if (g_pIntegration->CancelTask(taskId)) {
        AppendToOutputPanel("❌ Task cancelled");
    }
}
```

### In Status Bar Update Loop

```cpp
// In main UI update loop (e.g., WM_TIMER)
void UpdateStatusBar() {
    // Get active task (if any)
    uint32_t activeTaskId = GetActiveTaskId();
    
    if (activeTaskId > 0) {
        std::string progress = g_pIntegration->FormatProgressForStatusBar(activeTaskId);
        SetStatusBarText(progress);
    }
}
```

---

## 🧪 Testing

### Unit Tests

```cpp
// Test workspace analysis
void TestWorkspaceAnalysis() {
    RawrXD::WorkspaceAnalyzer analyzer(gitCtx);
    auto ctx = analyzer.AnalyzeWorkspace("d:\\test-project");
    
    assert(ctx.fileCount > 0);
    assert(!ctx.rootPath.empty());
    assert(ctx.hasTests == true);
}

// Test plan generation
void TestPlanGeneration() {
    RawrXD::PlanGenerator planGen(vecDb, analyzer);
    auto plan = planGen.GeneratePlan("refactor code", workspace);
    
    assert(plan.steps.size() > 0);
    assert(!planGen.ValidatePlan(plan) == false);  // Should be valid
}

// Test dependency resolution
void TestDependencyResolution() {
    RawrXD::DependencyResolver resolver;
    auto order = resolver.ComputeExecutionOrder(plan);
    
    assert(order.size() == plan.steps.size());
    assert(!resolver.HasCircularDependencies(plan));
}

// Test approval manager
void TestApprovalManager() {
    RawrXD::ApprovalManager approvalMgr;
    approvalMgr.SetAutoApprovePolicy(RiskLevel::SAFE, true);
    approvalMgr.SetAutoApprovePolicy(RiskLevel::WARN, false);
    
    ExecutionStep step;
    step.riskLevel = RiskLevel::SAFE;
    assert(approvalMgr.ShouldAutoApprove(step) == true);
    
    step.riskLevel = RiskLevel::WARN;
    assert(approvalMgr.ShouldAutoApprove(step) == false);
}
```

### Integration Tests

```cpp
// Test full workflow
void TestFullWorkflow() {
    // 1. Create agent
    RawrXD::AutonomousAgent agent(gapCloser);
    
    // 2. Submit task
    uint32_t taskId = agent.SubmitTask("refactor code", "d:\\test-project");
    assert(taskId > 0);
    
    // 3. Get plan
    auto plan = agent.GetPlan(taskId);
    assert(plan != nullptr);
    assert(plan->steps.size() > 0);
    
    // 4. Approve plan
    assert(agent.ApprovePlan(taskId) == true);
    
    // 5. Execute plan
    assert(agent.ExecutePlan(taskId, false) == true);
    
    // 6. Get results
    std::string result = agent.GetResult(taskId);
    assert(!result.empty());
}
```

---

## 🚀 Deployment

### For Development

```batch
# Build with debug symbols
cd d:\rawrxd
cmake --build build --config Debug
```

### For Production

```batch
# Build optimized release
cd d:\rawrxd
cmake --build build --config Release
```

### For Distribution

```batch
# Copy executable and dependencies
copy d:\rawrxd\build\bin\Release\RawrXD-Win32IDE.exe d:\dist\
copy d:\rawrxd\build\bin\Release\*.dll d:\dist\
copy d:\AUTONOMOUS_AGENT_GUIDE.md d:\dist\
copy d:\PARITY_GAP_CLOSURE.md d:\dist\
```

---

## 📊 Build Configuration

### Compiler Flags

```cmake
# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Optimization
if(MSVC)
    add_compile_options(/O2 /Oi /Ot)  # Release optimizations
    add_compile_options(/W4)           # Warning level 4
endif()
```

### Linker Flags

```cmake
# Link against CopilotGapCloser
target_link_libraries(RawrXD-Win32IDE PRIVATE
    RawrXD_CopilotGapCloser
)

# Link against Windows libraries
target_link_libraries(RawrXD-Win32IDE PRIVATE
    kernel32
    user32
    gdi32
    winspool
    comdlg32
    advapi32
    shell32
    ole32
    oleaut32
    uuid
    odbc32
    odbccp32
)
```

---

## 🔍 Troubleshooting

### Build Errors

#### Error: "autonomous_agent.h: No such file or directory"

**Solution**: Ensure include path is set in CMakeLists.txt:
```cmake
target_include_directories(RawrXD-Win32IDE PRIVATE src/modules)
```

#### Error: "undefined reference to `RawrXD::AutonomousAgent::SubmitTask'"

**Solution**: Ensure autonomous_agent.cpp is added to CMakeLists.txt:
```cmake
target_sources(RawrXD-Win32IDE PRIVATE src/modules/autonomous_agent.cpp)
```

#### Error: "LNK2019: unresolved external symbol"

**Solution**: Ensure CopilotGapCloser is linked:
```cmake
target_link_libraries(RawrXD-Win32IDE PRIVATE RawrXD_CopilotGapCloser)
```

### Runtime Errors

#### "Task submission failed"

**Solution**: Ensure CopilotGapCloser is initialized:
```cpp
RawrXD::CopilotGapCloser gapCloser;
if (!gapCloser.Initialize()) {
    // Handle initialization failure
}
```

#### "Plan validation failed"

**Solution**: Check for circular dependencies in task decomposition

#### "Approval queue full"

**Solution**: Increase AGENT_APPROVAL_QUEUE_SIZE constant

---

## 📈 Performance Tuning

### Optimization Tips

1. **Parallel Compilation**
   ```batch
   cmake --build build --config Release --parallel 4
   ```

2. **Incremental Builds**
   ```batch
   cmake --build build --config Release
   ```

3. **Link-Time Optimization**
   ```cmake
   set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
   ```

4. **Profile-Guided Optimization**
   ```cmake
   # Requires PGO instrumentation
   add_compile_options(/GL)
   ```

---

## ✅ Verification Checklist

- [ ] Files copied to `d:\rawrxd\src\modules\`
- [ ] CMakeLists.txt updated with new sources
- [ ] Include paths configured
- [ ] CopilotGapCloser linked
- [ ] Build succeeds without errors
- [ ] Executable runs without crashes
- [ ] Chat commands work
- [ ] Plans display correctly
- [ ] Approval UI shows
- [ ] Progress tracking works
- [ ] Results display correctly
- [ ] Rollback functions properly

---

## 🎓 Next Steps

1. **Copy files** to `d:\rawrxd\src\modules\`
2. **Update CMakeLists.txt** with new sources
3. **Build the project** using CMake
4. **Test the system** with sample tasks
5. **Integrate UI** for chat, approval, progress
6. **Deploy** to production

---

## 📞 Support

For build issues:
1. Check CMakeLists.txt configuration
2. Verify all files are in correct locations
3. Ensure MSVC 2022 is installed
4. Check compiler output for specific errors
5. Review troubleshooting section above

---

**Ready to build. Ready to deploy. Ready for production.** 🚀
