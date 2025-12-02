# 🧪 QtShell Backend Integration Test

**Test Date**: November 30, 2025  
**Build**: RawrXD-QtShell with Live LLM Streaming  
**Ollama Status**: ✅ ONLINE (`http://localhost:11434`)

---

## 📦 Available Models (Verified)

The orchestrator is pre-configured to use these models:

| Agent Type | Model Name | Status |
|------------|------------|--------|
| **Architect** | `quantumide-architect:latest` | ✅ Available |
| **Feature** | `quantumide-feature:latest` | ✅ Available |
| **Security** | `quantumide-security:latest` | ✅ Available |
| **Performance** | `quantumide-performance:latest` | ✅ Available |

---

## 🎯 Test Sequence

### Step 1: Launch Application
```powershell
& "C:\Users\HiH8e\OneDrive\Desktop\Powershield\RawrXD-ModelLoader\build-msvc\bin-msvc\Release\RawrXD-QtShell.exe"
```
**Expected**: Application opens with three panels visible.

---

### Step 2: Verify UI Initialization

**Goal Bar (Top)**:
- [ ] Input field is visible
- [ ] "Start Goal" button is enabled
- [ ] Mock status badge shows default state

**Agent Control Panel (Left Dock)**:
- [ ] Progress bar at 0%
- [ ] Active goal label empty
- [ ] Agent status labels (Feature/Security/Performance) show "Idle"

**Proposal Review (Right Dock)**:
- [ ] List widget is empty
- [ ] Ready to receive task widgets

---

### Step 3: Submit Mock Goal

**Action**: Click **"Start Goal"** button (goal input can be empty for mock mode).

**Expected Architect Behavior**:
- The `handleGoalSubmit()` method triggers `handleArchitectFinished()`
- Mock JSON architect output is sent to orchestrator:
```json
{
  "task_graph": [
    {
      "task_id": "T1_FEAT",
      "agent": "feature",
      "prompt": "Implement core auth service with JWT",
      "dependencies": []
    },
    {
      "task_id": "T2_SEC",
      "agent": "security",
      "prompt": "Add rate limiting and input validation",
      "dependencies": ["T1_FEAT"]
    },
    {
      "task_id": "T3_PERF",
      "agent": "performance",
      "prompt": "Optimize token caching",
      "dependencies": ["T1_FEAT"]
    }
  ]
}
```

---

### Step 4: Verify Task Execution

**T1_FEAT (Feature Agent)**:
- [ ] Task widget appears in Proposal Review panel
- [ ] Header shows: `[FEATURE] T1_FEAT`
- [ ] Initial color: **AMBER** (Running ⏳)
- [ ] Body text streams incrementally from LLM
- [ ] After completion: Header turns **GREEN** (Completed ✅)

**T2_SEC (Security Agent)**:
- [ ] Widget appears AFTER T1_FEAT completes (DAG dependency)
- [ ] Header shows: `[SECURITY] T2_SEC`
- [ ] Color: AMBER → GREEN
- [ ] Streams security analysis from `quantumide-security` model

**T3_PERF (Performance Agent)**:
- [ ] Widget appears AFTER T1_FEAT completes (parallel with T2)
- [ ] Header shows: `[PERFORMANCE] T3_PERF`
- [ ] Color: AMBER → GREEN
- [ ] Streams optimization suggestions from `quantumide-performance` model

---

### Step 5: Verify Signal Flow

**StreamerClient Signals**:
```cpp
// Emitted during streaming
emit chunkReceived(QString chunk);  // Each JSON line: {"response": "..."}

// Emitted when task completes
emit taskCompleted(bool success, QString taskId, QString model, QString fullOutput);
```

**AgentOrchestrator Signals**:
```cpp
// When task starts
emit taskStatusUpdated(taskId, "Running ⏳", agentType);

// During streaming
emit taskChunk(taskId, chunk, agentType);

// When task completes
emit taskStatusUpdated(taskId, "Completed ✅", agentType);

// When all tasks done
emit orchestrationFinished(true);
```

**MainWindow Slots**:
```cpp
handleTaskStatusUpdate()   → Updates TaskProposalWidget header + color
handleTaskStreaming()       → Appends chunk to TaskProposalWidget body
handleWorkflowFinished()    → Shows completion dialog/badge
```

---

## 🐛 Debug Checklist

### If No Streaming Occurs:

1. **Check Ollama Connection**:
```powershell
Invoke-WebRequest -Uri "http://localhost:11434/api/tags"
```
Expected: JSON response with model list.

2. **Check Network Reply Errors**:
   - Watch for `StreamerClient::errorOccurred` signal
   - Check console output for Qt warnings

3. **Verify Model Names**:
   - Orchestrator hardcodes: `quantumide-feature`, `quantumide-security`, `quantumide-performance`
   - If models have different names, edit `AgentOrchestrator::executeNextTasks()`:
```cpp
QString model = QStringLiteral("your-actual-model-name");
```

### If Tasks Don't Appear:

1. **Check Mock Architect JSON**:
   - Inspect `MainWindow::getMockArchitectJson()`
   - Ensure `task_graph` array is valid

2. **Verify Orchestrator Wiring**:
```cpp
// In MainWindow constructor:
connect(orchestrator_, &AgentOrchestrator::taskChunk, ...);
connect(orchestrator_, &AgentOrchestrator::taskStatusUpdated, ...);
```

3. **Check TaskNode Status**:
   - Add debug output in `AgentOrchestrator::executeNextTasks()`
   - Log when tasks transition: Pending → Running → Completed

---

## 🎨 Color Cue Reference

| Status | Color | Unicode | Trigger |
|--------|-------|---------|---------|
| **Running** | 🟡 Amber | ⏳ | `taskStatusUpdated(..., "Running ⏳", ...)` |
| **Completed** | 🟢 Green | ✅ | `taskStatusUpdated(..., "Completed ✅", ...)` |
| **Failed** | 🔴 Red | ❌ | `taskStatusUpdated(..., "Failed ❌", ...)` |
| **Blocked** | 🟠 Orange | 🛑 | `taskStatusUpdated(..., "Blocked 🛑", ...)` |
| **Retrying** | 🟡 Amber | 🔄 | `taskStatusUpdated(..., "Retrying (1/3)…", ...)` |

Colors are set in `TaskProposalWidget::setStatus()`:
```cpp
void setStatus(const QString& status) {
    if (status.contains("Running") || status.contains("Retrying")) {
        headerLabel_->setStyleSheet("background: #f59e0b; color: white;"); // Amber
    } else if (status.contains("Completed") || status.contains("Success")) {
        headerLabel_->setStyleSheet("background: #10b981; color: white;"); // Green
    } else if (status.contains("Failed") || status.contains("Blocked")) {
        headerLabel_->setStyleSheet("background: #ef4444; color: white;"); // Red
    }
}
```

---

## 📊 Expected Performance

| Metric | Target | Notes |
|--------|--------|-------|
| **Task Launch Time** | < 100ms | From `taskStarted` signal to HTTP POST |
| **First Chunk Latency** | 200-500ms | Depends on Ollama model size |
| **Streaming FPS** | 10-30 chunks/sec | Controlled by Ollama's token generation speed |
| **UI Responsiveness** | 60 FPS | Qt event loop should remain smooth during streaming |
| **Memory (3 tasks)** | < 60 MB | Initial 41MB + streaming buffers |

---

## ✅ Success Criteria

- [x] Application launches without crashes
- [ ] **Ollama endpoint is reachable**
- [ ] **"Start Goal" triggers mock architect workflow**
- [ ] **Task widgets appear in dependency order (T1 → T2/T3)**
- [ ] **Headers show correct agent types and colors**
- [ ] **Body text updates incrementally during streaming**
- [ ] **Colors transition AMBER → GREEN on completion**
- [ ] **All 3 tasks complete successfully**
- [ ] **`orchestrationFinished(true)` signal fires**

---

## 🚀 Next Phase: Real Architect Integration

Once mock workflow is validated, replace mock with real architect call:

```cpp
void MainWindow::handleGoalSubmit() {
    QString goal = goalInput_->text();
    if (goal.isEmpty()) return;
    
    // REAL MODE: Call architect model
    architectRunning_ = true;
    architectBuffer_.clear();
    streamer_->startGeneration("quantumide-architect", 
        "Break down this goal into tasks:\n" + goal);
}
```

Then parse `architectBuffer_` as JSON in `handleArchitectFinished()`.

---

**Test Status**: 🟡 Ready for manual verification  
**Blocker**: None  
**Next Step**: Click "Start Goal" and observe task streaming! 🎯
