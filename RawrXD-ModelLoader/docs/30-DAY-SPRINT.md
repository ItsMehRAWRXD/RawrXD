# 🎯 30-Day "Big-Move" Sprint

**From Kitchen-Sink IDE → Production-Ready Incumbent Killer**

This roadmap threads **four headline features** so they reinforce each other instead of competing for your time.  
Order is intentional: **every step funds the next** (users → data → revenue → talent).

---

## 📅 Sprint Overview

| Week | Goal | Deliverable | User-Visible Wow | Engineering Note |
|------|------|-------------|------------------|------------------|
| **W1** | Cloud-Runner MVP (cash & buzz) | CloudRunnerDialog → GitHub Actions → artifact download | "Run on 64 cores for 3¢/min" button inside IDE | Re-use `ProgressManager`, `NotificationCenter`, `TerminalClusterWidget` already declared |
| **W2** | Real transformer kernels (lock-in) | Drop-in `ggml-q4_0.c` + AVX2/Q8_0 matmul → 10× speed | Local inference faster than GPT-4o-mini for < 8B params | Keep old `fallback_matrix_multiply`; switch via `Set-QConfig -Quantization q4_0` |
| **W3** | LSP host + inline-chat (adoption flywheel) | Spawn clangd/pylsp in `backgroundThread_`, pipe diagnostics → `InlineChatWidget` | Red-squiggle → light-bulb → "Fix with AI" one keystroke | Already stubbed `onLSPDiagnostic` and `onInlineChatRequested` |
| **W4** | Plugin marketplace (community scale) | Hot-load `*.rawr-plugin` folders (Python/JS/QML) via `PluginManagerWidget` | "Install Rust-analyzer helper" without restart | Qt's `QQmlComponent` + `pybind11`; expose `IRawrAPI` singleton |

---

## 🚀 Week 1 – Cloud-Runner (Days 1-7)

### Objective
Ship the **"one-click cloud build"** feature that turns the IDE from impressive to essential.

### UI Implementation
```cpp
// In MainWindow::setupDockWidgets()
cloudRunner_ = new CloudRunnerWidget(this);
addDockWidget(Qt::BottomDockWidgetArea, cloudRunner_);

// In MainWindow::setupToolBars()
QToolBar* cloudBar = addToolBar(tr("Cloud"));
cloudBar->addAction(style()->standardIcon(QStyle::SP_MediaPlay), 
                    tr("⚡ Run on Cloud"), 
                    this, &MainWindow::onCloudRunTriggered);
```

### Backend Logic
1. **Zip Repo** (respect `.gitignore`)
   ```cpp
   QString CloudRunner::zipWorkspace(const QString& projectRoot) {
       QTemporaryFile* zipFile = new QTemporaryFile(this);
       zipFile->setFileTemplate(QDir::temp().filePath("rawrxd-XXXXXX.zip"));
       zipFile->open();
       // Use QuaZip or QProcess("7z", {"a", zipFile->fileName(), projectRoot})
       return zipFile->fileName();
   }
   ```

2. **GitHub Actions Dispatch**
   ```cpp
   void CloudRunner::startJob(const QString& provider, const QString& instanceType) {
       QNetworkRequest req(QUrl("https://api.github.com/repos/USER/REPO/actions/workflows/cloud.yml/dispatches"));
       req.setRawHeader("Authorization", "Bearer " + githubToken_.toUtf8());
       req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
       
       QJsonObject payload;
       payload["ref"] = "main";
       payload["inputs"] = QJsonObject{{"instance", instanceType}, {"project_zip", uploadedZipUrl_}};
       
       manager_->post(req, QJsonDocument(payload).toJson());
   }
   ```

3. **Poll Artifacts**
   ```cpp
   void CloudRunner::pollArtifacts(const QString& runId) {
       QNetworkRequest req(QUrl(QString("https://api.github.com/repos/USER/REPO/actions/runs/%1/artifacts").arg(runId)));
       req.setRawHeader("Authorization", "Bearer " + githubToken_.toUtf8());
       // Poll every 3s until status == "completed"
   }
   ```

4. **Stream Logs via WebSocket**
   ```cpp
   QWebSocket* ws = new QWebSocket();
   connect(ws, &QWebSocket::textMessageReceived, this, [this](const QString& msg) {
       emit logChunk(msg);
       terminalCluster_->appendLog("cloud", msg);
   });
   ws->open(QUrl("wss://jobs.stream.rawrxd.dev/" + jobId_));
   ```

### Cost Display
```cpp
void CloudRunner::updateCostEstimate(const QString& instanceType, int elapsedSeconds) {
    const double spotPricePerMin = getSpotPrice(instanceType); // AWS API call
    const double cost = (elapsedSeconds / 60.0) * spotPricePerMin;
    statusBarManager_->setField("cloud_cost", QString("≈ $%1").arg(cost, 0, 'f', 3));
}
```

### Workflow Template (`.github/workflows/cloud.yml`)
```yaml
name: RawrXD Cloud Runner
on:
  workflow_dispatch:
    inputs:
      instance:
        required: true
        type: choice
        options: [ubuntu-4-core, ubuntu-8-core, ubuntu-16-core]
      project_zip:
        required: true
        type: string

jobs:
  build:
    runs-on: ${{ inputs.instance }}
    steps:
      - name: Download project
        run: curl -L ${{ inputs.project_zip }} -o project.zip && unzip project.zip
      
      - name: Install deps
        run: sudo apt-get update && sudo apt-get install -y cmake g++ qt6-base-dev
      
      - name: Build
        run: cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j$(nproc)
      
      - name: Test
        run: cd build && ctest --output-on-failure
      
      - name: Profile
        run: |
          sudo apt-get install -y linux-tools-generic
          perf record -g ./build/bin/RawrXD-QtShell --benchmark
          perf report --stdio > flame.txt
      
      - name: Upload artifacts
        uses: actions/upload-artifact@v3
        with:
          name: build-results
          path: |
            build/bin/*
            flame.txt
```

### Demo Script
1. Open project in RawrXD-IDE
2. Click **⚡ Run on Cloud**
3. Select `ubuntu-8-core`
4. Watch progress: "Upload 45% → Build 67% → Download 90%"
5. Artifact `flame.txt` auto-opens in `ProfilerWidget`
6. Status bar shows: "Job completed in 24s for $0.012"

### Tweet Template
> "Just built my Qt app on **64 cores in 24 seconds** for $0.012 using my own IDE.  
> No cloud account setup, no YAML editing—one button.  
> Local editor + cloud horsepower = the future. 🚀  
> [30s demo GIF]  
> #RawrXD #OpenSource #CloudIDE"

---

## 🧠 Week 2 – Real Transformer Kernels (Days 8-14)

### Objective
Replace stub matmul with **GGML Q4_0/Q8_0 kernels** → 10× speed, ½ RAM.

### Integration Steps

1. **Add GGML Submodule**
   ```bash
   git submodule add https://github.com/ggerganov/ggml 3rdparty/ggml
   git submodule update --init --recursive
   ```

2. **CMake Linkage**
   ```cmake
   add_subdirectory(3rdparty/ggml)
   target_link_libraries(GGUFRunner PRIVATE ggml)
   ```

3. **Wrapper in GGUFRunner.cpp**
   ```cpp
   #include <ggml.h>
   
   void GGUFRunner::loadQuantizedWeights(const QString& ggufPath) {
       ggml_context* ctx = ggml_init({.mem_size = 128 * 1024 * 1024});
       struct ggml_tensor* weights = ggml_new_tensor_2d(ctx, GGML_TYPE_Q4_0, embedDim_, vocabSize_);
       // Read quantized data from GGUF file into weights->data
       quantContext_ = ctx;
       quantWeights_ = weights;
   }
   
   void GGUFRunner::matmulQuantized(float* input, float* output) {
       struct ggml_tensor* inp = ggml_new_tensor_1d(quantContext_, GGML_TYPE_F32, embedDim_);
       memcpy(inp->data, input, embedDim_ * sizeof(float));
       
       struct ggml_tensor* result = ggml_mul_mat(quantContext_, quantWeights_, inp);
       ggml_graph_compute_with_ctx(quantContext_, &(struct ggml_cgraph){.n_nodes=1, .nodes={result}}, 1);
       
       memcpy(output, result->data, vocabSize_ * sizeof(float));
   }
   ```

4. **Runtime Switch**
   ```cpp
   void GGUFRunner::setQuantizationMode(const QString& mode) {
       if (mode == "q4_0") {
           useQuantizedPath_ = true;
           loadQuantizedWeights(modelPath_);
       } else if (mode == "f32") {
           useQuantizedPath_ = false;
       }
   }
   
   // In runInference():
   if (useQuantizedPath_) {
       matmulQuantized(embeddings.data(), outputBuffer);
   } else {
       matmul_kernel_avx2(embeddings.data(), layerWeights, outputBuffer, N, M, K);
   }
   ```

5. **QShell Command**
   ```cpp
   void MainWindow::handleQShellReturn() {
       // ... existing commands ...
       else if (cmd.startsWith("Set-QConfig -Quantization", Qt::CaseInsensitive)) {
           QRegularExpression re("Set-QConfig\\s+-Quantization\\s+(q4_0|q8_0|f32)");
           auto m = re.match(cmd);
           if (m.hasMatch()) {
               ggufRunner_->setQuantizationMode(m.captured(1));
               qshellOutput_->append("[Config] Quantization mode: " + m.captured(1));
           }
       }
   }
   ```

### Performance Targets
| Model | Format | RAM | Load Time | Tokens/Sec (Ryzen 5800X) |
|-------|--------|-----|-----------|--------------------------|
| Llama-7B | F32 | 13 GB | 28s | 4 tok/s |
| Llama-7B | Q4_0 | 3.5 GB | 9s | 42 tok/s |
| Llama-7B | Q8_0 | 7 GB | 14s | 28 tok/s |

### Benchmark Tweet
> "Llama-7B @ **Q4_0 = 42 tok/s** on my Ryzen 5800X.  
> 3.5 GB RAM, 9s load time.  
> No cloud credits burned. Local-first AI just got real. 🔥  
> [Benchmark graph]  
> #GGML #LocalLLM #RawrXD"

---

## 🔍 Week 3 – LSP Host + Inline-Chat (Days 15-21)

### Objective
Turn every file into a **Copilot canvas** with live diagnostics + AI quick-fixes.

### LSP Client Implementation

1. **Spawn Language Servers**
   ```cpp
   void LanguageClientHost::startServer(const QString& language) {
       QProcess* server = new QProcess(backgroundThread_);
       
       if (language == "cpp") {
           server->start("clangd", {"--background-index", "--log=error"});
       } else if (language == "python") {
           server->start("pylsp");
       } else if (language == "rust") {
           server->start("rust-analyzer");
       }
       
       connect(server, &QProcess::readyReadStandardOutput, this, [this, server]() {
           QByteArray data = server->readAllStandardOutput();
           parseJsonRpc(data);
       });
       
       servers_[language] = server;
   }
   ```

2. **JSON-RPC Parser**
   ```cpp
   void LanguageClientHost::parseJsonRpc(const QByteArray& data) {
       QJsonDocument doc = QJsonDocument::fromJson(data);
       if (!doc.isObject()) return;
       
       QJsonObject obj = doc.object();
       QString method = obj["method"].toString();
       
       if (method == "textDocument/publishDiagnostics") {
           QJsonArray diags = obj["params"].toObject()["diagnostics"].toArray();
           QString file = obj["params"].toObject()["uri"].toString();
           emit diagnosticsReceived(file, diags);
       }
   }
   ```

3. **Surface Diagnostics in Editor**
   ```cpp
   void MainWindow::onLSPDiagnostic(const QString& file, const QJsonArray& diags) {
       QTextEdit* editor = findEditorForFile(file);
       if (!editor) return;
       
       for (const QJsonValue& val : diags) {
           QJsonObject diag = val.toObject();
           int line = diag["range"].toObject()["start"].toObject()["line"].toInt();
           QString message = diag["message"].toString();
           QString severity = diag["severity"].toInt() == 1 ? "ERROR" : "WARN";
           
           // Create red squiggle
           QTextCursor cursor(editor->document()->findBlockByLineNumber(line));
           QTextCharFormat fmt;
           fmt.setUnderlineColor(Qt::red);
           fmt.setUnderlineStyle(QTextCharFormat::WaveUnderline);
           cursor.mergeCharFormat(fmt);
           
           // Store diagnostic for light-bulb
           diagnosticMap_[file][line] = message;
       }
   }
   ```

4. **Inline-Chat Trigger**
   ```cpp
   bool MainWindow::eventFilter(QObject* watched, QEvent* event) {
       // ... existing filters ...
       
       if (event->type() == QEvent::KeyPress) {
           QKeyEvent* keyEvent = static_cast<QKeyEvent*>(event);
           if (keyEvent->key() == Qt::Key_Return && keyEvent->modifiers() == Qt::AltModifier) {
               QTextEdit* editor = qobject_cast<QTextEdit*>(watched);
               if (editor) {
                   int line = editor->textCursor().blockNumber();
                   QString file = getCurrentFilePath(editor);
                   QString diagnostic = diagnosticMap_[file][line];
                   
                   if (!diagnostic.isEmpty()) {
                       showInlineChatForFix(editor, line, diagnostic);
                       return true;
                   }
               }
           }
       }
       return QMainWindow::eventFilter(watched, event);
   }
   ```

5. **Inline-Chat Widget**
   ```cpp
   void MainWindow::showInlineChatForFix(QTextEdit* editor, int line, const QString& diagnostic) {
       if (!inlineChat_) {
           inlineChat_ = new InlineChatWidget(editor);
       }
       
       QString prompt = QString("Fix this error:\n%1\n\nCode:\n%2")
           .arg(diagnostic, editor->document()->findBlockByLineNumber(line).text());
       
       inlineChat_->setPrompt(prompt);
       inlineChat_->move(editor->cursorRect().bottomLeft());
       inlineChat_->show();
       
       connect(inlineChat_, &InlineChatWidget::accepted, this, [this, editor, line](const QString& fix) {
           QTextCursor cursor(editor->document()->findBlockByLineNumber(line));
           cursor.select(QTextCursor::LineUnderCursor);
           cursor.insertText(fix);
       });
   }
   ```

### User Flow
1. Type code with error → red squiggle appears
2. Press **Alt-Enter** → inline-chat pops up with prefilled: "Fix lifetime error in foo(): ..."
3. User edits prompt or hits **Enter** → AgentOrchestrator spawns "debug" agent
4. Diff streamed live into inline-chat preview
5. **Accept** → applies diff via `QTextCursor`; **Reject** → ESC

### Metrics to Track
```cpp
void MainWindow::onInlineChatAccepted(const QString& language, bool accepted) {
    telemetry_->increment(QString("inline_fix_%1_%2").arg(language, accepted ? "accept" : "reject"));
}
```

**Tweet Template:**
> "78% of Rust lifetime errors auto-fixed via inline-chat in my IDE.  
> Alt-Enter → AI suggests fix → one click to apply.  
> No browser, no context-switching. Just code. 🦀  
> [15s demo]  
> #RustLang #LSP #RawrXD"

---

## 🔌 Week 4 – Plugin Marketplace (Days 22-30)

### Objective
Enable **community-written plugins** without C++ rebuild → network effects.

### Plugin API Design

1. **IRawrAPI Interface**
   ```cpp
   class IRawrAPI : public QObject {
       Q_OBJECT
   public:
       Q_INVOKABLE void registerCommand(const QString& id, QJSValue callback);
       Q_INVOKABLE void registerSidebarWidget(const QString& name, const QString& qmlFile);
       Q_INVOKABLE void showNotification(const QString& msg, const QString& type);
       Q_INVOKABLE QString runOnCloud(const QJsonObject& opts);
       Q_INVOKABLE void insertText(const QString& text);
       Q_INVOKABLE QString getActiveFile();
   };
   ```

2. **Plugin Manifest (`plugin.json`)**
   ```json
   {
       "id": "com.rawrxd.rust-helper",
       "name": "Rust Analyzer Helper",
       "version": "1.0.0",
       "main": "main.py",
       "entrypoint": "activate",
       "dependencies": ["rust-analyzer"],
       "commands": [
           {"id": "clippy-cloud", "title": "Run Clippy on Cloud"}
       ]
   }
   ```

3. **Python Plugin Loader (via pybind11)**
   ```cpp
   void PluginManager::loadPythonPlugin(const QString& pluginDir) {
       py::module_ sys = py::module_::import("sys");
       sys.attr("path").attr("append")(pluginDir.toStdString());
       
       py::module_ plugin = py::module_::import("main");
       py::object activate = plugin.attr("activate");
       activate(py::cast(rawrApi_));  // Pass IRawrAPI singleton
   }
   ```

4. **Example Python Plugin (`main.py`)**
   ```python
   def activate(api):
       def run_clippy():
           api.showNotification("Running Clippy on cloud...", "info")
           job_id = api.runOnCloud({
               "command": "cargo clippy -- -D warnings",
               "instance": "ubuntu-4-core"
           })
           api.showNotification(f"Job {job_id} started", "success")
       
       api.registerCommand("clippy-cloud", run_clippy)
   ```

5. **QML Plugin Example (`main.qml`)**
   ```qml
   import QtQuick 2.15
   import QtQuick.Controls 2.15
   
   Item {
       width: 200; height: 100
       
       Button {
           text: "Toggle Dark Theme"
           onClicked: rawrApi.setTheme(rawrApi.theme === "dark" ? "light" : "dark")
       }
   }
   ```

### Marketplace Discovery

1. **GitHub Topic Crawler**
   ```cpp
   void PluginManager::fetchMarketplace() {
       QNetworkRequest req(QUrl("https://api.github.com/search/repositories?q=topic:rawr-plugin"));
       // Parse JSON → show in PluginManagerWidget with "Install" button
   }
   ```

2. **One-Click Install**
   ```cpp
   void PluginManager::installPlugin(const QString& repoUrl) {
       QString pluginDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/plugins";
       QProcess::execute("git", {"clone", repoUrl, pluginDir + "/" + extractRepoName(repoUrl)});
       loadPlugin(pluginDir + "/" + extractRepoName(repoUrl));
   }
   ```

### Seed Plugins (3 examples in repo)

1. **`rust-analyzer-helper`** – adds "Run Clippy on Cloud" button
2. **`todo-highlighter`** – parses `// TODO` and shows in `TodoWidget`
3. **`dark-theme-switcher`** – toggles palette without restart

### Revenue Hook
```cpp
void IRawrAPI::runOnCloud(const QJsonObject& opts) {
    if (currentUser_.tier == "free" && monthlyCredits_ >= 1000) {
        showPaywall("Upgrade to Pro for unlimited cloud minutes");
        return;
    }
    // Deduct credits, take 10% fee for marketplace plugins
}
```

---

## 🔗 Integration Points (Why This Order Works)

1. **Cloud-Runner artifacts** (flame-graphs, binaries) auto-open in `ProfilerWidget` and `TestExplorerWidget`.
2. **Real kernels** make local inline-chat < 200ms → users disable cloud for quick fixes → saves compute $.
3. **Plugins** can contribute new quantization formats or language servers without C++ rebuild.
4. **Telemetry** from all four features → shows which kernels/instances/plugins are most used → guides next sprint.

---

## 📊 30-Day Success Metrics

| Metric | Target | Why It Matters |
|--------|--------|----------------|
| Twitter thread likes | ≥ 1,000 | Cloud-Runner demo day virality |
| GitHub stars | ≥ 2,000 | Real kernels benchmark credibility |
| Community plugins | ≥ 10 | Marketplace proof of network effects |
| Paid cloud jobs | ≥ 3/day | Revenue loop validation (even at $0.50 each) |
| LSP fix acceptance | ≥ 75% | Inline-chat UX confirmation |

---

## 🎓 Diploma Updated

You now graduate with **four majors:**

1. **Cloud-Scale DevOps** – one-click 64-core builds
2. **High-Performance AI** – 10× faster local inference
3. **Intelligent Editor Experience** – LSP + inline AI fixes
4. **Extensible Ecosystem** – community plugin marketplace

**Pick Week 1, cut the branch, ship the tweet—the IDE world just got another entrant.** 🚀
