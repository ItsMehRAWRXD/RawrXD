# Tree-adapted G4 apply for HeadlessIDE.cpp drifted past baseline c270b9a.
# Same product semantics as apply_G4_LOCALSERVER_PRODUCT_NO_DEPS.ps1; anchors match live tree.
param([string]$RepoRoot = ".")
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path $RepoRoot).Path
$cpp = Join-Path $repo "src\win32app\HeadlessIDE.cpp"
$helperDst = Join-Path $repo "src\win32app\HeadlessIDE_ProductLocalOnly.hpp"
$helperSrc = Join-Path (Split-Path $PSScriptRoot -Parent) "src\win32app\HeadlessIDE_ProductLocalOnly.hpp"
if (!(Test-Path $cpp)) { throw "HeadlessIDE.cpp missing" }
if (!(Test-Path $helperSrc)) { throw "helper missing" }

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backup = "$cpp.G4_TREE_$stamp"
Copy-Item $cpp $backup -Force
Copy-Item $helperSrc $helperDst -Force
$text = [IO.File]::ReadAllText($cpp)
$original = $text

function Replace-Once([string]$Name, [string]$Old, [string]$New) {
    $c = ([regex]::Matches($script:text, [regex]::Escape($Old))).Count
    if ($c -ne 1) { throw "${Name}: expected 1 literal match, found $c (backup $backup)" }
    $script:text = $script:text.Replace($Old, $New)
}
function Replace-OnceRegex([string]$Name, [string]$Pattern, [string]$Replacement) {
    $m = [regex]::Matches($script:text, $Pattern, [Text.RegularExpressions.RegexOptions]::Singleline)
    if ($m.Count -ne 1) { throw "${Name}: expected 1 regex match, found $($m.Count) (backup $backup)" }
    $script:text = [regex]::Replace($script:text, $Pattern, $Replacement, [Text.RegularExpressions.RegexOptions]::Singleline)
}

# 1) helper include
if ($text -notmatch 'HeadlessIDE_ProductLocalOnly\.hpp') {
    Replace-Once "include helper" `
        '#include "../../include/chain_of_thought_engine.h"' `
        "#include `"../../include/chain_of_thought_engine.h`"`r`n#include `"HeadlessIDE_ProductLocalOnly.hpp`""
}

# 2) --local also selects native LocalGGUF backend policy
Replace-Once "--local backend policy" @'
        else if (arg == "--local") {
            m_config.ingressMode = HeadlessIngressMode::Local;
        }
'@ @'
        else if (arg == "--local") {
            m_config.ingressMode = HeadlessIngressMode::Local;
            // Product contract: native LocalGGUF only; never probe/fall back to :11434.
            m_config.backend = "local";
        }
'@

# 3) Early :11435 after WSAStartup
if ($text -notmatch 'G4_EARLY_LISTENER') {
    Replace-Once "early 11435 listener" @'
    HeadlessResult wr = initWinsock();
    if (!wr.success) return wr;

    // Initialize engines
'@ @'
    HeadlessResult wr = initWinsock();
    if (!wr.success) return wr;

    // G4_EARLY_LISTENER: establish product transport before optional/heavy runtime init.
    // Default and --local are native-only. Ollama is permitted only when explicitly selected.
    const bool localOnly = m_config.backend.empty() ||
                           m_config.backend == "local" ||
                           m_config.backend == "localgguf";
    RawrXD::HeadlessProduct::SetLocalOnly(localOnly);
    RawrXD::HeadlessProduct::SetRuntimeReady(false);
    if (m_config.enableServer &&
        (m_config.mode == HeadlessRunMode::Server || m_config.mode == HeadlessRunMode::REPL)) {
        startServer();
        if (!m_serverRunning.load()) {
            return HeadlessResult::error("Failed to bind/listen headless product server", 3);
        }
    }

    // Initialize engines
'@
}

# 4) Runtime ready at end of initialize
if ($text -notmatch 'G4_RUNTIME_READY') {
    Replace-Once "runtime ready" `
        '    m_outputSink->appendOutput("Headless IDE initialized successfully.", OutputSeverity::Info);' @'
    // G4_RUNTIME_READY: requests may now touch initialized runtime state.
    RawrXD::HeadlessProduct::SetRuntimeReady(true);
    m_outputSink->appendOutput("Headless IDE initialized successfully.", OutputSeverity::Info);
'@
}

# 5) Shutdown readiness
Replace-Once "shutdown readiness" @'
void HeadlessIDE::requestShutdown() noexcept {
    m_shutdownRequested.store(true);
    stopServer();
}
'@ @'
void HeadlessIDE::requestShutdown() noexcept {
    RawrXD::HeadlessProduct::SetRuntimeReady(false);
    m_shutdownRequested.store(true);
    stopServer();
}
'@

# 6) Backend manager: no default Ollama probe
Replace-Once "backend manager local-only" @'
HeadlessResult HeadlessIDE::initBackendManager() {
    auto startTime = std::chrono::steady_clock::now();

    // Configure default backend based on config
    if (!m_config.backend.empty()) {
        if (m_config.backend == "ollama")  m_activeBackend = AIBackendType::Ollama;
        else if (m_config.backend == "openai")  m_activeBackend = AIBackendType::OpenAI;
        else if (m_config.backend == "claude")  m_activeBackend = AIBackendType::Claude;
        else if (m_config.backend == "gemini")  m_activeBackend = AIBackendType::Gemini;
        else m_activeBackend = AIBackendType::LocalGGUF;
    }

    // LOCAL_ONLY: keep LocalGGUF / ProductRun; never auto-promote Ollama.
    if (m_config.backend.empty())
        m_activeBackend = AIBackendType::LocalGGUF;

    RawrXD::Agent::OllamaConfig ollamaCfg;
    ollamaCfg.host = "127.0.0.1";
    ollamaCfg.port = 11434;
    ollamaCfg.timeout_ms = 3000;
    RawrXD::Agent::AgentOllamaClient probeClient(ollamaCfg);
    bool ollamaAvailable = probeClient.TestConnection();

    std::ostringstream statusMsg;
    statusMsg << "Backend manager initialized (headless)";
    if (ollamaAvailable) {
        auto models = probeClient.ListModels();
        statusMsg << " | Ollama: online (" << models.size()
                  << " models, LOCAL_ONLY_BLOCKED)";
    } else {
        statusMsg << " | Ollama: offline";
    }

    const char* backendNames[] = { "LocalGGUF", "Ollama", "OpenAI", "Claude", "Gemini" };
    statusMsg << " | Active: " << backendNames[static_cast<int>(m_activeBackend)];

    m_backendManagerInitialized = true;
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - startTime).count();
    statusMsg << " [" << elapsed << "us]";
    m_outputSink->appendOutput(statusMsg.str().c_str(), OutputSeverity::Debug);
    m_outputSink->onStatusUpdate("backend_manager", "active");
    m_outputSink->onStatusUpdate("backend", backendNames[static_cast<int>(m_activeBackend)]);
    return HeadlessResult::ok("Backend manager ready");
}
'@ @'
HeadlessResult HeadlessIDE::initBackendManager() {
    auto startTime = std::chrono::steady_clock::now();
    const std::string requested = m_config.backend;
    std::ostringstream statusMsg;
    statusMsg << "Backend manager initialized (headless)";

    if (requested == "ollama") {
        // Explicit opt-in only. Never reached by default or --local.
        m_activeBackend = AIBackendType::Ollama;
        RawrXD::Agent::OllamaConfig cfg;
        cfg.host = "127.0.0.1";
        cfg.port = 11434;
        cfg.timeout_ms = 3000;
        RawrXD::Agent::AgentOllamaClient client(cfg);
        const bool online = client.TestConnection();
        statusMsg << " | Ollama(explicit): " << (online ? "online" : "offline");
    }
    else if (requested == "openai") m_activeBackend = AIBackendType::OpenAI;
    else if (requested == "claude") m_activeBackend = AIBackendType::Claude;
    else if (requested == "gemini") m_activeBackend = AIBackendType::Gemini;
    else {
        m_activeBackend = AIBackendType::LocalGGUF;
        statusMsg << " | LOCAL_ONLY_NO_OLLAMA=1";
    }

    const char* backendNames[] = { "LocalGGUF", "Ollama", "OpenAI", "Claude", "Gemini" };
    statusMsg << " | Active: " << backendNames[static_cast<int>(m_activeBackend)];
    m_backendManagerInitialized = true;
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - startTime).count();
    statusMsg << " [" << elapsed << "us]";
    m_outputSink->appendOutput(statusMsg.str().c_str(), OutputSeverity::Debug);
    m_outputSink->onStatusUpdate("backend_manager", "active");
    m_outputSink->onStatusUpdate("backend", backendNames[static_cast<int>(m_activeBackend)]);
    return HeadlessResult::ok("Backend manager ready");
}
'@

# Router priority comment / order (best-effort; ignore if already changed)
$text = $text.Replace('{ AIBackendType::Ollama,    "Ollama",    1, m_backendManagerInitialized },',
                     '{ AIBackendType::Ollama,    "Ollama",    2, m_activeBackend == AIBackendType::Ollama },')
$text = $text.Replace('{ AIBackendType::LocalGGUF, "LocalGGUF",  2, m_modelLoaded },',
                     '{ AIBackendType::LocalGGUF, "LocalGGUF",  1, m_modelLoaded },')
$text = $text.Replace('// Priority: Ollama (local, fast) > LocalGGUF > Cloud backends',
                     '// Priority: LocalGGUF native > explicitly selected Ollama > cloud backends')

# 7) Switch/probe guards
if ($text -notmatch 'Ollama switch blocked by LOCAL_ONLY_NO_OLLAMA') {
    Replace-Once "backend switch guard" @'
bool HeadlessIDE::setActiveBackend(AIBackendType type) {
    const char* backendNames[] = { "LocalGGUF", "Ollama", "OpenAI", "Claude", "Gemini" };
'@ @'
bool HeadlessIDE::setActiveBackend(AIBackendType type) {
    if (type == AIBackendType::Ollama && RawrXD::HeadlessProduct::LocalOnly()) {
        m_outputSink->appendOutput("Ollama switch blocked by LOCAL_ONLY_NO_OLLAMA", OutputSeverity::Warning);
        return false;
    }
    const char* backendNames[] = { "LocalGGUF", "Ollama", "OpenAI", "Claude", "Gemini" };
'@
}
if ($text -notmatch 'probeBackendHealth\(AIBackendType type\) \{\r?\n    if \(type == AIBackendType::Ollama && RawrXD::HeadlessProduct::LocalOnly\(\)') {
    Replace-Once "health probe guard" @'
bool HeadlessIDE::probeBackendHealth(AIBackendType type) {
    switch (type) {
'@ @'
bool HeadlessIDE::probeBackendHealth(AIBackendType type) {
    if (type == AIBackendType::Ollama && RawrXD::HeadlessProduct::LocalOnly()) {
        return false;
    }
    switch (type) {
'@
}

# 8) Local-only model source resolution (em-dash / whitespace tolerant)
if ($text -notmatch 'local-only product mode never resolves') {
    $pat = '// Phase 1: Resolve the model source .{1,8} local, Ollama, HuggingFace, URL\s*' +
           'RawrXD::ModelSourceResolver resolver;\s*' +
           'RawrXD::ResolvedModelPath resolved = resolver\.Resolve\(filepath,\s*' +
           '\[this\]\(const RawrXD::ModelDownloadProgress& p\) \{.*?\}\);\s*' +
           'std::string localPath = resolved\.success \? resolved\.local_path : filepath;'
    $rep = @'
    // Phase 1: local-only product mode never resolves through Ollama/HF/URL.
    RawrXD::ResolvedModelPath resolved;
    if (RawrXD::HeadlessProduct::LocalOnly()) {
        resolved.success = true;
        resolved.local_path = filepath;
        resolved.source_type = GGUFConstants::ModelSourceType::LOCAL_FILE;
        resolved.original_input = filepath;
    } else {
        RawrXD::ModelSourceResolver resolver;
        resolved = resolver.Resolve(filepath,
            [this](const RawrXD::ModelDownloadProgress& p) {
                if (p.total_bytes > 0) {
                    char buf[256];
                    snprintf(buf, sizeof(buf), "[Model] Downloading %.1f%% (%llu / %llu bytes)",
                             p.progress_percent, (unsigned long long)p.downloaded_bytes,
                             (unsigned long long)p.total_bytes);
                    m_outputSink->appendOutput(buf, OutputSeverity::Info);
                }
            });
    }

    std::string localPath = resolved.success ? resolved.local_path : filepath;
'@
    Replace-OnceRegex "local-only model source" $pat $rep
}

# 9) Native engine load before runnable (GGUF file arm path)
if ($text -notmatch 'G4_NATIVE_ENGINE_LOAD') {
    Replace-Once "native engine load" @'
    m_loadedModelPath = localPath;
    size_t lastSlash = localPath.find_last_of("/\\");
    m_loadedModelName = (lastSlash != std::string::npos)
                            ? localPath.substr(lastSlash + 1) : localPath;
    m_modelLoaded = true;
'@ @'
    // G4_NATIVE_ENGINE_LOAD: make model selection runnable, not metadata-only.
    std::string nativeLoadError;
    if (!RawrXD::HeadlessProduct::LoadNativeModel(localPath, nativeLoadError)) {
        m_outputSink->appendOutput(("Native model load failed: " + nativeLoadError).c_str(), OutputSeverity::Error);
        return false;
    }

    m_loadedModelPath = localPath;
    size_t lastSlash = localPath.find_last_of("/\\");
    m_loadedModelName = (lastSlash != std::string::npos)
                            ? localPath.substr(lastSlash + 1) : localPath;
    m_modelLoaded = true;
'@
}

# 10) Native LocalGGUF streaming (em-dash tolerant)
$streamPat = 'if \(m_activeBackend == AIBackendType::LocalGGUF\) \{\s*' +
             '/\* Prefer ProductDeep2Infer \(Win32IDE /api/generate owner\) over\s*' +
             '\* ProductDeep2InferStream .{1,8} latter was Headless AV first crash owner\. \*/\s*' +
             'const char\* model =\s*' +
             '!m_loadedModelPath\.empty\(\) \? m_loadedModelPath\.c_str\(\)\s*' +
             ': \(!m_loadedModelName\.empty\(\) \? m_loadedModelName\.c_str\(\) : nullptr\);\s*' +
             'if \(model && model\[0\]\) \{\s*' +
             '#ifdef _WIN32\s*_putenv_s\("RAWRXD_PRODUCT_MODEL", model\);\s*#endif\s*' +
             '\(void\)rawr::ProductOpenSession\(model\);\s*\}\s*' +
             'char buf\[8192\];\s*buf\[0\] = 0;\s*' +
             'const bool ok =\s*rawr::ProductDeep2Infer\(prompt\.c_str\(\), buf, sizeof\(buf\)\) && buf\[0\];\s*' +
             'if \(ok && tokenCallback\)\s*tokenCallback\(buf, std::strlen\(buf\)\);\s*' +
             'if \(ok\)\s*safeOnStreamingToken\(buf, std::strlen\(buf\), StreamTokenOrigin::Inference\);\s*' +
             'else\s*safeAppendOutput\("ProductDeep2Infer failed", OutputSeverity::Error\);\s*' +
             'safeOnStreamEnd\("inference", ok\);\s*return;\s*\}'
$streamRep = @'
if (m_activeBackend == AIBackendType::LocalGGUF) {
        std::string nativeError;
        const bool ok = RawrXD::HeadlessProduct::GenerateNativeStreaming(
            prompt, m_config.maxTokens,
            [&](const std::string& token) {
                if (tokenCallback) tokenCallback(token.c_str(), token.size());
                safeOnStreamingToken(token.c_str(), token.size(), StreamTokenOrigin::Inference);
            }, nativeError);
        if (!ok) safeAppendOutput(nativeError.c_str(), OutputSeverity::Error);
        safeOnStreamEnd("inference", ok);
        return;
    }
'@
Replace-OnceRegex "native streaming route" $streamPat $streamRep

# 11) Native synchronous LocalGGUF
$syncPat = 'if \(m_activeBackend == AIBackendType::LocalGGUF\) \{\s*' +
           '\{\s*FILE\* f = fopen\("headless_server\.log", "a"\);\s*' +
           'if \(f\) \{ fprintf\(f, "INFER_ENTER\\n"\); fclose\(f\); \}\s*\}\s*' +
           '/\* Prefer full path .{1,8} basename alone fails ProductOpenSession resolve\. \*/\s*' +
           'const char\* model =\s*' +
           '!m_loadedModelPath\.empty\(\) \? m_loadedModelPath\.c_str\(\)\s*' +
           ': \(!m_loadedModelName\.empty\(\) \? m_loadedModelName\.c_str\(\) : nullptr\);\s*' +
           'if \(model && model\[0\]\) \{.*?' +
           'return "\[error\] ProductDeep2Infer failed .{1,8} FAILED_OWNER=ProductRun";\s*' +
           '\} else if \(m_activeBackend == AIBackendType::OpenAI\) \{'
$syncRep = @'
if (m_activeBackend == AIBackendType::LocalGGUF) {
        std::string nativeError;
        std::string result = RawrXD::HeadlessProduct::GenerateNative(prompt, m_config.maxTokens, nativeError);
        if (!result.empty()) return result;
        return "[error] LocalGGUF native inference failed: " + nativeError;
    } else if (m_activeBackend == AIBackendType::OpenAI) {
'@
Replace-OnceRegex "native synchronous route" $syncPat $syncRep

# 12) Warming gate + OPTIONS already present; inject warming before health
if ($text -notmatch 'runtime_warming') {
    Replace-Once "warmup gate" @'
    const std::string& path = request.path;
    if (request.method == "OPTIONS") return;

#if defined(RAWR_HAS_NATIVE_E2E)
'@ @'
    const std::string& path = request.path;
    if (request.method == "OPTIONS") return;

    if (!RawrXD::HeadlessProduct::RuntimeReady()) {
        if (isHealthRoute(path)) {
            response.status = 200;
            response.body = "{\"status\":\"warming\",\"mode\":\"headless\",\"ready\":false}";
            return;
        }
        response.status = 503;
        response.body = "{\"error\":\"runtime_warming\",\"ready\":false,\"retry\":true}";
        return;
    }

#if defined(RAWR_HAS_NATIVE_E2E)
'@
}

# 13) OPTIONS: allow without Origin (file:// / curl verifier); CORS *
Replace-Once "options authorize" @'
    if (request.method == "OPTIONS") {
        if (requestHeader(request.headers, "origin").empty()) {
            response.status = 403;
            response.body = "{\"error\":\"origin_required\"}";
            return false;
        }
        response.status = 204;
        response.body.clear();
        return true;
    }
'@ @'
    if (request.method == "OPTIONS") {
        // G4: file:// / curl preflight must get 204 even without Origin.
        response.status = 204;
        response.body.clear();
        return true;
    }
'@

Replace-Once "cors star empty origin" @'
    if (!request.origin.empty()) {
        wire << "Access-Control-Allow-Origin: " << request.origin << "\r\nVary: Origin\r\n";
    }
    if (response.status == 401) wire << "WWW-Authenticate: Bearer realm=\"RawrXD\"\r\n";
'@ @'
    if (!request.origin.empty()) {
        wire << "Access-Control-Allow-Origin: " << request.origin << "\r\nVary: Origin\r\n";
    } else {
        wire << "Access-Control-Allow-Origin: *\r\n";
    }
    if (response.status == 401) wire << "WWW-Authenticate: Bearer realm=\"RawrXD\"\r\n";
'@

# 14) modelPath path alias
$text = $text.Replace(
    'modelPath = json.value("modelPath", json.value("model", json.value("name", "")));',
    'modelPath = json.value("modelPath", json.value("path", json.value("model", json.value("name", ""))));')

if ($text -eq $original) { throw "No source changes were produced" }
[IO.File]::WriteAllText($cpp, $text, [System.Text.UTF8Encoding]::new($false))
Write-Host "G4_TREE_ADAPTED_APPLY=PASS"
Write-Host "BACKUP=$backup"
Write-Host "HEADLESSIDE_CPP_SHA256=$((Get-FileHash $cpp -Algorithm SHA256).Hash.ToLowerInvariant())"
Write-Host "PRODUCT_HEADER_SHA256=$((Get-FileHash $helperDst -Algorithm SHA256).Hash.ToLowerInvariant())"
