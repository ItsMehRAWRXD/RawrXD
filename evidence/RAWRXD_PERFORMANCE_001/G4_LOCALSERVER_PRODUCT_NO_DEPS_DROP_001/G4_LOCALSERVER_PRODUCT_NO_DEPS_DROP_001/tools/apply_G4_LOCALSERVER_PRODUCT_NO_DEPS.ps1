param(
    [Parameter(Mandatory=$false)]
    [string]$RepoRoot = "."
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path $RepoRoot).Path
$cpp = Join-Path $repo "src\win32app\HeadlessIDE.cpp"
$helperDst = Join-Path $repo "src\win32app\HeadlessIDE_ProductLocalOnly.hpp"
$helperSrc = Join-Path (Split-Path $PSScriptRoot -Parent) "src\win32app\HeadlessIDE_ProductLocalOnly.hpp"

if (!(Test-Path $cpp)) { throw "HeadlessIDE.cpp not found: $cpp" }
if (!(Test-Path $helperSrc)) { throw "Drop helper not found: $helperSrc" }

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backup = "$cpp.G4_PRE_$stamp"
Copy-Item $cpp $backup -Force
Copy-Item $helperSrc $helperDst -Force

$text = [IO.File]::ReadAllText($cpp)
$original = $text

function Replace-OnceRegex([string]$Name, [string]$Pattern, [string]$Replacement) {
    $script:matches = [regex]::Matches($script:text, $Pattern, [Text.RegularExpressions.RegexOptions]::Singleline)
    if ($script:matches.Count -ne 1) {
        throw "${Name}: expected exactly 1 source match, found $($script:matches.Count). Source left backed up at $backup"
    }
    $script:text = [regex]::Replace($script:text, $Pattern, $Replacement, [Text.RegularExpressions.RegexOptions]::Singleline)
}

function Replace-Literal([string]$Name, [string]$Old, [string]$New) {
    $count = 0; $pos = 0
    while (($pos = $script:text.IndexOf($Old, $pos, [StringComparison]::Ordinal)) -ge 0) { $count++; $pos += $Old.Length }
    if ($count -ne 1) { throw "${Name}: expected exactly 1 source match, found $count. Source left backed up at $backup" }
    $script:text = $script:text.Replace($Old, $New)
}

# 1) Header-only product helper; no CMake source-list change.
if ($text -notmatch 'HeadlessIDE_ProductLocalOnly\.hpp') {
    Replace-Literal "include helper" '#include "../../include/chain_of_thought_engine.h"' "#include \"../../include/chain_of_thought_engine.h\"`r`n#include \"HeadlessIDE_ProductLocalOnly.hpp\""
}

# 2) --local becomes an explicit native LocalGGUF policy selector.
if ($text -notmatch 'arg == "--local"') {
    $pat = 'if \(arg == "--headless"\) \{\s*// Already in headless mode \(this flag is consumed by main_win32\.cpp\)\s*continue;\s*\}'
    $rep = @'
if (arg == "--headless") {
            // Already in headless mode (this flag is consumed by main_win32.cpp)
            continue;
        }
        else if (arg == "--local") {
            // Product contract: native LocalGGUF only; never probe/fall back to :11434.
            m_config.backend = "local";
        }
'@
    Replace-OnceRegex "--local parser" $pat $rep
}

# 3) Own :11435 immediately after WinSock instead of after the full optional-init chain.
if ($text -notmatch 'G4_EARLY_LISTENER') {
    $pat = 'HeadlessResult wr = initWinsock\(\);\s*if \(!wr\.success\) return wr;'
    $rep = @'
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
'@
    Replace-OnceRegex "early 11435 listener" $pat $rep
}

# 4) Runtime readiness only flips after initialization completes.
if ($text -notmatch 'G4_RUNTIME_READY') {
    Replace-Literal "runtime ready" '    m_outputSink->appendOutput("Headless IDE initialized successfully.", OutputSeverity::Info);' @'
    // G4_RUNTIME_READY: requests may now touch initialized runtime state.
    RawrXD::HeadlessProduct::SetRuntimeReady(true);
    m_outputSink->appendOutput("Headless IDE initialized successfully.", OutputSeverity::Info);
'@
}

# 5) Shutdown closes readiness before transport.
$pat = 'void HeadlessIDE::requestShutdown\(\) noexcept \{\s*m_shutdownRequested\.store\(true\);\s*stopServer\(\);\s*\}'
$rep = @'
void HeadlessIDE::requestShutdown() noexcept {
    RawrXD::HeadlessProduct::SetRuntimeReady(false);
    m_shutdownRequested.store(true);
    stopServer();
}
'@
Replace-OnceRegex "shutdown readiness" $pat $rep

# 6) Backend init: no default Ollama probe or auto-selection. Explicit --backend ollama remains available.
$pat = 'HeadlessResult HeadlessIDE::initBackendManager\(\) \{.*?\n\}\s*\n\s*HeadlessResult HeadlessIDE::initLLMRouter\(\) \{'
$rep = @'
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

HeadlessResult HeadlessIDE::initLLMRouter() {
'@
Replace-OnceRegex "backend manager local-only" $pat $rep

# Truthful router availability/priority: native first, explicit Ollama only.
$text = $text.Replace('{ AIBackendType::Ollama,    "Ollama",    1, m_backendManagerInitialized },',
                     '{ AIBackendType::Ollama,    "Ollama",    2, m_activeBackend == AIBackendType::Ollama },')
$text = $text.Replace('{ AIBackendType::LocalGGUF, "LocalGGUF",  2, m_modelLoaded },',
                     '{ AIBackendType::LocalGGUF, "LocalGGUF",  1, m_modelLoaded },')
$text = $text.Replace('// Priority: Ollama (local, fast) > LocalGGUF > Cloud backends',
                     '// Priority: LocalGGUF native > explicitly selected Ollama > cloud backends')


# Strict policy lock: runtime backend switching/probing cannot contact 11434 while local-only.
$setPat = 'bool HeadlessIDE::setActiveBackend\(AIBackendType type\) \{\s*const char\* backendNames\[\] ='
$setRep = @'
bool HeadlessIDE::setActiveBackend(AIBackendType type) {
    if (type == AIBackendType::Ollama && RawrXD::HeadlessProduct::LocalOnly()) {
        m_outputSink->appendOutput("Ollama switch blocked by LOCAL_ONLY_NO_OLLAMA", OutputSeverity::Warning);
        return false;
    }
    const char* backendNames[] =
'@
Replace-OnceRegex "local-only backend switch guard" $setPat $setRep

$probePat = 'bool HeadlessIDE::probeBackendHealth\(AIBackendType type\) \{\s*switch \(type\) \{'
$probeRep = @'
bool HeadlessIDE::probeBackendHealth(AIBackendType type) {
    if (type == AIBackendType::Ollama && RawrXD::HeadlessProduct::LocalOnly()) {
        return false;
    }
    switch (type) {
'@
Replace-OnceRegex "local-only health probe guard" $probePat $probeRep

# 7) Local-only model resolution cannot reinterpret a basename as an Ollama/HF/network source.
if ($text -notmatch 'local-only product mode never resolves') {
$pat = '// Phase 1: Resolve the model source — local, Ollama, HuggingFace, URL\s*RawrXD::ModelSourceResolver resolver;\s*RawrXD::ResolvedModelPath resolved = resolver\.Resolve\(filepath,\s*\[this\]\(const RawrXD::ModelDownloadProgress& p\) \{.*?\}\);\s*\s*std::string localPath = resolved\.success \? resolved\.local_path : filepath;'
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

# 8) Metadata-open alone is not a runnable model. Load into the process-wide native engine before declaring success.
if ($text -notmatch 'G4_NATIVE_ENGINE_LOAD') {
    Replace-Literal "native engine load" '    // Store state' @'
    // G4_NATIVE_ENGINE_LOAD: make model selection runnable, not metadata-only.
    std::string nativeLoadError;
    if (!RawrXD::HeadlessProduct::LoadNativeModel(localPath, nativeLoadError)) {
        m_outputSink->appendOutput(("Native model load failed: " + nativeLoadError).c_str(), OutputSeverity::Error);
        loader->Close();
        return false;
    }

    // Store state
'@
}

# 9) Native LocalGGUF streaming path. Ollama code is retained only for explicit Ollama selection.
$pat = 'void HeadlessIDE::runInferenceStreaming\(const std::string& prompt,\s*std::function<void\(const char\*, size_t\)> tokenCallback\) \{.*?\n\}\s*\n\s*// ============================================================================\s*\n// Backend Switcher \(Phase 8B\)'
$rep = @'
void HeadlessIDE::runInferenceStreaming(const std::string& prompt,
                                         std::function<void(const char*, size_t)> tokenCallback) {
    if (!m_modelLoaded) {
        m_outputSink->appendOutput("No model loaded for streaming inference", OutputSeverity::Error);
        return;
    }

    m_outputSink->onStreamStart("inference");

    if (m_activeBackend == AIBackendType::LocalGGUF) {
        std::string nativeError;
        const bool ok = RawrXD::HeadlessProduct::GenerateNativeStreaming(
            prompt, m_config.maxTokens,
            [&](const std::string& token) {
                if (tokenCallback) tokenCallback(token.c_str(), token.size());
                m_outputSink->onStreamingToken(token.c_str(), token.size(), StreamTokenOrigin::Inference);
            }, nativeError);
        if (!ok) m_outputSink->appendOutput(nativeError.c_str(), OutputSeverity::Error);
        m_outputSink->onStreamEnd("inference", ok);
        return;
    }

    if (m_activeBackend == AIBackendType::Ollama) {
        if (RawrXD::HeadlessProduct::LocalOnly()) {
            m_outputSink->appendOutput("Ollama blocked by LOCAL_ONLY_NO_OLLAMA", OutputSeverity::Error);
            m_outputSink->onStreamEnd("inference", false);
            return;
        }
        RawrXD::Agent::OllamaConfig cfg;
        cfg.host = "127.0.0.1";
        cfg.port = 11434;
        cfg.temperature = m_config.temperature;
        cfg.max_tokens = m_config.maxTokens;
        cfg.use_gpu = true;
        cfg.num_gpu = 99;
        RawrXD::Agent::AgentOllamaClient client(cfg);
        std::vector<RawrXD::Agent::ChatMessage> messages;
        messages.push_back({"system", "You are RawrXD IDE's embedded AI assistant.", "", {}});
        messages.push_back({"user", prompt, "", {}});
        bool streamOk = client.ChatStream(
            messages, nlohmann::json::array(),
            [&](const std::string& token) {
                if (tokenCallback) tokenCallback(token.c_str(), token.size());
                m_outputSink->onStreamingToken(token.c_str(), token.size(), StreamTokenOrigin::Inference);
            },
            [](const std::string&, const nlohmann::json&) {},
            [&](const std::string&, uint64_t, uint64_t, double) {},
            [&](const std::string& err) {
                m_outputSink->appendOutput(("Stream error: " + err).c_str(), OutputSeverity::Error);
            });
        m_outputSink->onStreamEnd("inference", streamOk);
        return;
    }

    std::string result = runInference(prompt);
    if (tokenCallback && !result.empty()) tokenCallback(result.c_str(), result.size());
    m_outputSink->onStreamEnd("inference", !result.empty());
}

// ============================================================================
// Backend Switcher (Phase 8B)
'@
Replace-OnceRegex "native streaming route" $pat $rep

# 10) Synchronous LocalGGUF routing uses the same shared native engine; no hidden :11434 fallback.
$pat = 'std::string HeadlessIDE::routeInferenceRequest\(const std::string& prompt\) \{.*?\n\}\s*\n\s*// ============================================================================\s*\n// LLM Router \(Phase 8C\)'
$rep = @'
std::string HeadlessIDE::routeInferenceRequest(const std::string& prompt) {
    m_inferenceRequestCount++;
    recordSimpleEvent("inference_request");

    if (m_activeBackend == AIBackendType::LocalGGUF) {
        std::string nativeError;
        std::string result = RawrXD::HeadlessProduct::GenerateNative(prompt, m_config.maxTokens, nativeError);
        if (!result.empty()) return result;
        return "[error] LocalGGUF native inference failed: " + nativeError;
    }

    if (m_activeBackend == AIBackendType::Ollama) {
        if (RawrXD::HeadlessProduct::LocalOnly())
            return "[error] Ollama blocked by LOCAL_ONLY_NO_OLLAMA";

        RawrXD::Agent::OllamaConfig cfg;
        cfg.host = "127.0.0.1";
        cfg.port = 11434;
        cfg.temperature = m_config.temperature;
        cfg.max_tokens = m_config.maxTokens;
        cfg.use_gpu = true;
        cfg.num_gpu = 99;
        RawrXD::Agent::AgentOllamaClient client(cfg);
        std::vector<RawrXD::Agent::ChatMessage> messages;
        messages.push_back({"system", "You are RawrXD IDE's embedded AI assistant.", "", {}});
        if (m_modelLoaded) messages.push_back({"system", "Loaded model: " + m_loadedModelName, "", {}});
        messages.push_back({"user", prompt, "", {}});
        auto result = client.ChatSync(messages);
        if (result.success) return result.response;
        return "[error] Explicit Ollama inference failed: " + result.error_message;
    }

    if (m_engineManager) {
        std::string currentId = m_engineManager->GetCurrentEngine();
        auto* engine = currentId.empty() ? nullptr : m_engineManager->GetEngine(currentId);
        if (engine && engine->loaded)
            return "[error] Selected engine has no HeadlessIDE inference adapter: " + engine->name;
    }
    return "[error] Selected backend is unavailable in HeadlessIDE";
}

// ============================================================================
// LLM Router (Phase 8C)
'@
Replace-OnceRegex "native synchronous route" $pat $rep

# 11) file:// CORS preflight + startup gate. Health remains reachable while warming.
$old = '    if (path == "/api/status" || path == "/api/headless/status") {'
$new = @'
    if (method == "OPTIONS") {
        statusCode = 204;
        responseBody.clear();
    }
    else if (!RawrXD::HeadlessProduct::RuntimeReady()) {
        if (path == "/health" || path == "/api/health") {
            statusCode = 200;
            responseBody = "{\"status\":\"warming\",\"mode\":\"headless\",\"ready\":false}";
        } else {
            statusCode = 503;
            responseBody = "{\"error\":\"runtime_warming\",\"ready\":false,\"retry\":true}";
        }
    }
    else if (path == "/api/status" || path == "/api/headless/status") {
'@
Replace-Literal "warmup/CORS routing" $old $new


# Product parity aliases used by standalone beacon/diagnostics. Tool/MOTD path is intentionally untouched.
if ($text -notmatch 'path == "/api/backends"') {
$backendOld = @'
    else if (path == "/api/backend/status") {
        responseBody = "{\"status\":\"" + getBackendStatusString() + "\"}";
    }
'@
$backendNew = @'
    else if (path == "/api/backend/status") {
        responseBody = "{\"status\":\"" + getBackendStatusString() + "\"}";
    }
    else if (path == "/api/backends" || path == "/api/backends/status") {
        responseBody = "{\"active\":\"" + std::string(
            m_activeBackend == AIBackendType::LocalGGUF ? "LocalGGUF" :
            m_activeBackend == AIBackendType::Ollama ? "Ollama" : "Other") +
            "\",\"localOnly\":" +
            std::string(RawrXD::HeadlessProduct::LocalOnly() ? "true" : "false") + "}";
    }
    else if (path == "/api/agents/status") {
        responseBody = "{\"status\":\"ready\",\"mode\":\"headless\"}";
    }
    else if (path == "/api/failures") {
        responseBody = "{\"stats\":\"" + getFailureDetectorStats() + "\"}";
    }
'@
Replace-Literal "product diagnostic aliases" $backendOld $backendNew
}

# 12) /api/chat product alias and safe JSON serialization.
$old = '    else if (path == "/api/generate" && method == "POST") {'
$new = '    else if ((path == "/api/generate" || path == "/api/chat") && method == "POST") {'
Replace-Literal "chat alias" $old $new
$text = $text.Replace('            prompt = j.value("prompt", "");', '            prompt = j.value("prompt", j.value("message", ""));')
$text = $text.Replace('        responseBody = "{\"response\":\"" + result + "\"}";',
                     '        responseBody = nlohmann::json{{"response", result}, {"backend", "local"}}.dump();')

# Accept path alias used by browser-native registration payloads.
$text = $text.Replace('modelPath = j.value("modelPath", j.value("model", j.value("name", "")));',
                     'modelPath = j.value("modelPath", j.value("path", j.value("model", j.value("name", ""))));')

# 13) Correct HTTP reason phrase and complete CORS contract.
if ($text -notmatch 'HeadlessProduct::HttpReason') {
Replace-Literal "status reason" '    resp << "HTTP/1.1 " << statusCode << " " << (statusCode == 200 ? "OK" : "Not Found") << "\r\n";' @'
    resp << "HTTP/1.1 " << statusCode << " " << RawrXD::HeadlessProduct::HttpReason(statusCode) << "\r\n";
'@
}
if ($text -notmatch 'Access-Control-Allow-Methods') {
Replace-Literal "CORS headers" '    resp << "Access-Control-Allow-Origin: *\r\n";' @'
    resp << "Access-Control-Allow-Origin: *\r\n";
    resp << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
    resp << "Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With\r\n";
    resp << "Access-Control-Max-Age: 600\r\n";
'@
}

if ($text -eq $original) { throw "No source changes were produced" }
[IO.File]::WriteAllText($cpp, $text, [System.Text.UTF8Encoding]::new($false))

$shaCpp = (Get-FileHash $cpp -Algorithm SHA256).Hash.ToLowerInvariant()
$shaHdr = (Get-FileHash $helperDst -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "G4_SOURCE_APPLY=PASS"
Write-Host "PATCHED=$cpp"
Write-Host "ADDED=$helperDst"
Write-Host "BACKUP=$backup"
Write-Host "HEADLESSIDE_CPP_SHA256=$shaCpp"
Write-Host "PRODUCT_HEADER_SHA256=$shaHdr"
Write-Host "NO_NEW_EXTERNAL_DEPS=1"
Write-Host "NEXT=RELINK RawrXD-Win32IDE.exe with the tree's existing known-good exclusive build/link recipe"
