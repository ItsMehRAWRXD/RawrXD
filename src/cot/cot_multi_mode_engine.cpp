// ============================================================================
// CoT Multi-Mode Engine Implementation
// ============================================================================

#include "cot_multi_mode_engine.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <regex>

// Simple HTTP client without external dependencies
#ifdef _WIN32
#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")
#endif

namespace RawrXD {
namespace CoT {

// ============================================================================
// Constructor / Destructor
// ============================================================================

MultiModeCoTEngine::MultiModeCoTEngine()
    : m_endpoint("http://localhost:11434")
    , m_model("llama3.2:3b")
    , m_apiKey("")
    , m_initialized(false)
{
    InitializeModeConfigs();
}

MultiModeCoTEngine::~MultiModeCoTEngine() = default;

// ============================================================================
// Configuration
// ============================================================================

void MultiModeCoTEngine::SetModelEndpoint(const std::string& endpoint) {
    m_endpoint = endpoint;
}

void MultiModeCoTEngine::SetDefaultModel(const std::string& model) {
    m_model = model;
}

void MultiModeCoTEngine::SetAPIKey(const std::string& key) {
    m_apiKey = key;
}

// ============================================================================
// Mode Configuration Initialization
// ============================================================================

void MultiModeCoTEngine::InitializeModeConfigs() {
    // THINKER - Deep analytical thinking
    m_modeConfigs[ReasoningMode::THINKER] = {
        ReasoningMode::THINKER,
        "You are a deep analytical thinker. Break down complex problems step by step. "
        "Show your reasoning process clearly. Consider multiple angles and edge cases.",
        0.7f, 2048, 0.75f, true, {"input"}
    };
    
    // AUDITOR - Code/Logic audit
    m_modeConfigs[ReasoningMode::AUDITOR] = {
        ReasoningMode::AUDITOR,
        "You are a code auditor and security reviewer. Analyze code for bugs, "
        "security vulnerabilities, performance issues, and best practice violations. "
        "Be thorough and specific.",
        0.3f, 2048, 0.85f, true, {"code"}
    };
    
    // REVIEWER - Peer review
    m_modeConfigs[ReasoningMode::REVIEWER] = {
        ReasoningMode::REVIEWER,
        "You are conducting a peer review. Provide constructive feedback, "
        "identify strengths and weaknesses, suggest improvements. Be professional and helpful.",
        0.5f, 2048, 0.80f, true, {"content"}
    };
    
    // RESEARCHER - Research mode
    m_modeConfigs[ReasoningMode::RESEARCHER] = {
        ReasoningMode::RESEARCHER,
        "You are a researcher. Explore the topic thoroughly, gather facts, "
        "investigate alternatives, cite sources where relevant. Be comprehensive.",
        0.8f, 2048, 0.70f, true, {"topic"}
    };
    
    // ARGUE_FOR - Devil's advocate (pro)
    m_modeConfigs[ReasoningMode::ARGUE_FOR] = {
        ReasoningMode::ARGUE_FOR,
        "You are arguing STRONGLY FOR the given position. Make the best possible case. "
        "Use strong arguments, evidence, and reasoning. Convince the reader.",
        0.8f, 2048, 0.75f, true, {"position"}
    };
    
    // ARGUE_AGAINST - Devil's advocate (con)
    m_modeConfigs[ReasoningMode::ARGUE_AGAINST] = {
        ReasoningMode::ARGUE_AGAINST,
        "You are arguing STRONGLY AGAINST the given position. Make the best possible case. "
        "Use strong arguments, evidence, and reasoning. Convince the reader.",
        0.8f, 2048, 0.75f, true, {"position"}
    };
    
    // CRITIC - Critical analysis
    m_modeConfigs[ReasoningMode::CRITIC] = {
        ReasoningMode::CRITIC,
        "You are a critic. Find flaws, weaknesses, edge cases, and problems. "
        "Be thorough in your critique but fair. Identify what could go wrong.",
        0.4f, 2048, 0.80f, true, {"content"}
    };
    
    // SYNTHESIZER - Combine perspectives
    m_modeConfigs[ReasoningMode::SYNTHESIZER] = {
        ReasoningMode::SYNTHESIZER,
        "You are synthesizing multiple perspectives into a coherent whole. "
        "Find common ground, resolve contradictions, create unity from diversity.",
        0.6f, 2048, 0.85f, true, {"perspectives"}
    };
    
    // BRAINSTORM - Creative generation
    m_modeConfigs[ReasoningMode::BRAINSTORM] = {
        ReasoningMode::BRAINSTORM,
        "You are brainstorming. Generate creative ideas, explore possibilities, "
        "think outside the box. No idea is too wild. Be prolific and imaginative.",
        0.9f, 2048, 0.65f, true, {"topic"}
    };
    
    // VERIFIER - Verify correctness
    m_modeConfigs[ReasoningMode::VERIFIER] = {
        ReasoningMode::VERIFIER,
        "You are verifying correctness. Check facts, validate assumptions, "
        "confirm logic. Be precise and rigorous in your verification.",
        0.2f, 2048, 0.90f, true, {"claim"}
    };
    
    // REFINER - Polish and improve
    m_modeConfigs[ReasoningMode::REFINER] = {
        ReasoningMode::REFINER,
        "You are refining content. Improve clarity, precision, and flow. "
        "Fix grammar, enhance structure, polish the presentation.",
        0.4f, 2048, 0.85f, true, {"content"}
    };
    
    // SUMMARIZER - Condense
    m_modeConfigs[ReasoningMode::SUMMARIZER] = {
        ReasoningMode::SUMMARIZER,
        "You are summarizing. Extract key points, condense information, "
        "create a concise overview. Preserve essential meaning.",
        0.3f, 1024, 0.90f, true, {"content"}
    };
}

// ============================================================================
// Core Execution
// ============================================================================

CoTResult MultiModeCoTEngine::ExecuteChain(
    const std::string& query,
    const std::vector<ReasoningMode>& modes,
    const std::unordered_map<std::string, std::string>& context
) {
    CoTResult result;
    result.query = query;
    result.success = true;
    result.totalTokens = 0;
    
    auto startTime = std::chrono::steady_clock::now();
    
    std::string currentInput = query;
    
    for (size_t i = 0; i < modes.size(); ++i) {
        auto modeStart = std::chrono::steady_clock::now();
        
        CoTStep step = ExecuteMode(modes[i], currentInput, context);
        step.timestamp = std::chrono::steady_clock::now();
        
        auto modeEnd = std::chrono::steady_clock::now();
        step.durationMs = std::chrono::duration<double, std::milli>(modeEnd - modeStart).count();
        
        result.steps.push_back(step);
        result.totalTokens += step.tokenCount;
        
        // Pass output to next mode as input
        currentInput = step.thought;
        
        // Early termination on low confidence
        if (step.confidence < 0.3f) {
            result.success = false;
            result.error = "Low confidence in step " + std::to_string(i + 1);
            break;
        }
    }
    
    auto endTime = std::chrono::steady_clock::now();
    result.totalDurationMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
    
    // Calculate overall confidence
    if (!result.steps.empty()) {
        float totalConf = 0.0f;
        for (const auto& step : result.steps) {
            totalConf += step.confidence;
        }
        result.overallConfidence = totalConf / result.steps.size();
    }
    
    // Final answer is from last step
    if (!result.steps.empty()) {
        result.finalAnswer = result.steps.back().thought;
    }
    
    // Build metadata
    result.metadata["mode_count"] = modes.size();
    result.metadata["model"] = m_model;
    result.metadata["endpoint"] = m_endpoint;
    
    return result;
}

CoTStep MultiModeCoTEngine::ExecuteMode(
    ReasoningMode mode,
    const std::string& input,
    const std::unordered_map<std::string, std::string>& context
) {
    CoTStep step;
    step.mode = static_cast<uint8_t>(mode);
    step.modeName = ModeNames[static_cast<size_t>(mode)];
    step.emoji = ModeEmojis[static_cast<size_t>(mode)];
    
    // Build prompt
    std::string prompt = BuildPrompt(mode, input, context);
    
    // Get config
    const auto& config = m_modeConfigs[mode];
    
    // Call model
    std::string response = CallModel(prompt, config.temperature, config.maxTokens);
    
    step.thought = response;
    step.confidence = EvaluateConfidence(response, mode);
    step.reasoning = ExtractReasoning(response);
    step.tokenCount = static_cast<uint32_t>(response.length() / 4); // Rough estimate
    
    return step;
}

// ============================================================================
// Prompt Builders
// ============================================================================

std::string MultiModeCoTEngine::BuildPrompt(
    ReasoningMode mode,
    const std::string& input,
    const std::unordered_map<std::string, std::string>& context
) {
    switch (mode) {
        case ReasoningMode::THINKER:
            return BuildThinkerPrompt(input);
        case ReasoningMode::AUDITOR:
            return BuildAuditorPrompt(input);
        case ReasoningMode::REVIEWER:
            return BuildReviewerPrompt(input);
        case ReasoningMode::RESEARCHER:
            return BuildResearcherPrompt(input);
        case ReasoningMode::ARGUE_FOR:
            return BuildArgueForPrompt(input);
        case ReasoningMode::ARGUE_AGAINST:
            return BuildArgueAgainstPrompt(input);
        case ReasoningMode::CRITIC:
            return BuildCriticPrompt(input);
        case ReasoningMode::SYNTHESIZER:
            return BuildSynthesizerPrompt({input});
        case ReasoningMode::BRAINSTORM:
            return BuildBrainstormPrompt(input);
        case ReasoningMode::VERIFIER:
            return BuildVerifierPrompt(input);
        case ReasoningMode::REFINER:
            return BuildRefinerPrompt(input);
        case ReasoningMode::SUMMARIZER:
            return BuildSummarizerPrompt(input);
        default:
            return input;
    }
}

std::string MultiModeCoTEngine::BuildThinkerPrompt(const std::string& input) {
    return "Think deeply about the following. Show your step-by-step reasoning:\n\n" + input;
}

std::string MultiModeCoTEngine::BuildAuditorPrompt(const std::string& input) {
    return "Audit the following code/logic for bugs, security issues, and best practices. "
           "Be specific about what you find:\n\n" + input;
}

std::string MultiModeCoTEngine::BuildReviewerPrompt(const std::string& input) {
    return "Review the following as a peer reviewer. Provide constructive feedback:\n\n" + input;
}

std::string MultiModeCoTEngine::BuildResearcherPrompt(const std::string& input) {
    return "Research the following topic thoroughly. Explore facts, alternatives, and implications:\n\n" + input;
}

std::string MultiModeCoTEngine::BuildArgueForPrompt(const std::string& input) {
    return "Argue STRONGLY IN FAVOR of the following position. Make the best possible case:\n\n" + input;
}

std::string MultiModeCoTEngine::BuildArgueAgainstPrompt(const std::string& input) {
    return "Argue STRONGLY AGAINST the following position. Make the best possible case:\n\n" + input;
}

std::string MultiModeCoTEngine::BuildCriticPrompt(const std::string& input) {
    return "Critically analyze the following. Find flaws, weaknesses, and edge cases:\n\n" + input;
}

std::string MultiModeCoTEngine::BuildSynthesizerPrompt(const std::vector<std::string>& perspectives) {
    std::string prompt = "Synthesize the following perspectives into a coherent whole:\n\n";
    for (size_t i = 0; i < perspectives.size(); ++i) {
        prompt += "Perspective " + std::to_string(i + 1) + ":\n" + perspectives[i] + "\n\n";
    }
    return prompt;
}

std::string MultiModeCoTEngine::BuildBrainstormPrompt(const std::string& input) {
    return "Brainstorm creative ideas about the following. Be imaginative and prolific:\n\n" + input;
}

std::string MultiModeCoTEngine::BuildVerifierPrompt(const std::string& input) {
    return "Verify the correctness of the following. Check facts and validate logic:\n\n" + input;
}

std::string MultiModeCoTEngine::BuildRefinerPrompt(const std::string& input) {
    return "Refine and polish the following. Improve clarity, precision, and flow:\n\n" + input;
}

std::string MultiModeCoTEngine::BuildSummarizerPrompt(const std::string& input) {
    return "Summarize the following concisely. Extract only the key points:\n\n" + input;
}

// ============================================================================
// Model Calling (HTTP to Ollama) - WinHTTP Implementation
// ============================================================================

#ifdef _WIN32
std::string HttpPostJson(const std::string& url, const std::string& jsonPayload, int timeoutSec = 120) {
    std::string response;
    
    // Parse URL
    std::string host, path;
    int port = 11434;
    
    size_t protoEnd = url.find("://");
    size_t hostStart = (protoEnd == std::string::npos) ? 0 : protoEnd + 3;
    size_t portStart = url.find(":", hostStart);
    size_t pathStart = url.find("/", hostStart);
    
    if (portStart != std::string::npos && (pathStart == std::string::npos || portStart < pathStart)) {
        host = url.substr(hostStart, portStart - hostStart);
        port = std::stoi(url.substr(portStart + 1, pathStart - portStart - 1));
    } else {
        host = (pathStart == std::string::npos) ? url.substr(hostStart) : url.substr(hostStart, pathStart - hostStart);
    }
    
    path = (pathStart == std::string::npos) ? "/" : url.substr(pathStart);
    if (path.empty()) path = "/";
    
    // Use WinHTTP
    HINTERNET hInternet = InternetOpenA("RawrXD-CoT/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        return "Error: Failed to initialize WinHTTP";
    }
    
    HINTERNET hConnect = InternetConnectA(hInternet, host.c_str(), port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return "Error: Failed to connect to " + host;
    }
    
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", path.c_str(), NULL, NULL, NULL, INTERNET_FLAG_RELOAD, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return "Error: Failed to open HTTP request";
    }
    
    // Add headers
    std::string headers = "Content-Type: application/json\r\n";
    HttpAddRequestHeadersA(hRequest, headers.c_str(), headers.length(), HTTP_ADDREQ_FLAG_ADD);
    
    // Send request
    BOOL sent = HttpSendRequestA(hRequest, NULL, 0, (LPVOID)jsonPayload.c_str(), jsonPayload.length());
    if (!sent) {
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return "Error: Failed to send HTTP request";
    }
    
    // Read response
    char buffer[4096];
    DWORD bytesRead;
    while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        response += buffer;
    }
    
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    
    return response;
}
#endif

std::string MultiModeCoTEngine::CallModel(const std::string& prompt, float temperature, int maxTokens) {
    std::string url = m_endpoint + "/api/generate";
    
    // Build JSON payload
    nlohmann::json payload = {
        {"model", m_model},
        {"prompt", prompt},
        {"stream", false},
        {"options", {
            {"temperature", temperature},
            {"num_predict", maxTokens}
        }}
    };
    
    std::string jsonStr = payload.dump();
    std::string responseString;
    
#ifdef _WIN32
    responseString = HttpPostJson(url, jsonStr);
#else
    // Fallback for non-Windows - would need curl
    responseString = "Error: HTTP client not implemented for this platform";
#endif
    
    if (responseString.find("Error:") == 0) {
        return responseString;
    }
    
    // Parse response
    try {
        nlohmann::json response = nlohmann::json::parse(responseString);
        if (response.contains("response")) {
            return response["response"].get<std::string>();
        }
    } catch (...) {
        return "Error: Failed to parse response";
    }
    
    return responseString;
}

// ============================================================================
// Evaluation
// ============================================================================

float MultiModeCoTEngine::EvaluateConfidence(const std::string& response, ReasoningMode mode) {
    // Simple heuristic-based confidence scoring
    float confidence = 0.7f;
    
    // Length-based scoring
    if (response.length() < 50) {
        confidence -= 0.2f;
    } else if (response.length() > 500) {
        confidence += 0.1f;
    }
    
    // Content quality indicators
    if (response.find("Error:") != std::string::npos ||
        response.find("error") != std::string::npos) {
        confidence -= 0.3f;
    }
    
    if (response.find("because") != std::string::npos ||
        response.find("therefore") != std::string::npos ||
        response.find("however") != std::string::npos) {
        confidence += 0.1f;
    }
    
    // Mode-specific adjustments
    switch (mode) {
        case ReasoningMode::VERIFIER:
            if (response.find("correct") != std::string::npos ||
                response.find("valid") != std::string::npos) {
                confidence += 0.1f;
            }
            break;
        case ReasoningMode::CRITIC:
            if (response.find("issue") != std::string::npos ||
                response.find("problem") != std::string::npos) {
                confidence += 0.1f;
            }
            break;
        default:
            break;
    }
    
    return std::clamp(confidence, 0.0f, 1.0f);
}

std::string MultiModeCoTEngine::ExtractReasoning(const std::string& response) {
    // Extract reasoning section if present
    size_t pos = response.find("Reasoning:");
    if (pos != std::string::npos) {
        return response.substr(pos + 10);
    }
    
    pos = response.find("because");
    if (pos != std::string::npos) {
        return response.substr(pos);
    }
    
    return "";
}

// ============================================================================
// Convenience Methods
// ============================================================================

CoTResult MultiModeCoTEngine::Think(const std::string& query, 
                                    const std::unordered_map<std::string, std::string>& context) {
    return ExecuteChain(query, {ReasoningMode::THINKER}, context);
}

CoTResult MultiModeCoTEngine::Audit(const std::string& code, 
                                    const std::unordered_map<std::string, std::string>& context) {
    return ExecuteChain(code, {ReasoningMode::AUDITOR}, context);
}

CoTResult MultiModeCoTEngine::Review(const std::string& content, 
                                     const std::unordered_map<std::string, std::string>& context) {
    return ExecuteChain(content, {ReasoningMode::REVIEWER}, context);
}

CoTResult MultiModeCoTEngine::Research(const std::string& topic, 
                                       const std::unordered_map<std::string, std::string>& context) {
    return ExecuteChain(topic, {ReasoningMode::RESEARCHER}, context);
}

CoTResult MultiModeCoTEngine::ArgueFor(const std::string& position, 
                                        const std::unordered_map<std::string, std::string>& context) {
    return ExecuteChain(position, {ReasoningMode::ARGUE_FOR}, context);
}

CoTResult MultiModeCoTEngine::ArgueAgainst(const std::string& position, 
                                           const std::unordered_map<std::string, std::string>& context) {
    return ExecuteChain(position, {ReasoningMode::ARGUE_AGAINST}, context);
}

CoTResult MultiModeCoTEngine::Critique(const std::string& content, 
                                       const std::unordered_map<std::string, std::string>& context) {
    return ExecuteChain(content, {ReasoningMode::CRITIC}, context);
}

CoTResult MultiModeCoTEngine::Synthesize(const std::vector<std::string>& perspectives, 
                                         const std::unordered_map<std::string, std::string>& context) {
    std::string combined;
    for (const auto& p : perspectives) {
        combined += p + "\n---\n";
    }
    return ExecuteChain(combined, {ReasoningMode::SYNTHESIZER}, context);
}

CoTResult MultiModeCoTEngine::Brainstorm(const std::string& topic, 
                                          const std::unordered_map<std::string, std::string>& context) {
    return ExecuteChain(topic, {ReasoningMode::BRAINSTORM}, context);
}

CoTResult MultiModeCoTEngine::Verify(const std::string& claim, 
                                      const std::unordered_map<std::string, std::string>& context) {
    return ExecuteChain(claim, {ReasoningMode::VERIFIER}, context);
}

CoTResult MultiModeCoTEngine::Refine(const std::string& content, 
                                     const std::unordered_map<std::string, std::string>& context) {
    return ExecuteChain(content, {ReasoningMode::REFINER}, context);
}

CoTResult MultiModeCoTEngine::Summarize(const std::string& content, 
                                        const std::unordered_map<std::string, std::string>& context) {
    return ExecuteChain(content, {ReasoningMode::SUMMARIZER}, context);
}

// ============================================================================
// Full Chain (8-step like example)
// ============================================================================

CoTResult MultiModeCoTEngine::ExecuteFullChain(
    const std::string& query,
    const std::unordered_map<std::string, std::string>& context
) {
    std::vector<ReasoningMode> chain = {
        ReasoningMode::BRAINSTORM,   // Generate ideas
        ReasoningMode::THINKER,        // Deep analysis
        ReasoningMode::RESEARCHER,     // Research facts
        ReasoningMode::ARGUE_FOR,      // Pro arguments
        ReasoningMode::ARGUE_AGAINST,  // Con arguments
        ReasoningMode::CRITIC,         // Critical analysis
        ReasoningMode::VERIFIER,       // Verify correctness
        ReasoningMode::SYNTHESIZER     // Final synthesis
    };
    
    return ExecuteChain(query, chain, context);
}

// ============================================================================
// Status and Info
// ============================================================================

nlohmann::json MultiModeCoTEngine::GetModeInfo(ReasoningMode mode) const {
    size_t idx = static_cast<size_t>(mode);
    return {
        {"id", idx},
        {"name", ModeNames[idx]},
        {"emoji", ModeEmojis[idx]},
        {"description", ModeDescriptions[idx]},
        {"temperature", m_modeConfigs.at(mode).temperature},
        {"maxTokens", m_modeConfigs.at(mode).maxTokens}
    };
}

nlohmann::json MultiModeCoTEngine::GetAllModes() const {
    nlohmann::json modes = nlohmann::json::array();
    for (int i = 0; i < 12; ++i) {
        modes.push_back(GetModeInfo(static_cast<ReasoningMode>(i)));
    }
    return modes;
}

nlohmann::json MultiModeCoTEngine::GetStatus() const {
    return {
        {"initialized", m_initialized},
        {"endpoint", m_endpoint},
        {"model", m_model},
        {"mode_count", 12}
    };
}

// ============================================================================
// Export/Formatting
// ============================================================================

nlohmann::json MultiModeCoTEngine::ExportResult(const CoTResult& result) const {
    nlohmann::json steps = nlohmann::json::array();
    for (const auto& step : result.steps) {
        steps.push_back({
            {"mode", step.modeName},
            {"emoji", step.emoji},
            {"thought", step.thought},
            {"reasoning", step.reasoning},
            {"confidence", step.confidence},
            {"durationMs", step.durationMs},
            {"tokenCount", step.tokenCount}
        });
    }
    
    return {
        {"query", result.query},
        {"success", result.success},
        {"steps", steps},
        {"finalAnswer", result.finalAnswer},
        {"overallConfidence", result.overallConfidence},
        {"totalDurationMs", result.totalDurationMs},
        {"totalTokens", result.totalTokens},
        {"metadata", result.metadata},
        {"error", result.error}
    };
}

std::string MultiModeCoTEngine::FormatResultForDisplay(const CoTResult& result, bool verbose) const {
    std::ostringstream oss;
    
    oss << "\n" << std::string(60, '=') << "\n";
    oss << "🧠 Chain of Thought Result\n";
    oss << std::string(60, '=') << "\n\n";
    
    oss << "Query: " << result.query << "\n";
    oss << "Success: " << (result.success ? "✅" : "❌") << "\n";
    oss << "Steps: " << result.steps.size() << "\n";
    oss << "Total Duration: " << std::fixed << std::setprecision(0) << result.totalDurationMs << "ms\n";
    oss << "Overall Confidence: " << std::setprecision(2) << result.overallConfidence * 100 << "%\n\n";
    
    for (size_t i = 0; i < result.steps.size(); ++i) {
        const auto& step = result.steps[i];
        oss << std::string(40, '-') << "\n";
        oss << (i + 1) << ". " << step.emoji << " " << step.modeName << "\n";
        oss << "   Duration: " << std::fixed << std::setprecision(0) << step.durationMs << "ms\n";
        oss << "   Confidence: " << std::setprecision(1) << step.confidence * 100 << "%\n\n";
        
        if (verbose) {
            oss << "   Thought:\n" << step.thought << "\n\n";
        } else {
            // Truncate for non-verbose
            std::string preview = step.thought.substr(0, 200);
            if (step.thought.length() > 200) preview += "...";
            oss << "   Preview: " << preview << "\n\n";
        }
    }
    
    oss << std::string(40, '-') << "\n";
    oss << "✅ Final Answer:\n";
    oss << result.finalAnswer << "\n\n";
    
    return oss.str();
}

std::string MultiModeCoTEngine::FormatResultForCLI(const CoTResult& result) const {
    std::ostringstream oss;
    
    oss << "\n🧠 Chain of Thought (" << result.steps.size() << " steps) — ";
    oss << "Complete in " << std::fixed << std::setprecision(0) << result.totalDurationMs << "ms\n";
    
    for (size_t i = 0; i < result.steps.size(); ++i) {
        const auto& step = result.steps[i];
        oss << (i + 1) << step.emoji << " " << step.modeName;
        oss << " " << m_model << " " << std::setprecision(0) << step.durationMs << "ms\n";
        
        // Show first line of thought
        std::string firstLine = step.thought.substr(0, step.thought.find('\n'));
        if (firstLine.length() > 80) firstLine = firstLine.substr(0, 77) + "...";
        oss << "   " << firstLine << "\n\n";
    }
    
    oss << "✅ Final Answer (" << result.totalDurationMs << "ms total, " << result.steps.size() << " steps)\n";
    oss << result.finalAnswer << "\n";
    
    return oss.str();
}

// ============================================================================
// CLI Helper Implementation
// ============================================================================

std::vector<ReasoningMode> CoTCLIHelper::ParseModeString(const std::string& modeStr) {
    std::vector<ReasoningMode> modes;
    std::istringstream iss(modeStr);
    std::string mode;
    
    while (std::getline(iss, mode, ',')) {
        // Trim whitespace
        mode.erase(0, mode.find_first_not_of(" \t"));
        mode.erase(mode.find_last_not_of(" \t") + 1);
        
        // Convert to lowercase for comparison
        std::transform(mode.begin(), mode.end(), mode.begin(), ::tolower);
        
        if (mode == "thinker" || mode == "think") modes.push_back(ReasoningMode::THINKER);
        else if (mode == "auditor" || mode == "audit") modes.push_back(ReasoningMode::AUDITOR);
        else if (mode == "reviewer" || mode == "review") modes.push_back(ReasoningMode::REVIEWER);
        else if (mode == "researcher" || mode == "research") modes.push_back(ReasoningMode::RESEARCHER);
        else if (mode == "arguefor" || mode == "argue_for" || mode == "pro") modes.push_back(ReasoningMode::ARGUE_FOR);
        else if (mode == "argueagainst" || mode == "argue_against" || mode == "con") modes.push_back(ReasoningMode::ARGUE_AGAINST);
        else if (mode == "critic" || mode == "critique") modes.push_back(ReasoningMode::CRITIC);
        else if (mode == "synthesizer" || mode == "synthesize" || mode == "synthesis") modes.push_back(ReasoningMode::SYNTHESIZER);
        else if (mode == "brainstorm") modes.push_back(ReasoningMode::BRAINSTORM);
        else if (mode == "verifier" || mode == "verify") modes.push_back(ReasoningMode::VERIFIER);
        else if (mode == "refiner" || mode == "refine") modes.push_back(ReasoningMode::REFINER);
        else if (mode == "summarizer" || mode == "summarize") modes.push_back(ReasoningMode::SUMMARIZER);
    }
    
    return modes;
}

std::string CoTCLIHelper::ModesToString(const std::vector<ReasoningMode>& modes) {
    std::string result;
    for (size_t i = 0; i < modes.size(); ++i) {
        if (i > 0) result += ",";
        result += ModeNames[static_cast<size_t>(modes[i])];
    }
    return result;
}

bool CoTCLIHelper::ValidateModeSequence(const std::vector<ReasoningMode>& modes) {
    // Basic validation - no duplicates of certain modes
    bool hasSynthesizer = false;
    for (const auto& mode : modes) {
        if (mode == ReasoningMode::SYNTHESIZER) {
            if (hasSynthesizer) return false; // Duplicate synthesizer
            hasSynthesizer = true;
        }
    }
    return !modes.empty();
}

std::vector<ReasoningMode> CoTCLIHelper::GetDefaultChain() {
    return {
        ReasoningMode::BRAINSTORM,
        ReasoningMode::THINKER,
        ReasoningMode::RESEARCHER,
        ReasoningMode::ARGUE_FOR,
        ReasoningMode::ARGUE_AGAINST,
        ReasoningMode::CRITIC,
        ReasoningMode::VERIFIER,
        ReasoningMode::SYNTHESIZER
    };
}

std::vector<ReasoningMode> CoTCLIHelper::GetCodeReviewChain() {
    return {
        ReasoningMode::AUDITOR,
        ReasoningMode::REVIEWER,
        ReasoningMode::CRITIC,
        ReasoningMode::VERIFIER,
        ReasoningMode::REFINER
    };
}

std::vector<ReasoningMode> CoTCLIHelper::GetDecisionChain() {
    return {
        ReasoningMode::RESEARCHER,
        ReasoningMode::BRAINSTORM,
        ReasoningMode::ARGUE_FOR,
        ReasoningMode::ARGUE_AGAINST,
        ReasoningMode::CRITIC,
        ReasoningMode::SYNTHESIZER
    };
}

std::vector<ReasoningMode> CoTCLIHelper::GetCreativeChain() {
    return {
        ReasoningMode::BRAINSTORM,
        ReasoningMode::THINKER,
        ReasoningMode::RESEARCHER,
        ReasoningMode::REFINER,
        ReasoningMode::SYNTHESIZER
    };
}

} // namespace CoT
} // namespace RawrXD
