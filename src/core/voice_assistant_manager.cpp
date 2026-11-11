// voice_assistant_manager.cpp — Voice Assistant Manager Implementation
// Implements Siri, Alexa, and Hybrid voice assistants with RAG integration
// ============================================================================

#include "voice_assistant_manager.hpp"
#include "IDE_Telemetry.hpp"
#include <regex>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <thread>

// ============================================================================
// Constants
// ============================================================================

constexpr size_t MAX_SESSION_HISTORY_ENTRIES = 50;

// ============================================================================
// VoiceAssistantManager Implementation
// ============================================================================

VoiceAssistantManager::VoiceAssistantManager()
    : m_siriAssistant(std::make_unique<SiriStyleAssistant>())
    , m_alexaAssistant(std::make_unique<AlexaStyleAssistant>())
    , m_hybridAssistant(std::make_unique<HybridAssistant>())
    , m_microChain(nullptr)
    , m_commandDispatcher(std::make_shared<VoiceAssistantCommandDispatcher>())
    , m_voiceOutputEnabled(true)
    , m_responseStyle("conversational")
{
    m_commandDispatcher->register_default_ide_actions();
}

VoiceAssistantManager::~VoiceAssistantManager() = default;

nlohmann::json VoiceAssistantManager::process_voice_input(
    const std::string& text,
    const std::string& assistant_type,
    const std::string& session_id
) {
    // Rate limiting check
    std::string client_id = session_id.empty() ? 
        std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id())) : session_id;
    
    auto rate_result = rawrxd::utils::check_rag_rate_limit(client_id);
    if (!rate_result.allowed) {
        nlohmann::json error;
        error["success"] = false;
        error["error"] = "Rate limit exceeded. Please retry after " + 
                        std::to_string(rate_result.retry_after_ms) + "ms";
        error["retry_after_ms"] = rate_result.retry_after_ms;
        error["rate_limited"] = true;
        return error;
    }
    
    std::string sid = session_id.empty() ? create_session() : session_id;
    
    Session* session = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(m_sessions_mutex);
        auto it = m_sessions.find(sid);
        if (it != m_sessions.end()) {
            session = &it->second;
        }
    }
    
    nlohmann::json result = route_to_assistant(text, assistant_type, session);
    
    result["session_id"] = sid;
    result["timestamp"] = std::time(nullptr);
    
    if (session) {
        nlohmann::json msg;
        msg["user_input"] = text;
        msg["assistant_response"] = result;
        msg["timestamp"] = std::time(nullptr);
        
        {
            std::unique_lock<std::shared_mutex> lock(m_sessions_mutex);
            session->messages.push_back(msg);
            trim_session_history(*session);
        }
    }
    
    return result;
}

void VoiceAssistantManager::trim_session_history(Session& session) {
    while (session.messages.size() > MAX_SESSION_HISTORY_ENTRIES) {
        session.messages.erase(session.messages.begin());
    }
}

nlohmann::json VoiceAssistantManager::get_assistant_info() const {
    nlohmann::json j;
    j["assistants"]["siri"]["name"] = "Siri-Style Assistant";
    j["assistants"]["siri"]["description"] = "Conversational, personal, witty";
    j["assistants"]["siri"]["capabilities"] = {"conversation", "information", "reminders", "weather"};
    
    j["assistants"]["alexa"]["name"] = "Alexa-Style Assistant";
    j["assistants"]["alexa"]["description"] = "Task-oriented, smart home control";
    j["assistants"]["alexa"]["capabilities"] = {"smart_home", "shopping", "music", "timers"};
    
    j["assistants"]["hybrid"]["name"] = "Hybrid Assistant";
    j["assistants"]["hybrid"]["description"] = "Adaptive, best of both worlds";
    j["assistants"]["hybrid"]["capabilities"] = {"adaptive", "multi_domain", "context_aware"};
    
    j["features"]["voice_output"] = m_voiceOutputEnabled;
    j["features"]["response_style"] = m_responseStyle;
    j["features"]["micro_chain_connected"] = (m_microChain != nullptr);
    
    return j;
}

std::string VoiceAssistantManager::create_session() {
    // Use cryptographically secure UUID v4 instead of rand()
    std::string session_id = rawrxd::utils::generate_session_id();
    
    Session s;
    s.session_id = session_id;
    s.assistant_type = "hybrid";
    s.created_at = std::to_string(std::time(nullptr));
    
    {
        std::unique_lock<std::shared_mutex> lock(m_sessions_mutex);
        m_sessions[session_id] = std::move(s);
    }
    
    return session_id;
}

void VoiceAssistantManager::end_session(const std::string& session_id) {
    std::unique_lock<std::shared_mutex> lock(m_sessions_mutex);
    m_sessions.erase(session_id);
}

nlohmann::json VoiceAssistantManager::get_session_history(const std::string& session_id) const {
    std::shared_lock<std::shared_mutex> lock(m_sessions_mutex);
    auto it = m_sessions.find(session_id);
    if (it != m_sessions.end()) {
        nlohmann::json j;
        j["session_id"] = session_id;
        j["messages"] = it->second.messages;
        j["created_at"] = it->second.created_at;
        return j;
    }
    return nlohmann::json{{"error", "Session not found"}};
}

void VoiceAssistantManager::set_micro_chain(void* chain) {
    m_microChain = chain;
}

void* VoiceAssistantManager::get_micro_chain() const {
    return m_microChain;
}

void VoiceAssistantManager::set_command_dispatcher(std::shared_ptr<VoiceAssistantCommandDispatcher> dispatcher) {
    m_commandDispatcher = dispatcher ? dispatcher : std::make_shared<VoiceAssistantCommandDispatcher>();
}

std::shared_ptr<VoiceAssistantCommandDispatcher> VoiceAssistantManager::get_command_dispatcher() const {
    return m_commandDispatcher;
}

nlohmann::json VoiceAssistantManager::dispatch_ide_action(IntentType intent, const std::unordered_map<std::string, std::string>& entities) {
    if (!m_commandDispatcher || !m_commandDispatcher->has_action(intent)) {
        nlohmann::json error_response;
        error_response["success"] = false;
        error_response["error"] = "No IDE action registered for intent: " + VoiceAssistantUtils::intent_to_string(intent);
        error_response["intent"] = VoiceAssistantUtils::intent_to_string(intent);
        return error_response;
    }
    
    IDEAction action = m_commandDispatcher->get_action(intent);
    
    nlohmann::json entities_json = nlohmann::json::object();
    for (const auto& [key, value] : entities) {
        entities_json[key] = value;
    }
    
    nlohmann::json response;
    response["success"] = true;
    response["intent"] = VoiceAssistantUtils::intent_to_string(intent);
    response["command_id"] = action.command_id;
    response["description"] = action.description;
    response["requires_confirmation"] = action.requires_confirmation;
    response["entities"] = entities_json;
    response["dispatched"] = true;
    return response;
}

void VoiceAssistantManager::set_context_analyzer(std::shared_ptr<CodebaseContextAnalyzer> analyzer) {
    m_contextAnalyzer = analyzer;
}

std::shared_ptr<CodebaseContextAnalyzer> VoiceAssistantManager::get_context_analyzer() const {
    return m_contextAnalyzer;
}

nlohmann::json VoiceAssistantManager::query_codebase(const std::string& natural_language_query,
                                                      const std::string& current_file,
                                                      int current_line) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    nlohmann::json result = execute_rag_pipeline(natural_language_query, current_file, current_line);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto latency_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    
    result["query_latency_ms"] = latency_ms;
    result["timestamp"] = std::time(nullptr);
    
    return result;
}

nlohmann::json VoiceAssistantManager::execute_rag_pipeline(const std::string& query,
                                                              const std::string& current_file,
                                                              int current_line) {
    PERF_SCOPE("VoiceAssistant.RAG_Execute");
    
    nlohmann::json response;
    
    if (!m_contextAnalyzer) {
        response["status"] = "error";
        response["message"] = "Codebase analyzer not initialized. Please wait for indexing to complete.";
        response["suggestion"] = "Try again in a few moments, or check if the project has been loaded.";
        response["error_code"] = "ANALYZER_NOT_READY";
        return response;
    }

    try {
        ScopeInfo scope;
        {
            PERF_SCOPE("VoiceAssistant.RAG_ScopeAnalysis");
            scope = m_contextAnalyzer->analyzeCurrentScope(current_file, current_line, 0);
        }
        
        std::vector<Symbol> symbols;
        {
            PERF_SCOPE("VoiceAssistant.RAG_VectorSearch");
            symbols = m_contextAnalyzer->getRelevantSymbols(query, scope);
        }
        
        response["status"] = "success";
        response["query"] = query;
        response["current_context"]["file"] = current_file;
        response["current_context"]["line"] = current_line;
        response["current_context"]["scope_type"] = scope.type;
        response["current_context"]["scope_name"] = scope.name;
        
        response["results"] = nlohmann::json::array();
        response["result_count"] = static_cast<int>(symbols.size());
        
        for (const auto& symbol : symbols) {
            nlohmann::json item;
            item["name"] = symbol.name;
            item["type"] = symbol.type;
            item["file"] = symbol.filePath;
            item["line"] = symbol.lineNumber;
            item["signature"] = symbol.signature;
            response["results"].push_back(item);
        }
        
        if (!current_file.empty()) {
            PERF_SCOPE("VoiceAssistant.RAG_Dependencies");
            auto dependencies = m_contextAnalyzer->getDependencies(current_file);
            response["dependencies"] = dependencies;
            response["dependency_count"] = static_cast<int>(dependencies.size());
        }
        
    } catch (const std::exception& e) {
        response["status"] = "error";
        response["message"] = std::string("RAG pipeline error: ") + e.what();
        response["error_type"] = "execution_error";
        response["error_code"] = "RAG_EXCEPTION";
    }

    return response;
}

void VoiceAssistantManager::enable_voice_output(bool enable) {
    m_voiceOutputEnabled = enable;
}

void VoiceAssistantManager::set_response_style(const std::string& style) {
    m_responseStyle = style;
}

void VoiceAssistantManager::set_wake_word(const std::string& assistant_type, const std::string& wake_word) {
    // Placeholder for wake word customization
}

std::string VoiceAssistantManager::generate_session_id() {
    // Use cryptographically secure UUID v4
    return rawrxd::utils::generate_session_id();
}

nlohmann::json VoiceAssistantManager::route_to_assistant(
    const std::string& text,
    const std::string& assistant_type,
    const Session* session
) {
    nlohmann::json context = session ? nlohmann::json{{"history", session->messages}} : nlohmann::json::object();
    
    if (assistant_type == "siri") {
        return m_siriAssistant->process_command(text, context);
    } else if (assistant_type == "alexa") {
        return m_alexaAssistant->process_command(text, context);
    } else {
        return m_hybridAssistant->process_command(text, context);
    }
}

// ============================================================================
// SiriStyleAssistant Implementation
// ============================================================================

SiriStyleAssistant::SiriStyleAssistant()
    : m_personalityTraits({"helpful", "witty", "conversational", "personal"})
{
}

nlohmann::json SiriStyleAssistant::process_command(const std::string& text, const nlohmann::json& context) {
    nlohmann::json intent_result = parse_intent(text);
    nlohmann::json response = generate_response(text, intent_result, context);
    
    response["personality_trait"] = m_personalityTraits[rand() % m_personalityTraits.size()];
    
    nlohmann::json hist;
    hist["user_input"] = text;
    hist["assistant_response"] = response["response"];
    hist["intent"] = intent_result["intent"];
    m_conversationHistory.push_back(hist);
    
    return response;
}

nlohmann::json SiriStyleAssistant::parse_intent(const std::string& text) {
    std::string text_lower = text;
    std::transform(text_lower.begin(), text_lower.end(), text_lower.begin(), ::tolower);
    
    std::vector<std::pair<std::string, std::vector<std::string>>> intent_patterns = {
        {"weather", {"weather", "temperature", "forecast", "rain", "sunny"}},
        {"timer", {"timer", "countdown", "alarm", "set"}},
        {"reminder", {"remind", "reminder", "don't forget", "remember"}},
        {"calculation", {"calculate", "what is", "how much", "plus", "minus", "times"}},
        {"search", {"search", "find", "look up", "who is", "what is"}},
        {"smart_home", {"turn on", "turn off", "switch", "light", "thermostat"}},
        {"code_generation", {"create", "build", "make", "generate", "write code"}},
        {"code_analysis", {"analyze", "review", "check", "debug", "fix"}},
        {"ide_build", {"build", "compile", "make project", "build solution"}},
        {"ide_run", {"run", "execute", "start program"}},
        {"ide_debug", {"debug", "start debugging", "run with debugger"}},
        {"ide_open_file", {"open file", "open document", "load file"}},
        {"ide_save_file", {"save", "save file"}},
        {"ide_close_file", {"close file", "close document"}},
        {"ide_find", {"find", "search for", "locate"}},
        {"ide_replace", {"replace", "find and replace"}},
        {"ide_goto_line", {"go to line", "jump to line", "line"}},
        {"ide_toggle_theme", {"dark mode", "light mode", "toggle theme", "change theme"}},
        {"ide_toggle_output", {"output panel", "show output", "hide output"}},
        {"ide_toggle_terminal", {"terminal", "show terminal", "hide terminal"}},
        {"ide_explain_code", {"explain", "what does this do", "explain code"}},
        {"ide_fix_code", {"fix", "fix this", "repair code"}},
        {"ide_optimize_code", {"optimize", "improve", "make faster"}},
        {"ide_open_settings", {"settings", "preferences", "options"}}
    };
    
    std::string detected_intent = "information";
    double confidence = 0.3;
    
    for (const auto& pattern : intent_patterns) {
        for (const std::string& keyword : pattern.second) {
            if (text_lower.find(keyword) != std::string::npos) {
                detected_intent = pattern.first;
                confidence = 0.8;
                break;
            }
        }
        if (confidence > 0.5) break;
    }
    
    auto entities = extract_entities(text, detected_intent);
    
    nlohmann::json result;
    result["intent"] = detected_intent;
    result["confidence"] = confidence;
    
    // Convert unordered_map to json object
    nlohmann::json entities_json = nlohmann::json::object();
    for (const auto& [key, value] : entities) {
        entities_json[key] = value;
    }
    result["entities"] = entities_json;
    
    return result;
}

std::unordered_map<std::string, std::string> SiriStyleAssistant::extract_entities(const std::string& text, const std::string& intent) {
    std::unordered_map<std::string, std::string> entities;
    std::string text_lower = text;
    std::transform(text_lower.begin(), text_lower.end(), text_lower.begin(), ::tolower);
    
    if (intent == "weather") {
        std::regex location_regex(R"(in (\w+)|at (\w+))");
        std::smatch match;
        if (std::regex_search(text_lower, match, location_regex)) {
            entities["location"] = match[1].matched ? match[1].str() : match[2].str();
        }
        std::regex time_regex(R"(today|tomorrow|now)");
        if (std::regex_search(text_lower, match, time_regex)) {
            entities["time"] = match[0].str();
        }
    } else if (intent == "timer") {
        std::regex duration_regex(R"((\d+)\s*(minute|hour|second))");
        std::smatch match;
        if (std::regex_search(text_lower, match, duration_regex)) {
            entities["duration"] = match[1].str();
            entities["unit"] = match[2].str();
        }
    } else if (intent == "reminder") {
        std::regex task_regex(R"(to (.+)|about (.+))");
        std::smatch match;
        if (std::regex_search(text_lower, match, task_regex)) {
            entities["task"] = match[1].matched ? match[1].str() : match[2].str();
        }
    }
    
    return entities;
}

nlohmann::json SiriStyleAssistant::generate_response(const std::string& text, const nlohmann::json& intent_result, const nlohmann::json& context) {
    std::string intent = intent_result["intent"];
    nlohmann::json entities = intent_result["entities"];
    
    std::unordered_map<std::string, std::vector<std::string>> templates = {
        {"weather", {
            "Let me check the weather for you. {location} looks {condition} with a temperature of {temp}.",
            "The weather in {location} is {condition}. Currently {temp}."
        }},
        {"timer", {
            "Timer set for {duration} {unit}. I'll let you know when it's up!",
            "Okay, counting down {duration} {unit} starting now."
        }},
        {"reminder", {
            "I'll remind you to {task}. Consider it done!",
            "Reminder set for {task}. I've got your back."
        }},
        {"calculation", {
            "Let me calculate that... The answer is {result}.",
            "Working it out... That would be {result}."
        }},
        {"search", {
            "Let me look that up for you... Here's what I found about {topic}.",
            "Searching... I found some information about {topic}."
        }},
        {"smart_home", {
            "Okay, {action} the {device}.",
            "Sure, {action} {device} now."
        }},
        {"code_generation", {
            "I'll help you create that. Let me generate the code for {description}.",
            "Creating {description}... Here's what I've come up with."
        }},
        {"code_analysis", {
            "Analyzing your code... I found {issues} issues and {suggestions} improvements.",
            "Let me review that... Here's my analysis."
        }},
        {"information", {
            "Here's what I know about that...",
            "Let me help with that information..."
        }}
    };
    
    std::vector<std::string> intent_templates = templates.count(intent) ? templates[intent] : templates["information"];
    std::string template_str = intent_templates[rand() % intent_templates.size()];
    
    std::string response = template_str;
    for (auto it = entities.begin(); it != entities.end(); ++it) {
        std::string placeholder = "{" + it.key() + "}";
        size_t pos = response.find(placeholder);
        while (pos != std::string::npos) {
            response.replace(pos, placeholder.length(), it.value().get<std::string>());
            pos = response.find(placeholder);
        }
    }
    
    if (rand() % 100 < 30) {
        std::vector<std::string> quirks = {
            "By the way, that's one of my favorite questions!",
            "Interesting! I was just thinking about that!",
            "You know, you're asking all the right questions today!"
        };
        response = quirks[rand() % quirks.size()] + " " + response;
    }
    
    nlohmann::json result;
    result["assistant"] = "Siri-Style";
    result["response"] = response;
    result["voice_output"] = response;
    result["intent"] = intent;
    result["confidence"] = intent_result["confidence"];
    result["entities"] = entities;
    result["suggested_actions"] = get_suggested_actions(intent);
    result["processing_time"] = 0.001;
    
    IntentType typedIntent = VoiceAssistantUtils::string_to_intent(intent);
    if (VoiceAssistantUtils::is_ide_action_intent(typedIntent)) {
        result["ide_action"]["command_id"] = VoiceAssistantUtils::get_ide_command_id(typedIntent);
        result["ide_action"]["description"] = VoiceAssistantUtils::get_ide_action_description(typedIntent);
        result["ide_action"]["dispatched"] = false;
    }
    
    return result;
}

std::vector<std::string> SiriStyleAssistant::get_suggested_actions(const std::string& intent) {
    std::unordered_map<std::string, std::vector<std::string>> suggestions = {
        {"weather", {"5-day forecast", "Weather alerts", "Radar map"}},
        {"timer", {"Add 5 minutes", "Stop timer", "New timer"}},
        {"reminder", {"Set location-based reminder", "Add to calendar", "Share reminder"}},
        {"search", {"Related searches", "Save result", "Share information"}},
        {"code_generation", {"Run code", "Save to file", "Explain code"}},
        {"code_analysis", {"Fix issues", "Optimize", "Refactor"}},
        {"ide_build", {"Run project", "Clean build", "Rebuild"}},
        {"ide_run", {"Debug", "Stop", "Build first"}},
        {"ide_debug", {"Set breakpoint", "Step over", "Continue"}},
        {"ide_open_file", {"Recent files", "Open folder", "New file"}},
        {"ide_save_file", {"Save all", "Save as"}},
        {"ide_goto_line", {"Go to symbol", "Go to definition"}},
        {"ide_toggle_theme", {"Theme picker", "High contrast"}},
        {"ide_explain_code", {"Fix code", "Optimize code", "Document code"}},
        {"ide_fix_code", {"Explain code", "Optimize code"}},
        {"ide_optimize_code", {"Explain code", "Fix code"}},
        {"ide_open_settings", {"Keyboard shortcuts", "Extensions"}}
    };
    
    return suggestions.count(intent) ? suggestions[intent] : std::vector<std::string>{"How else can I help?"};
}

// ============================================================================
// AlexaStyleAssistant Implementation
// ============================================================================

AlexaStyleAssistant::AlexaStyleAssistant()
    : m_wakeWord("alexa")
{
    m_deviceStates["living_room_light"] = "off";
    m_deviceStates["thermostat"] = "72";
    m_deviceStates["music"] = "stopped";
}

nlohmann::json AlexaStyleAssistant::process_command(const std::string& text, const nlohmann::json& context) {
    std::string cleaned_text = remove_wake_word(text);
    nlohmann::json analysis = analyze_command(cleaned_text);
    nlohmann::json response = execute_command(analysis);
    
    nlohmann::json result;
    result["assistant"] = "Alexa-Style";
    result["response"] = response["response"];
    result["voice_output"] = response["voice_output"];
    result["skill_used"] = analysis["skill"];
    result["action_performed"] = analysis["action"];
    result["device_affected"] = analysis.value("device", "");
    result["confidence"] = analysis["confidence"];
    result["processing_time"] = 0.001;
    
    // Convert device_states to json
    nlohmann::json device_states_json = nlohmann::json::object();
    for (const auto& [key, value] : m_deviceStates) {
        device_states_json[key] = value;
    }
    result["device_states"] = device_states_json;
    
    IntentType typedIntent = VoiceAssistantUtils::string_to_intent(analysis["skill"].get<std::string>());
    if (VoiceAssistantUtils::is_ide_action_intent(typedIntent)) {
        result["intent"] = analysis["skill"];
        result["ide_action"]["command_id"] = VoiceAssistantUtils::get_ide_command_id(typedIntent);
        result["ide_action"]["description"] = VoiceAssistantUtils::get_ide_action_description(typedIntent);
        result["ide_action"]["dispatched"] = false;
    }
    
    return result;
}

std::string AlexaStyleAssistant::remove_wake_word(const std::string& text) {
    std::string cleaned = text;
    std::transform(cleaned.begin(), cleaned.end(), cleaned.begin(), ::tolower);
    
    std::vector<std::string> wake_words = {m_wakeWord, "computer", "echo"};
    for (const std::string& wake_word : wake_words) {
        size_t pos = cleaned.find(wake_word);
        if (pos != std::string::npos) {
            cleaned.erase(pos, wake_word.length());
            while (!cleaned.empty() && isspace(cleaned[0])) {
                cleaned.erase(0, 1);
            }
            break;
        }
    }
    
    return cleaned;
}

nlohmann::json AlexaStyleAssistant::analyze_command(const std::string& text) {
    std::string text_lower = text;
    std::transform(text_lower.begin(), text_lower.end(), text_lower.begin(), ::tolower);
    
    std::vector<std::pair<std::string, std::vector<std::string>>> ide_patterns = {
        {"ide_build", {"build", "compile", "make project", "build solution"}},
        {"ide_run", {"run", "execute", "start program"}},
        {"ide_debug", {"debug", "start debugging", "run with debugger"}},
        {"ide_open_file", {"open file", "open document", "load file"}},
        {"ide_save_file", {"save", "save file"}},
        {"ide_close_file", {"close file", "close document"}},
        {"ide_find", {"find", "search for", "locate"}},
        {"ide_replace", {"replace", "find and replace"}},
        {"ide_goto_line", {"go to line", "jump to line", "line"}},
        {"ide_toggle_theme", {"dark mode", "light mode", "toggle theme", "change theme"}},
        {"ide_toggle_output", {"output panel", "show output", "hide output"}},
        {"ide_toggle_terminal", {"terminal", "show terminal", "hide terminal"}},
        {"ide_explain_code", {"explain", "what does this do", "explain code"}},
        {"ide_fix_code", {"fix", "fix this", "repair code"}},
        {"ide_optimize_code", {"optimize", "improve", "make faster"}},
        {"ide_open_settings", {"settings", "preferences", "options"}}
    };
    
    std::string detected_skill = "information";
    std::string detected_action = "inform";
    double confidence = 0.8;
    std::string device;
    std::string value;
    
    for (const auto& pattern : ide_patterns) {
        for (const std::string& keyword : pattern.second) {
            if (text_lower.find(keyword) != std::string::npos) {
                detected_skill = pattern.first;
                detected_action = "execute";
                confidence = 0.9;
                break;
            }
        }
        if (detected_skill != "information") break;
    }
    
    std::unordered_map<std::string, std::string> device_patterns = {
        {"lights", R"((light|lights|lamp|bulb))"},
        {"thermostat", R"((thermostat|temperature|heat|ac))"},
        {"music", R"((music|song|playlist|album))"},
        {"tv", R"((tv|television|netflix|movie))"}
    };
    
    std::unordered_map<std::string, std::string> action_patterns = {
        {"turn_on", R"((turn on|switch on|enable|start))"},
        {"turn_off", R"((turn off|switch off|disable|stop))"},
        {"set", R"((set|adjust|change).*to (\d+))"},
        {"play", R"((play|start).*(music|song))"},
        {"increase", R"((increase|raise|up).*(volume|temperature))"},
        {"decrease", R"((decrease|lower|down).*(volume|temperature))"}
    };
    
    for (const auto& device_pair : device_patterns) {
        std::regex device_regex(device_pair.second);
        if (std::regex_search(text_lower, device_regex)) {
            detected_skill = "smart_home";
            device = device_pair.first;
            
            for (const auto& action_pair : action_patterns) {
                std::regex action_regex(action_pair.second);
                std::smatch match;
                if (std::regex_search(text_lower, match, action_regex)) {
                    detected_action = action_pair.first;
                    if (detected_action == "set" && match.size() > 2) {
                        value = match[2].str();
                    }
                    break;
                }
            }
            break;
        }
    }
    
    nlohmann::json result;
    result["skill"] = detected_skill;
    result["action"] = detected_action;
    result["device"] = device;
    result["value"] = value;
    result["confidence"] = confidence;
    result["original_text"] = text;
    return result;
}

nlohmann::json AlexaStyleAssistant::execute_command(const nlohmann::json& analysis) {
    std::string skill = analysis["skill"];
    std::string action = analysis["action"];
    std::string device = analysis.value("device", "");
    std::string value = analysis.value("value", "");
    
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> templates = {
        {"smart_home", {
            {"turn_on", "Okay, turning on the {device}."},
            {"turn_off", "Sure, turning off the {device}."},
            {"set", "Setting {device} to {value}."},
            {"play", "Playing music on {device}."},
            {"increase", "Increasing {device}."},
            {"decrease", "Decreasing {device}."}
        }},
        {"information", {
            {"inform", "Here's what I found."}
        }}
    };
    
    if (skill == "smart_home" && !device.empty()) {
        if (action == "turn_on") {
            m_deviceStates[device] = "on";
        } else if (action == "turn_off") {
            m_deviceStates[device] = "off";
        } else if (action == "set" && !value.empty()) {
            m_deviceStates[device] = value;
        }
    }
    
    std::string template_str = templates.count(skill) && templates[skill].count(action) 
        ? templates[skill][action] 
        : "Okay.";
    
    std::string response = template_str;
    size_t pos = response.find("{device}");
    if (pos != std::string::npos) {
        response.replace(pos, 8, device);
    }
    
    pos = response.find("{value}");
    if (pos != std::string::npos) {
        response.replace(pos, 7, value);
    }
    
    nlohmann::json result;
    result["response"] = response;
    result["voice_output"] = std::string("<alexa_sound> ") + response;
    return result;
}

// ============================================================================
// HybridAssistant Implementation
// ============================================================================

HybridAssistant::HybridAssistant()
    : m_siriComponent(std::make_unique<SiriStyleAssistant>())
    , m_alexaComponent(std::make_unique<AlexaStyleAssistant>())
{
}

nlohmann::json HybridAssistant::process_command(const std::string& text, const nlohmann::json& context) {
    bool use_siri = should_use_siri(text);
    
    nlohmann::json result;
    if (use_siri) {
        result = m_siriComponent->process_command(text, context);
        result["assistant_style"] = "siri";
        result["mode"] = "conversational";
    } else {
        result = m_alexaComponent->process_command(text, context);
        result["assistant_style"] = "alexa";
        result["mode"] = "task";
    }
    
    result["hybrid_features"]["style_switching"] = true;
    result["hybrid_features"]["multi_domain"] = true;
    result["hybrid_features"]["context_aware"] = true;
    
    return result;
}

bool HybridAssistant::should_use_siri(const std::string& text) {
    std::string text_lower = text;
    std::transform(text_lower.begin(), text_lower.end(), text_lower.begin(), ::tolower);
    
    std::vector<std::string> siri_indicators = {
        "how are you", "tell me", "what do you think", "can we talk",
        "that's interesting", "thank you", "please", "?"
    };
    
    std::vector<std::string> alexa_indicators = {
        "turn on", "set to", "play music", "add to cart",
        "what time", "set timer", "volume up"
    };
    
    int siri_score = 0;
    int alexa_score = 0;
    
    for (const std::string& indicator : siri_indicators) {
        if (text_lower.find(indicator) != std::string::npos) {
            siri_score++;
        }
    }
    
    for (const std::string& indicator : alexa_indicators) {
        if (text_lower.find(indicator) != std::string::npos) {
            alexa_score++;
        }
    }
    
    return siri_score > alexa_score;
}

// ============================================================================
// Utility Functions
// ============================================================================

namespace VoiceAssistantUtils {
    std::string intent_to_string(IntentType intent) {
        switch (intent) {
            case IntentType::WEATHER: return "weather";
            case IntentType::TIMER: return "timer";
            case IntentType::REMINDER: return "reminder";
            case IntentType::CALCULATION: return "calculation";
            case IntentType::SEARCH: return "search";
            case IntentType::SMART_HOME: return "smart_home";
            case IntentType::ENTERTAINMENT: return "entertainment";
            case IntentType::INFORMATION: return "information";
            case IntentType::COMMUNICATION: return "communication";
            case IntentType::CODE_GENERATION: return "code_generation";
            case IntentType::CODE_ANALYSIS: return "code_analysis";
            case IntentType::DEBUGGING: return "debugging";
            case IntentType::OPTIMIZATION: return "optimization";
            case IntentType::IDE_BUILD: return "ide_build";
            case IntentType::IDE_OPEN_FILE: return "ide_open_file";
            case IntentType::IDE_SAVE_FILE: return "ide_save_file";
            case IntentType::IDE_CLOSE_FILE: return "ide_close_file";
            case IntentType::IDE_FIND: return "ide_find";
            case IntentType::IDE_REPLACE: return "ide_replace";
            case IntentType::IDE_GOTO_LINE: return "ide_goto_line";
            case IntentType::IDE_TOGGLE_THEME: return "ide_toggle_theme";
            case IntentType::IDE_TOGGLE_OUTPUT: return "ide_toggle_output";
            case IntentType::IDE_TOGGLE_TERMINAL: return "ide_toggle_terminal";
            case IntentType::IDE_RUN: return "ide_run";
            case IntentType::IDE_DEBUG: return "ide_debug";
            case IntentType::IDE_EXPLAIN_CODE: return "ide_explain_code";
            case IntentType::IDE_FIX_CODE: return "ide_fix_code";
            case IntentType::IDE_OPTIMIZE_CODE: return "ide_optimize_code";
            case IntentType::IDE_OPEN_SETTINGS: return "ide_open_settings";
            case IntentType::CODE_EXPLAIN_SYMBOL: return "code_explain_symbol";
            case IntentType::CODE_FIND_REFERENCES: return "code_find_references";
            case IntentType::CODE_GET_DEPENDENCIES: return "code_get_dependencies";
            case IntentType::CODE_SUGGEST_FIX: return "code_suggest_fix";
            case IntentType::CODE_ARCHITECTURE_QUERY: return "code_architecture_query";
            case IntentType::UNKNOWN: return "unknown";
            default: return "unknown";
        }
    }
    
    IntentType string_to_intent(const std::string& str) {
        static const std::unordered_map<std::string, IntentType> map = {
            {"weather", IntentType::WEATHER},
            {"timer", IntentType::TIMER},
            {"reminder", IntentType::REMINDER},
            {"calculation", IntentType::CALCULATION},
            {"search", IntentType::SEARCH},
            {"smart_home", IntentType::SMART_HOME},
            {"entertainment", IntentType::ENTERTAINMENT},
            {"information", IntentType::INFORMATION},
            {"communication", IntentType::COMMUNICATION},
            {"code_generation", IntentType::CODE_GENERATION},
            {"code_analysis", IntentType::CODE_ANALYSIS},
            {"debugging", IntentType::DEBUGGING},
            {"optimization", IntentType::OPTIMIZATION},
            {"ide_build", IntentType::IDE_BUILD},
            {"ide_open_file", IntentType::IDE_OPEN_FILE},
            {"ide_save_file", IntentType::IDE_SAVE_FILE},
            {"ide_close_file", IntentType::IDE_CLOSE_FILE},
            {"ide_find", IntentType::IDE_FIND},
            {"ide_replace", IntentType::IDE_REPLACE},
            {"ide_goto_line", IntentType::IDE_GOTO_LINE},
            {"ide_toggle_theme", IntentType::IDE_TOGGLE_THEME},
            {"ide_toggle_output", IntentType::IDE_TOGGLE_OUTPUT},
            {"ide_toggle_terminal", IntentType::IDE_TOGGLE_TERMINAL},
            {"ide_run", IntentType::IDE_RUN},
            {"ide_debug", IntentType::IDE_DEBUG},
            {"ide_explain_code", IntentType::IDE_EXPLAIN_CODE},
            {"ide_fix_code", IntentType::IDE_FIX_CODE},
            {"ide_optimize_code", IntentType::IDE_OPTIMIZE_CODE},
            {"ide_open_settings", IntentType::IDE_OPEN_SETTINGS},
            {"code_explain_symbol", IntentType::CODE_EXPLAIN_SYMBOL},
            {"code_find_references", IntentType::CODE_FIND_REFERENCES},
            {"code_get_dependencies", IntentType::CODE_GET_DEPENDENCIES},
            {"code_suggest_fix", IntentType::CODE_SUGGEST_FIX},
            {"code_architecture_query", IntentType::CODE_ARCHITECTURE_QUERY}
        };
        auto it = map.find(str);
        return it != map.end() ? it->second : IntentType::UNKNOWN;
    }
    
    bool is_ide_action_intent(IntentType intent) {
        return intent >= IntentType::IDE_BUILD && intent <= IntentType::IDE_OPEN_SETTINGS;
    }
    
    std::string get_ide_command_id(IntentType intent) {
        switch (intent) {
            case IntentType::IDE_BUILD: return "IDM_BUILD_SOLUTION";
            case IntentType::IDE_OPEN_FILE: return "IDM_FILE_OPEN";
            case IntentType::IDE_SAVE_FILE: return "IDM_FILE_SAVE";
            case IntentType::IDE_CLOSE_FILE: return "IDM_FILE_CLOSE";
            case IntentType::IDE_FIND: return "IDM_EDIT_FIND";
            case IntentType::IDE_REPLACE: return "IDM_EDIT_REPLACE";
            case IntentType::IDE_GOTO_LINE: return "IDM_GOTO_LINE";
            case IntentType::IDE_TOGGLE_THEME: return "IDM_VIEW_THEME_TOGGLE";
            case IntentType::IDE_TOGGLE_OUTPUT: return "IDM_VIEW_OUTPUT_PANEL";
            case IntentType::IDE_TOGGLE_TERMINAL: return "IDM_VIEW_TERMINAL";
            case IntentType::IDE_RUN: return "IDM_BUILD_RUN";
            case IntentType::IDE_DEBUG: return "IDM_DBG_LAUNCH";
            case IntentType::IDE_EXPLAIN_CODE: return "IDM_AGENT_EXPLAIN";
            case IntentType::IDE_FIX_CODE: return "IDM_AGENT_FIX";
            case IntentType::IDE_OPTIMIZE_CODE: return "IDM_AGENT_OPTIMIZE";
            case IntentType::IDE_OPEN_SETTINGS: return "IDM_TOOLS_SETTINGS";
            default: return "";
        }
    }
    
    std::string get_ide_action_description(IntentType intent) {
        switch (intent) {
            case IntentType::IDE_BUILD: return "Build the current project";
            case IntentType::IDE_OPEN_FILE: return "Open a file";
            case IntentType::IDE_SAVE_FILE: return "Save the current file";
            case IntentType::IDE_CLOSE_FILE: return "Close the current file";
            case IntentType::IDE_FIND: return "Find in current file";
            case IntentType::IDE_REPLACE: return "Replace in current file";
            case IntentType::IDE_GOTO_LINE: return "Go to specific line";
            case IntentType::IDE_TOGGLE_THEME: return "Toggle light/dark theme";
            case IntentType::IDE_TOGGLE_OUTPUT: return "Toggle output panel";
            case IntentType::IDE_TOGGLE_TERMINAL: return "Toggle terminal panel";
            case IntentType::IDE_RUN: return "Run the current project";
            case IntentType::IDE_DEBUG: return "Start debugging";
            case IntentType::IDE_EXPLAIN_CODE: return "Explain selected code";
            case IntentType::IDE_FIX_CODE: return "Fix selected code";
            case IntentType::IDE_OPTIMIZE_CODE: return "Optimize selected code";
            case IntentType::IDE_OPEN_SETTINGS: return "Open IDE settings";
            default: return "Unknown IDE action";
        }
    }
}

// ============================================================================
// VoiceAssistantCommandDispatcher Implementation
// ============================================================================

VoiceAssistantCommandDispatcher::VoiceAssistantCommandDispatcher() {
    register_default_ide_actions();
}

void VoiceAssistantCommandDispatcher::register_action(IntentType intent, const IDEAction& action) {
    m_actions[static_cast<int>(intent)] = action;
}

bool VoiceAssistantCommandDispatcher::has_action(IntentType intent) const {
    return m_actions.count(static_cast<int>(intent)) > 0;
}

IDEAction VoiceAssistantCommandDispatcher::get_action(IntentType intent) const {
    auto it = m_actions.find(static_cast<int>(intent));
    if (it != m_actions.end()) {
        return it->second;
    }
    return IDEAction{"", "Unknown action", false, false};
}

std::vector<IDEAction> VoiceAssistantCommandDispatcher::get_all_actions() const {
    std::vector<IDEAction> result;
    for (const auto& pair : m_actions) {
        result.push_back(pair.second);
    }
    return result;
}

void VoiceAssistantCommandDispatcher::register_default_ide_actions() {
    m_actions.clear();
    
    register_action(IntentType::IDE_BUILD, IDEAction{"IDM_BUILD_SOLUTION", "Build the current project", false, true});
    register_action(IntentType::IDE_RUN, IDEAction{"IDM_BUILD_RUN", "Run the current project", false, true});
    register_action(IntentType::IDE_DEBUG, IDEAction{"IDM_DBG_LAUNCH", "Start debugging", false, true});
    register_action(IntentType::IDE_OPEN_FILE, IDEAction{"IDM_FILE_OPEN", "Open a file", false, false});
    register_action(IntentType::IDE_SAVE_FILE, IDEAction{"IDM_FILE_SAVE", "Save the current file", false, true});
    register_action(IntentType::IDE_CLOSE_FILE, IDEAction{"IDM_FILE_CLOSE", "Close the current file", true, true});
    register_action(IntentType::IDE_FIND, IDEAction{"IDM_EDIT_FIND", "Find in current file", false, true});
    register_action(IntentType::IDE_REPLACE, IDEAction{"IDM_EDIT_REPLACE", "Replace in current file", true, true});
    register_action(IntentType::IDE_GOTO_LINE, IDEAction{"IDM_GOTO_LINE", "Go to specific line", false, true});
    register_action(IntentType::IDE_TOGGLE_THEME, IDEAction{"IDM_VIEW_THEME_TOGGLE", "Toggle light/dark theme", false, false});
    register_action(IntentType::IDE_TOGGLE_OUTPUT, IDEAction{"IDM_VIEW_OUTPUT_PANEL", "Toggle output panel", false, false});
    register_action(IntentType::IDE_TOGGLE_TERMINAL, IDEAction{"IDM_VIEW_TERMINAL", "Toggle terminal panel", false, false});
    register_action(IntentType::IDE_EXPLAIN_CODE, IDEAction{"IDM_AGENT_EXPLAIN", "Explain selected code", false, true});
    register_action(IntentType::IDE_FIX_CODE, IDEAction{"IDM_AGENT_FIX", "Fix selected code", true, true});
    register_action(IntentType::IDE_OPTIMIZE_CODE, IDEAction{"IDM_AGENT_OPTIMIZE", "Optimize selected code", false, true});
    register_action(IntentType::IDE_OPEN_SETTINGS, IDEAction{"IDM_TOOLS_SETTINGS", "Open IDE settings", false, false});
}
