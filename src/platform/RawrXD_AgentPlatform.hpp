//============================================================================
// RawrXD_AgentPlatform.hpp
// Unified Agent Platform Layer - Integrates MCP, Tool Registry, Session Manager
// Connects Sovereign Substrate to IDE Shell
//============================================================================

#pragma once

#include "../Ship/MCPServer.hpp"
#include "../Ship/RawrXD_ToolRegistry.hpp"
#include "../history/runoff/part_0019/d__src_agent_cycled_agent_orchestrator.hpp"
#include "../nevm/autonomous_agentic_loop.hpp"

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <mutex>
#include <chrono>
#include <future>

namespace RawrXD {
namespace Platform {

//============================================================================
// Forward Declarations
//============================================================================

class SessionManager;
class AgentSession;
class ModeRouter;
class ToolBridge;
class ExtensionHost;
class ModelRegistry;
class PermissionPolicy;

//============================================================================
// Agent Mode (Extended from CycledAgentOrchestrator)
//============================================================================

enum class AgentMode : uint8_t {
    ASK = 0,      // Read-only Q&A
    PLAN = 1,     // Creates execution graph
    EDIT = 2,     // File mutations with approval
    AGENT = 3,    // Full autonomous execution
    DEBUG = 4,    // Debug mode (from CycledAgentOrchestrator)
    REVIEW = 5    // Code review mode
};

enum class PermissionLevel : uint8_t {
    READ_ONLY = 0,      // Ask mode
    FILE_EDIT = 1,      // Edit mode with approval
    EXECUTE = 2,        // Run commands
    AUTONOMOUS = 3      // Full agent mode
};

//============================================================================
// Chat Message (Extended from ChatSession)
//============================================================================

struct ChatMessage {
    std::string id;
    std::string role;           // "user", "assistant", "system", "tool"
    std::string content;
    std::string tool_calls;     // JSON array of tool invocations
    std::string tool_results;   // JSON array of tool results
    std::chrono::system_clock::time_point timestamp;
    uint64_t token_count;
    
    // For tool messages
    std::string tool_name;
    std::string tool_input;
    std::string tool_output;
};

//============================================================================
// Tool Context (Bridge between MCP and RawrXD ToolRegistry)
//============================================================================

struct ToolContext {
    uint64_t session_id;
    PermissionLevel permission;
    std::string working_directory;
    std::map<std::string, std::string> environment;
    std::vector<std::string> allowed_tools;
    std::vector<std::string> blocked_tools;
    
    // Execution constraints
    uint32_t timeout_ms;
    size_t max_output_size;
    bool require_approval;
};

using ToolFunction = std::function<std::string(const std::string& input, const ToolContext& ctx)>;

struct UnifiedTool {
    std::string name;
    std::string description;
    std::string category;       // "filesystem", "system", "git", "mcp", etc.
    std::string input_schema;   // JSON schema
    std::string output_schema;  // JSON schema
    PermissionLevel min_permission;
    DangerLevel danger_level;   // From RawrXD_ToolRegistry
    ToolFunction execute;
    bool is_mcp;               // True if from MCP server
    std::string mcp_server;      // MCP server name if applicable
};

//============================================================================
// Unified Tool Registry (Bridges MCP + RawrXD Tools)
//============================================================================

class UnifiedToolRegistry {
public:
    static UnifiedToolRegistry& Instance() {
        static UnifiedToolRegistry instance;
        return instance;
    }

    // Register RawrXD native tool
    void RegisterNativeTool(const UnifiedTool& tool) {
        std::lock_guard<std::mutex> lock(mutex_);
        tools_[tool.name] = tool;
    }

    // Register MCP tool (from external server)
    void RegisterMCPTool(const MCP::MCPTool& mcp_tool, const std::string& server_name) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        UnifiedTool tool;
        tool.name = std::string(mcp_tool.name.begin(), mcp_tool.name.end());
        tool.description = std::string(mcp_tool.description.begin(), mcp_tool.description.end());
        tool.input_schema = std::string(mcp_tool.inputSchema.begin(), mcp_tool.inputSchema.end());
        tool.category = "mcp";
        tool.min_permission = PermissionLevel::EXECUTE;
        tool.danger_level = DangerLevel::Normal;
        tool.is_mcp = true;
        tool.mcp_server = server_name;
        
        // MCP tools delegate to MCP client
        tool.execute = [this, server_name, tool_name = tool.name](const std::string& input, 
                                                                  const ToolContext& ctx) {
            return ExecuteMCPTool(server_name, tool_name, input);
        };
        
        tools_[tool.name] = tool;
    }

    // Get tool by name
    const UnifiedTool* GetTool(const std::string& name) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tools_.find(name);
        return (it != tools_.end()) ? &it->second : nullptr;
    }

    // List all tools
    std::vector<UnifiedTool> ListTools() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<UnifiedTool> result;
        for (const auto& [name, tool] : tools_) {
            result.push_back(tool);
        }
        return result;
    }

    // List tools by category
    std::vector<UnifiedTool> ListToolsByCategory(const std::string& category) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<UnifiedTool> result;
        for (const auto& [name, tool] : tools_) {
            if (tool.category == category) {
                result.push_back(tool);
            }
        }
        return result;
    }

    // Execute tool with permission check
    std::string ExecuteTool(const std::string& name, const std::string& input, 
                          const ToolContext& ctx, bool& approved) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = tools_.find(name);
        if (it == tools_.end()) {
            return R"({"error": "Tool not found: )" + name + "\"})";
        }
        
        const auto& tool = it->second;
        
        // Permission check
        if (static_cast<int>(ctx.permission) < static_cast<int>(tool.min_permission)) {
            return R"({"error": "Permission denied for tool: )" + name + "\"})";
        }
        
        // Approval check for dangerous tools
        if (tool.danger_level >= DangerLevel::Destructive || ctx.require_approval) {
            if (!approved) {
                return R"({"status": "approval_required", "tool": ")" + name + 
                       R"(", "reason": "Destructive operation requires approval"})";
            }
        }
        
        // Execute
        try {
            return tool.execute(input, ctx);
        } catch (const std::exception& e) {
            return R"({"error": "Execution failed: )" + std::string(e.what()) + "\"})";
        }
    }

    // Get tools available for a permission level
    std::vector<UnifiedTool> GetAvailableTools(PermissionLevel level) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<UnifiedTool> result;
        for (const auto& [name, tool] : tools_) {
            if (static_cast<int>(level) >= static_cast<int>(tool.min_permission)) {
                result.push_back(tool);
            }
        }
        return result;
    }

    // Export as MCP tools format
    std::vector<MCP::MCPTool> ExportMCPTools() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<MCP::MCPTool> result;
        for (const auto& [name, tool] : tools_) {
            MCP::MCPTool mcp_tool;
            mcp_tool.name = std::wstring(tool.name.begin(), tool.name.end());
            mcp_tool.description = std::wstring(tool.description.begin(), tool.description.end());
            mcp_tool.inputSchema = std::wstring(tool.input_schema.begin(), tool.input_schema.end());
            result.push_back(mcp_tool);
        }
        return result;
    }

private:
    UnifiedToolRegistry() = default;
    mutable std::mutex mutex_;
    std::map<std::string, UnifiedTool> tools_;
    
    std::string ExecuteMCPTool(const std::string& server, const std::string& tool, 
                               const std::string& input) {
        // Delegate to MCP client
        // This would connect to the MCP server and execute the tool
        return R"({"status": "mcp_delegated", "server": ")" + server + 
               R"(", "tool": ")" + tool + R"(", "input": )" + input + "}";
    }
};

//============================================================================
// Agent Session (Extended from ChatSession)
//============================================================================

class AgentSession {
public:
    AgentSession(uint64_t id, AgentMode mode, const std::string& model)
        : id_(id), mode_(mode), model_(model), active_(true) {
        created_at_ = std::chrono::system_clock::now();
        last_activity_ = created_at_;
    }

    // Session ID
    uint64_t GetId() const { return id_; }
    
    // Mode
    AgentMode GetMode() const { return mode_; }
    void SetMode(AgentMode mode) { mode_ = mode; }
    
    // Model
    std::string GetModel() const { return model_; }
    void SetModel(const std::string& model) { model_ = model; }
    
    // Messages
    void AddMessage(const ChatMessage& msg) {
        std::lock_guard<std::mutex> lock(mutex_);
        messages_.push_back(msg);
        last_activity_ = std::chrono::system_clock::now();
    }
    
    std::vector<ChatMessage> GetMessages() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return messages_;
    }
    
    std::vector<ChatMessage> GetRecentMessages(int count) const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (count >= static_cast<int>(messages_.size())) {
            return messages_;
        }
        return std::vector<ChatMessage>(messages_.end() - count, messages_.end());
    }
    
    // Build prompt with history
    std::string BuildPromptWithHistory(int max_history = 10) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::ostringstream prompt;
        
        int start = std::max(0, static_cast<int>(messages_.size()) - max_history);
        for (size_t i = start; i < messages_.size(); ++i) {
            prompt << "[" << messages_[i].role << "]: " << messages_[i].content << "\n\n";
        }
        
        return prompt.str();
    }
    
    // Available tools based on mode
    std::vector<UnifiedTool> GetAvailableTools() const {
        PermissionLevel perm = ModeToPermission(mode_);
        return UnifiedToolRegistry::Instance().GetAvailableTools(perm);
    }
    
    // Activity
    bool IsActive() const { return active_; }
    void SetActive(bool active) { active_ = active; }
    
    std::chrono::system_clock::time_point GetLastActivity() const {
        return last_activity_;
    }
    
    // Tool execution
    std::string ExecuteTool(const std::string& tool_name, const std::string& input, bool& approved) {
        ToolContext ctx;
        ctx.session_id = id_;
        ctx.permission = ModeToPermission(mode_);
        ctx.require_approval = (mode_ == AgentMode::EDIT || mode_ == AgentMode::AGENT);
        
        return UnifiedToolRegistry::Instance().ExecuteTool(tool_name, input, ctx, approved);
    }

private:
    uint64_t id_;
    AgentMode mode_;
    std::string model_;
    std::vector<ChatMessage> messages_;
    mutable std::mutex mutex_;
    
    std::chrono::system_clock::time_point created_at_;
    std::chrono::system_clock::time_point last_activity_;
    bool active_;
    
    PermissionLevel ModeToPermission(AgentMode mode) const {
        switch (mode) {
            case AgentMode::ASK: return PermissionLevel::READ_ONLY;
            case AgentMode::PLAN: return PermissionLevel::READ_ONLY;
            case AgentMode::EDIT: return PermissionLevel::FILE_EDIT;
            case AgentMode::AGENT: return PermissionLevel::AUTONOMOUS;
            case AgentMode::DEBUG: return PermissionLevel::EXECUTE;
            case AgentMode::REVIEW: return PermissionLevel::READ_ONLY;
            default: return PermissionLevel::READ_ONLY;
        }
    }
};

//============================================================================
// Session Manager (Multi-session orchestration)
//============================================================================

class SessionManager {
public:
    static SessionManager& Instance() {
        static SessionManager instance;
        return instance;
    }

    // Create new session
    uint64_t CreateSession(AgentMode mode, const std::string& model) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        uint64_t id = next_id_++;
        sessions_[id] = std::make_unique<AgentSession>(id, mode, model);
        
        return id;
    }

    // Get session
    AgentSession* GetSession(uint64_t id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(id);
        return (it != sessions_.end()) ? it->second.get() : nullptr;
    }

    // Close session
    void CloseSession(uint64_t id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(id);
        if (it != sessions_.end()) {
            it->second->SetActive(false);
            sessions_.erase(it);
        }
    }

    // List active sessions
    std::vector<AgentSession*> ListSessions() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<AgentSession*> result;
        for (const auto& [id, session] : sessions_) {
            if (session->IsActive()) {
                result.push_back(session.get());
            }
        }
        return result;
    }

    // Get session count
    size_t GetSessionCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return sessions_.size();
    }

    // Cleanup inactive sessions
    void CleanupInactive(int timeout_minutes = 30) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now = std::chrono::system_clock::now();
        
        for (auto it = sessions_.begin(); it != sessions_.end();) {
            auto last_activity = it->second->GetLastActivity();
            auto duration = std::chrono::duration_cast<std::chrono::minutes>(now - last_activity);
            
            if (duration.count() > timeout_minutes) {
                it = sessions_.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    SessionManager() : next_id_(1) {}
    mutable std::mutex mutex_;
    std::map<uint64_t, std::unique_ptr<AgentSession>> sessions_;
    uint64_t next_id_;
};

//============================================================================
// Mode Router (Routes requests to appropriate handler)
//============================================================================

class ModeRouter {
public:
    using AskHandler = std::function<std::string(const std::string& query, AgentSession* session)>;
    using PlanHandler = std::function<std::string(const std::string& task, AgentSession* session)>;
    using EditHandler = std::function<std::string(const std::string& instruction, AgentSession* session)>;
    using AgentHandler = std::function<std::string(const std::string& goal, AgentSession* session)>;

    void SetAskHandler(AskHandler handler) { ask_handler_ = handler; }
    void SetPlanHandler(PlanHandler handler) { plan_handler_ = handler; }
    void SetEditHandler(EditHandler handler) { edit_handler_ = handler; }
    void SetAgentHandler(AgentHandler handler) { agent_handler_ = handler; }

    std::string Route(AgentMode mode, const std::string& input, AgentSession* session) {
        switch (mode) {
            case AgentMode::ASK:
                if (ask_handler_) return ask_handler_(input, session);
                return "Ask handler not configured";
                
            case AgentMode::PLAN:
                if (plan_handler_) return plan_handler_(input, session);
                return "Plan handler not configured";
                
            case AgentMode::EDIT:
                if (edit_handler_) return edit_handler_(input, session);
                return "Edit handler not configured";
                
            case AgentMode::AGENT:
                if (agent_handler_) return agent_handler_(input, session);
                return "Agent handler not configured";
                
            default:
                return "Unknown mode";
        }
    }

private:
    AskHandler ask_handler_;
    PlanHandler plan_handler_;
    EditHandler edit_handler_;
    AgentHandler agent_handler_;
};

//============================================================================
// Extension Host (VS Code compatibility layer)
//============================================================================

struct ExtensionManifest {
    std::string id;
    std::string name;
    std::string version;
    std::string publisher;
    std::string description;
    std::vector<std::string> contributes_commands;
    std::vector<UnifiedTool> contributes_tools;
    std::map<std::string, std::string> activation_events;
    bool enabled;
};

class ExtensionHost {
public:
    static ExtensionHost& Instance() {
        static ExtensionHost instance;
        return instance;
    }

    void LoadExtension(const ExtensionManifest& manifest) {
        std::lock_guard<std::mutex> lock(mutex_);
        extensions_[manifest.id] = manifest;
        
        // Register contributed tools
        for (const auto& tool : manifest.contributes_tools) {
            UnifiedToolRegistry::Instance().RegisterNativeTool(tool);
        }
    }

    void UnloadExtension(const std::string& id) {
        std::lock_guard<std::mutex> lock(mutex_);
        extensions_.erase(id);
    }

    std::vector<ExtensionManifest> ListExtensions() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ExtensionManifest> result;
        for (const auto& [id, ext] : extensions_) {
            result.push_back(ext);
        }
        return result;
    }

    bool IsExtensionLoaded(const std::string& id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return extensions_.find(id) != extensions_.end();
    }

private:
    ExtensionHost() = default;
    mutable std::mutex mutex_;
    std::map<std::string, ExtensionManifest> extensions_;
};

//============================================================================
// Model Registry (Model selection and routing)
//============================================================================

struct ModelProfile {
    std::string name;
    std::string provider;       // "local", "openai", "anthropic", etc.
    std::string endpoint;
    std::string api_key;
    size_t context_length;
    std::vector<std::string> capabilities;  // "coding", "planning", "tool-use"
    float temperature;
    float top_p;
    bool supports_tools;
    bool supports_streaming;
};

class ModelRegistry {
public:
    static ModelRegistry& Instance() {
        static ModelRegistry instance;
        return instance;
    }

    void RegisterModel(const ModelProfile& model) {
        std::lock_guard<std::mutex> lock(mutex_);
        models_[model.name] = model;
    }

    const ModelProfile* GetModel(const std::string& name) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = models_.find(name);
        return (it != models_.end()) ? &it->second : nullptr;
    }

    std::vector<ModelProfile> ListModels() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ModelProfile> result;
        for (const auto& [name, model] : models_) {
            result.push_back(model);
        }
        return result;
    }

    std::vector<ModelProfile> GetModelsForCapability(const std::string& capability) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ModelProfile> result;
        for (const auto& [name, model] : models_) {
            if (std::find(model.capabilities.begin(), model.capabilities.end(), capability) 
                != model.capabilities.end()) {
                result.push_back(model);
            }
        }
        return result;
    }

    // Select best model for a task
    std::string SelectModelForTask(const std::string& task_type) const {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Simple selection logic - can be enhanced
        if (task_type == "coding") {
            auto coding_models = GetModelsForCapability("coding");
            if (!coding_models.empty()) return coding_models[0].name;
        } else if (task_type == "planning") {
            auto planning_models = GetModelsForCapability("planning");
            if (!planning_models.empty()) return planning_models[0].name;
        }
        
        // Default to first available
        if (!models_.empty()) return models_.begin()->second.name;
        return "";
    }

private:
    ModelRegistry() = default;
    mutable std::mutex mutex_;
    std::map<std::string, ModelProfile> models_;
};

//============================================================================
// Sovereign IDE (Main Platform Controller)
//============================================================================

class SovereignIDE {
public:
    SovereignIDE() {
        // Initialize default models
        InitializeDefaultModels();
        
        // Initialize mode router
        InitializeModeHandlers();
    }

    // Start the platform
    void Start() {
        // Start MCP server
        MCP::MCPServer::Config config;
        config.port = 8080;
        mcp_server_ = std::make_unique<MCP::MCPServer>(config);
        mcp_server_->Start();
        
        // Start autonomous agent loop
        agent_loop_ = std::make_unique<NEVM::Agentic::AutonomousAgenticLoop>(5000);
        agent_loop_->Start();
        
        running_ = true;
    }

    // Stop the platform
    void Stop() {
        running_ = false;
        
        if (agent_loop_) {
            agent_loop_->Stop();
        }
        
        if (mcp_server_) {
            mcp_server_->Stop();
        }
    }

    // Create new chat session
    uint64_t CreateSession(AgentMode mode, const std::string& model = "") {
        std::string selected_model = model;
        if (selected_model.empty()) {
            selected_model = ModelRegistry::Instance().SelectModelForTask("general");
        }
        
        return SessionManager::Instance().CreateSession(mode, selected_model);
    }

    // Send message to session
    std::string SendMessage(uint64_t session_id, const std::string& message) {
        auto session = SessionManager::Instance().GetSession(session_id);
        if (!session) {
            return "Error: Session not found";
        }
        
        // Add user message
        ChatMessage user_msg;
        user_msg.role = "user";
        user_msg.content = message;
        user_msg.timestamp = std::chrono::system_clock::now();
        session->AddMessage(user_msg);
        
        // Route to appropriate handler
        auto response = router_.Route(session->GetMode(), message, session);
        
        // Add assistant message
        ChatMessage assistant_msg;
        assistant_msg.role = "assistant";
        assistant_msg.content = response;
        assistant_msg.timestamp = std::chrono::system_clock::now();
        session->AddMessage(assistant_msg);
        
        return response;
    }

    // Get session info
    std::string GetSessionInfo(uint64_t session_id) const {
        auto session = SessionManager::Instance().GetSession(session_id);
        if (!session) return "Session not found";
        
        std::ostringstream oss;
        oss << "Session " << session_id << "\n";
        oss << "  Mode: " << static_cast<int>(session->GetMode()) << "\n";
        oss << "  Model: " << session->GetModel() << "\n";
        oss << "  Messages: " << session->GetMessages().size() << "\n";
        return oss.str();
    }

    // Get platform status
    std::string GetStatus() const {
        std::ostringstream oss;
        oss << "RawrXD Sovereign IDE Status\n";
        oss << "============================\n";
        oss << "Running: " << (running_ ? "Yes" : "No") << "\n";
        oss << "Active Sessions: " << SessionManager::Instance().GetSessionCount() << "\n";
        oss << "Available Tools: " << UnifiedToolRegistry::Instance().ListTools().size() << "\n";
        oss << "Loaded Extensions: " << ExtensionHost::Instance().ListExtensions().size() << "\n";
        oss << "Registered Models: " << ModelRegistry::Instance().ListModels().size() << "\n";
        return oss.str();
    }

private:
    bool running_ = false;
    std::unique_ptr<MCP::MCPServer> mcp_server_;
    std::unique_ptr<NEVM::Agentic::AutonomousAgenticLoop> agent_loop_;
    ModeRouter router_;

    void InitializeDefaultModels() {
        // Register default local model
        ModelProfile local;
        local.name = "local-phi3";
        local.provider = "local";
        local.endpoint = "localhost:8080";
        local.context_length = 32768;
        local.capabilities = {"coding", "planning", "tool-use"};
        local.temperature = 0.7f;
        local.top_p = 0.9f;
        local.supports_tools = true;
        local.supports_streaming = true;
        ModelRegistry::Instance().RegisterModel(local);
    }

    void InitializeModeHandlers() {
        // Ask handler - read-only Q&A
        router_.SetAskHandler([](const std::string& query, AgentSession* session) {
            // Build context with available tools
            auto tools = session->GetAvailableTools();
            std::string tool_list;
            for (const auto& tool : tools) {
                tool_list += "- " + tool.name + ": " + tool.description + "\n";
            }
            
            return "Ask mode response for: " + query + 
                   "\n\nAvailable tools:\n" + tool_list;
        });

        // Plan handler - creates execution graph
        router_.SetPlanHandler([](const std::string& task, AgentSession* session) {
            return "Plan generated for task: " + task + 
                   "\n\n1. Analyze requirements\n" +
                   "2. Design solution\n" +
                   "3. Implement changes\n" +
                   "4. Validate results\n" +
                   "\nApprove to execute?";
        });

        // Edit handler - file mutations
        router_.SetEditHandler([](const std::string& instruction, AgentSession* session) {
            bool approved = false;
            auto result = session->ExecuteTool("write_file", 
                R"({"path": "example.txt", "content": "")" + instruction + "\"})", approved);
            return "Edit result: " + result;
        });

        // Agent handler - full autonomous execution
        router_.SetAgentHandler([](const std::string& goal, AgentSession* session) {
            return "Autonomous execution started for goal: " + goal +
                   "\nConnecting to Sovereign Agentic Loop...";
        });
    }
};

} // namespace Platform
} // namespace RawrXD
