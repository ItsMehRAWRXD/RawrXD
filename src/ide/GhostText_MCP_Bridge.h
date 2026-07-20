//=============================================================================
// GhostText_MCP_Bridge.h
// RawrXD IDE - GhostText to MCP Integration Bridge
//
// Connects the GhostText inline completion engine to MCP tool servers
// for enhanced AI-powered editing capabilities
//=============================================================================

#pragma once

#include "MCP_Transport_Native.h"
#include "../ide/GhostTextIntegration_Wiring.h"
#include <nlohmann/json.hpp>
#include <functional>
#include <memory>
#include <string>

namespace RawrXD {
namespace IDE {

//=============================================================================
// Forward Declarations
//=============================================================================

class GhostTextEngine;
struct GhostTextSuggestion;

//=============================================================================
// MCP Tool Definition
//=============================================================================

/// Represents an MCP tool capability
struct MCPTool {
    std::string name;
    std::string description;
    nlohmann::json inputSchema;
    bool isAvailable = false;
};

/// MCP tool call result
struct MCPToolResult {
    bool success = false;
    nlohmann::json result;
    std::string errorMessage;
    DWORD executionTimeMs = 0;
};

//=============================================================================
// GhostText MCP Bridge
//=============================================================================

/// Bridges GhostText inline completion with MCP tool servers
/// 
/// This class integrates the GhostTextEngine with MCP (Model Context Protocol)
/// servers to provide:
/// - Enhanced context gathering via MCP tools
/// - Real-time code analysis from external services
/// - Multi-model routing through MCP gateways
/// - Streaming completions via SSE
class GhostTextMCPBridge {
public:
    //=========================================================================
    // Construction/Destruction
    //=========================================================================
    
    GhostTextMCPBridge();
    ~GhostTextMCPBridge();
    
    // Non-copyable
    GhostTextMCPBridge(const GhostTextMCPBridge&) = delete;
    GhostTextMCPBridge& operator=(const GhostTextMCPBridge&) = delete;
    
    // Movable
    GhostTextMCPBridge(GhostTextMCPBridge&&) noexcept;
    GhostTextMCPBridge& operator=(GhostTextMCPBridge&&) noexcept;
    
    //=========================================================================
    // Initialization
    //=========================================================================
    
    /// Initialize the bridge with MCP server configuration
    /// 
    /// @param serverUrl - MCP server base URL
    /// @param authToken - Optional OAuth bearer token
    /// @return true on success, false on failure
    bool Initialize(const std::wstring& serverUrl, 
                    const std::wstring& authToken = L"");
    
    /// Shutdown and cleanup
    void Shutdown();
    
    /// Check if bridge is initialized and connected
    bool IsConnected() const;
    
    //=========================================================================
    // GhostText Engine Integration
    //=========================================================================
    
    /// Attach to a GhostTextEngine instance
    /// 
    /// @param pEngine - Pointer to GhostTextEngine
    void AttachToEngine(GhostTextEngine* pEngine);
    
    /// Detach from current engine
    void DetachFromEngine();
    
    /// Get attached engine
    GhostTextEngine* GetAttachedEngine() const;
    
    //=========================================================================
    // MCP Tool Operations
    //=========================================================================
    
    /// Discover available tools from MCP server
    /// 
    /// @return Vector of available tools
    std::vector<MCPTool> DiscoverTools();
    
    /// Call an MCP tool synchronously
    /// 
    /// @param toolName - Name of the tool to call
    /// @param arguments - Tool arguments as JSON
    /// @param timeoutMs - Timeout in milliseconds
    /// @return Tool execution result
    MCPToolResult CallTool(const std::string& toolName,
                           const nlohmann::json& arguments,
                           DWORD timeoutMs = 30000);
    
    /// Call an MCP tool asynchronously
    /// 
    /// @param toolName - Name of the tool to call
    /// @param arguments - Tool arguments as JSON
    /// @param callback - Callback for result
    void CallToolAsync(const std::string& toolName,
                       const nlohmann::json& arguments,
                       std::function<void(const MCPToolResult&)> callback);
    
    //=========================================================================
    // Context Enhancement
    //=========================================================================
    
    /// Enhance completion context using MCP tools
    /// 
    /// Called before sending completion request to gather additional
    /// context from MCP tools (e.g., file contents, symbol definitions)
    /// 
    /// @param documentPath - Path to current document
    /// @param cursorLine - Current cursor line
    /// @param cursorColumn - Current cursor column
    /// @return Enhanced context as JSON
    nlohmann::json EnhanceContext(const std::wstring& documentPath,
                                   int cursorLine,
                                   int cursorColumn);
    
    /// Request completion via MCP server
    /// 
    /// @param prefix - Text before cursor
    /// @param suffix - Text after cursor
    /// @param context - Additional context
    /// @return Suggestion from MCP server
    std::optional<GhostTextSuggestion> RequestCompletion(
        const std::string& prefix,
        const std::string& suffix,
        const nlohmann::json& context);
    
    //=========================================================================
    // Streaming Support
    //=========================================================================
    
    /// Start streaming completions via SSE
    /// 
    /// @param prefix - Text before cursor
    /// @param suffix - Text after cursor
    /// @param onToken - Callback for each token received
    /// @return true if streaming started
    bool StartStreamingCompletion(const std::string& prefix,
                                   const std::string& suffix,
                                   std::function<void(const std::string&)> onToken);
    
    /// Stop streaming
    void StopStreaming();
    
    /// Check if currently streaming
    bool IsStreaming() const;
    
    //=========================================================================
    // Event Handlers
    //=========================================================================
    
    /// Set handler for MCP connection events
    void SetOnConnectionStateChanged(std::function<void(bool connected)> handler);
    
    /// Set handler for tool availability changes
    void SetOnToolsChanged(std::function<void(const std::vector<MCPTool>&)> handler);
    
    /// Set handler for errors
    void SetOnError(std::function<void(const std::string&)> handler);
    
private:
    //=========================================================================
    // Private Implementation
    //=========================================================================
    
    class Impl;
    std::unique_ptr<Impl> m_pImpl;
};

//=============================================================================
// GhostText Engine Extension
//=============================================================================

/// Extended GhostTextEngine that uses MCP for completions
class GhostTextEngineMCP : public GhostTextEngine {
public:
    GhostTextEngineMCP();
    ~GhostTextEngineMCP() override;
    
    /// Initialize with MCP bridge
    bool InitializeWithMCP(const std::wstring& mcpServerUrl,
                          const std::wstring& authToken = L"");
    
    /// Get MCP bridge
    GhostTextMCPBridge* GetMCPBridge() const;
    
protected:
    /// Override to use MCP for completions
    void OnTriggerCompletion() override;
    
    /// Override to enhance context with MCP tools
    nlohmann::json BuildCompletionContext() override;
    
private:
    std::unique_ptr<GhostTextMCPBridge> m_mcpBridge;
    bool m_useMCP = false;
};

//=============================================================================
// Utility Functions
//=============================================================================

/// Convert GhostText suggestion to MCP tool result format
nlohmann::json SuggestionToMCPResult(const GhostTextSuggestion& suggestion);

/// Convert MCP result to GhostText suggestion
GhostTextSuggestion MCPResultToSuggestion(const nlohmann::json& result);

/// Build MCP initialization request
nlohmann::json BuildMCPInitializeRequest(const std::string& clientName,
                                          const std::string& clientVersion);

/// Parse MCP server capabilities
struct MCPServerCapabilities {
    bool supportsStreaming = false;
    bool supportsTools = false;
    std::vector<std::string> supportedModels;
    std::vector<std::string> supportedEncodings;
};

MCPServerCapabilities ParseMCPCapabilities(const nlohmann::json& capabilities);

} // namespace IDE
} // namespace RawrXD
