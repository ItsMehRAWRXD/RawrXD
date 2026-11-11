// ============================================================================
// Win32IDE_Core_Patched.cpp - Modified Initialization Sequence
// ============================================================================
// This file contains the PATCHED version of the deferred initialization
// handler that properly wires up AgentBridge and other missing components.
//
// Apply this patch to Win32IDE_Core.cpp around line 1816 (WM_APP + 1004 handler)
// ============================================================================

// ============================================================================
// PATCH: Modified WM_APP_DEFERRED_INIT_BACKEND handler
// Location: Win32IDE_Core.cpp, line ~1816
// Replace the existing handler with this code
// ============================================================================

/*
REPLACE THIS EXISTING CODE:
==============================
case WM_APP + 1004:  // WM_APP_DEFERRED_INIT_BACKEND
{
    this->initBackendManager();
    this->initLLMRouter();
    finalizeCopilotChatInterlockAfterDeferredLoad();
    return 0;
}
==============================

WITH THIS PATCHED CODE:
*/

case WM_APP + 1004:  // WM_APP_DEFERRED_INIT_BACKEND
{
    using namespace RawrXD;
    
    LOG_INFO("Core: Starting deferred backend initialization");
    
    // Stage 1: Initialize Backend Infrastructure
    __try {
        this->initBackendManager();
        LOG_INFO("Core: BackendManager initialized");
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG_ERROR("Core: BackendManager initialization failed - continuing");
    }
    
    // Stage 2: Initialize LLM Router
    __try {
        this->initLLMRouter();
        LOG_INFO("Core: LLMRouter initialized");
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG_ERROR("Core: LLMRouter initialization failed - continuing");
    }
    
    // Stage 3: Initialize AgentBridge (P0 Critical Feature)
    // This was MISSING in the original code - the broken dependency chain
    if (FeatureRegistry::IsAgentBridgeEnabled()) {
        LOG_INFO("Core: AgentBridge is enabled, attempting initialization");
        
        if (AgentBridgeInit::InitializeSafe(this)) {
            LOG_INFO("Core: AgentBridge initialized successfully");
            
            // Now initialize dependent autonomous systems
            InitializeAutonomousSystemsSafe();
        } else {
            AgentBridgeInit::InitStatus status = AgentBridgeInit::GetStatus();
            LOG_WARNING("Core: AgentBridge initialization failed: " + status.lastError);
            OutputDebugStringA("[Core] AgentBridge unavailable - continuing without AI features\n");
        }
    } else {
        LOG_INFO("Core: AgentBridge is disabled by feature registry");
    }
    
    // Stage 4: Initialize optional subsystems (P2 features)
    InitializeOptionalSubsystemsSafe();
    
    // Stage 5: Finalize Copilot Chat interlock
    __try {
        finalizeCopilotChatInterlockAfterDeferredLoad();
        LOG_INFO("Core: CopilotChat interlock finalized");
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG_ERROR("Core: CopilotChat interlock failed - continuing");
    }
    
    LOG_INFO("Core: Deferred backend initialization complete");
    return 0;
}

// ============================================================================
// NEW HELPER FUNCTIONS - Add these to Win32IDE class
// ============================================================================

/*
Add these method declarations to Win32IDE.h (private section):

private:
    void InitializeAutonomousSystemsSafe();
    void InitializeOptionalSubsystemsSafe();
*/

/*
Add these implementations to Win32IDE_Core.cpp (after the WM handler):
*/

void Win32IDE::InitializeAutonomousSystemsSafe()
{
    using namespace RawrXD;
    
    LOG_INFO("Core: Initializing autonomous systems");
    
    // Initialize AgenticIntegration
    if (FeatureRegistry::IsAgenticIntegrationEnabled()) {
        __try {
            if (!m_agenticIntegration) {
                m_agenticIntegration = std::make_unique<Win32IDE_AgenticIntegration>();
                LOG_INFO("Core: AgenticIntegration initialized");
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            LOG_ERROR("Core: AgenticIntegration init failed");
        }
    }
    
    // Initialize AutonomousFeatureEngine
    if (FeatureRegistry::IsAutonomousFeatureEngineEnabled()) {
        __try {
            if (!m_autonomousFeatureEngine) {
                m_autonomousFeatureEngine = std::make_unique<AutonomousFeatureEngine>();
                LOG_INFO("Core: AutonomousFeatureEngine initialized");
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            LOG_ERROR("Core: AutonomousFeatureEngine init failed");
        }
    }
    
    // Initialize AutonomousOrchestrator
    if (FeatureRegistry::IsAutonomousOrchestratorEnabled()) {
        __try {
            if (!m_autonomousOrchestrator) {
                m_autonomousOrchestrator = std::make_unique<RawrXD::AutonomousIntelligenceOrchestrator>();
                LOG_INFO("Core: AutonomousOrchestrator initialized");
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            LOG_ERROR("Core: AutonomousOrchestrator init failed");
        }
    }
    
    // Initialize AutonomousModelManager
    if (FeatureRegistry::IsAutonomousModelManagerEnabled()) {
        __try {
            if (!m_autonomousModelManager) {
                m_autonomousModelManager = std::make_unique<RawrXD::AutonomousModelManager>();
                LOG_INFO("Core: AutonomousModelManager initialized");
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            LOG_ERROR("Core: AutonomousModelManager init failed");
        }
    }
    
    LOG_INFO("Core: Autonomous systems initialization complete");
}

void Win32IDE::InitializeOptionalSubsystemsSafe()
{
    using namespace RawrXD;
    
    LOG_INFO("Core: Initializing optional subsystems");
    
    // Voice Assistant (P2 - Optional)
    if (FeatureRegistry::IsVoiceAssistantEnabled()) {
        __try {
            // VoiceAssistant initialization would go here
            // Currently disabled by default
            LOG_INFO("Core: VoiceAssistant would initialize here (currently disabled)");
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            LOG_ERROR("Core: VoiceAssistant init failed");
        }
    }
    
    // Extension Host (P2 - Optional)
    if (FeatureRegistry::IsExtensionHostEnabled()) {
        __try {
            // ExtensionHost initialization would go here
            LOG_INFO("Core: ExtensionHost would initialize here (currently disabled)");
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            LOG_ERROR("Core: ExtensionHost init failed");
        }
    }
    
    // Plugin System (v1.1 feature)
    if (FeatureRegistry::IsPluginSystemEnabled()) {
        __try {
            // NativePluginManager initialization would go here
            LOG_INFO("Core: PluginSystem would initialize here (v1.1 feature)");
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            LOG_ERROR("Core: PluginSystem init failed");
        }
    }
    
    LOG_INFO("Core: Optional subsystems initialization complete");
}

// ============================================================================
// END OF PATCH
// ============================================================================
