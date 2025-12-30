;==========================================================================
; agent_orchestrator_main.asm - Main Entry Point for Agentic Orchestrator
; ==========================================================================
; Coordinates the initialization and execution of all MASM-native agents.
;==========================================================================

option casemap:none

include windows.inc

;==========================================================================
; EXTERNAL DECLARATIONS
;==========================================================================
EXTERN agentic_bridge_initialize:PROC
EXTERN agent_meta_learn_init:PROC
EXTERN agent_telemetry_init:PROC
EXTERN agent_auto_update_check:PROC
EXTERN agentic_failure_detector_init:PROC
EXTERN tokenizer_init:PROC
EXTERN gpu_backend_init:PROC
EXTERN metrics_init:PROC
EXTERN security_init:PROC
EXTERN proxy_server_init:PROC
EXTERN agent_rollback_check:PROC
EXTERN inference_engine_init:PROC
EXTERN zero_touch_install:PROC
EXTERN sla_manager_check:PROC
EXTERN migrate_memory_db:PROC
EXTERN coordinator_init:PROC
EXTERN bridge_init:PROC
EXTERN run_diagnostics:PROC
EXTERN terminal_init:PROC
EXTERN git_is_available:PROC
EXTERN semantic_init:PROC
EXTERN session_init:PROC
EXTERN agentic_extensions_init:PROC
EXTERN ai_routing_init:PROC
EXTERN autonomous_core_init:PROC
EXTERN ide_features_init:PROC
EXTERN cloud_api_init:PROC
EXTERN performance_engine_init:PROC
EXTERN ggml_core_init:PROC
EXTERN lsp_init:PROC
EXTERN activity_bar_init:PROC
EXTERN ai_chat_panel_init:PROC
EXTERN console_log:PROC

;==========================================================================
; DATA SECTION
;==========================================================================
.data
    szOrchestratorInit BYTE "AgenticOrchestrator: Initializing MASM-native services...", 0
    szOrchestratorReady BYTE "AgenticOrchestrator: System READY (Zero C++ Core)", 0

.code

;==========================================================================
; agent_orchestrator_main()
;==========================================================================
PUBLIC agent_orchestrator_main
agent_orchestrator_main PROC
    sub rsp, 32
    
    lea rcx, szOrchestratorInit
    call console_log
    
    ; 1. Initialize GPU Backend
    call gpu_backend_init
    
    ; 2. Initialize Security
    call security_init
    
    ; 3. Initialize Failure Detector
    call agentic_failure_detector_init
    
    ; 4. Initialize Inference Engine
    call inference_engine_init
    
    ; 5. Initialize Bridge
    call agentic_bridge_initialize
    
    ; 6. Initialize Meta-Learning
    call agent_meta_learn_init
    
    ; 7. Initialize Telemetry
    call agent_telemetry_init
    
    ; 8. Initialize Tokenizer
    call tokenizer_init
    
    ; 9. Initialize Metrics
    call metrics_init
    
    ; 10. Initialize Proxy Server
    mov rcx, 8080       ; Default port
    call proxy_server_init
    
    ; 11. Install Zero-Touch Triggers
    call zero_touch_install
    
    ; 12. Initialize SLA Monitoring
    call sla_manager_check
    
    ; 13. Check for Regression/Rollback
    call agent_rollback_check
    
    ; 14. Check for Updates
    call agent_auto_update_check
    
    ; 15. Initialize Memory Backend
    call migrate_memory_db
    
    ; 16. Initialize Agent Coordinator
    call coordinator_init
    
    ; 17. Initialize Agentic Bridge (MASM version)
    xor rcx, rcx ; Default path
    call bridge_init
    
    ; 18. Run System Diagnostics
    call run_diagnostics
    
    ; 19. Initialize Sandboxed Terminal
    call terminal_init
    
    ; 20. Check Git Availability
    call git_is_available
    
    ; 21. Initialize Semantic Analyzer
    call semantic_init
    
    ; 22. Initialize Session Manager
    call session_init
    
    ; 23. Initialize Agentic Extensions
    call agentic_extensions_init
    
    ; 24. Initialize AI Routing
    call ai_routing_init
    
    ; 25. Initialize Autonomous Core
    call autonomous_core_init
    
    ; 26. Initialize IDE Features
    call ide_features_init
    
    ; 27. Initialize Cloud API & Server
    call cloud_api_init
    
    ; 28. Initialize Performance Engine
    call performance_engine_init
    
    ; 29. Initialize GGML Core
    call ggml_core_init
    
    ; 30. Initialize LSP Client
    xor rcx, rcx ; Default server path
    call lsp_init
    
    ; 31. Initialize UI Widgets (if HWND available)
    ; xor rcx, rcx ; HWND would go here
    ; call activity_bar_init
    ; call ai_chat_panel_init
    
    lea rcx, szOrchestratorReady
    call console_log
    
    add rsp, 32
    ret
agent_orchestrator_main ENDP

END





