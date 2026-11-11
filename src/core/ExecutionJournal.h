//==============================================================================
// ExecutionJournal.h - Event-sourced audit and replay system
//
// Provides immutable event logging for:
// - User requests
// - Agent decisions
// - SEG workflow execution
// - Subsystem invocations
// - File modifications
// - Policy decisions
//
// Enables: debugging, replay, rollback, audit, timeline reconstruction
//==============================================================================

#ifndef EXECUTION_JOURNAL_H
#define EXECUTION_JOURNAL_H

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
// Version & Constants
//==============================================================================

#define JOURNAL_VERSION "1.0.0"
#define JOURNAL_MAX_EVENT_SIZE 4096
#define JOURNAL_MAX_EVENTS 100000
#define JOURNAL_PATH "logs/sovereign.journal"

//==============================================================================
// Event Types
//==============================================================================

typedef enum {
    // User interaction
    EVENT_USER_REQUEST = 0,          // User submitted a goal
    EVENT_USER_APPROVAL,             // User approved an action
    EVENT_USER_REJECTION,            // User rejected an action
    
    // Planning
    EVENT_PLAN_GENERATED,            // Agent created a plan
    EVENT_PLAN_MODIFIED,             // Plan was adjusted
    EVENT_PLAN_REJECTED,             // Plan failed validation
    
    // Workflow
    EVENT_WORKFLOW_CREATED,          // SEG workflow instantiated
    EVENT_WORKFLOW_STARTED,          // Execution began
    EVENT_WORKFLOW_COMPLETED,        // All nodes finished
    EVENT_WORKFLOW_FAILED,           // Workflow failed
    
    // Node execution
    EVENT_NODE_STARTED,              // Individual node began
    EVENT_NODE_COMPLETED,            // Node finished successfully
    EVENT_NODE_FAILED,               // Node failed
    EVENT_NODE_RETRY,                // Node retry attempted
    
    // Subsystem
    EVENT_SUBSYSTEM_INVOKED,         // Subsystem called
    EVENT_SUBSYSTEM_COMPLETED,       // Subsystem returned
    EVENT_SUBSYSTEM_ERROR,           // Subsystem error
    
    // Agent
    EVENT_AGENT_GENERATED,           // Agent produced output
    EVENT_AGENT_FIXED,               // Agent fixed code
    EVENT_AGENT_OPTIMIZED,           // Agent optimized code
    EVENT_AGENT_ANALYZED,            // Agent analyzed error
    
    // Files
    EVENT_FILE_CREATED,              // New file written
    EVENT_FILE_MODIFIED,             // File changed
    EVENT_FILE_DELETED,              // File removed
    EVENT_FILE_VERSIONED,            // Snapshot saved
    
    // Compilation
    EVENT_COMPILE_STARTED,           // Compiler invoked
    EVENT_COMPILE_SUCCEEDED,         // Build passed
    EVENT_COMPILE_FAILED,            // Build failed
    
    // Tests
    EVENT_TEST_STARTED,              // Test run began
    EVENT_TEST_PASSED,               // Test succeeded
    EVENT_TEST_FAILED,               // Test failed
    
    // Policy
    EVENT_POLICY_CHECK,              // Policy evaluated
    EVENT_POLICY_ALLOWED,            // Action approved
    EVENT_POLICY_DENIED,             // Action rejected
    EVENT_POLICY_APPROVAL_REQUIRED,  // Needs user confirmation
    
    // Telemetry
    EVENT_METRIC_RECORDED,           // Performance metric
    EVENT_TELEMETRY_BATCH,           // Batch of metrics
    
    // System
    EVENT_SYSTEM_INIT,               // Runtime started
    EVENT_SYSTEM_SHUTDOWN,           // Runtime stopped
    EVENT_CHECKPOINT_CREATED         // Recovery point saved
} EventType;

//==============================================================================
// Event Severity
//==============================================================================

typedef enum {
    SEVERITY_DEBUG = 0,
    SEVERITY_INFO,
    SEVERITY_WARNING,
    SEVERITY_ERROR,
    SEVERITY_CRITICAL
} EventSeverity;

//==============================================================================
// Event Structure (Immutable)
//==============================================================================

typedef struct JournalEvent {
    // Header
    uint64_t timestamp_ms;           // Unix timestamp with ms
    uint64_t sequence_number;        // Global ordering
    EventType type;
    EventSeverity severity;
    
    // Context
    uint64_t session_id;             // User session
    uint64_t workflow_id;            // Associated workflow
    uint32_t node_id;                // Associated node
    char subsystem[64];              // Subsystem name
    
    // Content
    char description[256];           // Human-readable summary
    char data[JOURNAL_MAX_EVENT_SIZE]; // JSON payload
    size_t data_len;
    
    // Integrity
    uint64_t previous_hash;          // Chain for tamper detection
    uint64_t event_hash;             // This event's hash
} JournalEvent;

//==============================================================================
// Event Payload Structures (for data field)
//==============================================================================

// EVENT_USER_REQUEST
typedef struct UserRequestPayload {
    char goal[1024];
    char context[2048];
    int auto_approve;
} UserRequestPayload;

// EVENT_PLAN_GENERATED
typedef struct PlanGeneratedPayload {
    char plan_id[64];
    int num_steps;
    char estimated_duration[32];
    char plan_json[2048];
} PlanGeneratedPayload;

// EVENT_NODE_COMPLETED
typedef struct NodeCompletedPayload {
    char node_name[128];
    char subsystem[64];
    char command[256];
    uint64_t duration_ms;
    int exit_code;
    char output_preview[512];
} NodeCompletedPayload;

// EVENT_FILE_MODIFIED
typedef struct FileModifiedPayload {
    char path[512];
    uint64_t previous_version;
    uint64_t new_version;
    size_t bytes_changed;
    char diff_preview[1024];
} FileModifiedPayload;

// EVENT_COMPILE_FAILED
typedef struct CompileFailedPayload {
    char language[32];
    char file_path[512];
    int error_count;
    int warning_count;
    char error_summary[1024];
} CompileFailedPayload;

// EVENT_AGENT_GENERATED
typedef struct AgentGeneratedPayload {
    char prompt_preview[512];
    char model[64];
    int tokens_input;
    int tokens_output;
    uint64_t generation_ms;
    float tokens_per_sec;
    char output_preview[1024];
} AgentGeneratedPayload;

// EVENT_METRIC_RECORDED
typedef struct MetricRecordedPayload {
    char metric_name[128];
    double value;
    char unit[32];
    char subsystem[64];
} MetricRecordedPayload;

//==============================================================================
// Journal API
//==============================================================================

// Initialize journal subsystem
int Journal_Init(const char* journal_path);

// Shutdown and flush
int Journal_Shutdown(void);

// Append event (primary interface)
int Journal_AppendEvent(const JournalEvent* event);

// Convenience functions for common events
int Journal_LogUserRequest(const char* goal, const char* context);
int Journal_LogPlanGenerated(const char* plan_id, const char* plan_json);
int Journal_LogNodeStarted(uint64_t workflow_id, uint32_t node_id, const char* subsystem);
int Journal_LogNodeCompleted(uint64_t workflow_id, uint32_t node_id, uint64_t duration_ms, int exit_code);
int Journal_LogFileModified(const char* path, uint64_t old_version, uint64_t new_version);
int Journal_LogCompileFailed(const char* language, const char* file, const char* errors);
int Journal_LogAgentGenerated(const char* model, int tokens_in, int tokens_out, uint64_t duration_ms);
int Journal_LogPolicyDecision(const char* action, int allowed, const char* reason);

//==============================================================================
// Query & Replay
//==============================================================================

// Query events by type
int Journal_QueryByType(EventType type, JournalEvent* events, int max_events, int* count);

// Query events by workflow
int Journal_QueryByWorkflow(uint64_t workflow_id, JournalEvent* events, int max_events, int* count);

// Query events by time range
int Journal_QueryByTime(uint64_t start_ms, uint64_t end_ms, JournalEvent* events, int max_events, int* count);

// Get event at sequence number
int Journal_GetEvent(uint64_t sequence_number, JournalEvent* event);

// Get latest N events
int Journal_GetRecentEvents(int n, JournalEvent* events, int* count);

// Replay workflow from events
int Journal_ReplayWorkflow(uint64_t workflow_id, void (*callback)(const JournalEvent* event));

//==============================================================================
// Rollback & Recovery
//==============================================================================

// Create checkpoint
int Journal_CreateCheckpoint(const char* name);

// Restore to checkpoint
int Journal_RestoreCheckpoint(const char* name);

// Get file version at point in time
int Journal_GetFileVersion(const char* path, uint64_t timestamp_ms, char* version_path, size_t size);

// Undo last N file modifications
int Journal_UndoFileChanges(int n);

//==============================================================================
// Export & Analysis
//==============================================================================

// Export to JSON
int Journal_ExportToJSON(const char* output_path, uint64_t start_ms, uint64_t end_ms);

// Generate timeline report
int Journal_GenerateTimeline(uint64_t workflow_id, char* report, size_t report_size);

// Calculate statistics
int Journal_GetStatistics(uint64_t* total_events, uint64_t* first_timestamp, uint64_t* last_timestamp);

// Get success rate
int Journal_GetSuccessRate(EventType type, double* rate);

//==============================================================================
// Integration Helpers
//==============================================================================

// Auto-log from SEG
int Journal_LogFromSEG(uint64_t workflow_id, uint32_t node_id, const char* event_type, const char* data);

// Auto-log from Agent
int Journal_LogFromAgent(const char* action, const char* model, int success, const char* details);

// Auto-log from Subsystem
int Journal_LogFromSubsystem(const char* subsystem, const char* command, int exit_code, uint64_t duration_ms);

#ifdef __cplusplus
}
#endif

#endif // EXECUTION_JOURNAL_H
