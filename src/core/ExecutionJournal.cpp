//==============================================================================
// ExecutionJournal.cpp - Event-sourced audit and replay system
//
// Immutable append-only log with integrity checking
//==============================================================================

#include "ExecutionJournal.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <windows.h>

//==============================================================================
// Internal State
//==============================================================================

typedef struct JournalState {
    FILE* journal_file;
    uint64_t sequence_number;
    uint64_t previous_hash;
    uint64_t session_id;
    int is_initialized;
    char journal_path[512];
    CRITICAL_SECTION lock;
} JournalState;

static JournalState g_journal = {0};

//==============================================================================
// Timing
//==============================================================================

static uint64_t GetTimestampMs() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    // Convert from 100-nanosecond intervals to milliseconds
    // and adjust for Unix epoch (11644473600000 milliseconds)
    return (uli.QuadPart / 10000) - 11644473600000ULL;
}

static uint64_t GenerateSessionId() {
    return GetTimestampMs() ^ (uint64_t)GetCurrentThreadId();
}

//==============================================================================
// Hashing (simple FNV-1a for integrity)
//==============================================================================

static uint64_t HashEvent(const JournalEvent* event) {
    const uint64_t FNV_PRIME = 1099511628211ULL;
    const uint64_t FNV_OFFSET = 14695981039346656037ULL;
    
    uint64_t hash = FNV_OFFSET;
    
    // Hash header
    hash ^= event->timestamp_ms;
    hash *= FNV_PRIME;
    hash ^= event->sequence_number;
    hash *= FNV_PRIME;
    hash ^= event->type;
    hash *= FNV_PRIME;
    hash ^= event->severity;
    hash *= FNV_PRIME;
    
    // Hash content
    for (size_t i = 0; i < event->data_len; i++) {
        hash ^= (uint64_t)event->data[i];
        hash *= FNV_PRIME;
    }
    
    return hash;
}

//==============================================================================
// Initialization
//==============================================================================

int Journal_Init(const char* journal_path) {
    if (g_journal.is_initialized) {
        return 0;
    }
    
    InitializeCriticalSection(&g_journal.lock);
    
    // Set path
    if (journal_path) {
        strncpy(g_journal.journal_path, journal_path, sizeof(g_journal.journal_path) - 1);
    } else {
        strcpy(g_journal.journal_path, JOURNAL_PATH);
    }
    
    // Ensure directory exists
    char dir[512];
    strncpy(dir, g_journal.journal_path, sizeof(dir) - 1);
    char* last_slash = strrchr(dir, '/');
    if (!last_slash) last_slash = strrchr(dir, '\\');
    if (last_slash) {
        *last_slash = '\0';
        CreateDirectoryA(dir, NULL);  // OK if already exists
    }
    
    // Open journal file (append mode)
    g_journal.journal_file = fopen(g_journal.journal_path, "ab");
    if (!g_journal.journal_file) {
        fprintf(stderr, "[Journal] Failed to open journal file: %s\n", g_journal.journal_path);
        return -1;
    }
    
    // Generate session ID
    g_journal.session_id = GenerateSessionId();
    
    // Read last sequence number and hash
    fseek(g_journal.journal_file, 0, SEEK_END);
    long file_size = ftell(g_journal.journal_file);
    
    if (file_size >= (long)sizeof(JournalEvent)) {
        // Read last event for chain continuity
        JournalEvent last_event;
        fseek(g_journal.journal_file, -(long)sizeof(JournalEvent), SEEK_END);
        fread(&last_event, sizeof(JournalEvent), 1, g_journal.journal_file);
        g_journal.sequence_number = last_event.sequence_number + 1;
        g_journal.previous_hash = last_event.event_hash;
    } else {
        g_journal.sequence_number = 1;
        g_journal.previous_hash = 0;
    }
    
    // Seek to end for appending
    fseek(g_journal.journal_file, 0, SEEK_END);
    
    g_journal.is_initialized = 1;
    
    // Log system init
    JournalEvent init_event = {0};
    init_event.type = EVENT_SYSTEM_INIT;
    init_event.severity = SEVERITY_INFO;
    snprintf(init_event.description, sizeof(init_event.description), 
             "Sovereign Runtime initialized");
    Journal_AppendEvent(&init_event);
    
    printf("[Journal] Initialized. Session: %llu, Sequence: %llu\n",
           g_journal.session_id, g_journal.sequence_number);
    
    return 0;
}

int Journal_Shutdown(void) {
    if (!g_journal.is_initialized) {
        return 0;
    }
    
    // Log system shutdown
    JournalEvent shutdown_event = {0};
    shutdown_event.type = EVENT_SYSTEM_SHUTDOWN;
    shutdown_event.severity = SEVERITY_INFO;
    snprintf(shutdown_event.description, sizeof(shutdown_event.description),
             "Sovereign Runtime shutting down");
    Journal_AppendEvent(&shutdown_event);
    
    // Flush and close
    if (g_journal.journal_file) {
        fflush(g_journal.journal_file);
        fclose(g_journal.journal_file);
        g_journal.journal_file = NULL;
    }
    
    DeleteCriticalSection(&g_journal.lock);
    
    g_journal.is_initialized = 0;
    printf("[Journal] Shutdown complete.\n");
    
    return 0;
}

//==============================================================================
// Core Event Logging
//==============================================================================

int Journal_AppendEvent(const JournalEvent* event) {
    if (!g_journal.is_initialized || !g_journal.journal_file) {
        return -1;
    }
    
    EnterCriticalSection(&g_journal.lock);
    
    // Prepare event
    JournalEvent write_event = *event;
    write_event.timestamp_ms = GetTimestampMs();
    write_event.sequence_number = g_journal.sequence_number++;
    write_event.session_id = g_journal.session_id;
    write_event.previous_hash = g_journal.previous_hash;
    write_event.event_hash = HashEvent(&write_event);
    
    // Write to file
    size_t written = fwrite(&write_event, sizeof(JournalEvent), 1, g_journal.journal_file);
    fflush(g_journal.journal_file);
    
    // Update chain
    g_journal.previous_hash = write_event.event_hash;
    
    LeaveCriticalSection(&g_journal.lock);
    
    return (written == 1) ? 0 : -1;
}

//==============================================================================
// Convenience Functions
//==============================================================================

int Journal_LogUserRequest(const char* goal, const char* context) {
    JournalEvent event = {0};
    event.type = EVENT_USER_REQUEST;
    event.severity = SEVERITY_INFO;
    
    snprintf(event.description, sizeof(event.description), "User request: %.200s", goal);
    
    // Build JSON payload
    snprintf(event.data, sizeof(event.data),
        "{\"goal\":\"%s\",\"context\":\"%s\",\"timestamp\":%llu}",
        goal ? goal : "", context ? context : "", GetTimestampMs());
    event.data_len = strlen(event.data);
    
    return Journal_AppendEvent(&event);
}

int Journal_LogPlanGenerated(const char* plan_id, const char* plan_json) {
    JournalEvent event = {0};
    event.type = EVENT_PLAN_GENERATED;
    event.severity = SEVERITY_INFO;
    
    snprintf(event.description, sizeof(event.description), 
             "Plan generated: %s", plan_id);
    
    snprintf(event.data, sizeof(event.data),
        "{\"plan_id\":\"%s\",\"plan\":%s}",
        plan_id ? plan_id : "", plan_json ? plan_json : "{}");
    event.data_len = strlen(event.data);
    
    return Journal_AppendEvent(&event);
}

int Journal_LogNodeStarted(uint64_t workflow_id, uint32_t node_id, const char* subsystem) {
    JournalEvent event = {0};
    event.type = EVENT_NODE_STARTED;
    event.severity = SEVERITY_DEBUG;
    event.workflow_id = workflow_id;
    event.node_id = node_id;
    
    strncpy(event.subsystem, subsystem ? subsystem : "", sizeof(event.subsystem) - 1);
    snprintf(event.description, sizeof(event.description),
             "Node %u started in workflow %llu", node_id, workflow_id);
    
    snprintf(event.data, sizeof(event.data),
        "{\"workflow_id\":%llu,\"node_id\":%u,\"subsystem\":\"%s\"}",
        workflow_id, node_id, subsystem ? subsystem : "");
    event.data_len = strlen(event.data);
    
    return Journal_AppendEvent(&event);
}

int Journal_LogNodeCompleted(uint64_t workflow_id, uint32_t node_id, 
                              uint64_t duration_ms, int exit_code) {
    JournalEvent event = {0};
    event.type = (exit_code == 0) ? EVENT_NODE_COMPLETED : EVENT_NODE_FAILED;
    event.severity = (exit_code == 0) ? SEVERITY_INFO : SEVERITY_ERROR;
    event.workflow_id = workflow_id;
    event.node_id = node_id;
    
    snprintf(event.description, sizeof(event.description),
             "Node %u %s in %llu ms (exit: %d)",
             node_id, (exit_code == 0) ? "completed" : "failed", 
             duration_ms, exit_code);
    
    snprintf(event.data, sizeof(event.data),
        "{\"workflow_id\":%llu,\"node_id\":%u,\"duration_ms\":%llu,\"exit_code\":%d}",
        workflow_id, node_id, duration_ms, exit_code);
    event.data_len = strlen(event.data);
    
    return Journal_AppendEvent(&event);
}

int Journal_LogFileModified(const char* path, uint64_t old_version, uint64_t new_version) {
    JournalEvent event = {0};
    event.type = EVENT_FILE_MODIFIED;
    event.severity = SEVERITY_INFO;
    
    snprintf(event.description, sizeof(event.description),
             "File modified: %s (v%llu -> v%llu)", path, old_version, new_version);
    
    snprintf(event.data, sizeof(event.data),
        "{\"path\":\"%s\",\"old_version\":%llu,\"new_version\":%llu}",
        path ? path : "", old_version, new_version);
    event.data_len = strlen(event.data);
    
    return Journal_AppendEvent(&event);
}

int Journal_LogCompileFailed(const char* language, const char* file, const char* errors) {
    JournalEvent event = {0};
    event.type = EVENT_COMPILE_FAILED;
    event.severity = SEVERITY_ERROR;
    
    strncpy(event.subsystem, language ? language : "", sizeof(event.subsystem) - 1);
    snprintf(event.description, sizeof(event.description),
             "Compilation failed: %s (%s)", file, language);
    
    // Truncate errors if too long
    char truncated_errors[2048];
    strncpy(truncated_errors, errors ? errors : "", sizeof(truncated_errors) - 1);
    truncated_errors[sizeof(truncated_errors) - 1] = '\0';
    
    // Escape quotes
    for (char* p = truncated_errors; *p; p++) {
        if (*p == '"') *p = '\'';
        if (*p == '\n') *p = ' ';
    }
    
    snprintf(event.data, sizeof(event.data),
        "{\"language\":\"%s\",\"file\":\"%s\",\"errors\":\"%.1000s...\"}",
        language ? language : "", file ? file : "", truncated_errors);
    event.data_len = strlen(event.data);
    
    return Journal_AppendEvent(&event);
}

int Journal_LogAgentGenerated(const char* model, int tokens_in, int tokens_out, 
                               uint64_t duration_ms) {
    JournalEvent event = {0};
    event.type = EVENT_AGENT_GENERATED;
    event.severity = SEVERITY_INFO;
    
    strncpy(event.subsystem, model ? model : "", sizeof(event.subsystem) - 1);
    snprintf(event.description, sizeof(event.description),
             "Agent generated %d tokens using %s in %llu ms",
             tokens_out, model, duration_ms);
    
    float tps = duration_ms > 0 ? (float)tokens_out / (duration_ms / 1000.0f) : 0;
    
    snprintf(event.data, sizeof(event.data),
        "{\"model\":\"%s\",\"tokens_in\":%d,\"tokens_out\":%d,"
        "\"duration_ms\":%llu,\"tokens_per_sec\":%.2f}",
        model ? model : "", tokens_in, tokens_out, duration_ms, tps);
    event.data_len = strlen(event.data);
    
    return Journal_AppendEvent(&event);
}

int Journal_LogPolicyDecision(const char* action, int allowed, const char* reason) {
    JournalEvent event = {0};
    event.type = allowed ? EVENT_POLICY_ALLOWED : EVENT_POLICY_DENIED;
    event.severity = allowed ? SEVERITY_DEBUG : SEVERITY_WARNING;
    
    snprintf(event.description, sizeof(event.description),
             "Policy %s: %s", allowed ? "allowed" : "denied", action);
    
    snprintf(event.data, sizeof(event.data),
        "{\"action\":\"%s\",\"allowed\":%s,\"reason\":\"%s\"}",
        action ? action : "", allowed ? "true" : "false", reason ? reason : "");
    event.data_len = strlen(event.data);
    
    return Journal_AppendEvent(&event);
}

//==============================================================================
// Query Functions (Basic Implementation)
//==============================================================================

int Journal_GetRecentEvents(int n, JournalEvent* events, int* count) {
    if (!g_journal.is_initialized || !g_journal.journal_file || n <= 0) {
        *count = 0;
        return -1;
    }
    
    EnterCriticalSection(&g_journal.lock);
    
    // Get file size
    fseek(g_journal.journal_file, 0, SEEK_END);
    long file_size = ftell(g_journal.journal_file);
    
    // Calculate how many events to read
    int events_in_file = file_size / sizeof(JournalEvent);
    int events_to_read = (n < events_in_file) ? n : events_in_file;
    
    // Seek to start position
    long start_pos = file_size - (events_to_read * sizeof(JournalEvent));
    fseek(g_journal.journal_file, start_pos, SEEK_SET);
    
    // Read events
    *count = (int)fread(events, sizeof(JournalEvent), events_to_read, g_journal.journal_file);
    
    // Seek back to end
    fseek(g_journal.journal_file, 0, SEEK_END);
    
    LeaveCriticalSection(&g_journal.lock);
    
    return 0;
}

int Journal_QueryByType(EventType type, JournalEvent* events, int max_events, int* count) {
    if (!g_journal.is_initialized || !g_journal.journal_file) {
        *count = 0;
        return -1;
    }
    
    EnterCriticalSection(&g_journal.lock);
    
    // Save current position
    long current_pos = ftell(g_journal.journal_file);
    
    // Scan from beginning
    fseek(g_journal.journal_file, 0, SEEK_SET);
    
    *count = 0;
    JournalEvent event;
    while (fread(&event, sizeof(JournalEvent), 1, g_journal.journal_file) == 1) {
        if (event.type == type && *count < max_events) {
            events[*count] = event;
            (*count)++;
        }
    }
    
    // Restore position
    fseek(g_journal.journal_file, current_pos, SEEK_SET);
    
    LeaveCriticalSection(&g_journal.lock);
    
    return 0;
}

int Journal_ExportToJSON(const char* output_path, uint64_t start_ms, uint64_t end_ms) {
    if (!g_journal.is_initialized || !g_journal.journal_file) {
        return -1;
    }
    
    FILE* out = fopen(output_path, "w");
    if (!out) return -1;
    
    fprintf(out, "[\n");
    
    EnterCriticalSection(&g_journal.lock);
    
    // Save position
    long current_pos = ftell(g_journal.journal_file);
    
    // Scan and export
    fseek(g_journal.journal_file, 0, SEEK_SET);
    
    JournalEvent event;
    int first = 1;
    while (fread(&event, sizeof(JournalEvent), 1, g_journal.journal_file) == 1) {
        if (event.timestamp_ms >= start_ms && event.timestamp_ms <= end_ms) {
            if (!first) fprintf(out, ",\n");
            first = 0;
            
            fprintf(out, "  {\n");
            fprintf(out, "    \"sequence\": %llu,\n", event.sequence_number);
            fprintf(out, "    \"timestamp\": %llu,\n", event.timestamp_ms);
            fprintf(out, "    \"type\": %d,\n", event.type);
            fprintf(out, "    \"severity\": %d,\n", event.severity);
            fprintf(out, "    \"description\": \"%s\",\n", event.description);
            fprintf(out, "    \"data\": %s\n", event.data_len > 0 ? event.data : "{}");
            fprintf(out, "  }");
        }
    }
    
    // Restore position
    fseek(g_journal.journal_file, current_pos, SEEK_SET);
    
    LeaveCriticalSection(&g_journal.lock);
    
    fprintf(out, "\n]\n");
    fclose(out);
    
    return 0;
}

int Journal_GetStatistics(uint64_t* total_events, uint64_t* first_timestamp, 
                           uint64_t* last_timestamp) {
    if (!g_journal.is_initialized || !g_journal.journal_file) {
        return -1;
    }
    
    EnterCriticalSection(&g_journal.lock);
    
    // Save position
    long current_pos = ftell(g_journal.journal_file);
    
    // Get file size
    fseek(g_journal.journal_file, 0, SEEK_END);
    long file_size = ftell(g_journal.journal_file);
    *total_events = file_size / sizeof(JournalEvent);
    
    if (*total_events > 0) {
        // First event
        fseek(g_journal.journal_file, 0, SEEK_SET);
        JournalEvent first;
        fread(&first, sizeof(JournalEvent), 1, g_journal.journal_file);
        *first_timestamp = first.timestamp_ms;
        
        // Last event
        fseek(g_journal.journal_file, -(long)sizeof(JournalEvent), SEEK_END);
        JournalEvent last;
        fread(&last, sizeof(JournalEvent), 1, g_journal.journal_file);
        *last_timestamp = last.timestamp_ms;
    } else {
        *first_timestamp = 0;
        *last_timestamp = 0;
    }
    
    // Restore position
    fseek(g_journal.journal_file, current_pos, SEEK_SET);
    
    LeaveCriticalSection(&g_journal.lock);
    
    return 0;
}
