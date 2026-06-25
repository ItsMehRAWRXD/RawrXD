// agentic_condition_evaluator.cpp - Production Implementation
// Evaluates boolean conditions for agentic workflow gates
// ============================================================================

#include <windows.h>
#include <cstdlib>
#include <cstring>
#include <cctype>

// ============================================================================
// State
// ============================================================================
static volatile LONG g_initialized = 0;
static volatile LONG g_evalCount = 0;
static volatile LONG g_trueCount = 0;

// ============================================================================
// Helper: Trim whitespace
// ============================================================================
static char* Trim(char* s) {
    while (isspace((unsigned char)*s)) ++s;
    if (*s == 0) return s;
    char* end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) --end;
    end[1] = 0;
    return s;
}

// ============================================================================
// Helper: Parse numeric value from string
// ============================================================================
static double ParseValue(const char* s) {
    char* end = nullptr;
    double val = strtod(s, &end);
    (void)end;
    return val;
}

// ============================================================================
// Helper: Evaluate simple condition string
// Supports: ==, !=, <, >, <=, >=
// Returns: 1 = true, 0 = false, -1 = error/unknown
// ============================================================================
static int EvaluateCondition(const char* condition) {
    if (!condition || !*condition) return -1;
    
    char buf[512];
    size_t len = strlen(condition);
    if (len >= sizeof(buf)) len = sizeof(buf) - 1;
    memcpy(buf, condition, len);
    buf[len] = 0;
    
    char* p = buf;
    // Find operator
    char* opPos = nullptr;
    char op[3] = {0};
    
    for (size_t i = 0; buf[i]; ++i) {
        if (buf[i] == '=' && buf[i+1] == '=') { opPos = &buf[i]; op[0] = '='; op[1] = '='; buf[i] = 0; break; }
        if (buf[i] == '!' && buf[i+1] == '=') { opPos = &buf[i]; op[0] = '!'; op[1] = '='; buf[i] = 0; break; }
        if (buf[i] == '<' && buf[i+1] == '=') { opPos = &buf[i]; op[0] = '<'; op[1] = '='; buf[i] = 0; break; }
        if (buf[i] == '>' && buf[i+1] == '=') { opPos = &buf[i]; op[0] = '>'; op[1] = '='; buf[i] = 0; break; }
        if (buf[i] == '<') { opPos = &buf[i]; op[0] = '<'; buf[i] = 0; break; }
        if (buf[i] == '>') { opPos = &buf[i]; op[0] = '>'; buf[i] = 0; break; }
    }
    
    if (!opPos) {
        // No operator found - treat as truthiness check
        char* trimmed = Trim(buf);
        if (_stricmp(trimmed, "true") == 0 || _stricmp(trimmed, "1") == 0 || _stricmp(trimmed, "yes") == 0) return 1;
        if (_stricmp(trimmed, "false") == 0 || _stricmp(trimmed, "0") == 0 || _stricmp(trimmed, "no") == 0) return 0;
        return strlen(trimmed) > 0 ? 1 : 0;
    }
    
    char* left = Trim(buf);
    char* right = Trim(opPos + (op[1] ? 2 : 1));
    
    // Try numeric comparison first
    char* lEnd = nullptr, *rEnd = nullptr;
    double leftVal = strtod(left, &lEnd);
    double rightVal = strtod(right, &rEnd);
    
    if (*lEnd == 0 && *rEnd == 0) {
        // Pure numeric comparison
        if (op[0] == '=' && op[1] == '=') return leftVal == rightVal ? 1 : 0;
        if (op[0] == '!' && op[1] == '=') return leftVal != rightVal ? 1 : 0;
        if (op[0] == '<' && op[1] == '=') return leftVal <= rightVal ? 1 : 0;
        if (op[0] == '>' && op[1] == '=') return leftVal >= rightVal ? 1 : 0;
        if (op[0] == '<') return leftVal < rightVal ? 1 : 0;
        if (op[0] == '>') return leftVal > rightVal ? 1 : 0;
    }
    
    // String comparison
    int cmp = _stricmp(left, right);
    if (op[0] == '=' && op[1] == '=') return cmp == 0 ? 1 : 0;
    if (op[0] == '!' && op[1] == '=') return cmp != 0 ? 1 : 0;
    if (op[0] == '<' && op[1] == '=') return cmp <= 0 ? 1 : 0;
    if (op[0] == '>' && op[1] == '=') return cmp >= 0 ? 1 : 0;
    if (op[0] == '<') return cmp < 0 ? 1 : 0;
    if (op[0] == '>') return cmp > 0 ? 1 : 0;
    
    return -1;
}

// ============================================================================
// Exported API
// ============================================================================
extern "C" __declspec(dllexport) int agentic_condition_evaluator_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1; // Already initialized
    InterlockedExchange(&g_evalCount, 0);
    InterlockedExchange(&g_trueCount, 0);
    return 1;
}

extern "C" __declspec(dllexport) int agentic_condition_evaluator_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int agentic_condition_evaluator_Evaluate(const char* condition) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return -1;
    if (!condition) return -1;
    
    InterlockedIncrement(&g_evalCount);
    int result = EvaluateCondition(condition);
    if (result == 1) InterlockedIncrement(&g_trueCount);
    return result;
}

extern "C" __declspec(dllexport) int agentic_condition_evaluator_GetStats(int* totalEvals, int* trueEvals) {
    if (totalEvals) *totalEvals = static_cast<int>(InterlockedCompareExchange(&g_evalCount, 0, 0));
    if (trueEvals) *trueEvals = static_cast<int>(InterlockedCompareExchange(&g_trueCount, 0, 0));
    return 1;
}
