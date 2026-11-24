// =============================================================================
// sast_rules/c_cpp_rules.inc — S1 declarative C/C++ rule table.
// Included inside an anonymous namespace in sast_rule_engine.cpp as kSastRules.
// Patterns are ECMAScript regex, matched case-insensitively per line.
// needs_state=true rules consult the per-file freed-variable state machine.
// =============================================================================
static const RawRule kSastRules[] = {
    // --- Buffer handling (CWE-120 / CWE-121) --------------------------------
    {"SAST001", "Unbounded strcpy", "CWE-120", Severity::Error,
     R"(\bstrcpy\s*\()",
     "strcpy() has no length limit; use strcpy_s or strlcpy", false},
    {"SAST002", "Unbounded strcat", "CWE-120", Severity::Error,
     R"(\bstrcat\s*\()",
     "strcat() has no length limit; use strcat_s or append with bounds", false},
    {"SAST003", "Unbounded sprintf", "CWE-120", Severity::Error,
     R"(\bsprintf\s*\()",
     "sprintf() can overflow the destination; use snprintf", false},
    {"SAST004", "gets() is unsafe", "CWE-242", Severity::Critical,
     R"(\bgets\s*\()",
     "gets() cannot be bounded and is removed in C11; use fgets", false},
    {"SAST005", "scanf without field width", "CWE-120", Severity::Warning,
     R"(\bscanf\s*\(\s*"(?:%s|%\[))",
     "scanf %s/%[ without a field width can overflow the target", false},

    // --- Injection (CWE-78 / CWE-134) ---------------------------------------
    {"SAST006", "system() call", "CWE-78", Severity::Error,
     R"(\bsystem\s*\()",
     "system() invokes a shell; validate input and avoid shell metacharacters", false},
    {"SAST007", "popen() call", "CWE-78", Severity::Warning,
     R"(\bpopen\s*\()",
     "popen() invokes a shell; prefer CreateProcess with an argv array", false},
    {"SAST008", "printf with non-literal format", "CWE-134", Severity::Error,
     R"(\b(?:printf|fprintf|sprintf|snprintf)\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*[,)])",
     "format string is a variable; a literal format prevents format-string attacks", false},

    // --- Memory (CWE-416 / CWE-476) ------------------------------------------
    {"SAST009", "Use after free", "CWE-416", Severity::Critical,
     R"(\bfree\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\))",
     "variable dereferenced after free(); set it to NULL immediately", true},
    {"SAST010", "malloc result not checked", "CWE-476", Severity::Warning,
     R"((?:malloc|calloc|realloc)\s*\([^)]*\)\s*;)",
     "allocation result used without a NULL check", false},

    // --- Integer / conversion (CWE-190 / CWE-681) ----------------------------
    {"SAST011", "atoi into size/alloc", "CWE-190", Severity::Warning,
     R"(\b(?:malloc|calloc|realloc|alloca)\s*\([^)]*\batoi\s*\()",
     "atoi() result used as an allocation size without range validation", false},

    // --- Hardcoded credentials (CWE-798) --------------------------------------
    {"SAST012", "Hardcoded password", "CWE-798", Severity::Critical,
     R"(\b(?:password|passwd|pwd|secret|api_?key)\s*=\s*"[^"]{4,}")",
     "literal credential in source; load from a secret store or environment", false},
};

static const size_t kSastRuleCount = sizeof(kSastRules) / sizeof(kSastRules[0]);
static const RawRule* const kSastRuleBegin = kSastRules;
static const RawRule* const kSastRuleEnd = kSastRules + kSastRuleCount;