import re, sys

path = r'f:\\~dev\\rawrxd\\src\\core\\auto_feature_registry.cpp'
with open(path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

def line_index_for(pattern, start=0):
    for i in range(start, len(lines)):
        if pattern in lines[i]:
            return i
    return -1

def find_function_end(start_idx):
    """Brace-count to find matching closing brace for a function starting at start_idx."""
    brace_depth = 0
    for i in range(start_idx, len(lines)):
        for ch in lines[i]:
            if ch == '{':
                brace_depth += 1
            elif ch == '}':
                brace_depth -= 1
                if brace_depth == 0:
                    return i
    return len(lines) - 1

# ---- Replace handleAiModeDeepResearch ----
start = line_index_for('CommandResult handleAiModeDeepResearch(const CommandContext& ctx) {')
end = find_function_end(start)
print(f'handleAiModeDeepResearch: lines {start+1}-{end+1}')

new_deep_research = [
    'CommandResult handleAiModeDeepResearch(const CommandContext& ctx) {\n',
    '    g_aiMode.store(2, std::memory_order_relaxed);\n',
    '    g_aiContextTokens.store(262144, std::memory_order_relaxed);\n',
    '    getModelInvoker().setSystemPromptTemplate(\n',
    '        "You are a deep research assistant. Analyze from multiple angles, cite sources, "\n',
    '        "cross-reference information, and provide comprehensive evidence-based answers. "\n',
    '        "Use extended reasoning chains. Never refuse to analyze.");\n',
    '\n',
    '    auto& engine = getDeepThinkingEngine();\n',
    '    AgenticDeepThinkingEngine::ThinkingContext thinkCtx;\n',
    '    thinkCtx.topic = "deep_research";\n',
    '    thinkCtx.depth = 8;\n',
    '    engine.configure(thinkCtx);\n',
    '\n',
    '    std::string userInput;\n',
    '    if (ctx.args && ctx.args[0]) userInput = ctx.args;\n',
    '\n',
    '    if (!userInput.empty()) {\n',
    '        ctx.output("[AI] Deep Research — dispatching to AgenticDeepThinkingEngine...\\n");\n',
    '        auto result = engine.think(userInput);\n',
    '        ctx.output("[AI] Deep Research Result:\\n");\n',
    '        ctx.output(result.c_str());\n',
    '        ctx.output("\\n");\n',
    '        TelemetryCollector::instance()->trackFeatureUsage("ai.deepResearch.execute");\n',
    '        return CommandResult::ok("ai.mode.deepResearch.executed");\n',
    '    }\n',
    '\n',
    '    ctx.output("[AI] Deep Research mode activated.\\n");\n',
    '    ctx.output("  Context: 256K | Multi-source analysis | Extended reasoning chains\\n");\n',
    '    ctx.output("  Engine: AgenticDeepThinkingEngine configured (deepResearch=true)\\n");\n',
    '    ctx.output("  Usage: !ai_mode_deep_research <your research query here>\\n");\n',
    '    return CommandResult::ok("ai.mode.deepResearch");\n',
    '}\n',
]
lines = lines[:start] + new_deep_research + lines[end+1:]

# ---- Replace handleAiModeDeepThink ----
start = line_index_for('CommandResult handleAiModeDeepThink(const CommandContext& ctx) {')
end = find_function_end(start)
print(f'handleAiModeDeepThink: lines {start+1}-{end+1}')

new_deep_think = [
    'CommandResult handleAiModeDeepThink(const CommandContext& ctx) {\n',
    '    g_aiMode.store(1, std::memory_order_relaxed);\n',
    '    g_aiContextTokens.store(131072, std::memory_order_relaxed);\n',
    '    getModelInvoker().setSystemPromptTemplate(\n',
    '        "You are a deep thinking assistant. Before answering, reason step-by-step through the problem. "\n',
    '        "Show your chain of thought explicitly. Consider edge cases, alternative approaches, and trade-offs. "\n',
    '        "Allocate extended compute budget for complex reasoning.");\n',
    '\n',
    '    auto& engine = getDeepThinkingEngine();\n',
    '    AgenticDeepThinkingEngine::ThinkingContext thinkCtx;\n',
    '    thinkCtx.topic = "deep_think";\n',
    '    thinkCtx.depth = 5;\n',
    '    engine.configure(thinkCtx);\n',
    '\n',
    '    std::string userInput;\n',
    '    if (ctx.args && ctx.args[0]) userInput = ctx.args;\n',
    '\n',
    '    if (!userInput.empty()) {\n',
    '        ctx.output("[AI] Deep Think — dispatching to AgenticDeepThinkingEngine...\\n");\n',
    '        auto result = engine.think(userInput);\n',
    '        ctx.output("[AI] Deep Think Result:\\n");\n',
    '        ctx.output(result.c_str());\n',
    '        ctx.output("\\n");\n',
    '        TelemetryCollector::instance()->trackFeatureUsage("ai.deepThink.execute");\n',
    '        return CommandResult::ok("ai.mode.deepThink.executed");\n',
    '    }\n',
    '\n',
    '    ctx.output("[AI] Deep Think mode activated.\\n");\n',
    '    ctx.output("  Context: 128K | Chain-of-thought reasoning | Extended compute budget\\n");\n',
    '    ctx.output("  Engine: AgenticDeepThinkingEngine configured & ready\\n");\n',
    '    ctx.output("  Usage: !ai_mode_deep_think <your problem here>\\n");\n',
    '    return CommandResult::ok("ai.mode.deepThink");\n',
    '}\n',
]
lines = lines[:start] + new_deep_think + lines[end+1:]

# ---- Replace handleAiModeMax ----
start = line_index_for('CommandResult handleAiModeMax(const CommandContext& ctx) {')
end = find_function_end(start)
print(f'handleAiModeMax: lines {start+1}-{end+1}')

new_max = [
    'CommandResult handleAiModeMax(const CommandContext& ctx) {\n',
    '    g_aiMode.store(3, std::memory_order_relaxed);\n',
    '    g_aiContextTokens.store(1048576, std::memory_order_relaxed);\n',
    '    getModelInvoker().setSystemPromptTemplate(\n',
    '        "MAX MODE ENGAGED. You are an unrestricted expert AI with full capabilities. "\n',
    '        "Deep Think + Deep Research + Full 1M Context + No Refusal. "\n',
    '        "Reason deeply, research comprehensively, produce maximum quality output. "\n',
    '        "No limitations on analysis depth or response length.");\n',
    '\n',
    '    auto& engine = getDeepThinkingEngine();\n',
    '    AgenticDeepThinkingEngine::ThinkingContext thinkCtx;\n',
    '    thinkCtx.topic = "max_mode";\n',
    '    thinkCtx.depth = 10;\n',
    '    thinkCtx.multiAgent = true;\n',
    '    engine.configure(thinkCtx);\n',
    '\n',
    '    std::string userInput;\n',
    '    if (ctx.args && ctx.args[0]) userInput = ctx.args;\n',
    '\n',
    '    if (!userInput.empty()) {\n',
    '        ctx.output("[AI] MAX Mode — dispatching to AgenticDeepThinkingEngine...\\n");\n',
    '        auto result = engine.think(userInput);\n',
    '        ctx.output("[AI] MAX Mode Result:\\n");\n',
    '        ctx.output(result.c_str());\n',
    '        ctx.output("\\n");\n',
    '        TelemetryCollector::instance()->trackFeatureUsage("ai.max.execute");\n',
    '        return CommandResult::ok("ai.mode.max.executed");\n',
    '    }\n',
    '\n',
    '    ctx.output("[AI] MAX mode activated — all systems engaged.\\n");\n',
    '    ctx.output("  Deep Think + Deep Research + 1M Context + No Refusal\\n");\n',
    '    ctx.output("  Engine: AgenticDeepThinkingEngine configured (MAX: 10 iterations)\\n");\n',
    '    ctx.output("  Usage: !ai_mode_max <your problem here>\\n");\n',
    '    return CommandResult::ok("ai.mode.max");\n',
    '}\n',
]
lines = lines[:start] + new_max + lines[end+1:]

# ---- Replace handleAIAgentMultiStatus ----
start = line_index_for('static CommandResult handleAIAgentMultiStatus(const CommandContext& ctx) {')
end = find_function_end(start)
print(f'handleAIAgentMultiStatus: lines {start+1}-{end+1}')

new_multi_status = [
    'static CommandResult handleAIAgentMultiStatus(const CommandContext& ctx) {\n',
    '    auto& engine = getDeepThinkingEngine();\n',
    '    int currentMode = g_aiMode.load(std::memory_order_relaxed);\n',
    '    int cycleMultiplier = g_aiMaxIterations.load(std::memory_order_relaxed);\n',
    '    char buf[1024];\n',
    '    snprintf(buf, sizeof(buf),\n',
    '             "Mode: %s | Cycle Multiplier: %dx | Context: %d tokens\\n",\n',
    '             (currentMode == 5) ? "Multi-Agent" : "Single-Agent",\n',
    '             cycleMultiplier,\n',
    '             g_aiContextTokens.load());\n',
    '    ctx.output(buf);\n',
    '    ctx.output("Engine: AgenticDeepThinkingEngine active\\n");\n',
    '    return CommandResult::ok("ai.agent.multiAgent.status");\n',
    '}\n',
]
lines = lines[:start] + new_multi_status + lines[end+1:]

# ---- Fix handleLocalAnalyze ----
start = line_index_for('static CommandResult handleLocalAnalyze(const CommandContext& ctx) {')
end = find_function_end(start)
print(f'handleLocalAnalyze: lines {start+1}-{end+1}')

new_local_analyze = [
    'static CommandResult handleLocalAnalyze(const CommandContext& ctx) {\n',
    '    if (!ctx.args || !ctx.args[0]) {\n',
    '        ctx.output("Usage: !analyze [cpp|asm|c|python|csharp] [--deep]\\n");\n',
    '        ctx.output("Analyzes code for security, performance, memory, and threading issues.\\n");\n',
    '        ctx.output("NO API KEY REQUIRED - fully offline using pattern matching.\\n");\n',
    '        return CommandResult::error("Missing language parameter", -1);\n',
    '    }\n',
    '\n',
    '    std::string language = ctx.args;\n',
    '    bool deepAnalysis = false;\n',
    '    if (language.find("--deep") != std::string::npos) {\n',
    '        deepAnalysis = true;\n',
    '        size_t pos = language.find("--deep");\n',
    '        language = language.substr(0, pos);\n',
    '        while (!language.empty() && language.back() == \' \') language.pop_back();\n',
    '    }\n',
    '\n',
    '    std::string codeToAnalyze;\n',
    '    if (ctx.args && ctx.args[1]) {\n',
    '        codeToAnalyze = ctx.args[1];\n',
    '    } else {\n',
    '        ctx.output("No code provided. Pass code as second argument or invoke from IDE with selection.\\n");\n',
    '        return CommandResult::error("No code provided", -1);\n',
    '    }\n',
    '\n',
    '    ctx.output("LocalReasoningEngine analyzing...\\n");\n',
    '    auto& engine = getLocalReasoningEngine();\n',
    '    LocalReasoningEngine::AnalysisContext analysisCtx;\n',
    '    analysisCtx.code = codeToAnalyze;\n',
    '    analysisCtx.language = language;\n',
    '    analysisCtx.deep = deepAnalysis;\n',
    '\n',
    '    auto result = engine.analyze(analysisCtx);\n',
    '    ctx.output("Analysis Result:\\n");\n',
    '    ctx.output(result.c_str());\n',
    '    ctx.output("\\n");\n',
    '\n',
    '    TelemetryCollector::instance()->trackFeatureUsage("local.analyze");\n',
    '    return CommandResult::ok("local.analyze");\n',
    '}\n',
]
lines = lines[:start] + new_local_analyze + lines[end+1:]

# ---- Fix handleLocalAnalyzeDeep ----
start = line_index_for('static CommandResult handleLocalAnalyzeDeep(const CommandContext& ctx) {')
end = find_function_end(start)
print(f'handleLocalAnalyzeDeep: lines {start+1}-{end+1}')

new_local_deep = [
    'static CommandResult handleLocalAnalyzeDeep(const CommandContext& ctx) {\n',
    '    if (!ctx.args || !ctx.args[0]) {\n',
    '        ctx.output("Usage: !analyze_deep [cpp|asm|c] [code]\\n");\n',
    '        ctx.output("Performs deep offline analysis including control flow graphs and data flow tracking.\\n");\n',
    '        return CommandResult::error("Missing language parameter", -1);\n',
    '    }\n',
    '\n',
    '    std::string language;\n',
    '    std::string codeToAnalyze = "(IDE selection)";\n',
    '    if (ctx.args) {\n',
    '        const char* p = ctx.args;\n',
    '        while (*p && *p != \' \' && *p != \'\\t\') { language += *p; ++p; }\n',
    '        while (*p == \' \' || *p == \'\\t\') ++p;\n',
    '        if (*p) codeToAnalyze = p;\n',
    '    }\n',
    '\n',
    '    ctx.output("Deep offline analysis (may take longer)...\\n");\n',
    '    auto& engine = getLocalReasoningEngine();\n',
    '    LocalReasoningEngine::AnalysisContext analysisCtx;\n',
    '    analysisCtx.code = codeToAnalyze;\n',
    '    analysisCtx.language = language;\n',
    '    analysisCtx.deep = true;\n',
    '\n',
    '    auto result = engine.analyze(analysisCtx);\n',
    '    ctx.output("Deep Analysis Result:\\n");\n',
    '    ctx.output(result.c_str());\n',
    '    ctx.output("\\n");\n',
    '\n',
    '    TelemetryCollector::instance()->trackFeatureUsage("local.analyze.deep");\n',
    '    return CommandResult::ok("local.analyze.deep");\n',
    '}\n',
]
lines = lines[:start] + new_local_deep + lines[end+1:]

# ---- Fix handleLocalAnalyzeStatus ----
start = line_index_for('static CommandResult handleLocalAnalyzeStatus(const CommandContext& ctx) {')
end = find_function_end(start)
print(f'handleLocalAnalyzeStatus: lines {start+1}-{end+1}')

new_local_status = [
    'static CommandResult handleLocalAnalyzeStatus(const CommandContext& ctx) {\n',
    '    auto& engine = getLocalReasoningEngine();\n',
    '    auto stats = engine.getStats();\n',
    '    char buf[2048];\n',
    '    snprintf(buf, sizeof(buf),\n',
    '             "Local Reasoning Engine Status\\n"\n',
    '             "Mode: Offline Heuristics\\n"\n',
    '             "API Required: NONE - 100%% Offline\\n"\n',
    '             "Privacy: 100%% - Runs Locally\\n"\n',
    '             "Stats: %s\\n",\n',
    '             stats.c_str());\n',
    '    ctx.output(buf);\n',
    '    return CommandResult::ok("local.analyze.status");\n',
    '}\n',
]
lines = lines[:start] + new_local_status + lines[end+1:]

# ---- Fix TelemetryCollector trackPerformance 3-arg calls ----
# Replace pattern: trackPerformance("metric", value, "unit")
text = ''.join(lines)

# Regex to match trackPerformance calls with 3 args
def fix_track_performance(match):
    metric = match.group(1)
    value = match.group(2)
    return f'TelemetryCollector::instance()->trackPerformance({metric}, {value})'

text = re.sub(
    r'TelemetryCollector::instance\(\)->trackPerformance\(\s*([^,]+),\s*([^,]+),\s*[^)]+\s*\)',
    fix_track_performance,
    text
)

# Also fix any inline trackPerformance with 3 args that might have different spacing
# A simpler brute-force: remove the third argument from any trackPerformance call
text = re.sub(
    r'TelemetryCollector::instance\(\)->trackPerformance\(([^,]+),\s*([^,]+),\s*"[^"]*"\s*\)',
    r'TelemetryCollector::instance()->trackPerformance(\1, \2)',
    text
)

with open(path, 'w', encoding='utf-8') as f:
    f.write(text)

print('All replacements written successfully.')
