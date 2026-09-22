import re, sys

path = r'f:\~dev\rawrxd\src\core\auto_feature_registry.cpp'
with open(path, 'r', encoding='utf-8') as f:
    text = f.read()

def replace_block(old, new):
    if old in text:
        text_out = text.replace(old, new, 1)
        if text_out is not text:
            print(f'Replaced block ({len(old)} chars)')
            return text_out
    print(f'BLOCK NOT FOUND ({len(old)} chars)')
    return text

# Block 1: handleAgentExecuteCmd
text = replace_block(
'''        InvocationParams params;
        params.wish = ctx.args;
        params.maxTokens = 4096;
        params.timeoutMs = 60000;
        ctx.output("[Agent] Dispatching to model invoker...\\n");
        getModelInvoker().invokeAsync(params);''',
'''        std::string wish = ctx.args;
        ctx.output("[Agent] Dispatching to model invoker...\\n");
        getModelInvoker().invokeAsync(wish);''')

# Block 2: handleAiExplainCode
text = replace_block(
'''        InvocationParams params;
        params.wish = std::string("Explain this code in detail, including its purpose, algorithm, and any subtleties:\\n") + ctx.args;
        params.maxTokens = g_aiContextTokens.load();
        params.timeoutMs = 30000;
        getModelInvoker().invokeAsync(params);''',
'''        std::string wish = std::string("Explain this code in detail, including its purpose, algorithm, and any subtleties:\\n") + ctx.args;
        getModelInvoker().invokeAsync(wish);''')

# Block 3: handleAiFixErrors
text = replace_block(
'''    InvocationParams params;
    params.wish = "Analyze the following code for errors and generate fixes. If a specific target is given, focus on that:\\n";
    if (ctx.args && ctx.args[0]) params.wish += ctx.args;
    else params.wish += "(scan current file for all errors)";
    params.maxTokens = g_aiContextTokens.load();
    params.timeoutMs = 30000;
    ctx.output("[AI] Scanning for errors and generating fixes...\\n");
    getModelInvoker().invokeAsync(params);''',
'''    std::string wish = "Analyze the following code for errors and generate fixes. If a specific target is given, focus on that:\\n";
    if (ctx.args && ctx.args[0]) wish += ctx.args;
    else wish += "(scan current file for all errors)";
    ctx.output("[AI] Scanning for errors and generating fixes...\\n");
    getModelInvoker().invokeAsync(wish);''')

# Block 4: handleAiGenerateDocs
text = replace_block(
'''    InvocationParams params;
    params.wish = "Generate comprehensive documentation (Doxygen-style for C++, docstrings for Python) for:\\n";
    if (ctx.args && ctx.args[0]) params.wish += ctx.args;
    else params.wish += "(current file/selection)";
    params.maxTokens = g_aiContextTokens.load();
    params.timeoutMs = 30000;
    ctx.output("[AI] Generating documentation...\\n");
    getModelInvoker().invokeAsync(params);''',
'''    std::string wish = "Generate comprehensive documentation (Doxygen-style for C++, docstrings for Python) for:\\n";
    if (ctx.args && ctx.args[0]) wish += ctx.args;
    else wish += "(current file/selection)";
    ctx.output("[AI] Generating documentation...\\n");
    getModelInvoker().invokeAsync(wish);''')

# Block 5: handleAiGenerateTests
text = replace_block(
'''    InvocationParams params;
    params.wish = "Generate comprehensive unit tests (using the project's test framework) for:\\n";
    if (ctx.args && ctx.args[0]) params.wish += ctx.args;
    else params.wish += "(current file/function)";
    params.maxTokens = g_aiContextTokens.load();
    params.timeoutMs = 30000;
    ctx.output("[AI] Generating tests...\\n");
    getModelInvoker().invokeAsync(params);''',
'''    std::string wish = "Generate comprehensive unit tests (using the project's test framework) for:\\n";
    if (ctx.args && ctx.args[0]) wish += ctx.args;
    else wish += "(current file/function)";
    ctx.output("[AI] Generating tests...\\n");
    getModelInvoker().invokeAsync(wish);''')

# Block 6: handleAiInlineComplete
text = replace_block(
'''    InvocationParams params;
    params.wish = "Provide inline code completion at cursor position for the current context.";
    params.maxTokens = 256; // FIM completions are short
    params.timeoutMs = 5000; // Fast turnaround needed
    ctx.output("[AI] Inline completion activated — dispatching to FIM model...\\n");
    getModelInvoker().invokeAsync(params);''',
'''    std::string wish = "Provide inline code completion at cursor position for the current context.";
    ctx.output("[AI] Inline completion activated — dispatching to FIM model...\\n");
    getModelInvoker().invokeAsync(wish);''')

# Block 7: handleAiOptimizeCode
text = replace_block(
'''    InvocationParams params;
    params.wish = "Analyze and optimize the following code for performance. Focus on: algorithmic complexity, "
                  "cache-friendly access patterns, SIMD opportunities, and memory allocation reduction.\\n";
    if (ctx.args && ctx.args[0]) params.wish += ctx.args;
    else params.wish += "(current selection/file)";
    params.maxTokens = g_aiContextTokens.load();
    params.timeoutMs = 30000;
    ctx.output("[AI] Optimization analysis in progress...\\n");
    getModelInvoker().invokeAsync(params);''',
'''    std::string wish = "Analyze and optimize the following code for performance. Focus on: algorithmic complexity, "
                  "cache-friendly access patterns, SIMD opportunities, and memory allocation reduction.\\n";
    if (ctx.args && ctx.args[0]) wish += ctx.args;
    else wish += "(current selection/file)";
    ctx.output("[AI] Optimization analysis in progress...\\n");
    getModelInvoker().invokeAsync(wish);''')

# Block 8: handleAiRefactor
text = replace_block(
'''    InvocationParams params;
    params.wish = "Refactor the following code while preserving behavior. Apply: extract methods, "
                  "reduce complexity, improve naming, eliminate duplication, apply SOLID principles.\\n";
    if (ctx.args && ctx.args[0]) params.wish += ctx.args;
    else params.wish += "(current selection/file)";
    params.maxTokens = g_aiContextTokens.load();
    params.timeoutMs = 30000;
    ctx.output("[AI] Refactoring in progress...\\n");
    getModelInvoker().invokeAsync(params);''',
'''    std::string wish = "Refactor the following code while preserving behavior. Apply: extract methods, "
                  "reduce complexity, improve naming, eliminate duplication, apply SOLID principles.\\n";
    if (ctx.args && ctx.args[0]) wish += ctx.args;
    else wish += "(current selection/file)";
    ctx.output("[AI] Refactoring in progress...\\n");
    getModelInvoker().invokeAsync(wish);''')

# Fix 3-arg setLLMBackend
text = replace_block(
'''            getModelInvoker().setLLMBackend(
                best->filename, "local://gguf", "");''',
'''            getModelInvoker().setLLMBackend(
                best->filename, "local://gguf");''')

text = replace_block(
'''    getModelInvoker().setLLMBackend(
        s_bfActiveModelPath, "local://gguf", "");''',
'''    getModelInvoker().setLLMBackend(
        s_bfActiveModelPath, "local://gguf");''')

# Fix OllamaConfig.num_ctx -> contextLength
text = replace_block('cfg.num_ctx = tokens;', 'cfg.contextLength = tokens;')

with open(path, 'w', encoding='utf-8') as f:
    f.write(text)

print('Script complete')
