# Chain of Thought (CoT) Multi-Mode System
## RawrXD CLI v4.0 — 12 Reasoning Modes

---

## Overview

The CoT Multi-Mode System provides **12 specialized reasoning modes** that can be chained together for comprehensive AI-powered analysis. Each mode represents a distinct cognitive approach, from deep analytical thinking to creative brainstorming.

---

## The 12 Reasoning Modes

| # | Mode | Emoji | Description | Best For |
|---|------|-------|-------------|----------|
| 1 | **Thinker** | 💭 | Deep analytical thinking and step-by-step reasoning | Complex problem solving |
| 2 | **Auditor** | 🔍 | Code/logic audit for bugs, security, best practices | Code review, security analysis |
| 3 | **Reviewer** | 👁️ | Peer review style analysis with constructive feedback | Content review, feedback |
| 4 | **Researcher** | 📚 | Research and fact-finding, exploring alternatives | Investigation, learning |
| 5 | **ArgueFor** | ✅ | Devil's advocate — argue strongly FOR a position | Pros analysis, advocacy |
| 6 | **ArgueAgainst** | ❌ | Devil's advocate — argue strongly AGAINST a position | Cons analysis, critique |
| 7 | **Critic** | ⚠️ | Critical analysis — find flaws, weaknesses, edge cases | Risk assessment, QA |
| 8 | **Synthesizer** | ✨ | Combine multiple perspectives into coherent whole | Decision making, summary |
| 9 | **Brainstorm** | 💡 | Generate creative ideas and explore possibilities | Ideation, creativity |
| 10 | **Verifier** | ✓ | Verify correctness, validate assumptions, check facts | Fact checking, validation |
| 11 | **Refiner** | 🔧 | Refine and polish — improve clarity and precision | Editing, polishing |
| 12 | **Summarizer** | 📝 | Summarize concisely — extract key points | TL;DR, executive summary |

---

## CLI Commands

### Primary CoT Command

```
/cot <query>                    # Run default 8-step chain
/cot --modes <modes> <query>    # Run with specific modes
/cot --single <mode> <query>    # Run single mode
/cot --chain <type> <query>     # Run predefined chain
/cot --list                     # List all 12 modes
/cot --status                   # Show CoT engine status
/cot --last                     # Show last result
/cot --export <file>            # Export last result to JSON
```

### Individual Mode Shortcuts

```
/thinker <query>       # Deep analysis
/auditor <code>        # Code audit
/reviewer <content>    # Peer review
/researcher <topic>    # Research mode
/arguefor <position>   # Argue for
/argueagainst <position> # Argue against
/critic <content>      # Critical analysis
/synthesizer <perspectives> # Synthesize
/brainstorm <topic>    # Generate ideas
/verifier <claim>      # Verify correctness
/refiner <content>     # Polish content
/summarizer <content>  # Summarize
```

---

## Usage Examples

### Example 1: Default Chain (8 steps)

```
cli> /cot "How do I optimize this function?"

🧠 Chain of Thought (8 steps) — Complete in 127917ms
1💡 Brainstorm llama3.2:3b 18772ms
   Generate ideas for optimization...

2💭 Thinker llama3.2:3b 7647ms
   Analyze the algorithmic complexity...

3📚 Researcher llama3.2:3b 11379ms
   Research common optimization patterns...

4✅ ArgueFor llama3.2:3b 12310ms
   Arguments for memoization approach...

5❌ ArgueAgainst llama3.2:3b 11370ms
   Arguments against premature optimization...

6⚠️ Critic llama3.2:3b 18854ms
   Edge cases and potential issues...

7✓ Verifier llama3.2:3b 15413ms
   Verify the proposed solution...

8✨ Synthesizer llama3.2:3b 32136ms
   Final synthesized recommendation...

✅ Final Answer (127917ms total, 8 steps)
Based on the analysis, here are the optimization recommendations...
```

### Example 2: Custom Mode Chain

```
cli> /cot --modes thinker,critic,synthesizer "Is this design good?"

🧠 Chain of Thought (3 steps) — Complete in 45231ms
1💭 Thinker llama3.2:3b 15423ms
   Analyzing the design patterns used...

2⚠️ Critic llama3.2:3b 18234ms
   Identifying potential weaknesses...

3✨ Synthesizer llama3.2:3b 11574ms
   Combining insights into final assessment...

✅ Final Answer (45231ms total, 3 steps)
The design has several strengths but also some areas...
```

### Example 3: Code Review Chain

```
cli> /cot --chain code "int factorial(int n) { return n <= 1 ? 1 : n * factorial(n-1); }"

🧠 Chain of Thought (5 steps) — Complete in 89342ms
1🔍 Auditor llama3.2:3b 22341ms
   Checking for stack overflow risk...

2👁️ Reviewer llama3.2:3b 18765ms
   Peer review feedback...

3⚠️ Critic llama3.2:3b 24532ms
   Edge cases: negative inputs...

4✓ Verifier llama3.2:3b 12345ms
   Verifying correctness...

5🔧 Refiner llama3.2:3b 11359ms
   Polished version with error handling...

✅ Final Answer (89342ms total, 5 steps)
The recursive factorial implementation is correct but...
```

### Example 4: Single Mode

```
cli> /cot --single brainstorm "Ideas for a new feature"

🧠 Chain of Thought (1 steps) — Complete in 8934ms
1💡 Brainstorm llama3.2:3b 8934ms
   1. AI-powered code completion...
   2. Real-time collaboration...
   3. Integrated debugging...

✅ Final Answer (8934ms total, 1 steps)
Here are 10 creative ideas for your new feature...
```

---

## Predefined Chains

### Default Chain (8 steps)
```
Brainstorm → Thinker → Researcher → ArgueFor → ArgueAgainst → Critic → Verifier → Synthesizer
```
Best for: General analysis and decision making

### Code Chain (5 steps)
```
Auditor → Reviewer → Critic → Verifier → Refiner
```
Best for: Code review and optimization

### Decision Chain (6 steps)
```
Researcher → Brainstorm → ArgueFor → ArgueAgainst → Critic → Synthesizer
```
Best for: Making complex decisions

### Creative Chain (5 steps)
```
Brainstorm → Thinker → Researcher → Refiner → Synthesizer
```
Best for: Creative projects and content creation

---

## Configuration

### Set Model
```
/cot --model llama3.2:3b
/cot --model codellama:latest
/cot --model qwen2.5-coder:latest
```

### Set Endpoint
```
/cot --endpoint http://localhost:11434
/cot --endpoint http://192.168.1.100:11434
```

---

## Export Results

```
/cot "Analyze this code"
/cot --export analysis_result.json
```

Exported JSON structure:
```json
{
  "query": "Analyze this code",
  "success": true,
  "steps": [
    {
      "mode": "Brainstorm",
      "emoji": "💡",
      "thought": "...",
      "confidence": 0.85,
      "durationMs": 18772
    }
  ],
  "finalAnswer": "...",
  "overallConfidence": 0.82,
  "totalDurationMs": 127917
}
```

---

## Integration with GUI

The CoT system is designed to be monolithic — the same backend powers both CLI and GUI:

```cpp
// CLI usage
CoT::MultiModeCoTEngine engine;
auto result = engine.ExecuteFullChain("query");

// GUI usage (same engine)
CoT::MultiModeCoTEngine engine;
auto result = engine.ExecuteFullChain("query");
// Render result.steps in UI with progress indicators
```

---

## Architecture

```
┌─────────────────────────────────────────┐
│           CLI / GUI Layer               │
│  ┌─────────────────────────────────┐    │
│  │  /cot command handlers          │    │
│  │  - Mode parsing                 │    │
│  │  - Chain execution              │    │
│  │  - Result formatting            │    │
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│      CoT Multi-Mode Engine              │
│  ┌─────────────────────────────────┐    │
│  │  12 Mode Configurations         │    │
│  │  - System prompts               │    │
│  │  - Temperature settings         │    │
│  │  - Confidence thresholds        │    │
│  └─────────────────────────────────┘    │
│  ┌─────────────────────────────────┐    │
│  │  Chain Execution Engine         │    │
│  │  - Sequential mode execution  │    │
│  │  - Context passing              │    │
│  │  - Progress tracking            │    │
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│         Model Interface (Ollama)          │
│  ┌─────────────────────────────────┐    │
│  │  HTTP API calls                 │    │
│  │  - /api/generate                │    │
│  │  - Streaming support            │    │
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘
```

---

## Testing

Run the comprehensive test suite:

```bash
build_cot.bat
```

Tests cover:
- Mode enumeration (12 modes)
- Engine initialization
- Mode info retrieval
- CLI helper functions
- Result structure
- Prompt builders
- Confidence evaluation
- Integration tests
- Formatting

---

## Performance

Typical execution times (with llama3.2:3b on RTX 4090):

| Chain Type | Steps | Typical Duration |
|------------|-------|------------------|
| Single mode | 1 | 5-15s |
| Code review | 5 | 60-90s |
| Default chain | 8 | 90-180s |
| Full analysis | 12 | 120-300s |

---

## Future Enhancements

1. **Parallel Mode Execution** — Run independent modes concurrently
2. **Adaptive Chains** — Dynamically adjust chain based on intermediate results
3. **Mode-specific Models** — Use different models for different modes
4. **Caching** — Cache mode results for similar queries
5. **Streaming** — Stream results as each mode completes

---

## License

Part of RawrXD IDE v4.0 — Integrated into the monolithic 152+ feature system.
