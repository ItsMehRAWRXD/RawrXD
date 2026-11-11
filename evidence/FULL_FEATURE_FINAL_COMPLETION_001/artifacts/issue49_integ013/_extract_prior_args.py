import re
p = r"C:\Users\Garrett\.cursor\projects\g-dev\agent-transcripts\4aa15404-044f-497e-b610-6cef7366d9ff\subagents\c6eb7cc8-ddfd-4f2c-881f-168261b48769.jsonl"
with open(p, "r", encoding="utf-8", errors="replace") as f:
    for i, line in enumerate(f, 1):
        if "tip013_loop_exclusive_08_11" in line and "deep2_agentic_loop" in line:
            for m in re.finditer(
                r"(?:--max-wall-time-sec|--prefill-chunk|--max-steps|--max-new|--context-size)\s+\S+",
                line,
            ):
                print(i, m.group(0))
            for m in re.finditer(
                r"(max-wall-time-sec|prefill-chunk|max-steps|AgentWaitSec)[^\d]{0,16}(\d+)",
                line,
            ):
                print(i, m.group(1), m.group(2))
