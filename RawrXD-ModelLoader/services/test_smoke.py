import httpx
import json
import sys
import io

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

SWARM_HOST = "http://localhost:8001"
TIMEOUT = 45


def test_endpoint(path, data=None, method="POST"):
    url = f"{SWARM_HOST}{path}"
    print(f"\n--- Testing {method} {path} ---")
    try:
        if method == "POST":
            response = httpx.post(url, json=data, timeout=TIMEOUT)
        elif method == "GET":
            response = httpx.get(url, timeout=TIMEOUT)
        else:
            raise ValueError(f"Unsupported method: {method}")

        response.raise_for_status()

        if "application/json" in response.headers.get("content-type", ""):
            return response.json()

        print(f"[FAIL] Response content type is not JSON: {response.headers.get('content-type')}")
        raise ValueError("Non-JSON response received.")

    except httpx.RequestError as e:
        print(f"[FAIL] Request failed: {e}")
        raise
    except httpx.HTTPStatusError as e:
        print(f"[FAIL] HTTP Error {e.response.status_code}: {e.response.text.strip()}")
        raise
    except Exception as e:
        print(f"[FAIL] Unexpected Error: {e}")
        raise


def run_ask_test():
    print("Running synchronous Q&A test (/ask)...")
    payload = {
        "question": "What is the key benefit of the HexMag architecture?",
        "code": "class BotState: pass",
    }
    result = test_endpoint("/ask", payload)

    if not result.get("answer"):
        raise AssertionError(f"'/ask' response missing 'answer' field: {result}")

    print(f"[PASS] /ask succeeded. Answer length: {len(result['answer'])} chars.")
    print(f"  Snippet: {result['answer'][:60]}...")


def run_agent_test():
    """Architect → Codegen → Verification handoff chain must emit goal.satisfied."""
    print("Running autonomous agent test (/agent)...")
    goal = "Fix the compile error in this project and verify the program runs."
    payload = {"goal": goal, "max_time": 30}
    url = f"{SWARM_HOST}/agent"

    try:
        with httpx.stream("POST", url, json=payload, timeout=TIMEOUT) as r:
            r.raise_for_status()

            satisfied = False
            saw_handoff = False
            roles = []
            for line in r.iter_lines():
                line = line.strip()
                if not line.startswith("data:"):
                    continue
                try:
                    msg = json.loads(line[5:].strip())
                except json.JSONDecodeError:
                    continue

                kind = msg.get("kind")
                print(f"  SSE {kind} bot={msg.get('bot')} target={msg.get('target_role')}")
                if kind == "handoff":
                    saw_handoff = True
                    if msg.get("target_role"):
                        roles.append(msg["target_role"])
                if kind == "role.requested" and msg.get("target_role"):
                    roles.append(msg["target_role"])
                if kind == "goal.satisfied":
                    print(f"-> Goal satisfied by bot: {msg.get('bot')}")
                    satisfied = True
                    break
                if kind in ("error", "failed") and msg.get("detail"):
                    detail = str(msg.get("detail")).lower()
                    if "timeout" in detail or "idle" in detail:
                        raise AssertionError(f"Agent failed: {msg}")

            if not satisfied:
                raise AssertionError("Agent finished stream without emitting 'goal.satisfied'.")
            if not saw_handoff:
                raise AssertionError(
                    "Agent satisfied without any handoff (expected Architect→Codegen→Verify)."
                )

    except AssertionError:
        raise
    except Exception as e:
        print(f"[FAIL] Agent test failed: {e}")
        raise

    print(f"[PASS] /agent handoff chain OK roles={roles}")


if __name__ == "__main__":
    try:
        print("Starting HexMag Smoke Tests...")
        run_ask_test()
        run_agent_test()
        print("\n=== ALL HEXMAG SMOKE TESTS PASSED ===\n")
        sys.exit(0)
    except (AssertionError, ValueError, httpx.RequestError, httpx.HTTPStatusError) as e:
        print(f"\n=== HEXMAG SMOKE TESTS FAILED ===\nDetails: {e}")
        sys.exit(1)
