import httpx
import json
import time
import sys
import os

# Configuration: Use the test port defined in the CI workflow
# In a real setup, we might get this port via command line argument,
# but for the CI context, we hardcode the test port.
SWARM_HOST = "http://localhost:8001"
TIMEOUT = 45 # Max time for agent to finish

def test_endpoint(path, data=None, method='POST'):
    """Utility function to hit an endpoint and return JSON response."""
    url = f"{SWARM_HOST}{path}"
    print(f"\n--- Testing {method} {path} ---")
    try:
        if method == 'POST':
            response = httpx.post(url, json=data, timeout=TIMEOUT)
        elif method == 'GET':
             response = httpx.get(url, timeout=TIMEOUT)
        
        response.raise_for_status()
        
        # Check for JSON content type header
        if 'application/json' in response.headers.get('content-type', ''):
             return response.json()
        else:
             print(f"❌ Response content type is not JSON: {response.headers.get('content-type')}")
             raise ValueError("Non-JSON response received.")

    except httpx.RequestError as e:
        print(f"❌ Request failed: {e}")
        raise
    except httpx.HTTPStatusError as e:
        print(f"❌ HTTP Error {e.response.status_code}: {e.response.text.strip()}")
        raise
    except Exception as e:
        print(f"❌ Unexpected Error: {e}")
        raise


def run_swarm_readiness_test():
    """Verify the swarm actually has bots loaded.

    Without bots the engine falls back to canned answers in run_loop.py, so a
    green /ask or /agent would be a mocked success. This check fails the smoke
    test on an empty swarm instead of certifying it.
    """
    print("Verifying swarm readiness (bots loaded)...")
    result = test_endpoint("/health", method='GET')

    bots = result.get("bots")
    if not isinstance(bots, int) or bots < 1:
        raise AssertionError(
            f"Swarm has no bots loaded (health={result}); a zero-bot engine "
            "answers from canned fallbacks - refusing to treat that as success"
        )

    print(f"✅ Swarm ready with {bots} bot(s) loaded.")


def run_ask_test():
    """Tests the synchronous /ask endpoint."""
    print("Running synchronous Q&A test (/ask)...")
    # Ask the swarm for something the codegen bot actually handles, so the
    # answer comes from a real bot rather than run_loop.py's canned fallback.
    payload = {
        "question": "Write a small ASM parser in C++",
        "code": "class BotState: pass"
    }
    result = test_endpoint("/ask", payload)

    if not result.get("answer"):
        raise AssertionError(f"'/ask' response missing 'answer' field: {result}")

    print(f"✅ /ask succeeded. Answer length: {len(result['answer'])} chars.")
    print(f"  Snippet: {result['answer'][:60]}...")


def run_agent_test():
    """Tests the streaming /agent endpoint for goal satisfaction."""
    print("Running autonomous agent test (/agent)...")
    # A goal the codegen bot can satisfy, so goal.satisfied is emitted by a
    # real bot instead of the canned fallback.
    goal = "Generate a small ASM parser in C++ and satisfy the goal."
    payload = {"goal": goal, "max_time": 30}
    
    url = f"{SWARM_HOST}/agent"
    
    try:
        # Use httpx.stream to consume the Server-Sent Events (SSE) stream
        with httpx.stream("POST", url, json=payload, timeout=TIMEOUT) as r:
            r.raise_for_status()
            
            satisfied = False
            for line in r.iter_lines():
                line = line.strip()
                if line.startswith("data:"):
                    try:
                        msg = json.loads(line[5:].strip())
                        # Check for the terminal condition
                        if msg.get("kind") == "goal.satisfied":
                            print(f"→ Goal satisfied by bot: {msg.get('bot')}")
                            satisfied = True
                            break
                    except json.JSONDecodeError:
                        pass # Ignore malformed lines

            if not satisfied:
                raise AssertionError("Agent finished stream without emitting 'goal.satisfied'.")

    except Exception as e:
        print(f"❌ Agent test failed: {e}")
        raise

    print("✅ /agent succeeded and emitted 'goal.satisfied' autonomously.")


if __name__ == "__main__":
    try:
        print("Starting HexMag Smoke Tests...")

        run_swarm_readiness_test()
        run_ask_test()
        run_agent_test()

        print("\n=== ALL HEXMAG SMOKE TESTS PASSED ===\n")
        sys.exit(0)

    except (AssertionError, ValueError, httpx.RequestError, httpx.HTTPStatusError) as e:
        print(f"\n=== HEXMAG SMOKE TESTS FAILED ===\nDetails: {e}")
        sys.exit(1)

if __name__ == "__main__":
    sys.exit(main())
