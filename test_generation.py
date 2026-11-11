#!/usr/bin/env python3
"""Test generation with the fixed bridge."""

import sys
sys.path.insert(0, r"F:\rawrxd")

from backend.rawrxd_agent_bridge import generate_with_llama, run_agent_sync

# Test 1: Simple generation
print("=== Test 1: Simple generation ===")
prompt = "Hello, how are you?"
result = generate_with_llama(prompt, max_tokens=50)
print(f"Prompt: {prompt}")
print(f"Generated: {result}")

# Test 2: Agent loop test
print("\n=== Test 2: Agent loop ===")
prompt = "Read test_hello.py and tell me its contents"
result = run_agent_sync(prompt)
print(result)

# Test 3: Another generation test
print("\n=== Test 3: Code generation ===")
prompt = "Write a Python function to calculate fibonacci numbers"
result = generate_with_llama(prompt, max_tokens=100)
print(f"Prompt: {prompt}")
print(f"Generated: {result}")