#!/usr/bin/env python3
"""
Basic Inference Example for RawrXD

This example demonstrates how to use the RawrXD API for basic text generation.

Requirements:
    pip install requests

Usage:
    python basic_inference.py
"""

import requests
import json

# Configuration
API_BASE = "http://localhost:8080/v1"
MODEL = "llama-2-7b"

def chat_completion(messages, temperature=0.7, max_tokens=256):
    """
    Send a chat completion request to RawrXD.
    
    Args:
        messages: List of message dictionaries with 'role' and 'content'
        temperature: Sampling temperature (0.0-2.0)
        max_tokens: Maximum tokens to generate
    
    Returns:
        Generated text response
    """
    response = requests.post(
        f"{API_BASE}/chat/completions",
        json={
            "model": MODEL,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }
    )
    
    if response.status_code == 200:
        data = response.json()
        return data["choices"][0]["message"]["content"]
    else:
        raise Exception(f"API Error: {response.status_code} - {response.text}")

def text_completion(prompt, temperature=0.7, max_tokens=256):
    """
    Send a text completion request to RawrXD.
    
    Args:
        prompt: Input text prompt
        temperature: Sampling temperature
        max_tokens: Maximum tokens to generate
    
    Returns:
        Generated text
    """
    response = requests.post(
        f"{API_BASE}/completions",
        json={
            "model": MODEL,
            "prompt": prompt,
            "temperature": temperature,
            "max_tokens": max_tokens
        }
    )
    
    if response.status_code == 200:
        data = response.json()
        return data["choices"][0]["text"]
    else:
        raise Exception(f"API Error: {response.status_code} - {response.text}")

def main():
    print("RawrXD Basic Inference Example")
    print("=" * 50)
    
    # Example 1: Simple chat
    print("\n1. Simple Chat:")
    messages = [
        {"role": "user", "content": "What is the capital of France?"}
    ]
    response = chat_completion(messages)
    print(f"User: What is the capital of France?")
    print(f"Assistant: {response}")
    
    # Example 2: Multi-turn conversation
    print("\n2. Multi-turn Conversation:")
    messages = [
        {"role": "system", "content": "You are a helpful coding assistant."},
        {"role": "user", "content": "Write a Python function to calculate factorial."}
    ]
    response = chat_completion(messages, temperature=0.3)
    print(f"User: Write a Python function to calculate factorial.")
    print(f"Assistant: {response}")
    
    # Example 3: Text completion
    print("\n3. Text Completion:")
    prompt = "The quick brown fox"
    response = text_completion(prompt, max_tokens=50)
    print(f"Prompt: {prompt}")
    print(f"Completion: {response}")
    
    # Example 4: Creative writing
    print("\n4. Creative Writing (higher temperature):")
    messages = [
        {"role": "user", "content": "Write a haiku about programming"}
    ]
    response = chat_completion(messages, temperature=0.9)
    print(f"User: Write a haiku about programming")
    print(f"Assistant: {response}")

if __name__ == "__main__":
    main()
