#!/usr/bin/env python3
"""
Streaming Chat Example for RawrXD

This example demonstrates how to use streaming responses
from the RawrXD API in Python.

Requirements:
    pip install requests

Usage:
    python streaming_chat.py
"""

import requests
import json
import sys

# Configuration
API_BASE = "http://localhost:8080/v1"
MODEL = "llama-2-7b"


def stream_chat_completion(messages, temperature=0.7):
    """
    Stream chat completion responses from RawrXD.
    
    Args:
        messages: List of message dictionaries
        temperature: Sampling temperature
    
    Yields:
        Text chunks as they arrive
    """
    response = requests.post(
        f"{API_BASE}/chat/completions",
        json={
            "model": MODEL,
            "messages": messages,
            "temperature": temperature,
            "stream": True
        },
        stream=True
    )
    
    if response.status_code != 200:
        raise Exception(f"API Error: {response.status_code}")
    
    for line in response.iter_lines():
        if line:
            line = line.decode('utf-8')
            if line.startswith('data: '):
                data = line[6:]
                if data == '[DONE]':
                    return
                
                try:
                    parsed = json.loads(data)
                    content = parsed.get('choices', [{}])[0].get('delta', {}).get('content', '')
                    if content:
                        yield content
                except json.JSONDecodeError:
                    pass


def main():
    print("RawrXD Streaming Chat Example")
    print("=" * 50)
    
    # Example 1: Simple streaming
    print("\n1. Simple Streaming Chat:")
    messages = [{"role": "user", "content": "Count from 1 to 5"}]
    
    print("User: Count from 1 to 5")
    print("Assistant: ", end='', flush=True)
    
    for chunk in stream_chat_completion(messages):
        print(chunk, end='', flush=True)
    print("\n")
    
    # Example 2: Story generation
    print("\n2. Story Generation:")
    messages = [{"role": "user", "content": "Write a one-sentence story about AI."}]
    
    print("User: Write a one-sentence story about AI.")
    print("Assistant: ", end='', flush=True)
    
    for chunk in stream_chat_completion(messages):
        print(chunk, end='', flush=True)
    print("\n")
    
    # Example 3: Interactive chat
    print("\n3. Interactive Chat (type 'quit' to exit):")
    conversation = []
    
    while True:
        user_input = input("\nYou: ").strip()
        if user_input.lower() == 'quit':
            break
        
        conversation.append({"role": "user", "content": user_input})
        
        print("Assistant: ", end='', flush=True)
        response_text = ""
        
        for chunk in stream_chat_completion(conversation):
            print(chunk, end='', flush=True)
            response_text += chunk
        
        print()  # New line after response
        conversation.append({"role": "assistant", "content": response_text})


if __name__ == "__main__":
    main()
