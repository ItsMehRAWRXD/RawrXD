#!/usr/bin/env python3
"""
RawrXD OpenAI Compatibility Layer

This example shows how RawrXD can be used as a drop-in replacement
for OpenAI's API, requiring only a base URL change.

Usage:
    python integration_openai.py
    
Environment Variables:
    RAWRXD_URL - RawrXD server URL (default: http://localhost:8080)
"""

import os
from openai import OpenAI

# Configure client to use RawrXD instead of OpenAI
client = OpenAI(
    base_url=os.getenv("RAWRXD_URL", "http://localhost:8080"),
    api_key="not-needed"  # RawrXD doesn't require API key by default
)

def chat_completion_example():
    """Example: Chat completion with RawrXD."""
    print("=== Chat Completion Example ===\n")
    
    response = client.chat.completions.create(
        model="llama-2-7b-chat",  # Use your RawrXD model name
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What is the capital of France?"}
        ],
        temperature=0.7,
        max_tokens=100
    )
    
    print(f"Response: {response.choices[0].message.content}")
    print(f"Tokens used: {response.usage.total_tokens}")


def streaming_example():
    """Example: Streaming chat completion."""
    print("\n=== Streaming Example ===\n")
    
    stream = client.chat.completions.create(
        model="llama-2-7b-chat",
        messages=[
            {"role": "user", "content": "Count from 1 to 5"}
        ],
        stream=True
    )
    
    print("Response: ", end="", flush=True)
    for chunk in stream:
        if chunk.choices[0].delta.content:
            print(chunk.choices[0].delta.content, end="", flush=True)
    print()


def embeddings_example():
    """Example: Generate embeddings."""
    print("\n=== Embeddings Example ===\n")
    
    response = client.embeddings.create(
        model="llama-2-7b",
        input="The quick brown fox jumps over the lazy dog"
    )
    
    embedding = response.data[0].embedding
    print(f"Embedding dimension: {len(embedding)}")
    print(f"First 5 values: {embedding[:5]}")


def list_models_example():
    """Example: List available models."""
    print("\n=== List Models Example ===\n")
    
    models = client.models.list()
    print("Available models:")
    for model in models.data:
        print(f"  - {model.id}")


def function_calling_example():
    """Example: Function calling (if supported by model)."""
    print("\n=== Function Calling Example ===\n")
    
    # Note: Function calling requires a model fine-tuned for it
    # This is a demonstration of the API compatibility
    
    tools = [
        {
            "type": "function",
            "function": {
                "name": "get_weather",
                "description": "Get the current weather",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "location": {
                            "type": "string",
                            "description": "The city and state"
                        }
                    },
                    "required": ["location"]
                }
            }
        }
    ]
    
    try:
        response = client.chat.completions.create(
            model="llama-2-7b-chat",
            messages=[
                {"role": "user", "content": "What's the weather in Paris?"}
            ],
            tools=tools,
            tool_choice="auto"
        )
        
        print(f"Response: {response.choices[0].message}")
    except Exception as e:
        print(f"Note: Function calling may not be supported by this model")
        print(f"Error: {e}")


def completion_example():
    """Example: Text completion (legacy API)."""
    print("\n=== Text Completion Example ===\n")
    
    response = client.completions.create(
        model="llama-2-7b",
        prompt="The capital of France is",
        max_tokens=50
    )
    
    print(f"Completion: {response.choices[0].text}")


def main():
    """Run all examples."""
    print("RawrXD OpenAI Compatibility Demo")
    print("=" * 50)
    print(f"Server: {os.getenv('RAWRXD_URL', 'http://localhost:8080')}")
    print("=" * 50)
    
    try:
        list_models_example()
        chat_completion_example()
        streaming_example()
        embeddings_example()
        completion_example()
        function_calling_example()
        
        print("\n" + "=" * 50)
        print("All examples completed successfully!")
        print("=" * 50)
        
    except Exception as e:
        print(f"\nError: {e}")
        print("\nMake sure RawrXD server is running:")
        print("  rawrxd serve --model /path/to/model.gguf")


if __name__ == "__main__":
    main()
