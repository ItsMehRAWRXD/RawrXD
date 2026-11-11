# Hello Runtime Example

A minimal example demonstrating basic RawrXD usage.

## Building

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

## Running

```bash
./hello_runtime /path/to/model.gguf "Your prompt here"
```

## Expected Output

```
=== RawrXD Hello Runtime Example ===
Initializing RawrXD...
RawrXD initialized successfully!
Version: 1.0.0-rc1
Build: abc123

Loading model: models/llama-7b.gguf
Model loaded successfully!

Prompt: Explain quantum computing in simple terms:

Generating response...
----------------------------------------
Quantum computing is a type of computation that harnesses...
----------------------------------------

Statistics:
  Tokens generated: 128
  Tokens/second: 547.3
  Duration: 234ms
  Truncated: No

Shutting down...
Done!
```
