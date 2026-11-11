# RawrXD N-EVM Golden Output Samples

This directory contains sample golden output files for deterministic validation testing.

## Directory Structure

```
golden_samples/
├── simple_prompt/          # Basic "Hello world" prompt
│   ├── prompt.bin          # Input prompt (binary)
│   ├── tokens.bin          # Expected output tokens (int32 array)
│   ├── tokens.txt          # Human-readable token IDs
│   ├── metadata.json       # Generation parameters and hashes
│   └── README.txt          # Description
└── README.md               # This file
```

## Usage

### Validate Against Golden Output

```bash
nevm_validate.exe model.gguf --golden=golden_samples/simple_prompt --math=bitexact
```

### Generate New Golden Output

```bash
nevm_generate_golden.exe model.gguf --prompt="Your prompt here" --output=new_golden --math=bitexact
```

## File Formats

### prompt.bin
- Raw UTF-8 bytes of the input prompt
- Used to ensure exact input reproduction

### tokens.bin
- Array of int32 token IDs (little-endian)
- Expected output for deterministic validation

### tokens.txt
- Space-separated token IDs (human-readable)
- 10 tokens per line for readability

### metadata.json
- Generation parameters
- Hashes for integrity verification
- Timestamps and descriptions

## Creating New Samples

1. Generate with the tool:
   ```bash
   nevm_generate_golden.exe model.gguf -p "Your prompt" -o golden_samples/custom_prompt -m bitexact
   ```

2. Verify the output:
   ```bash
   nevm_validate.exe model.gguf --golden=golden_samples/custom_prompt --math=bitexact
   ```

3. Add to CI:
   - Copy to CI test data
   - Reference in test scripts

## CI Integration

Golden output tests should run in NIGHTLY mode:

```yaml
# .github/workflows/nightly.yml
- name: Golden Output Tests
  run: |
    nevm_validate.exe model.gguf --golden=golden_samples/simple_prompt --math=bitexact
    nevm_validate.exe model.gguf --golden=golden_samples/complex_prompt --math=bitexact
```

## Notes

- Always use `BitExact` math mode for golden output generation
- Use temperature=0.0 for deterministic results
- Document the model version used for generation
- Update golden outputs when model changes
