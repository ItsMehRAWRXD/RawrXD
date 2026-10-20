# Ollama local route smoke receipt

- Endpoint: http://127.0.0.1:11434/api/generate
- Model: nemotron-3-nano:4b
- Exit code: 0
- Model catalog count: 41
- Response: empty string
- Done: true
- Eval tokens: 8
- Eval duration: 52.166 ms

The local route completed generation and exposed the model catalog, but this
bounded probe returned an empty response body despite eval tokens. It is a
route reachability result, not a successful response-quality certification.
