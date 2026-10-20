# Ollama local route smoke receipt

- Endpoint: http://127.0.0.1:11434/api/generate
- Model: qwen2.5-coder:1.5b-base
- Exit code: 0
- Model catalog count: 41
- Response:  I am a chatbot that can help
- Eval tokens: 8
- Done reason: length

This proves the local Ollama HTTP route is reachable and returns a non-empty
generation through the committed route configuration. It does not certify RawrXD
native ROM execution or large-model correctness. The Nemotron 4B route probe in
`ollama_route_nemotron4b_20261020T142342` returned done=true but an empty
response, so model-specific response behavior remains observable.
