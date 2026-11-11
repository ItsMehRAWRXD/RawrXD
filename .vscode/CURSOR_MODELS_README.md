# Cursor Settings → Models: Avoid "Invalid model name"

The **"invalid model name"** message in Cursor appears when Cursor's **Settings → Models** list doesn't match what the backend returns from `GET /v1/models`.

## Fix

1. **Start RawrXD completion server** (so it serves `/v1/models`):
   ```text
   RawrXD.exe --http --port 8080
   ```
   Or with a model: `RawrXD.exe --http --port 8080 --model path/to/model.gguf`

2. **In Cursor: Settings → Models**
   - Add a **Custom** / **OpenAI-compatible** model.
   - Set **Base URL** to: `http://localhost:8080/v1`  
     (no trailing slash; Cursor will call `http://localhost:8080/v1/models`).
   - Set **Model** to one of the IDs returned by the server, for example:
     - `rawrxd` — default when no GGUF is loaded
     - `llama3`, `llama2`, `neural-chat` — if you use Ollama
     - `BigDaddyG-Q4_K_M` — local GGUF
     - Or the name of your loaded model (filename without `.gguf`).

3. **Use the same port** in Base URL as in `--port` (default is **8080**).

## What this repo does

- **Completion server** (`src/complete_server.cpp`) now implements:
  - `GET /v1/models` and `GET /api/models`
  - Returns an OpenAI-style list that includes the loaded model plus common IDs (`rawrxd`, `llama3`, `llama2`, `neural-chat`, `BigDaddyG-Q4_K_M`, etc.).
- **`.vscode/settings.json`** includes example Cursor model entries pointing at `http://localhost:8080/v1` and `model` values like `rawrxd` and `llama3`.

If your Cursor version uses different settings keys, copy the **Base URL** and **Model** values above into your Cursor Settings → Models UI.
