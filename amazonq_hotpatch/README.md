# Amazon Q VS Code local-model hotpatch

This patch routes Amazon Q chat generation to a local OpenAI-compatible endpoint while preserving the existing Amazon Q webview/chat UI.

It is intended for a local source build/fork of:
`aws/aws-toolkit-vscode`

## Files

Copy these into the upstream source tree:

- `localModelChatClient.ts` ->
  `packages/core/src/shared/clients/localModelChatClient.ts`
- `qDeveloperChatClient.ts` ->
  `packages/core/src/shared/clients/qDeveloperChatClient.ts`
- `codewhispererChatClient.ts` ->
  `packages/core/src/shared/clients/codewhispererChatClient.ts`

The latter two are replacement files based on upstream commit:
`36ad9035f4b921e12a9135f07a5f5134b71f704b`

## Environment

PowerShell example:

```powershell
$env:RAWRXD_Q_LOCAL="1"
$env:RAWRXD_Q_LOCAL_URL="http://127.0.0.1:11435/v1/chat/completions"
$env:RAWRXD_Q_LOCAL_MODEL="qwen3.5-40b"
$env:RAWRXD_Q_LOCAL_API_KEY="local"
$env:RAWRXD_Q_LOCAL_MAX_TOKENS="2048"
$env:RAWRXD_Q_LOCAL_TEMP="0.2"

code
```

The endpoint should accept an OpenAI-style request:

```json
{
  "model": "...",
  "messages": [{"role":"user","content":"..."}],
  "stream": false
}
```

and return assistant content in one of:

- `choices[0].message.content` (OpenAI-compatible)
- `message.content` (Ollama-like)
- `response`
- `content`
- raw text

## What it preserves

- Amazon Q chat panel / rendering
- current-message text
- prior conversation messages
- active editor text
- relevant document context
- both IAM and SSO client selection paths

## What this first hotpatch does NOT yet emulate

- Amazon Q cloud model selection
- Q citations/web references
- Q-native tool-use event mapping
- streaming token-by-token SSE rendering
- inline autocomplete (separate CodeWhisperer completion path)

Those can be patched separately once basic local chat is verified.

## Important

Do not redirect `q.us-east-1.amazonaws.com` or install a fake TLS certificate. The source-level client substitution is much cleaner and avoids impersonating AWS network services.
