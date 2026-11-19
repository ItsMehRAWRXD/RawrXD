# Nemotron 3.5 Lightning MTP recovery

## Immutable identities

- Ollama model: `nemotron-3.5-lightning:30b`
- Ollama model ID: `e7a64ff15fb1`
- Ollama Modelfile blob: `F:\\OllamaModels\\blobs\\sha256-5c19f6282f4fc51cb114cb6c876d70ca2fc3b9cf0fbd0a018d9908f4fe1f63b3`
- GGUF artifact: `F:\\OllamaModels\\gguf\\nemotron-3.5-lightning-30b-Q4_K_M.gguf`
- GGUF/blob SHA-256: `5C19F6282F4FC51CB114CB6C876D70CA2FC3B9CF0FBD0A018D9908F4FE1F63B3`
- GGUF/blob size: `25430738944` bytes
- Ollama version: `0.40.16`
- Ollama executable SHA-256: `4CCEFCBFECC50FB6526471ADABBC20869DD614E29E351120B15083CB174B0B8A`
- llama.cpp CLI: `F:\\rawrxd\\dist\\RawrXD_Enterprise_v3.0\\extras\\powershield\\tools\\llama-cli.exe`
- llama.cpp version: `7157 (583cb8341)`
- llama.cpp executable SHA-256: `634BE10F579FE2CB9701F92FD4F63AE23ECF10C2CB97BAA078A4F95EC9430594`

## Recovered model parameters

```ini
draft_num_predict=2
temperature=1
top_p=0.95
```

The archived benchmark receipt additionally records `gamma=4`, `ngram=3`,
and a 1,048,576-token trained context. It is a separate 64-token/128-output
spec benchmark and must not be substituted for the reported 106,116-token run.

## Reported benchmark, not yet reproducible

```ini
prompt_tokens=106116
generated_tokens=424
configured_context=262144
prompt_tps=1388.91
decode_tps=103.57
mtp_draft_tokens=2
mtp_acceptance=225/396=56.82%
gpu_selection=dual AMD (exact device indices not retained)
batch_settings=not retained
generation_parameters=not fully retained
```

## Acceptance state

```ini
MODEL_IDENTITY=RECOVERED
OLLAMA_IDENTITY=RECOVERED
LLAMACPP_IDENTITY=RECOVERED
ORIGINAL_INVOCATION=PARTIAL
MTP_ON_RUN=NOT_RUN
MTP_OFF_RUN=NOT_RUN
COMPARATIVE_CORRECTNESS=NOT_RUN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
