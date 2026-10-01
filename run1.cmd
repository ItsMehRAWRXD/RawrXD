@echo off
set PROMPT=Tools: RAWR_TOOL name=git_status | list_files (path) | read_file (path). To use a tool, reply EXACTLY: RAWR_TOOL name=<tool>. Otherwise reply with text only. Q: What branch am I on and is the worktree clean?
"F:\~dev\rawrxd\bin\deep2_generation_lifecycle_test.exe" "F:\OllamaModels\blobs\sha256-5c19f6282f4fc51cb114cb6c876d70ca2fc3b9cf0fbd0a018d9908f4fe1f63b3" --generations 1 --max-tokens 64 --eos-max-tokens 64 --prompt "%PROMPT%" > "F:\~dev\_batch3d_inference1.txt" 2>&1
