@echo off
set PROMPT=Tool returned: branch=model-correctness dirty=yes dirty_file_count=124. Reply EXACTLY two lines:
BRANCH=<value>
DIRTY_FILE_COUNT=<integer>
"F:\~dev\rawrxd\bin\deep2_generation_lifecycle_test.exe" "F:\OllamaModels\blobs\sha256-5c19f6282f4fc51cb114cb6c876d70ca2fc3b9cf0fbd0a018d9908f4fe1f63b3" --generations 1 --max-tokens 64 --eos-max-tokens 64 --prompt "%PROMPT%" > "F:\~dev\_batch3d_inference2.txt" 2>&1
