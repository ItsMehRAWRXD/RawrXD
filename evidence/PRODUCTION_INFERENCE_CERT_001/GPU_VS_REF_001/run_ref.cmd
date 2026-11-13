@echo off
cd /d "F:\OllamaModels\llama.cpp"
"F:\OllamaModels\llama.cpp\llama-cli.exe" -m "G:\~dev\rawrxd\models\tinyllama.gguf" -p Hello -n 16 --temp 0 --top-k 1 --top-p 1.0 --seed 0 -ngl 0 -cnv -st --jinja --no-warmup -c 2048 > "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\GPU_VS_REF_001\ref_llamacli.out.txt" 2> "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\GPU_VS_REF_001\ref_llamacli.err.txt"
echo EXIT=%ERRORLEVEL%> "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\GPU_VS_REF_001\ref_llamacli.exit.txt"
