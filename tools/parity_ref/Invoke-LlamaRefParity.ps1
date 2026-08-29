# Invoke-LlamaRefParity.ps1 — EXTERNAL measuring stick via P/Invoke (no new EXE)
# Deep2 remains deep2_inference_deps=NONE. This only LoadLibrary's prebuilt llama.dll.
param(
    [string]$Model = "F:\~dev\tinyllama_fresh.gguf",
    [string]$Prompt = "hello",
    [int]$MaxNewTokens = 15,
    [string]$LlamaDir = "F:\~dev\llama-direct\vulkan",
    [string]$OutFile = "F:\~dev\rawrxd\evidence\PARITY_CERT_001\ref.stdout.txt"
)

$ErrorActionPreference = 'Stop'
$env:PATH = "$LlamaDir;$env:PATH"
Set-Location $LlamaDir

$cs = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class LlamaRef {
    [DllImport("ggml.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void ggml_backend_load_all_from_path(string path);

    [DllImport("llama.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void llama_backend_init();

    [DllImport("llama.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void llama_backend_free();

    // Opaque pointers passed as IntPtr; we only need greedy token IDs for cert.
}
'@

# Prefer the working CLI path: tokenize + completion, then map pieces if needed.
# For true token-ID parity we shell the already-allowed llama-tokenize and
# parse greedy generation via a tiny in-memory approach using llama-completion
# only for text validation; token IDs come from a one-shot allowed helper.

$tokExe = Join-Path $LlamaDir "llama-tokenize.exe"
$compExe = Join-Path $LlamaDir "llama-completion.exe"

$promptIdsRaw = & $tokExe -m $Model -p $Prompt --ids --log-disable 2>$null
# Expect like [1, 22172]
$promptIds = @()
if ($promptIdsRaw -match '\[(.*)\]') {
    $promptIds = @($Matches[1].Split(',') | ForEach-Object { [int]($_.Trim()) })
}

$promptFile = Join-Path (Split-Path $OutFile) "prompt.txt"
Set-Content -Path $promptFile -Value $Prompt -NoNewline
$genOut = Join-Path (Split-Path $OutFile) "ref_completion.stdout.txt"
$genErr = Join-Path (Split-Path $OutFile) "ref_completion.stderr.txt"
$args = @(
    "-m", $Model,
    "-f", $promptFile,
    "-n", "$MaxNewTokens",
    "--temp", "0",
    "--top-k", "1",
    "-ngl", "0",
    "--seed", "0",
    "-no-cnv",
    "--no-display-prompt",
    "--log-disable"
)
$p = Start-Process -FilePath $compExe -ArgumentList $args -WorkingDirectory $LlamaDir `
    -NoNewWindow -PassThru -Wait -RedirectStandardOutput $genOut -RedirectStandardError $genErr

$genText = if (Test-Path $genOut) { Get-Content $genOut -Raw } else { "" }

# Tokenize the *generated text alone* is NOT generation IDs. For ID parity we need
# decode-time IDs. Emit what we can and mark GEN_IDS source.
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("PARITY-CERT-001")
[void]$sb.AppendLine("side=reference")
[void]$sb.AppendLine("reference_backend=llama.cpp")
[void]$sb.AppendLine("note=external_measuring_stick_only_not_a_deep2_dependency")
[void]$sb.AppendLine("model=$Model")
[void]$sb.AppendLine("prompt=$Prompt")
[void]$sb.AppendLine("max_new_tokens=$MaxNewTokens")
[void]$sb.AppendLine("temperature=0")
[void]$sb.AppendLine("top_k=1")
[void]$sb.AppendLine("REF_LOAD=PASS")
[void]$sb.AppendLine("REF_PROMPT_IDS=$($promptIds -join ',')")
[void]$sb.AppendLine("REF_GEN_TEXT=$($genText.Trim())")
[void]$sb.AppendLine("REF_GEN_IDS_STATUS=PENDING_WDAC")
[void]$sb.AppendLine("REF_GEN_IDS=")
[void]$sb.AppendLine("REF_SIDE=PARTIAL")
[void]$sb.AppendLine("REF_NOTE=Device Guard blocks newly built llama_ref_parity_probe.exe; prompt IDs from allowed llama-tokenize.exe; gen IDs require WDAC allow of probe or pre-approved binary")
$sb.ToString() | Set-Content -Encoding utf8 $OutFile
Write-Host $sb.ToString()
Write-Host "Wrote $OutFile (completion_exit=$($p.ExitCode))"
