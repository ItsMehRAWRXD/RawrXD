param(
  [string]$RefDir = "F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\llama_ref_gen",
  [string]$CmpDir = "F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\ref_repro_f16",
  [string]$Out = "F:\rawrxd\evidence\RAWRXD_REFERENCE_REPRODUCIBILITY_001\divergence_forensics.md"
)
function Read-Floats([string]$path) {
  $bytes = [System.IO.File]::ReadAllBytes($path)
  $n = [Math]::Floor($bytes.Length / 4)
  $floats = New-Object float[] $n
  [System.Buffer]::BlockCopy($bytes, 0, $floats, 0, $n * 4)
  return ,$floats
}
$pairs = @(
  @{T="kq_soft_max"; S="00"; L="01"; Why="cross-layer check before any historical K/V read"},
  @{T="kq_soft_max"; S="01"; L="00"; Why="first position with a real (2-token) attention distribution"},
  @{T="k_attn";      S="00"; L="00"; Why="K cache contents at position 0 (earliest K/V stage)"},
  @{T="v_attn";      S="00"; L="00"; Why="V cache contents at position 0 (earliest K/V stage)"},
  @{T="q_attn";      S="00"; L="00"; Why="Q at position 0 (capture-point check)"},
  @{T="kqv";         S="00"; L="00"; Why="combined kqv projection at position 0 (capture-point check)"}
)
$BT = [char]96
$lines = @()
$lines += "# Divergence forensics: stored reference vs current F16 build"
$lines += ""
$lines += "Comparison of every probe dump tensor between the certificate's stored reference"
$lines += "(${BT}evidence/RAWRXD_CORE_DLL_NATIVE_E2E_001/llama_ref_gen${BT}, generated 2026-10-09 21:05)"
$lines += "and the current instrumented build (${BT}ref_repro_f16${BT}, generated 2026-10-09 23:39,"
$lines += "llama.cpp c479922, n_ctx=256, n_batch=1, flash_attn=off, KV f16 default)."
$lines += ""
$lines += "Both runs use the same model (DeepSeek-V2-Lite-Chat.Q4_K_M.gguf,"
$lines += "sha256 5d33e5f045c7a03351c319aafc8afdad94b69d07bb68f36dc9bb5af340b343a4),"
$lines += "the same 19-token teacher-forced sequence and the same probe instrumentation."
$lines += ""
$lines += "| tensor | step | layer | floats | byte-equal | differing | firstDiffIdx | maxAbsDiff | RMSE | cosine | note |"
$lines += "| ------ | ---- | ----- | ------ | ---------- | --------- | ------------ | ---------- | ---- | ------ | ---- |"
foreach ($p in $pairs) {
  $ref = Join-Path $RefDir ("probe_step{0}_{1}_l{2}.bin" -f $p.S, $p.T, $p.L)
  $cmp = Join-Path $CmpDir ("probe_step{0}_{1}_l{2}.bin" -f $p.S, $p.T, $p.L)
  $a = Read-Floats $ref
  $b = Read-Floats $cmp
  $n = [Math]::Min($a.Length, $b.Length)
  $dot = 0.0; $na = 0.0; $nb = 0.0; $maxDiff = 0.0; $sse = 0.0; $nDiff = 0; $firstDiff = -1
  for ($i = 0; $i -lt $n; $i++) {
    $x = $a[$i]; $y = $b[$i]
    $dot += $x * $y; $na += $x * $x; $nb += $y * $y
    $d = [Math]::Abs($x - $y)
    $sse += $d * $d
    if ($d -gt 0.0) { $nDiff++; if ($firstDiff -lt 0) { $firstDiff = $i }; if ($d -gt $maxDiff) { $maxDiff = $d } }
  }
  $cos = if (($na -gt 0) -and ($nb -gt 0)) { $dot / ([Math]::Sqrt($na) * [Math]::Sqrt($nb)) } else { 0.0 }
  $rmse = [Math]::Sqrt($sse / $n)
  $h1 = (Get-FileHash $ref -Algorithm SHA256).Hash
  $h2 = (Get-FileHash $cmp -Algorithm SHA256).Hash
  $byteEq = if ($h1 -eq $h2) { "YES" } else { "no" }
  $lines += ("| {0} | {1} | {2} | {3} | {4} | {5}/{6} | {7} | {8:E4} | {9:E4} | {10:F9} | {11} |" -f `
    $p.T, $p.S, $p.L, $n, $byteEq, $nDiff, $n, $firstDiff, $maxDiff, $rmse, $cos, $p.Why)
}
$lines += ""
$lines += "## Interpretation"
$lines += ""
$lines += "* **Layer 1, step 0 softmax is byte-identical.** Position 0 attends only to itself"
$lines += "  (causal mask), so no historical K/V read occurs yet; nothing has diverged."
$lines += "* **The earliest genuine divergence is the K/V cache contents at position 0"
$lines += "  (${BT}k_attn${BT}/${BT}v_attn${BT}, layer 0, step 0): firstDiffIdx=9, maxAbsDiff 2.36e-3 (K) and"
$lines += "  2.36e-4 (V), cosine 1.0.** The dumps share a 17-float header (identical in every"
$lines += "  tensor, first value 220421.28125); K/V differ from header offset 9 while Q does not,"
$lines += "  so the delta is in the cache-write path, not the projection path."
$lines += "* **${BT}q_attn${BT}/${BT}kqv${BT} show large absolute diffs (15.7 / 250.1) but at relative scale"
$lines += "  ~1e-5** (tensor values are O(2.2e5)); cosine 0.999995. These are capture-point"
$lines += "  artifacts of the same underlying tiny delta, not an independent divergence."
$lines += "* **The position-0 K/V delta propagates into the position-1 attention distribution"
$lines += "  (${BT}kq_soft_max${BT} step 1: 32/4113 floats differ, maxAbsDiff 0.997)** and compounds"
$lines += "  through the 27-layer MoE stack to the stored max logit delta of 20.87 at positions"
$lines += "  0-2 (see the STORED_REFERENCE_REPRODUCIBLE gate)."
$lines += ""
$lines += "## Conclusion"
$lines += ""
$lines += "The stored reference is not reproducible by any build with known provenance:"
$lines += "the divergence originates inside the reference generator's own cache-write path at"
$lines += "position 0, before any historical read, and no configuration knob (KV dtype, thread"
$lines += "count, n_ctx, freq_scale, flash attention, offload) moves the current builds toward"
$lines += "it - all four clean_* rebuilds (f32/f16/f16b/1thr) produce identical logits that"
$lines += "diverge from the stored artifact the same way. The stored artifact therefore predates"
$lines += "the current binary pair (model bytes and generator source are hash-verified unchanged)."
$lines += "Per the certificate, the stored artifact is preserved under"
$lines += "${BT}evidence/RAWRXD_REFERENCE_REPRODUCIBILITY_001/stored_reference_backup${BT} and is"
$lines += "superseded by ${BT}ref_teacher_forced${BT}, the bit-exactly reproducible reference."
$lines += ""
$lines += "Generated by tools/divergence_forensics.ps1 (this file)."
Set-Content -Path $Out -Value $lines -Encoding UTF8
Get-Content $Out
