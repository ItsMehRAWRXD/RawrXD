# GGUF tensor-name reader -- RAWRXD_GEMMA4_ALIAS_PROBE_001
#
# Settles the hypothesis by evidence instead of assumption:
#   "the error log is false and the tensors are present under another name"
# is a CLAIM. This reads the archive's actual tensor table and decides it.
#
# GGUF layout:
#   magic "GGUF" | version u32 | tensor_count u64 | kv_count u64
#   kv_count *  { key:string, type:u32, value }
#   tensor_count * { name:string, n_dims:u32, dims:u64[n_dims], type:u32, offset:u64 }
#
# Header only; the multi-GB tensor data is never read.

param([string]$Model = "G:\~dev\rawrxd\models\_matrix_gdev\rawrxd\models\_matrix_f\_r1_iso\05_gemma4_e4b\gemma-4-E4B-it-Q4_K_M.gguf")

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Model)) { Write-Output "ABORT: $Model not found"; exit 2 }

$fs = [IO.File]::OpenRead($Model)
$br = New-Object IO.BinaryReader($fs)

function U8  { $br.ReadUInt64() }
function U32 { $br.ReadUInt32() }
function Str {
    $n = U8
    $b = $br.ReadBytes([int]$n)
    return [Text.Encoding]::UTF8.GetString($b)
}

$magic = [Text.Encoding]::ASCII.GetString($br.ReadBytes(4))
$ver   = U32
$nT    = U32        # GGUF v2 stores these as u32; v3 uses u64
$nKV   = U32
Write-Output "MODEL=$Model"
Write-Output "SIZE_BYTES=$($fs.Length)"
Write-Output "MAGIC=$magic VERSION=$ver TENSOR_COUNT=$nT KV_COUNT=$nKV"

if ($magic -ne 'GGUF') { Write-Output "ABORT: not a GGUF file"; $br.Close(); $fs.Close(); exit 3 }

# --- skip metadata KVs, recording any arch/name strings -------------------
$kv = @{}
for ($i = 0; $i -lt $nKV; $i++) {
    $k = Str
    $t = U32
    switch ($t) {
        0  { $v = $br.ReadByte() }
        1  { $v = $br.ReadSByte() }
        2  { $v = $br.ReadUInt16() }
        3  { $v = $br.ReadInt16() }
        4  { $v = $br.ReadUInt32() }
        5  { $v = $br.ReadInt32() }
        6  { $v = $br.ReadSingle() }
        7  { $v = $br.ReadByte() }
        8  { $v = Str }
        9  { $et = U32; $ec = U32; for ($j=0;$j -lt $ec;$j++) { switch ($et) { 0{$br.ReadByte()|Out-Null} 1{$br.ReadSByte()|Out-Null} 2{$br.ReadUInt16()|Out-Null} 3{$br.ReadInt16()|Out-Null} 4{$br.ReadUInt32()|Out-Null} 5{$br.ReadInt32()|Out-Null} 6{$br.ReadSingle()|Out-Null} 7{$br.ReadByte()|Out-Null} 8{Str|Out-Null} 10{$br.ReadUInt64()|Out-Null} 11{$br.ReadInt64()|Out-Null} 12{$br.ReadDouble()|Out-Null} } }; $v = "array[$ec] of type $et" }
        10 { $v = $br.ReadUInt64() }
        11 { $v = $br.ReadInt64() }
        12 { $v = $br.ReadDouble() }
        default { Write-Output "ABORT: unknown KV type $t at $i"; $br.Close(); $fs.Close(); exit 4 }
    }
    if ($k -match 'arch|model\.type|expert|context|head_count|name') { $kv[$k] = "$v" }
}

Write-Output ""
Write-Output "===== architecture metadata ====="
$kv.GetEnumerator() | Sort-Object Name | ForEach-Object { Write-Output ("  {0} = {1}" -f $_.Key, $_.Value) }

# --- read tensor names ----------------------------------------------------
$names = New-Object System.Collections.Generic.List[string]
for ($i = 0; $i -lt $nT; $i++) {
    $nm  = Str
    $nd  = U32
    for ($d = 0; $d -lt $nd; $d++) { U8 | Out-Null }
    U32 | Out-Null     # ggml type
    U8  | Out-Null     # offset
    $names.Add($nm)
}
$br.Close(); $fs.Close()

Write-Output ""
Write-Output "===== tensor names read: $($names.Count) ====="
Write-Output "--- distinct layer-0 names (attention layout, what the validator wants) ---"
$names | Where-Object { $_ -match '(^|\.)0\.|^blk\.0|block_att' } | Sort-Object -Unique | Select-Object -First 40 | ForEach-Object { Write-Output "  $_" }

Write-Output ""
Write-Output "--- any name containing 'q' + 'attn'/'q_proj'/'q_a' (the disputed role) ---"
$hits = @($names | Where-Object { $_ -match 'q' -and $_ -match 'attn|proj|_a$|query' } | Sort-Object -Unique)
Write-Output "  matches=$($hits.Count)"
$hits | Select-Object -First 25 | ForEach-Object { Write-Output "    $_" }

Write-Output ""
Write-Output "--- role resolution ---"
foreach ($role in @('attn_q_a','attn_k','attn_v','attn_output')) {
    $exact  = @($names | Where-Object { $_ -eq $role }).Count
    $byPart = @($names | Where-Object { $_ -like "*$role*" }).Count
    Write-Output ("  {0,-12} exact={1}  contains={2}" -f $role, $exact, $byPart)
}

$names | Sort-Object | Set-Content "F:\~dev\audit_tombstone_001\gemma4_tensor_names.txt"
Write-Output ""
Write-Output "FULL_NAME_LIST=F:\~dev\audit_tombstone_001\gemma4_tensor_names.txt"