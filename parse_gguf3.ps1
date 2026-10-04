$ErrorActionPreference='Stop'

# CRITICAL: every multi-byte field is coerced with [uint64]/[int64] BEFORE any
# bitwise op. PowerShell's -bor coerces to the type of the LEFT operand, so
# [byte]0x3E -bor 0xE900 silently truncates to 0x3E. That bug made every fp16
# scale look like a small subnormal and faked agreement with the audit.

$shard = "F:\OllamaModels\DeepSeek-R1-Q4_K_M-COMPLETE\DeepSeek-R1-Q4_K_M-00001-of-00011.gguf"
$fs = [System.IO.File]::Open($shard,'Open','Read','Read')
$br = New-Object System.IO.BinaryReader($fs)

function U8  { [uint64]$br.ReadByte() }
function U16 { [uint64]$br.ReadUInt16() }
function U32 { [uint64]$br.ReadUInt32() }
function U64 { [uint64]$br.ReadUInt64() }
function I8  { [int64]$br.ReadSByte() }
function I16 { [int64]$br.ReadInt16() }
function I32 { [int64]$br.ReadInt32() }
function I64 { [int64]$br.ReadInt64() }
function F32 { [double]$br.ReadSingle() }
function F64 { [double]$br.ReadDouble() }
function Str { $n=[uint64]$br.ReadUInt64(); [void]$br.ReadBytes([int]$n) }

$magic = [char[]]$br.ReadBytes(4) -join ''
$version = U32
$tensor_count = U64
$kv_count = U64
Write-Host ("GGUF magic={0} version={1} tensors={2} kv={3}" -f $magic,$version,$tensor_count,$kv_count)

function SkipVal([uint64]$t) {
    switch ($t) {
        1  { [void](U8)  }
        2  { [void](I16) }
        3  { [void](I32) }
        4  { [void](I64) }
        5  { [void](F32) }
        6  { [void](F64) }
        7  { Str }
        8  { $n=U64; [void]$br.ReadBytes([int]$n) }
        9  { $n=U64; $fs.Seek([int64]($n*2),'Current')|Out-Null }
        10 { $n=U64; $fs.Seek([int64]($n*4),'Current')|Out-Null }
        11 { $n=U64; $fs.Seek([int64]($n*8),'Current')|Out-Null }
        12 { $n=U64; $fs.Seek([int64]($n*4),'Current')|Out-Null }
        13 { $n=U64; $fs.Seek([int64]($n*8),'Current')|Out-Null }
        default { throw ("unknown gguf value type {0}" -f $t) }
    }
}

for ($i=0; $i -lt $kv_count; $i++) {
    $klen = U64
    $key  = [char[]]$br.ReadBytes([int]$klen) -join ''
    $vt   = U32
    if ($key -match 'general\.architecture|expert|context_length|embedding_length|head_count') {
        Write-Host ("  KV {0} = type {1} @ {2}" -f $key,$vt,$fs.Position)
    }
    SkipVal $vt
}
Write-Host ("KV_DONE pos={0}" -f $fs.Position)

$prevEnd = 0
for ($i=0; $i -lt $tensor_count; $i++) {
    $nlen = U64
    $name = [char[]]$br.ReadBytes([int]$nlen) -join ''
    $ndim = U32
    $dims = @()
    for ($j=0; $j -lt $ndim; $j++) { $dims += U64 }
    $ttype = U32
    $toff  = U64
    if ($name -like "*ffn_gate_exps*" -or $name -like "*ffn_down_exps*") {
        Write-Host ("TENSOR[{0}] {1} ndim={2} dims=[{3}] type={4} relOff={5}" -f $i,$name,$ndim,($dims -join ","),$ttype,$toff)
    }
}
$fs.Close()