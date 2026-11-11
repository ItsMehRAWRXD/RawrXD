$path = "F:\rawrxd\nemotron-bolt.gguf"
$fs = [System.IO.File]::OpenRead($path)
$br = New-Object System.IO.BinaryReader($fs)

function Read-UInt32 { $br.ReadUInt32() }
function Read-UInt64 { $br.ReadUInt64() }
function Read-Int64 { $br.ReadInt64() }
function Read-Float { $br.ReadSingle() }
function Read-String {
    $len = $br.ReadUInt64()
    $bytes = $br.ReadBytes([int]$len)
    [System.Text.Encoding]::UTF8.GetString($bytes)
}

$magic = $br.ReadBytes(4)
$version = $br.ReadUInt32()
$nTensors = $br.ReadUInt64()
$nMeta = $br.ReadUInt64()

Write-Host "Magic: $([System.Text.Encoding]::UTF8.GetString($magic)) Version: $version"
Write-Host "Tensors: $nTensors Meta: $nMeta"

$types = @{
    0="UINT8";1="INT8";2="UINT16";3="INT16";4="UINT32";5="INT32";6="FLOAT32";7="BOOL";8="STRING";9="ARRAY";10="UINT64";11="INT64";12="FLOAT64"
}

for ($i=0; $i -lt $nMeta; $i++) {
    $key = Read-String
    $vt = $br.ReadUInt32()
    switch ($vt) {
        8 { $slen=$br.ReadUInt64(); $val=[System.Text.Encoding]::UTF8.GetString($br.ReadBytes([int]$slen)) }
        9 { $at=$br.ReadUInt32(); $al=$br.ReadUInt64(); if($at -eq 8){$val=@();for($j=0;$j-lt$al;$j++){$sl=$br.ReadUInt64();$val+=[System.Text.Encoding]::UTF8.GetString($br.ReadBytes([int]$sl))}} else { $es=@{0:1;1:1;2:2;3:2;4:4;5:4;6:4;7:1}[$at]; if(-not $es){$es=4}; $br.ReadBytes([int]($al*$es)) | Out-Null; $val="[ARRAY t=$at n=$al]" } }
        6 { $val = $br.ReadSingle() }
        4 { $val = $br.ReadUInt32() }
        5 { $val = $br.ReadInt32() }
        10 { $val = $br.ReadUInt64() }
        11 { $val = $br.ReadInt64() }
        12 { $val = $br.ReadDouble() }
        default { $val = "UNKNOWN_TYPE_$vt" }
    }
    Write-Host "  $key = $val"
}

Write-Host "`n--- Tensors ---"
$tensorTypeMap = @{0="F32";1="F16";2="Q4_0";3="Q4_1";6="Q5_0";7="Q5_1";8="Q8_0";10="Q2_K";11="Q3_K";12="Q4_K";13="Q5_K";14="Q6_K";15="Q8_K";16="IQ2_XXS";17="IQ2_XS";18="IQ2_S";30="BF16";40="NVFP4"}
for ($i=0; $i -lt [math]::Min($nTensors, 200); $i++) {
    $name = Read-String
    $ndims = $br.ReadUInt32()
    $dims = @()
    for ($j=0; $j -lt $ndims; $j++) { $dims += $br.ReadUInt64() }
    $ttype = $br.ReadUInt32()
    $offset = $br.ReadUInt64()
    $tname = $tensorTypeMap[$ttype]
    if (-not $tname) { $tname = "TYPE_$ttype" }
    Write-Host "  $i: $name dims=$($dims -join 'x') type=$tname($ttype) offset=$offset"
}
$br.Close()
$fs.Close()
