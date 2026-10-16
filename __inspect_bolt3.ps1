$path = "F:\rawrxd\nemotron-bolt.gguf"
$fs = [System.IO.File]::OpenRead($path)
$br = New-Object System.IO.BinaryReader($fs)

$magic = $br.ReadBytes(4)
$version = $br.ReadUInt32()
$nTensors = $br.ReadUInt64()
$nMeta = $br.ReadUInt64()

Write-Host "Magic: $([System.Text.Encoding]::UTF8.GetString($magic)) Version: $version"
Write-Host "Tensors: $nTensors Meta: $nMeta"

# Read first 30 metadata entries only
$maxRead = [math]::Min($nMeta, 30)
for ($i=0; $i -lt $maxRead; $i++) {
    $klen = $br.ReadUInt64()
    $key = [System.Text.Encoding]::UTF8.GetString($br.ReadBytes([int]$klen))
    $vt = $br.ReadUInt32()
    switch ($vt) {
        8 { $slen=$br.ReadUInt64(); $val=[System.Text.Encoding]::UTF8.GetString($br.ReadBytes([int]$slen)) }
        9 { 
            $at=$br.ReadUInt32(); $al=$br.ReadUInt64()
            if($at -eq 8){
                $val=@(); for($j=0;$j-lt$al;$j++){$sl=$br.ReadUInt64();$val+=[System.Text.Encoding]::UTF8.GetString($br.ReadBytes([int]$sl))}
            } else {
                $es=1; if($at -eq 2 -or $at -eq 3){$es=2} elseif($at -ge 4 -and $at -le 6){$es=4} elseif($at -eq 7){$es=1}
                $br.ReadBytes([int]($al*$es)) | Out-Null
                $val="[ARRAY t=$at n=$al]"
            }
        }
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

$br.Close()
$fs.Close()
