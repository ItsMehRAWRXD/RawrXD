$ErrorActionPreference='Stop'
$p="F:\OllamaModels\DeepSeek-R1-Q4_K_M-COMPLETE\DeepSeek-R1-Q4_K_M-00001-of-00011.gguf"
$fs=[System.IO.File]::Open($p,'Open','Read','Read')
$br=New-Object System.IO.BinaryReader($fs)
$magic=[char[]]$br.ReadBytes(4) -join ''
$version=$br.ReadUInt32()
$tensor_count=$br.ReadUInt64()
$kv_count=$br.ReadUInt64()
Write-Host ("magic={0}  version={1}  tensor_count={2}  kv_count={3}" -f $magic,$version,$tensor_count,$kv_count)

# Skip KV - just jump past it
$fs.Seek(12+8+8,'Begin')|Out-Null  # magic+version+tensor_count+kv_count = 24 bytes
for($i=0;$i -lt $kv_count;$i++){
    $klen=$br.ReadUInt64()
    $fs.Seek($klen,'Current')|Out-Null
    $vtype=$br.ReadUInt32()
    switch($vtype){
        1 {$fs.Seek(1,'Current')|Out-Null}
        2 {$fs.Seek(2,'Current')|Out-Null}
        3 {$fs.Seek(4,'Current')|Out-Null}
        4 {$fs.Seek(8,'Current')|Out-Null}
        5 {$fs.Seek(4,'Current')|Out-Null}
        6 {$fs.Seek(8,'Current')|Out-Null}
        7 {$blen=$br.ReadUInt64(); $fs.Seek($blen,'Current')|Out-Null}
        8 {$arrlen=$br.ReadUInt64(); $fs.Seek($arrlen,'Current')|Out-Null}
        9 {$arrlen=$br.ReadUInt64(); $fs.Seek($arrlen*2,'Current')|Out-Null}
        10{$arrlen=$br.ReadUInt64(); $fs.Seek($arrlen*4,'Current')|Out-Null}
        11{$arrlen=$br.ReadUInt64(); $fs.Seek($arrlen*8,'Current')|Out-Null}
        12{$arrlen=$br.ReadUInt64(); $fs.Seek($arrlen*4,'Current')|Out-Null}
        13{$arrlen=$br.ReadUInt64(); $fs.Seek($arrlen*8,'Current')|Out-Null}
    }
}
Write-Host ("AFTER_KV pos={0}" -f $fs.Position)

# Now read tensors
for($i=0;$i -lt $tensor_count;$i++){
    $nlen=$br.ReadUInt64()
    $name=[char[]]$br.ReadBytes($nlen) -join ''
    $ndim=$br.ReadUInt32()
    $dims=@()
    for($j=0;$j -lt $ndim;$j++){ $dims+=$br.ReadUInt64() }
    $ttype=$br.ReadUInt32()
    $toff=$br.ReadUInt64()
    if($name -like "*ffn_gate_exps*"){
        Write-Host ("TENSOR {0}: name={1}  ndim={2}  dims={3}  type={4}  offset={5}" -f $i,$name,$ndim,$dims,$ttype,$toff)
    }
}
$fs.Close()