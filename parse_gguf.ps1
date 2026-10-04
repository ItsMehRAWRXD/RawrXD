$ErrorActionPreference='Stop'
$p="F:\OllamaModels\DeepSeek-R1-Q4_K_M-COMPLETE\DeepSeek-R1-Q4_K_M-00001-of-00011.gguf"
$fs=[System.IO.File]::Open($p,'Open','Read','Read')
$br=New-Object System.IO.BinaryReader($fs)
$magic=[char[]]$br.ReadBytes(4) -join ''
$version=$br.ReadUInt32()
$tensor_count=$br.ReadUInt64()
$kv_count=$br.ReadUInt64()
Write-Host ("magic={0}  version={1}  tensor_count={2}  kv_count={3}" -f $magic,$version,$tensor_count,$kv_count)

for($i=0;$i -lt $kv_count;$i++){
    $klen=$br.ReadUInt64()
    $key=[char[]]$br.ReadBytes($klen) -join ''
    $vtype=$br.ReadUInt32()
    switch($vtype){
        1 {$br.ReadByte()}
        2 {$br.ReadUInt16()}
        3 {$br.ReadUInt32()}
        4 {$br.ReadUInt64()}
        5 {$br.ReadSingle()}
        6 {$br.ReadDouble()}
        7 {$blen=$br.ReadUInt64(); $br.ReadBytes($blen)}
        8 {$arrlen=$br.ReadUInt64(); for($j=0;$j -lt $arrlen;$j++){ $br.ReadByte() }}
        9 {$arrlen=$br.ReadUInt64(); for($j=0;$j -lt $arrlen;$j++){ $br.ReadUInt16() }}
        10{$arrlen=$br.ReadUInt64(); for($j=0;$j -lt $arrlen;$j++){ $br.ReadUInt32() }}
        11{$arrlen=$br.ReadUInt64(); for($j=0;$j -lt $arrlen;$j++){ $br.ReadUInt64() }}
        12{$arrlen=$br.ReadUInt64(); for($j=0;$j -lt $arrlen;$j++){ $br.ReadSingle() }}
        13{$arrlen=$br.ReadUInt64(); for($j=0;$j -lt $arrlen;$j++){ $br.ReadDouble() }}
    }
}
Write-Host ("AFTER_KV pos={0}" -f $fs.Position)

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