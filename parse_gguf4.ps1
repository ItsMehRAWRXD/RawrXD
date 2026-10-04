$ErrorActionPreference='Stop'
$shard = "F:\OllamaModels\DeepSeek-R1-Q4_K_M-COMPLETE\DeepSeek-R1-Q4_K_M-00001-of-00011.gguf"
$fs = [System.IO.File]::Open($shard,'Open','Read','Read')
$br = New-Object System.IO.BinaryReader($fs)
function U32 { [uint64]$br.ReadUInt32() }
function U64 { [uint64]$br.ReadUInt64() }
$magic=[char[]]$br.ReadBytes(4) -join ''
$version=U32; $tensor_count=U64; $kv_count=U64
Write-Host ("GGUF v={0} tensors={1} kv={2}" -f $version,$tensor_count,$kv_count)

function SkipVal([uint64]$t){
  switch($t){
    1{[void]$br.ReadByte()}
    2{[void]$br.ReadUInt16()}
    3{[void]$br.ReadUInt32()}
    4{[void]$br.ReadUInt64()}
    5{[void]$br.ReadSingle()}
    6{[void]$br.ReadDouble()}
    7{$n=U64; $fs.Seek([int64]$n,'Current')|Out-Null}
    8{$n=U64; $fs.Seek([int64]$n,'Current')|Out-Null}
    9{$n=U64; $fs.Seek([int64]($n*2),'Current')|Out-Null}
    10{$n=U64; $fs.Seek([int64]($n*4),'Current')|Out-Null}
    11{$n=U64; $fs.Seek([int64]($n*8),'Current')|Out-Null}
    12{$n=U64; $fs.Seek([int64]($n*4),'Current')|Out-Null}
    13{$n=U64; $fs.Seek([int64]($n*8),'Current')|Out-Null}
    default{throw ("bad type $t")}
  }
}
for($i=0;$i -lt $kv_count;$i++){
  $klen=U64
  [void]$br.ReadBytes([int]$klen)
  $vt=U32
  SkipVal $vt
}
Write-Host ("KV_DONE pos={0}" -f $fs.Position)
for($i=0;$i -lt $tensor_count;$i++){
  $nlen=U64
  $name=[char[]]$br.ReadBytes([int]$nlen) -join ''
  $ndim=U32
  $dims=@()
  for($j=0;$j -lt $ndim;$j++){$dims+=$br.ReadUInt64()}
  $ttype=U32
  $toff=U64
  if($name -like "*ffn_gate_exps*" -or $name -like "*ffn_down_exps*"){
    Write-Host ("T[{0}] {1} ndim={2} dims=[{3}] type={4} relOff={5}" -f $i,$name,$ndim,($dims -join ","),$ttype,$toff)
  }
}
$fs.Close()