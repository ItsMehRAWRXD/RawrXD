$ErrorActionPreference = "Stop"
$root = "F:\~dev\rawrxd\src\remote64"

# MASM reserved-word collisions. Old .STRUCT.field  ->  New .STRUCT.field
$map = [ordered]@{
  '\.REMOTE_HEADER\.type\b'            = '.REMOTE_HEADER.msgType'
  '\.REMOTE_BUFFER\.ptr\b'             = '.REMOTE_BUFFER.dataPtr'
  '\.REMOTE_BUFFER\.size\b'            = '.REMOTE_BUFFER.dataSize'
  '\.REMOTE_BUFFER\.capacity\b'        = '.REMOTE_BUFFER.dataCapacity'
  '\.REMOTE_CAPTURE\.width\b'          = '.REMOTE_CAPTURE.frameW'
  '\.REMOTE_CAPTURE\.height\b'         = '.REMOTE_CAPTURE.frameH'
  '\.REMOTE_VIEWER\.width\b'           = '.REMOTE_VIEWER.frameW'
  '\.REMOTE_VIEWER\.height\b'          = '.REMOTE_VIEWER.frameH'
  '\.REMOTE_TILE_HEADER\.x\b'          = '.REMOTE_TILE_HEADER.tileX'
  '\.REMOTE_TILE_HEADER\.y\b'          = '.REMOTE_TILE_HEADER.tileY'
  '\.REMOTE_TILE_HEADER\.width\b'      = '.REMOTE_TILE_HEADER.tileW'
  '\.REMOTE_TILE_HEADER\.height\b'     = '.REMOTE_TILE_HEADER.tileH'
  '\.REMOTE_CURSOR\.x\b'               = '.REMOTE_CURSOR.cursorX'
  '\.REMOTE_CURSOR\.y\b'               = '.REMOTE_CURSOR.cursorY'
  '\bAUTH_INFO\b'                      = 'BCRYPT_AEAD_INFO'
}

$total = 0
foreach ($f in Get-ChildItem $root -Filter *.asm) {
  $text = Get-Content $f.FullName -Raw
  $orig = $text
  $n = 0
  foreach ($k in $map.Keys) {
    $c = ([regex]::Matches($text, $k)).Count
    if ($c -gt 0) { $n += $c; $text = [regex]::Replace($text, $k, $map[$k]) }
  }
  if ($text -ne $orig) {
    [System.IO.File]::WriteAllText($f.FullName, $text)
    $total += $n
    Write-Host ("{0,-28} {1,3} replacements" -f $f.Name, $n)
  }
}
Write-Host "TOTAL_REPLACEMENTS=$total"
