$phi = [IO.Path]::Combine('G:\~dev\rawrxd\_r1_iso\02_phi3_mini', 'Phi-3-mini-4k-instruct-q8_0.gguf')
Write-Output "PATH=$phi"
Write-Output "EXISTS=$([IO.File]::Exists($phi))"
$bytes = [Text.Encoding]::Unicode.GetBytes($phi)
# show backslash positions
$idxs = @()
for ($i = 0; $i -lt $phi.Length; $i++) {
  if ($phi[$i] -eq '\') { $idxs += $i }
}
Write-Output ("BACKSLASH_IDX=" + ($idxs -join ','))
Write-Output ("SEG=" + ($phi.Substring([Math]::Max(0,$phi.IndexOf('02_')), 40)))
