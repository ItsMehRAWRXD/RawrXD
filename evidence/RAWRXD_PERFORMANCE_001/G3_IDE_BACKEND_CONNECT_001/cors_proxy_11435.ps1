# SUPERSEDED by G3_IDE_BACKEND_FULLFIX_001 — DO NOT RUN. Real Origin:null + bunnyhop in RawrXD-Win32IDE.exe --headless --port 11435.
$ErrorActionPreference = 'Stop'
$upstream = 'http://127.0.0.1:11436'
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add('http://127.0.0.1:11435/')
$listener.Prefixes.Add('http://localhost:11435/')
try {
  $listener.Start()
} catch {
  Write-Error ("Failed to bind 11435: " + $_.Exception.Message)
  exit 1
}
Write-Output ("CORS_PROXY listening on 11435 -> " + $upstream)
while ($listener.IsListening) {
  $ctx = $listener.GetContext()
  try {
    $req = $ctx.Request
    $resp = $ctx.Response
    $resp.AddHeader('Access-Control-Allow-Origin', '*')
    $resp.AddHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
    $resp.AddHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
    if ($req.HttpMethod -eq 'OPTIONS') {
      $resp.StatusCode = 204
      $resp.Close()
      continue
    }
    $dest = $upstream + $req.Url.PathAndQuery
    $ureq = [System.Net.HttpWebRequest]::Create($dest)
    $ureq.Method = $req.HttpMethod
    $ureq.Timeout = 30000
    $ureq.ReadWriteTimeout = 30000
    if ($req.ContentType) { $ureq.ContentType = $req.ContentType }
    if ($req.HasEntityBody) {
      $ms = New-Object System.IO.MemoryStream
      $req.InputStream.CopyTo($ms)
      $bytes = $ms.ToArray()
      $ureq.ContentLength = $bytes.Length
      $os = $ureq.GetRequestStream()
      $os.Write($bytes, 0, $bytes.Length)
      $os.Close()
    }
    try {
      $uresp = $ureq.GetResponse()
    } catch [System.Net.WebException] {
      if ($null -ne $_.Exception.Response) {
        $uresp = $_.Exception.Response
      } else {
        throw
      }
    }
    $resp.StatusCode = [int]$uresp.StatusCode
    if ($uresp.ContentType) { $resp.ContentType = $uresp.ContentType }
    $stream = $uresp.GetResponseStream()
    $stream.CopyTo($resp.OutputStream)
    $stream.Close()
    $uresp.Close()
    $resp.Close()
  } catch {
    try {
      $safe = $_.Exception.Message -replace '[^\w\s\.:\-]', ''
      $body = '{"error":"proxy","message":"' + $safe + '"}'
      $msg = [Text.Encoding]::UTF8.GetBytes($body)
      $ctx.Response.StatusCode = 502
      $ctx.Response.ContentType = 'application/json'
      $ctx.Response.AddHeader('Access-Control-Allow-Origin', '*')
      $ctx.Response.OutputStream.Write($msg, 0, $msg.Length)
      $ctx.Response.Close()
    } catch {}
  }
}

