#Requires -Version 5.1
<#
.SYNOPSIS    Minimal yet elegant agentic loop for any Ollama model (PowerShell edition)
.DESCRIPTION ReAct loop: THINK → TOOL → OBSERVE → … → ANSWER.  Add tools by dropping a function in the plugin block.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)][string]$Prompt,
    [string]$Model = 'bigdaddyg-personalized-agentic:latest',
    [int]$MaxIter  = 10,
    [Uri]$Ollama   = 'http://localhost:11434'
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# -------------------------------------------------
# 1.  Micro plugin registry  ––  add your own here
# -------------------------------------------------
$PLUG = @{}

function Register-Tool {
    param($Name, $Func)
    $PLUG[$Name] = $Func
    try {
        $cmd = Get-Command $Func -ErrorAction SilentlyContinue
        if ($cmd) {
            $params = $cmd.Parameters.Keys | Where-Object { $_ -ne 'args' }
            $PLUG["${Name}_schema"] = $params -join ', '
        }
    } catch {
        # Schema registration is optional
    }
}

# ---------- core tools ----------
function shell        ($cmd)          { pwsh -NoP -C $cmd 2>&1 | Out-String }
function powershell   ($code)         { Invoke-Expression $code | Out-String }
function read_file    ($path)         { Get-Content $path -Raw }
function write_file   ($path, $text) { $text | Set-Content $path -Force; "ok" }
function list_dir     ($path = '.')   { Get-ChildItem $path | Select Name, Length, LastWriteTime | ConvertTo-Json }
function web_search   ($query) {
    $uri = "https://api.duckduckgo.com/?q=$([uri]::EscapeDataString($query))&format=json&no_html=1&skip_disambig=1"
    $r = Invoke-RestMethod $uri -Timeout 10
    $results = @()
    if ($r.RelatedTopics) {
        $results = $r.RelatedTopics | Select-Object -First 5 | ForEach-Object {
            @{ Text = $_.Text; FirstURL = $_.FirstURL }
        }
    }
    elseif ($r.Abstract) {
        $results = @(@{ Text = $r.Abstract; FirstURL = $r.AbstractURL })
    }
    elseif ($r.Heading) {
        $results = @(@{ Text = $r.Heading; FirstURL = $r.AbstractURL })
    }
    return ($results | ConvertTo-Json -Depth 3 -Compress)
}
# ---------- new tools ----------
function download_file($url, $out = (Split-Path -Leaf $url)) {
    Invoke-WebRequest $url -OutFile $out; "saved → $out"
}
function unzip        ($zip, $dest = '.') { Expand-Archive $zip $dest -Force; "ok" }
function hash_file    ($path, $algo = 'sha256') { (Get-FileHash $path -Algorithm $algo).Hash }
function reg_get      ($key, $value = '') { (Get-ItemProperty "Registry::$key" -Name $value -ErrorAction SilentlyContinue).$value }
function env_get      ($name) { [Environment]::GetEnvironmentVariable($name) }
function env_set      ($name, $val, $scope = 'Process') { [Environment]::SetEnvironmentVariable($name, $val, $scope); "ok" }
function clipboard    ($text = '') { if ($text) { Set-Clipboard $text; "ok" } else { Get-Clipboard } }
function speak        ($text) { Add-Type -AssemblyName System.Speech; (New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak($text); "ok" }
function read_json    ($path) { Get-Content $path -Raw | ConvertFrom-Json | ConvertTo-Json -Depth 10 }
function read_yaml    ($path) {
    try {
        # Try to use a YAML module if available, otherwise return error
        if (Get-Module -ListAvailable -Name powershell-yaml) {
            Import-Module powershell-yaml -ErrorAction SilentlyContinue
            ConvertFrom-Yaml (Get-Content $path -Raw) | ConvertTo-Json -Depth 10
        } else {
            "Error: YAML support requires 'powershell-yaml' module. Install with: Install-Module powershell-yaml"
        }
    } catch {
        "Error: $_"
    }
}
function csv_to_json  ($path) { Import-Csv $path | ConvertTo-Json }

# register everything - use function: drive syntax
Register-Tool 'shell' ${function:shell}
Register-Tool 'powershell' ${function:powershell}
Register-Tool 'read_file' ${function:read_file}
Register-Tool 'write_file' ${function:write_file}
Register-Tool 'list_dir' ${function:list_dir}
Register-Tool 'web_search' ${function:web_search}
Register-Tool 'download_file' ${function:download_file}
Register-Tool 'unzip' ${function:unzip}
Register-Tool 'hash_file' ${function:hash_file}
Register-Tool 'reg_get' ${function:reg_get}
Register-Tool 'env_get' ${function:env_get}
Register-Tool 'env_set' ${function:env_set}
Register-Tool 'clipboard' ${function:clipboard}
Register-Tool 'speak' ${function:speak}
Register-Tool 'read_json' ${function:read_json}
Register-Tool 'read_yaml' ${function:read_yaml}
Register-Tool 'csv_to_json' ${function:csv_to_json}

# -------------------------------------------------
# 2.  ReAct prompt – unchanged token count
# -------------------------------------------------
$SYS = @"
You are Agent-1B, an agentic assistant.
Tools: $($PLUG.Keys.Where{$_ -notmatch '_schema'} -join ', ')
Call: TOOL:name:{"arg":"value"}
Reply: ANSWER: <final answer>
"@

# -------------------------------------------------
# 3.  Tiny ReAct engine
# -------------------------------------------------
function Invoke-ToolCall {
    param($call)

    # Try to extract tool name and arguments
    $toolName = $null
    $argsText = $null

    # Pattern 1: TOOL:name:{"json"}
    if ($call -match '^TOOL:([^:]+):(.+)$') {
        $toolName = $Matches[1]
        $argsText = $Matches[2]
    }
    # Pattern 2: TOOL:name\nkey: value (YAML-style)
    elseif ($call -match '^TOOL:([^\r\n]+)') {
        $toolName = $Matches[1].Trim()
        # Extract everything after TOOL:name as arguments
        $argsText = $call -replace "^TOOL:$toolName[\r\n]+", ""
        # Remove ANSWER: line if present
        $argsText = $argsText -replace "[\r\n]+ANSWER:.*$", ""
    }

    if (!$toolName -or !$PLUG.ContainsKey($toolName)) {
        return "Unknown tool: $toolName"
    }

    try {
        $h = @{}

        # Try JSON first
        try {
            $jsonObj = $argsText | ConvertFrom-Json
            $jsonObj.PSObject.Properties | ForEach-Object { $h[$_.Name] = $_.Value }
        }
        catch {
            # Fall back to YAML-style key: value parsing
            $lines = $argsText -split "[\r\n]+" | Where-Object { $_.Trim() -and $_ -notmatch '^ANSWER:' }
            foreach ($line in $lines) {
                if ($line -match '^([^:]+):\s*(.+)$') {
                    $key = $matches[1].Trim()
                    $value = $matches[2].Trim()
                    # Remove quotes if present
                    $value = $value -replace '^["'']|["'']$', ''
                    $h[$key] = $value
                }
            }
        }

        if ($h.Count -eq 0) {
            return "Error: No arguments parsed from tool call"
        }

        $result = & $PLUG[$toolName] @h | Out-String
        return $result.Trim()
    }
    catch {
        return "Error: $_"
    }
}

function Start-AgenticLoop {
    param($UserPrompt)

    # Detect if model uses /api/generate (HF models) or /api/chat
    $useGenerate = $Model -match 'hf\.co|huggingface'
    $conversation = @()

    if ($useGenerate) {
        # For /api/generate, build prompt from messages
        $conversation = @($SYS, $UserPrompt)
    } else {
        # For /api/chat, use messages format
        $conversation = @(
            @{ role = 'system'; content = $SYS },
            @{ role = 'user';   content = $UserPrompt }
        )
    }

    $msgs = $conversation
    1..$MaxIter | ForEach-Object {
        Write-Host "[Iter $_]" -ForegroundColor Cyan
        try {
            if ($useGenerate) {
                # Build prompt from conversation history
                $prompt = $msgs -join "`n`n"
                $body = @{
                    model = $Model
                    prompt = $prompt
                    stream = $false
                } | ConvertTo-Json -Depth 10

                $uri = "$($Ollama.ToString().TrimEnd('/'))/api/generate"
                $resp = Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $body -TimeoutSec 60
                $txt = $resp.response
            } else {
                $body = @{
                    model = $Model
                    messages = $msgs
                    stream = $false
                } | ConvertTo-Json -Depth 10

                $uri = "$($Ollama.ToString().TrimEnd('/'))/api/chat"
                $resp = Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $body -TimeoutSec 60
                $txt = $resp.message.content
            }
            Write-Host "Agent: $txt" -ForegroundColor Yellow

            # Extract answer - handle both strict and loose formats
            $answer = $null
            if ($txt -match '^ANSWER:\s*(.+)') {
                $answer = $matches[1].Trim()
            }
            # Also check for answer after tool calls (loose format)
            elseif ($txt -match 'ANSWER:\s*(.+?)(?:\n|$)') {
                $answer = $matches[1].Trim()
                # If answer looks like a tool result, extract the actual value
                if ($answer -match 'result:\s*(.+)') {
                    $answer = $matches[1].Trim()
                }
            }

            if ($answer) {
                Write-Host "`n✅ $answer" -ForegroundColor Green
                return $answer
            }

            if ($txt -match '^TOOL:') {
                $obs = Invoke-ToolCall $txt
                $obsToSend = if ($obs.Length -gt 3000) { $obs.Substring(0, 3000) + '…' } else { $obs }
                Write-Host "Tool -> $($obsToSend.Substring(0, [Math]::Min(200, $obsToSend.Length)))$(if($obsToSend.Length -gt 200){'…'})" -ForegroundColor Magenta

                if ($useGenerate) {
                    $msgs += "`n$txt`nObservation: $obsToSend"
                } else {
                    $msgs += @{ role = 'assistant'; content = $txt }, @{ role = 'user'; content = "Observation: $obsToSend" }
                }
            }
            else {
                if ($useGenerate) {
                    $msgs += "`n$txt`nUse TOOL:name:json or ANSWER: text"
                } else {
                    $msgs += @{ role = 'assistant'; content = $txt }
                    $msgs += @{ role = 'user'; content = 'Use TOOL:name:json or ANSWER: text' }
                }
            }
        }
        catch {
            $errMsg = $_.Exception.Message
            if ($_.Exception.Response) {
                $statusCode = $_.Exception.Response.StatusCode.value__
                $errMsg = "$statusCode $errMsg"
            }
            Write-Host "Error: $errMsg" -ForegroundColor Red
            if ($useGenerate) {
                $msgs += "`nError: $errMsg"
            } else {
                $msgs += @{ role = 'user'; content = "Error: $errMsg" }
            }
        }
    }
    "Max iterations reached"
}

# -------------------------------------------------
# 4.  Go
# -------------------------------------------------
Write-Host "Agentic loop – model $Model" -ForegroundColor Cyan
Start-AgenticLoop $Prompt

