$ErrorActionPreference = 'Continue'

$gbnf = Get-Content -Raw -LiteralPath 'F:\rawrxd\evidence\structured_output.gbnf'
Write-Output "=== GRAMMAR CHARS: $($gbnf.Length) ==="

$ok = 0
$bad = 0
$failures = @()

$prompts = @(
    @{ c = 'You are auditing a repository. Call list_repo on the path src.';                 label = 'list_repo' },
    @{ c = 'Read the file README.md using read_file.';                                       label = 'read_file' },
    @{ c = 'Search the repository for the text model_invoker using search_text.';            label = 'search_text' },
    @{ c = 'Check the git status of the repository.';                                        label = 'git_status' },
    @{ c = 'Write a plan file to evidence/plan.md with a short plan.';                       label = 'write_file' },
    @{ c = 'Build the project using run_build.';                                             label = 'run_build' },
    @{ c = 'Run the test suite using run_tests.';                                            label = 'run_tests' },
    @{ c = 'You are done inspecting. Give the final answer with a summary and next actions.'; label = 'final' },
    @{ c = 'Summarize what you found and finish.';                                           label = 'final' },
    @{ c = 'Report the remaining work, then finish.';                                        label = 'final' }
)

Write-Output "=== 10 STRUCTURED GENERATIONS ==="
foreach ($p in $prompts) {
    $payload = @{
        model       = 'llama3.2-3b'
        messages    = @(@{ role = 'user'; content = $p.c })
        max_tokens  = 400
        temperature = 0.2
        grammar     = $gbnf
    } | ConvertTo-Json -Depth 10
    try {
        $r = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/v1/chat/completions' `
                    -Method Post -Body $payload -ContentType 'application/json' -TimeoutSec 200
        $text = $r.choices[0].message.content
        $parsed = $null
        try { $parsed = $text | ConvertFrom-Json -ErrorAction Stop } catch { }
        if ($parsed) {
            $ok++
            Write-Output "[$($p.label)] PARSE-OK  action=$($parsed.action) tool=$($parsed.tool)"
            if ($parsed.action -eq 'tool') {
                $pathOk = $true
                if ($parsed.args -and $parsed.args.PSObject.Properties.Name -contains 'path') {
                    Write-Output "           args.path=$($parsed.args.path)"
                }
            }
        } else {
            $bad++
            $script:failures += $text
            Write-Output "[$($p.label)] PARSE-FAIL: $($text)"
        }
    } catch {
        $bad++
        Write-Output "[$($p.label)] HTTP-FAIL: $($_.Exception.Message)"
    }
}

Write-Output ""
Write-Output "=== RESULT: parsed=$ok failed=$bad ==="
