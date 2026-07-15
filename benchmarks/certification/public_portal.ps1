#!/usr/bin/env pwsh
#==============================================================================
# RawrXD Sovereign Inferencer - Public Portal Generator
# Phase F.3 Batch 4/5: Web-Ready Evidence Portal
#==============================================================================
# Generates static HTML portal for public evidence consumption
#==============================================================================

[CmdletBinding()]
param(
    [Parameter()]
    [string]$EvidencePath = "..\evidence\RawrXD_Sovereign_Evidence",

    [Parameter()]
    [string]$CertificationPath = ".\CERTIFICATION.json",

    [Parameter()]
    [string]$OutputPath = ".\public_portal",

    [Parameter()]
    [string]$PortalTitle = "RawrXD Sovereign Evidence Portal",

    [Parameter()]
    [switch]$IncludeDownloadLinks,

    [Parameter()]
    [switch]$MinifyOutput
)

#==============================================================================
# Portal Configuration
#==============================================================================

$script:PortalConfig = @{
    Version = "1.0.0"
    Theme = @{
        Primary = "#2e7d32"
        Secondary = "#1976d2"
        Success = "#4caf50"
        Warning = "#ff9800"
        Danger = "#f44336"
        Background = "#fafafa"
        Card = "#ffffff"
    }
    Sections = @(
        "hero"
        "certification"
        "performance"
        "hardware"
        "methodology"
        "downloads"
    )
}

#==============================================================================
# Portal Generator Classes
#==============================================================================

class PublicPortalGenerator {
    [string]$EvidencePath
    [string]$CertificationPath
    [string]$OutputPath
    [hashtable]$CertificationData
    [hashtable]$EvidenceData
    [string]$GeneratedHTML

    PublicPortalGenerator([string]$evidence, [string]$cert, [string]$output) {
        $this.EvidencePath = $evidence
        $this.CertificationPath = $cert
        $this.OutputPath = $output
        $this.EvidenceData = @{}
    }

    [bool] LoadCertificationData() {
        if (-not (Test-Path $this.CertificationPath)) {
            Write-Warning "Certification not found: $($this.CertificationPath)"
            return $false
        }

        try {
            $this.CertificationData = Get-Content $this.CertificationPath | ConvertFrom-Json -AsHashtable
            Write-Host "✓ Certification data loaded" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Error "Failed to load certification: $_"
            return $false
        }
    }

    [bool] LoadEvidenceData() {
        $files = @{
            Hardware = "hardware_report.md"
            Inference = "inference_report.md"
            Hotpatch = "hotpatch_report.md"
            SIS = "sis_report.md"
            Evidence = "EVIDENCE_REPORT.md"
        }

        foreach ($key in $files.Keys) {
            $filePath = Join-Path $this.EvidencePath $files[$key]
            if (Test-Path $filePath) {
                $this.EvidenceData[$key] = Get-Content $filePath -Raw
            }
        }

        Write-Host "✓ Evidence data loaded ($($this.EvidenceData.Count) files)" -ForegroundColor Green
        return $true
    }

    [string] GenerateHeroSection() {
        $grade = $this.CertificationData.SIS.Grade
        $score = $this.CertificationData.SIS.Score
        $status = $this.CertificationData.Status
        $certId = $this.CertificationData.CertificationID

        $gradeColor = switch ($grade.Substring(0, 1)) {
            "A" { $script:PortalConfig.Theme.Success }
            "B" { $script:PortalConfig.Theme.Warning }
            default { $script:PortalConfig.Theme.Danger }
        }

        return @"
    <section class="hero">
        <div class="hero-content">
            <div class="certification-badge" style="border-color: $gradeColor">
                <div class="grade" style="color: $gradeColor">$grade</div>
                <div class="label">CERTIFIED</div>
            </div>
            <h1>RawrXD Sovereign Inferencer</h1>
            <p class="subtitle">Official Performance Certification</p>
            <div class="score-display">
                <div class="score-value" style="color: $gradeColor">$score</div>
                <div class="score-label">SIS Score</div>
            </div>
            <div class="cert-id">ID: $certId</div>
        </div>
    </section>
"@
    }

    [string] GenerateCertificationSection() {
        $issueDate = $this.CertificationData.IssueDate
        $expiryDate = $this.CertificationData.ExpiryDate
        $authority = $this.CertificationData.Authority

        $html = @"
    <section class="certification-details">
        <h2>📜 Certification Details</h2>
        <div class="cert-grid">
            <div class="cert-card">
                <div class="cert-icon">🏆</div>
                <div class="cert-label">Grade</div>
                <div class="cert-value grade-$($this.CertificationData.SIS.Grade.ToLower().Replace('+', '-plus').Replace('-', '-minus'))">$($this.CertificationData.SIS.Grade)</div>
            </div>
            <div class="cert-card">
                <div class="cert-icon">📊</div>
                <div class="cert-label">SIS Score</div>
                <div class="cert-value">$($this.CertificationData.SIS.Score)/100</div>
            </div>
            <div class="cert-card">
                <div class="cert-icon">✓</div>
                <div class="cert-label">Status</div>
                <div class="cert-value status-$($this.CertificationData.Status.ToLower())">$($this.CertificationData.Status)</div>
            </div>
            <div class="cert-card">
                <div class="cert-icon">📅</div>
                <div class="cert-label">Issued</div>
                <div class="cert-value">$([DateTime]::Parse($issueDate).ToString("yyyy-MM-dd"))</div>
            </div>
        </div>
        
        <div class="category-scores">
            <h3>Category Breakdown</h3>
            <div class="category-grid">
"@

        foreach ($cat in $this.CertificationData.SIS.CategoryScores.Keys) {
            $score = $this.CertificationData.SIS.CategoryScores[$cat]
            $weight = $this.CertificationData.SIS.Weights[$cat]
            $width = [math]::Min(100, $score)
            
            $html += @"
                <div class="category-item">
                    <div class="category-header">
                        <span class="category-name">$cat</span>
                        <span class="category-score">$score%</span>
                    </div>
                    <div class="category-bar">
                        <div class="category-fill" style="width: $width%"></div>
                    </div>
                    <div class="category-weight">Weight: $weight%</div>
                </div>
"@
        }

        $html += @"
            </div>
        </div>
    </section>
"@

        return $html
    }

    [string] GeneratePerformanceSection() {
        $valSummary = $this.CertificationData.ValidationSummary

        return @"
    <section class="performance">
        <h2>⚡ Performance Metrics</h2>
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-icon">🎯</div>
                <div class="metric-value">$($valSummary.TotalMetrics)</div>
                <div class="metric-label">Total Metrics</div>
            </div>
            <div class="metric-card pass">
                <div class="metric-icon">✓</div>
                <div class="metric-value">$($valSummary.PassCount)</div>
                <div class="metric-label">Passed</div>
            </div>
            <div class="metric-card warning">
                <div class="metric-icon">⚠</div>
                <div class="metric-value">$($valSummary.WarningCount)</div>
                <div class="metric-label">Warnings</div>
            </div>
            <div class="metric-card fail">
                <div class="metric-icon">✗</div>
                <div class="metric-value">$($valSummary.FailCount)</div>
                <div class="metric-label">Failed</div>
            </div>
        </div>
        
        <div class="validation-status status-$($valSummary.OverallStatus.ToLower())">
            <span class="status-icon"></span>
            <span class="status-text">Overall Status: $($valSummary.OverallStatus)</span>
        </div>
    </section>
"@
    }

    [string] GenerateMethodologySection() {
        return @"
    <section class="methodology">
        <h2>🔬 Methodology</h2>
        <div class="method-content">
            <h3>Benchmark Configuration</h3>
            <ul>
                <li><strong>Hardware:</strong> AMD RX 7800 XT with ROCm acceleration</li>
                <li><strong>Test Duration:</strong> 30 measured runs per benchmark</li>
                <li><strong>Confidence Level:</strong> 95% statistical confidence intervals</li>
                <li><strong>Comparison:</strong> Direct comparison with Ollama baseline</li>
            </ul>
            
            <h3>SIS Calculation</h3>
            <p>The Sovereign Inferencer Score (SIS) is calculated using weighted category scores:</p>
            <ul>
                <li>Inference Performance (25%)</li>
                <li>Agentic Capabilities (20%)</li>
                <li>Hotpatch Efficiency (20%)</li>
                <li>Security (15%)</li>
                <li>Compliance (10%)</li>
                <li>Usability (10%)</li>
            </ul>
            
            <h3>Grade Scale</h3>
            <div class="grade-scale">
                <div class="grade-item"><span class="grade-badge a-plus">A+</span> ≥95 (Exceptional)</div>
                <div class="grade-item"><span class="grade-badge a">A</span> 90-94 (Excellent)</div>
                <div class="grade-item"><span class="grade-badge a-minus">A-</span> 85-89 (Very Good)</div>
                <div class="grade-item"><span class="grade-badge b">B</span> 75-84 (Good)</div>
                <div class="grade-item"><span class="grade-badge c">C</span> 60-74 (Average)</div>
                <div class="grade-item"><span class="grade-badge f">F</span> &lt;60 (Below Standard)</div>
            </div>
        </div>
    </section>
"@
    }

    [string] GenerateDownloadsSection() {
        $html = @"
    <section class="downloads">
        <h2>📥 Downloads</h2>
        <div class="download-grid">
            <a href="EVIDENCE_REPORT.md" download class="download-card">
                <div class="download-icon">📄</div>
                <div class="download-title">Evidence Report</div>
                <div class="download-desc">Complete certification evidence</div>
            </a>
            <a href="sis_score.json" download class="download-card">
                <div class="download-icon">📊</div>
                <div class="download-title">SIS Score (JSON)</div>
                <div class="download-desc">Machine-readable scores</div>
            </a>
            <a href="hardware_report.md" download class="download-card">
                <div class="download-icon">🖥️</div>
                <div class="download-title">Hardware Report</div>
                <div class="download-desc">RX 7800 XT configuration</div>
            </a>
            <a href="inference_report.md" download class="download-card">
                <div class="download-icon">⚡</div>
                <div class="download-title">Inference Report</div>
                <div class="download-desc">TTFT/TPS benchmarks</div>
            </a>
            <a href="hotpatch_report.md" download class="download-card">
                <div class="download-icon">🔧</div>
                <div class="download-title">Hotpatch Report</div>
                <div class="download-desc">Deployment timing proof</div>
            </a>
            <a href="CERTIFICATION.json" download class="download-card">
                <div class="download-icon">🏆</div>
                <div class="download-title">Certification</div>
                <div class="download-desc">Official certificate data</div>
            </a>
        </div>
    </section>
"@

        return $html
    }

    [string] GenerateCSS() {
        return @"
        :root {
            --primary: $($script:PortalConfig.Theme.Primary);
            --secondary: $($script:PortalConfig.Theme.Secondary);
            --success: $($script:PortalConfig.Theme.Success);
            --warning: $($script:PortalConfig.Theme.Warning);
            --danger: $($script:PortalConfig.Theme.Danger);
            --bg: $($script:PortalConfig.Theme.Background);
            --card: $($script:PortalConfig.Theme.Card);
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: #333;
            line-height: 1.6;
        }
        
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        
        /* Hero Section */
        .hero {
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            padding: 60px 40px;
            border-radius: 16px;
            text-align: center;
            margin-bottom: 40px;
        }
        
        .certification-badge {
            display: inline-block;
            border: 4px solid;
            border-radius: 16px;
            padding: 20px 40px;
            margin-bottom: 30px;
            background: rgba(255,255,255,0.1);
        }
        
        .certification-badge .grade {
            font-size: 72px;
            font-weight: bold;
            line-height: 1;
        }
        
        .certification-badge .label {
            font-size: 14px;
            letter-spacing: 4px;
            margin-top: 5px;
        }
        
        .hero h1 { font-size: 42px; margin-bottom: 10px; }
        .hero .subtitle { font-size: 20px; opacity: 0.9; margin-bottom: 30px; }
        
        .score-display {
            display: inline-block;
            background: rgba(255,255,255,0.2);
            padding: 20px 40px;
            border-radius: 12px;
            margin: 20px 0;
        }
        
        .score-value { font-size: 56px; font-weight: bold; }
        .score-label { font-size: 16px; opacity: 0.9; }
        .cert-id { font-size: 12px; opacity: 0.7; margin-top: 20px; }
        
        /* Sections */
        section {
            background: var(--card);
            border-radius: 12px;
            padding: 40px;
            margin-bottom: 30px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        section h2 {
            font-size: 28px;
            margin-bottom: 30px;
            color: var(--primary);
            border-bottom: 3px solid var(--primary);
            padding-bottom: 10px;
        }
        
        section h3 {
            font-size: 20px;
            margin: 25px 0 15px;
            color: #555;
        }
        
        /* Certification Grid */
        .cert-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        
        .cert-card {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 25px;
            text-align: center;
            transition: transform 0.2s;
        }
        
        .cert-card:hover { transform: translateY(-5px); }
        .cert-icon { font-size: 32px; margin-bottom: 10px; }
        .cert-label { font-size: 12px; color: #666; text-transform: uppercase; }
        .cert-value { font-size: 24px; font-weight: bold; color: #333; margin-top: 5px; }
        
        .grade-a, .grade-a-plus, .grade-a-minus { color: var(--success); }
        .status-certified { color: var(--success); }
        
        /* Category Scores */
        .category-grid { display: grid; gap: 15px; }
        
        .category-item {
            background: #f8f9fa;
            padding: 15px 20px;
            border-radius: 8px;
        }
        
        .category-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
        }
        
        .category-name { font-weight: 600; }
        .category-score { font-weight: bold; color: var(--primary); }
        
        .category-bar {
            height: 8px;
            background: #e0e0e0;
            border-radius: 4px;
            overflow: hidden;
        }
        
        .category-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--primary), var(--secondary));
            border-radius: 4px;
            transition: width 1s ease;
        }
        
        .category-weight {
            font-size: 12px;
            color: #888;
            margin-top: 5px;
        }
        
        /* Performance Metrics */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .metric-card {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 25px;
            text-align: center;
        }
        
        .metric-card.pass { border-left: 4px solid var(--success); }
        .metric-card.warning { border-left: 4px solid var(--warning); }
        .metric-card.fail { border-left: 4px solid var(--danger); }
        
        .metric-icon { font-size: 28px; margin-bottom: 10px; }
        .metric-value { font-size: 36px; font-weight: bold; color: #333; }
        .metric-label { font-size: 14px; color: #666; margin-top: 5px; }
        
        .validation-status {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            border-radius: 8px;
            font-size: 18px;
            font-weight: 600;
        }
        
        .validation-status.status-pass { background: #e8f5e9; color: var(--success); }
        .validation-status.status-warning { background: #fff3e0; color: var(--warning); }
        .validation-status.status-fail { background: #ffebee; color: var(--danger); }
        
        /* Methodology */
        .method-content ul {
            margin: 15px 0 15px 30px;
        }
        
        .method-content li {
            margin: 8px 0;
        }
        
        .grade-scale {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 10px;
            margin-top: 20px;
        }
        
        .grade-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 6px;
        }
        
        .grade-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 14px;
        }
        
        .grade-badge.a-plus, .grade-badge.a, .grade-badge.a-minus { background: var(--success); color: white; }
        .grade-badge.b { background: var(--warning); color: white; }
        .grade-badge.c { background: #ffcc80; color: #333; }
        .grade-badge.f { background: var(--danger); color: white; }
        
        /* Downloads */
        .download-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }
        
        .download-card {
            display: block;
            background: #f8f9fa;
            border-radius: 10px;
            padding: 25px;
            text-decoration: none;
            color: inherit;
            transition: all 0.2s;
            border: 2px solid transparent;
        }
        
        .download-card:hover {
            transform: translateY(-3px);
            border-color: var(--primary);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        
        .download-icon { font-size: 32px; margin-bottom: 10px; }
        .download-title { font-weight: 600; margin-bottom: 5px; }
        .download-desc { font-size: 14px; color: #666; }
        
        /* Footer */
        footer {
            text-align: center;
            padding: 40px;
            color: #666;
            font-size: 14px;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .hero { padding: 40px 20px; }
            .hero h1 { font-size: 28px; }
            section { padding: 25px; }
        }
"@
    }

    [void] GeneratePortal() {
        Write-Host "`n=== Generating Public Portal ===" -ForegroundColor Cyan

        $css = $this.GenerateCSS()
        
        $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$PortalTitle</title>
    <style>
$css
    </style>
</head>
<body>
    <div class="container">
$($this.GenerateHeroSection())
$($this.GenerateCertificationSection())
$($this.GeneratePerformanceSection())
$($this.GenerateMethodologySection())
$($this.GenerateDownloadsSection())
        
        <footer>
            <p>RawrXD Sovereign Inferencer Certification Portal v$($script:PortalConfig.Version)</p>
            <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        </footer>
    </div>
</body>
</html>
"@

        $this.GeneratedHTML = $html
    }

    [void] SavePortal() {
        # Create output directory
        New-Item -ItemType Directory -Force -Path $this.OutputPath | Out-Null

        # Save HTML
        $indexPath = Join-Path $this.OutputPath "index.html"
        $this.GeneratedHTML | Out-File $indexPath -Encoding UTF8
        Write-Host "✓ Portal saved to: $indexPath" -ForegroundColor Green

        # Copy evidence files
        if (Test-Path $this.EvidencePath) {
            Copy-Item -Path "$($this.EvidencePath)\*" -Destination $this.OutputPath -Recurse -Force
            Write-Host "✓ Evidence files copied" -ForegroundColor Green
        }

        # Copy certification
        if (Test-Path $this.CertificationPath) {
            Copy-Item -Path $this.CertificationPath -Destination $this.OutputPath -Force
            Write-Host "✓ Certification copied" -ForegroundColor Green
        }
    }
}

#==============================================================================
# Main Execution
#==============================================================================

Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║           RawrXD Sovereign - Public Portal Generator                         ║
║           Phase F.3 Batch 4/5: Web-Ready Evidence Portal                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

$generator = [PublicPortalGenerator]::new($EvidencePath, $CertificationPath, $OutputPath)

# Load data
$generator.LoadCertificationData()
$generator.LoadEvidenceData()

# Generate portal
$generator.GeneratePortal()

# Save portal
$generator.SavePortal()

Write-Host "`n✓ Public portal generated successfully!" -ForegroundColor Green
Write-Host "  Location: $OutputPath" -ForegroundColor Cyan
Write-Host "  Open index.html in a browser to view" -ForegroundColor Gray
