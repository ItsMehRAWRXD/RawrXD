#!/usr/bin/env pwsh
#==============================================================================
# RawrXD Sovereign Inferencer - GitHub Release Packager
# Phase F.3 Batch 5/5: GitHub Release Asset Preparation
#==============================================================================
# Packages evidence for GitHub release with automated asset generation
#==============================================================================

[CmdletBinding()]
param(
    [Parameter()]
    [string]$EvidencePath = "..\evidence\RawrXD_Sovereign_Evidence",

    [Parameter()]
    [string]$CertificationPath = ".\CERTIFICATION.json",

    [Parameter()]
    [string]$PortalPath = ".\public_portal",

    [Parameter()]
    [string]$OutputPath = ".\release_assets",

    [Parameter()]
    [string]$Version = "1.0.0",

    [Parameter()]
    [switch]$CreateZip,

    [Parameter()]
    [switch]$GenerateReleaseNotes,

    [Parameter()]
    [switch]$UploadToGitHub
)

#==============================================================================
# Release Configuration
#==============================================================================

$script:ReleaseConfig = @{
    Repository = "ItsMehRAWRXD/RawrXD"
    ReleaseName = "Sovereign Certification v{0}"
    TagPrefix = "cert-"
    AssetNames = @{
        EvidencePackage = "RawrXD_Sovereign_Evidence_v{0}.zip"
        Certification = "CERTIFICATION_v{0}.json"
        Portal = "Evidence_Portal_v{0}.zip"
        ReleaseNotes = "RELEASE_NOTES_v{0}.md"
    }
}

#==============================================================================
# Release Packager Classes
#==============================================================================

class GitHubReleasePackager {
    [string]$EvidencePath
    [string]$CertificationPath
    [string]$PortalPath
    [string]$OutputPath
    [string]$Version
    [hashtable]$CertificationData
    [System.Collections.ArrayList]$Assets

    GitHubReleasePackager([string]$evidence, [string]$cert, [string]$portal, 
                          [string]$output, [string]$version) {
        $this.EvidencePath = $evidence
        $this.CertificationPath = $cert
        $this.PortalPath = $portal
        $this.OutputPath = $output
        $this.Version = $version
        $this.Assets = @()
    }

    [bool] LoadCertificationData() {
        if (-not (Test-Path $this.CertificationPath)) {
            Write-Warning "Certification not found: $($this.CertificationPath)"
            return $false
        }

        try {
            $this.CertificationData = Get-Content $this.CertificationPath | ConvertFrom-Json -AsHashtable
            return $true
        }
        catch {
            Write-Error "Failed to load certification: $_"
            return $false
        }
    }

    [void] CreateOutputDirectory() {
        New-Item -ItemType Directory -Force -Path $this.OutputPath | Out-Null
        Write-Host "✓ Output directory created: $($this.OutputPath)" -ForegroundColor Green
    }

    [string] PackageEvidence() {
        Write-Host "`n=== Packaging Evidence ===" -ForegroundColor Cyan

        $assetName = $script:ReleaseConfig.AssetNames.EvidencePackage -f $this.Version
        $assetPath = Join-Path $this.OutputPath $assetName

        if (Test-Path $this.EvidencePath) {
            Compress-Archive -Path "$($this.EvidencePath)\*" -DestinationPath $assetPath -Force
            Write-Host "✓ Evidence packaged: $assetName" -ForegroundColor Green
            
            $this.Assets.Add(@{
                Name = $assetName
                Path = $assetPath
                Size = (Get-Item $assetPath).Length
                Type = "Evidence Package"
            })

            return $assetPath
        }
        else {
            Write-Warning "Evidence path not found: $($this.EvidencePath)"
            return $null
        }
    }

    [string] CopyCertification() {
        Write-Host "`n=== Copying Certification ===" -ForegroundColor Cyan

        $assetName = $script:ReleaseConfig.AssetNames.Certification -f $this.Version
        $assetPath = Join-Path $this.OutputPath $assetName

        if (Test-Path $this.CertificationPath) {
            Copy-Item -Path $this.CertificationPath -Destination $assetPath -Force
            Write-Host "✓ Certification copied: $assetName" -ForegroundColor Green

            $this.Assets.Add(@{
                Name = $assetName
                Path = $assetPath
                Size = (Get-Item $assetPath).Length
                Type = "Certification JSON"
            })

            return $assetPath
        }
        else {
            Write-Warning "Certification not found: $($this.CertificationPath)"
            return $null
        }
    }

    [string] PackagePortal() {
        Write-Host "`n=== Packaging Portal ===" -ForegroundColor Cyan

        $assetName = $script:ReleaseConfig.AssetNames.Portal -f $this.Version
        $assetPath = Join-Path $this.OutputPath $assetName

        if (Test-Path $this.PortalPath) {
            Compress-Archive -Path "$($this.PortalPath)\*" -DestinationPath $assetPath -Force
            Write-Host "✓ Portal packaged: $assetName" -ForegroundColor Green

            $this.Assets.Add(@{
                Name = $assetName
                Path = $assetPath
                Size = (Get-Item $assetPath).Length
                Type = "Web Portal"
            })

            return $assetPath
        }
        else {
            Write-Warning "Portal path not found: $($this.PortalPath)"
            return $null
        }
    }

    [string] GenerateReleaseNotes() {
        Write-Host "`n=== Generating Release Notes ===" -ForegroundColor Cyan

        $grade = $this.CertificationData.SIS.Grade
        $score = $this.CertificationData.SIS.Score
        $certId = $this.CertificationData.CertificationID
        $issueDate = $this.CertificationData.IssueDate
        $expiryDate = $this.CertificationData.ExpiryDate

        $notes = @"
# RawrXD Sovereign Certification v$($this.Version)

## 🏆 Certification Summary

| Field | Value |
|-------|-------|
| **Grade** | $grade |
| **SIS Score** | $score/100 |
| **Certification ID** | $certId |
| **Issue Date** | $issueDate |
| **Valid Until** | $expiryDate |
| **Status** | $($this.CertificationData.Status) |

---

## 📊 Category Scores

"@

        foreach ($cat in $this.CertificationData.SIS.CategoryScores.Keys) {
            $catScore = $this.CertificationData.SIS.CategoryScores[$cat]
            $weight = $this.CertificationData.SIS.Weights[$cat]
            $notes += "| **$cat** | $catScore% (weight: $weight%) |`n"
        }

        $notes += @"

---

## 📦 Release Assets

"@

        foreach ($asset in $this.Assets) {
            $sizeMB = [math]::Round($asset.Size / 1MB, 2)
            $notes += "- **$($asset.Name)** ($sizeMB MB) - $($asset.Type)`n"
        }

        $notes += @"

---

## 🔬 Validation Summary

- **Total Metrics Validated:** $($this.CertificationData.ValidationSummary.TotalMetrics)
- **Passed:** $($this.CertificationData.ValidationSummary.PassCount)
- **Warnings:** $($this.CertificationData.ValidationSummary.WarningCount)
- **Failed:** $($this.CertificationData.ValidationSummary.FailCount)
- **Overall Status:** $($this.CertificationData.ValidationSummary.OverallStatus)

---

## 🚀 Quick Start

1. Download the Evidence Package for complete benchmark results
2. View the Certification JSON for machine-readable scores
3. Extract and open the Web Portal (index.html) in your browser

---

## 📋 Verification

To verify this certification:

```powershell
# Verify checksum
Get-FileHash CERTIFICATION_v$($this.Version).json -Algorithm SHA256

# Validate against targets
.\benchmarks\certification\results_validator.ps1 -ValidationReport .\validation_report.json
```

---

## 📝 Notes

This certification was generated automatically by the RawrXD Sovereign Certification Pipeline.

For questions or issues, please open an issue in the repository.

---

*Released: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")*
"@

        $assetName = $script:ReleaseConfig.AssetNames.ReleaseNotes -f $this.Version
        $assetPath = Join-Path $this.OutputPath $assetName
        $notes | Out-File $assetPath -Encoding UTF8

        Write-Host "✓ Release notes generated: $assetName" -ForegroundColor Green

        $this.Assets.Add(@{
            Name = $assetName
            Path = $assetPath
            Size = (Get-Item $assetPath).Length
            Type = "Documentation"
        })

        return $assetPath
    }

    [void] GenerateManifest() {
        Write-Host "`n=== Generating Asset Manifest ===" -ForegroundColor Cyan

        $manifest = @{
            Version = $this.Version
            Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            Certification = @{
                ID = $this.CertificationData.CertificationID
                Grade = $this.CertificationData.SIS.Grade
                Score = $this.CertificationData.SIS.Score
            }
            Assets = @()
        }

        foreach ($asset in $this.Assets) {
            $hash = (Get-FileHash $asset.Path -Algorithm SHA256).Hash
            $manifest.Assets += @{
                Name = $asset.Name
                Size = $asset.Size
                SHA256 = $hash
                Type = $asset.Type
            }
        }

        $manifestPath = Join-Path $this.OutputPath "MANIFEST.json"
        $manifest | ConvertTo-Json -Depth 10 | Out-File $manifestPath

        Write-Host "✓ Manifest generated: MANIFEST.json" -ForegroundColor Green
    }

    [void] DisplaySummary() {
        Write-Host @"

╔══════════════════════════════════════════════════════════════════════════════╗
║                    RELEASE ASSETS SUMMARY                                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
"@ -ForegroundColor Cyan

        foreach ($asset in $this.Assets) {
            $sizeMB = [math]::Round($asset.Size / 1MB, 2)
            Write-Host "║  ✓ $($asset.Name.PadRight(50)) $sizeMB MB" -ForegroundColor Green
        }

        Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host "`nTotal Assets: $($this.Assets.Count)" -ForegroundColor White
        Write-Host "Output Directory: $($this.OutputPath)" -ForegroundColor White
    }

    [void] CreateGitHubReleaseCommand() {
        $releaseName = $script:ReleaseConfig.ReleaseName -f $this.Version
        $tagName = "$($script:ReleaseConfig.TagPrefix)$($this.Version)"

        $command = @"
# GitHub Release Command
# Run the following to create the release:

cd $($this.OutputPath)

# Create release with gh CLI
gh release create $tagName `
  --title "$releaseName" `
  --notes-file "$($script:ReleaseConfig.AssetNames.ReleaseNotes -f $this.Version)" `
"@

        foreach ($asset in $this.Assets) {
            $command += "  $($asset.Name) ``
"
        }

        $command += "  --repo $($script:ReleaseConfig.Repository)`n"

        $commandPath = Join-Path $this.OutputPath "create_release.ps1"
        $command | Out-File $commandPath -Encoding UTF8

        Write-Host "`n✓ Release command saved to: $commandPath" -ForegroundColor Green
        Write-Host "  Run this script to create the GitHub release" -ForegroundColor Gray
    }
}

#==============================================================================
# Main Execution
#==============================================================================

Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║           RawrXD Sovereign - GitHub Release Packager                         ║
║           Phase F.3 Batch 5/5: Release Asset Preparation                       ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

$packager = [GitHubReleasePackager]::new($EvidencePath, $CertificationPath, 
                                          $PortalPath, $OutputPath, $Version)

# Load certification data
$packager.LoadCertificationData()

# Create output directory
$packager.CreateOutputDirectory()

# Package assets
$packager.PackageEvidence()
$packager.CopyCertification()
$packager.PackagePortal()
$packager.GenerateReleaseNotes()

# Generate manifest
$packager.GenerateManifest()

# Create GitHub release command
$packager.CreateGitHubReleaseCommand()

# Display summary
$packager.DisplaySummary()

Write-Host "`n✅ Phase F.3 Complete! All 5 batches finished." -ForegroundColor Green
Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "  1. Review assets in: $OutputPath" -ForegroundColor White
Write-Host "  2. Run create_release.ps1 to publish to GitHub" -ForegroundColor White
Write-Host "  3. Verify release at: https://github.com/$($script:ReleaseConfig.Repository)/releases" -ForegroundColor White
