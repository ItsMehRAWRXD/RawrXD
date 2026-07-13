@echo off
REM Create PR for v1.0.1-hotfix1-security branch
REM Run this script to create the PR using GitHub CLI

echo Creating PR for v1.0.1-hotfix1-security...
echo.

REM Check if gh CLI is installed
where gh >nul 2>nul
if %errorlevel% neq 0 (
    echo ERROR: GitHub CLI (gh) is not installed.
    echo Please install it from: https://cli.github.com/
    echo.
    echo Alternatively, create the PR manually at:
    echo https://github.com/ItsMehRAWRXD/RawrXD/compare/main...v1.0.1-hotfix1-security
    pause
    exit /b 1
)

REM Check if logged in
echo Checking GitHub CLI login status...
gh auth status >nul 2>nul
if %errorlevel% neq 0 (
    echo ERROR: Not logged in to GitHub CLI.
    echo Run: gh auth login
    pause
    exit /b 1
)

echo Creating PR...
gh pr create ^
  --repo ItsMehRAWRXD/RawrXD ^
  --base main ^
  --head v1.0.1-hotfix1-security ^
  --title "Security: v1.0.1 - Critical CVE Remediation (8 CVEs Fixed)" ^
  --body-file PR_DESCRIPTION.md ^
  --label "security,critical"

if %errorlevel% equ 0 (
    echo.
    echo SUCCESS: PR created!
    echo.
    pause
) else (
    echo.
    echo ERROR: Failed to create PR.
    echo Please create manually at:
    echo https://github.com/ItsMehRAWRXD/RawrXD/compare/main...v1.0.1-hotfix1-security
    echo.
    pause
)
