# Downpour v29 Titanium - GitHub Push Script
# Run this in PowerShell AS ADMINISTRATOR
# Usage: .\push_to_github.ps1 -Token "ghp_yourtoken"

param(
    [Parameter(Mandatory=$false)]
    [string]$Token = ""
)

$RepoPath = "C:\Users\purpl\Desktop\downpour_consolidated"
$GitHubUser = "christiand0797"
$GitHubRepo = "downpour"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Downpour v29 Titanium - GitHub Push" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

Set-Location $RepoPath

# Get token if not provided
if ($Token -eq "") {
    Write-Host "Enter your GitHub Personal Access Token" -ForegroundColor Yellow
    Write-Host "(Get one at https://github.com/settings/tokens/new - needs 'repo' scope)" -ForegroundColor Gray
    Write-Host ""
    $Token = Read-Host "Token"
}

if ($Token -eq "") {
    Write-Host "[ERROR] No token provided. Exiting." -ForegroundColor Red
    exit 1
}

# Configure git
Write-Host "[*] Configuring git..." -ForegroundColor Yellow
git config user.name "christiand0797"
git config user.email "christiand0797@email.com"

# Set remote with token
Write-Host "[*] Setting remote..." -ForegroundColor Yellow
git remote remove origin 2>$null
git remote add origin "https://${Token}@github.com/${GitHubUser}/${GitHubRepo}.git"

# Rename branch
git branch -m main 2>$null

# Stage all tracked files (respects .gitignore)
Write-Host "[*] Staging files..." -ForegroundColor Yellow
git add -A

# Show what's being committed
Write-Host ""
Write-Host "[*] Files to be pushed:" -ForegroundColor Yellow
git diff --cached --name-only

Write-Host ""
Write-Host "[*] Creating commit..." -ForegroundColor Yellow
$CommitMsg = @"
fix: Downpour v29 Titanium - bug fixes and performance improvements

CRITICAL BUG FIXES:
- FIX: All v28 references -> v29 (title/banner/loading screens)
- FIX: RemediationAction.action -> .action_type + .description
- FIX: USB monitor crash on window close (winfo_exists check)
- FIX: Firewall duplicate item prevention (_fw_filtering flag)
- FIX: nvidia-ml-py import (removed deprecated pynvml)
- FIX: sklearn warnings silenced
- FIX: COM init on ThreadPoolExecutor threads

LAUNCHER IMPROVEMENTS:
- nvidia-ml-py install verification with print check
- Python 3.13 support
- Better dependency error handling
- Memory check before launch

PERFORMANCE:
- 24fps rain animation with delta-time compensation
- Pre-allocated canvas items (no alloc/dealloc during render)
- Storm phases with threat-adaptive intensity

40+ Python modules included
"@

git commit -m $CommitMsg

Write-Host ""
Write-Host "[*] Pushing to GitHub..." -ForegroundColor Yellow
git push -u origin main --force

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host " SUCCESS! Pushed to GitHub!" -ForegroundColor Green
    Write-Host " https://github.com/christiand0797/downpour" -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor Green
    
    # Open the repo in browser
    Start-Process "https://github.com/christiand0797/downpour"
} else {
    Write-Host ""
    Write-Host "[ERROR] Push failed. Make sure:" -ForegroundColor Red
    Write-Host "  1. Your token has 'repo' scope" -ForegroundColor Red
    Write-Host "  2. The repo exists at github.com/christiand0797/downpour" -ForegroundColor Red
    Write-Host "  3. You are connected to the internet" -ForegroundColor Red
}

Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
