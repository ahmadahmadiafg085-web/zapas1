# rcedit_download.ps1
# Downloads rcedit.exe (small tool) and places it in C:\DevTools for icon editing.
# This script only provides the steps; run it in PowerShell as Administrator if you agree.
$installDir = "C:\DevTools"
if (-not (Test-Path $installDir)) { New-Item -ItemType Directory -Path $installDir | Out-Null }
$rcUrl = "https://github.com/electron/rcedit/releases/download/v1.1.1/rcedit-x64.exe"
$dest = Join-Path $installDir "rcedit.exe"

Write-Host "Downloading rcedit from $rcUrl ..."
try {
    Invoke-WebRequest -Uri $rcUrl -OutFile $dest -UseBasicParsing -ErrorAction Stop
    Write-Host "Saved to $dest"
} catch {
    Write-Error "Failed to download rcedit. Please download manually from GitHub releases and place rcedit.exe in C:\DevTools"
}
