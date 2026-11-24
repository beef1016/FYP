<#
    Refresh the local CISA KEV (Known Exploited Vulnerabilities) catalog used for
    OFFLINE exploit-correlation enrichment (Windows canonical copy).

    The running ExploitLink app NEVER fetches this itself — it only reads the
    local mirror. Run this out-of-band so scans stay offline while the data is
    kept current.

    Usage:  powershell -File scripts\update_kev.ps1
#>
$ErrorActionPreference = "Stop"

$FeedUrl  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
$DestDir  = Join-Path (Split-Path $PSScriptRoot -Parent) "app\data\kev"
$DestFile = Join-Path $DestDir "known_exploited_vulnerabilities.json"

New-Item -ItemType Directory -Force -Path $DestDir | Out-Null

Write-Host "[KEV] Downloading CISA KEV feed..."
Write-Host "[KEV]   $FeedUrl"

$Tmp = "$DestFile.tmp"
Invoke-WebRequest -Uri $FeedUrl -OutFile $Tmp -UseBasicParsing

# Validate shape before replacing.
$data = Get-Content $Tmp -Raw | ConvertFrom-Json
if (-not $data.vulnerabilities -or $data.vulnerabilities.Count -eq 0) {
    Remove-Item $Tmp -Force
    throw "Downloaded file has no 'vulnerabilities' array — aborting."
}
Write-Host ("[KEV] Validated catalog: {0} known-exploited CVEs." -f $data.vulnerabilities.Count)

Move-Item -Force $Tmp $DestFile
Write-Host "[KEV] Saved to $DestFile"
Write-Host "[KEV] Done. The next scan's correlation will use the refreshed catalog."
