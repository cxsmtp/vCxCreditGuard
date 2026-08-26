# ============================================================================
# run-podman.ps1 - build and run CxCreditGuard with Podman in one shot.
#
#   .\run-podman.ps1          # build image, (re)start container, print URL/logs
#   .\run-podman.ps1 -Logs    # just tail the running container's logs
#   .\run-podman.ps1 -Down    # stop and remove the container (keeps your data)
#   .\run-podman.ps1 -Purge   # stop/remove the container and delete its data
#
# Data (SQLite db, master key, initial admin password) lives in a named Podman
# volume `cxcreditguard-data`, so it survives rebuilds and container restarts.
# The UI is served at http://localhost:8000 (override with -HostPort).
# ============================================================================
param(
    [switch]$Logs,          # tail the running container's logs
    [switch]$Down,          # stop and remove the container (keep the data volume)
    [switch]$Purge,         # stop/remove the container and delete the data volume
    [int]$HostPort = $(if ($env:CXCG_HOST_PORT) { [int]$env:CXCG_HOST_PORT } else { 8000 })
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$Image     = 'cxcreditguard:podman'
$Container = 'cxcreditguard'
$Volume    = 'cxcreditguard-data'

function Assert-Podman {
    if (-not (Get-Command podman -ErrorAction SilentlyContinue)) {
        throw 'podman was not found on PATH. Install Podman Desktop and restart this shell.'
    }
}

function Ensure-Volume {
    podman volume exists $Volume 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "==> Creating data volume '$Volume'"
        podman volume create $Volume
        if ($LASTEXITCODE -ne 0) { throw 'Failed to create the data volume.' }
    }
}

Assert-Podman

if ($Logs) {
    podman logs -f $Container
    exit $LASTEXITCODE
}

if ($Down -or $Purge) {
    Write-Host "==> Removing container '$Container'"
    podman rm -f $Container 2>$null | Out-Null
    if ($Purge) {
        Write-Host "==> Deleting data volume '$Volume'"
        podman volume rm -f $Volume 2>$null | Out-Null
        Write-Host 'All local CxCreditGuard data has been deleted.'
    }
    exit 0
}

Write-Host "==> Building image '$Image' (first run downloads base images, be patient)"
podman build -f deploy/podman/Dockerfile -t $Image .
if ($LASTEXITCODE -ne 0) { throw 'Image build failed.' }

Ensure-Volume

Write-Host "==> (Re)starting container '$Container'"
podman rm -f $Container 2>$null | Out-Null
podman run -d --name $Container --restart unless-stopped `
    -p "${HostPort}:8000" `
    -v "${Volume}:/app/data" `
    $Image
if ($LASTEXITCODE -ne 0) { throw 'Failed to start the container.' }

Write-Host ''
Write-Host "CxCreditGuard is starting up..."
Write-Host "  UI:  http://localhost:$HostPort"
Write-Host "  API: http://localhost:$HostPort/api"
Write-Host "  Docs:http://localhost:$HostPort/docs  (development mode only)"
Write-Host ''
Write-Host "Waiting for it to become ready, then showing the startup log (it"
Write-Host "includes the one-time initial admin credentials on a fresh volume)..."
Write-Host ''

$ready = $false
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Seconds 1
    $ok = Invoke-WebRequest -Uri "http://localhost:$HostPort/healthz" -UseBasicParsing -ErrorAction SilentlyContinue
    if ($ok -and $ok.StatusCode -eq 200) { $ready = $true; break }
}
if (-not $ready) {
    Write-Host 'Container did not answer /healthz within 60s yet - showing logs:'
} else {
    Write-Host "Ready. UI is live at http://localhost:$HostPort"
}
podman logs --tail 60 $Container