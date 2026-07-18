# BRICK setup verification — no Docker required
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$passed = 0
$failed = 0

# Redirect Go temp dir away from a full C: drive
$tmpDir = Join-Path $root "tmp"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$env:GOTMPDIR = $tmpDir
$env:TEMP = $tmpDir
$env:TMP = $tmpDir

function Test-Step($name, [scriptblock]$block) {
    Write-Host "  $name... " -NoNewline
    try {
        & $block
        Write-Host "OK" -ForegroundColor Green
        $script:passed++
    } catch {
        Write-Host "FAIL" -ForegroundColor Red
        Write-Host "    $_" -ForegroundColor Red
        $script:failed++
    }
}

Write-Host "`nBRICK Setup Verification (Cloud Mode)`n" -ForegroundColor Cyan

Test-Step "Go installed" { if (-not (Get-Command go -ErrorAction SilentlyContinue)) { throw "Go not found" } }
Test-Step "Node.js installed" { if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw "Node not found" } }
Test-Step "Backend builds" { Push-Location "$root\backend"; go build -buildvcs=false -o brick.exe .; if ($LASTEXITCODE -ne 0) { throw "build failed" }; Pop-Location }
Test-Step "Chaincode builds" { Push-Location "$root\blockchain\chaincode"; go build -buildvcs=false .; if ($LASTEXITCODE -ne 0) { throw "build failed" }; Pop-Location }
Test-Step "Frontend builds" { Push-Location "$root\frontend"; npm run build 2>&1 | Out-Null; if ($LASTEXITCODE -ne 0) { throw "build failed" }; Pop-Location }
Test-Step "Cloud ledger data exists" { if (-not (Test-Path "$root\data\cloud-ledger.json")) { throw "missing cloud-ledger.json" } }
Test-Step "Connection profile exists" { if (-not (Test-Path "$root\connection-cloud.json")) { throw "missing connection-cloud.json" } }

$backendRunning = $false
try {
    $health = Invoke-RestMethod -Uri "http://localhost:8080/api/health" -TimeoutSec 3
    if ($health.ledgerMode -eq "cloud") { $backendRunning = $true }
} catch {}

if ($backendRunning) {
    Test-Step "Backend health check" { if ($health.status -ne "healthy") { throw "unhealthy" } }
    $headers = @{ "X-User-Identity" = "admin"; "X-Org-ID" = "Org1MSP" }
    Test-Step "Admin session API" {
        $session = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/brick/session/admin" -Headers $headers
        if ($session.identity.userId -ne "admin") { throw "unexpected identity" }
    }
} else {
    Write-Host "  Backend not running — skipping live API tests (start with .\start.ps1)" -ForegroundColor Yellow
}

Write-Host "`nResults: $passed passed, $failed failed`n" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
if ($failed -gt 0) { exit 1 }
