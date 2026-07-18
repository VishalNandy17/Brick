# BRICK — Start backend + frontend (no Docker required)
Write-Host "Starting BRICK (cloud ledger mode)..." -ForegroundColor Cyan

$root = Split-Path -Parent $MyInvocation.MyCommand.Path

# Go uses %TEMP% on C: by default; redirect to project tmp when C: is low on space.
$tmpDir = Join-Path $root "tmp"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$env:GOTMPDIR = $tmpDir
$env:TEMP = $tmpDir
$env:TMP = $tmpDir

# Build backend
Write-Host "`n[1/3] Building backend..." -ForegroundColor Yellow
Push-Location "$root\backend"
go build -buildvcs=false -o brick.exe .
if ($LASTEXITCODE -ne 0) { Pop-Location; exit 1 }
Pop-Location

# Start backend in new window
Write-Host "[2/3] Starting backend on http://localhost:8080" -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$env:GOTMPDIR='$tmpDir'; cd '$root\backend'; .\brick.exe"

Start-Sleep -Seconds 2

# Start frontend in new window
Write-Host "[3/3] Starting frontend on http://localhost:3000" -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root\frontend'; npm run dev"

Write-Host "`nBRICK is starting!" -ForegroundColor Green
Write-Host "  Frontend: http://localhost:3000"
Write-Host "  Backend:  http://localhost:8080/api/health"
Write-Host "  Demo login: admin / Org1MSP"
Write-Host "`nPress any key to exit this launcher (servers keep running)..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
