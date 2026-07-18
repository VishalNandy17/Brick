# Create directories on D: drive for Go caching to avoid C: drive space issues
New-Item -ItemType Directory -Force -Path "D:\go-cache\tmp" | Out-Null
New-Item -ItemType Directory -Force -Path "D:\go-cache\build" | Out-Null
New-Item -ItemType Directory -Force -Path "D:\go-cache\mod" | Out-Null

# Set Go environment variables for this session
$env:GOTMPDIR  = "D:\go-cache\tmp"
$env:GOCACHE   = "D:\go-cache\build"
$env:GOMODCACHE = "D:\go-cache\mod"

Write-Host "Go cache shifted to D:\go-cache\" -ForegroundColor Green
Write-Host "Starting BRICK Backend..." -ForegroundColor Cyan

# Run the Go app (using '.' to compile all files; -buildvcs=false avoids git status errors)
go run -buildvcs=false .
