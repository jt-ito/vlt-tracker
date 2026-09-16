$ErrorActionPreference = "Stop"

$startTime = Get-Date
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Build & Push started at: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# Read version dynamically from package.json
$packageJsonPath = Join-Path $PSScriptRoot "package.json"
if (-not (Test-Path $packageJsonPath)) {
    Write-Error "Could not find package.json in $PSScriptRoot"
    exit 1
}

$version = (Get-Content $packageJsonPath -Raw | ConvertFrom-Json).version
if (-not $version) {
    Write-Error "Could not extract version from package.json"
    exit 1
}

$imageLatest = "jteaito/vlt-tracker:latest"
$imageVersion = "jteaito/vlt-tracker:$version"

Write-Host "Target Image Tags:" -ForegroundColor Yellow
Write-Host "  - $imageLatest" -ForegroundColor Yellow
Write-Host "  - $imageVersion" -ForegroundColor Yellow
Write-Host ""

Write-Host "Starting Docker build..." -ForegroundColor Green
docker build -t $imageLatest -t $imageVersion $PSScriptRoot

if ($LASTEXITCODE -ne 0) {
    $endTime = Get-Date
    $elapsed = $endTime - $startTime
    Write-Error "Docker build failed after $($elapsed.ToString('hh\:mm\:ss'))."
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "Pushing $imageLatest..." -ForegroundColor Green
docker push $imageLatest
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to push $imageLatest"
    exit $LASTEXITCODE
}

Write-Host "Pushing $imageVersion..." -ForegroundColor Green
docker push $imageVersion
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to push $imageVersion"
    exit $LASTEXITCODE
}

$endTime = Get-Date
$elapsed = $endTime - $startTime

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Successfully built and pushed tags: latest, $version" -ForegroundColor Green
Write-Host "Finished at: $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
Write-Host "Total elapsed time: $($elapsed.ToString('hh\:mm\:ss'))" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
