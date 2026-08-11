docker build -t jteaito/vlt-tracker:latest .
if ($LASTEXITCODE -eq 0) {
    docker push jteaito/vlt-tracker:latest
} else {
    Write-Error "Docker build failed."
}
