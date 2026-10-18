# PowerShell Demo Reset Script
$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Closed-Loop Attack-Path Agent Demo Reset" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

$endpoint = "http://localhost:8000/reset"

try {
    Write-Host "Sending POST request to $endpoint..." -ForegroundColor Yellow
    $response = Invoke-RestMethod -Uri $endpoint -Method Post
    if ($response.success) {
        Write-Host "Lab reset successful!" -ForegroundColor Green
        Write-Host "Attack paths restored: $($response.attack_paths_count)" -ForegroundColor Green
        Write-Host "Baseline vulnerable topology ready." -ForegroundColor Green
    } else {
        Write-Host "Reset returned unsuccessful status." -ForegroundColor Red
    }
} catch {
    Write-Host "Warning: Could not connect to $endpoint." -ForegroundColor Yellow
    Write-Host "Ensure the FastAPI server is running (`uvicorn app.main:app` or `docker compose up`)." -ForegroundColor Gray
}

Write-Host "`nOpening http://localhost:8000 in your browser..." -ForegroundColor Cyan
Start-Process "http://localhost:8000"
