$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$dockerCandidates = @(
    (Get-Command docker -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1),
    "$env:LOCALAPPDATA\Programs\DockerDesktop\resources\bin\docker.exe",
    "$env:ProgramFiles\Docker\Docker\resources\bin\docker.exe"
) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

if (-not $dockerCandidates) {
    throw "Docker CLI не найден. Убедитесь, что Docker Desktop установлен и запущен."
}

$dockerExe = $dockerCandidates[0]
$env:PATH = (Split-Path -Parent $dockerExe) + ";" + $env:PATH
& $dockerExe compose --project-directory $projectRoot up --build -d

Write-Host ""
Write-Host "Кабинет врача:    http://localhost:5173" -ForegroundColor Green
Write-Host "Кабинет пациента: http://localhost:5174" -ForegroundColor Green
Write-Host "Flask API:         http://localhost:5000/api/health" -ForegroundColor Green
