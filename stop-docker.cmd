@echo off
setlocal
cd /d "%~dp0"

for /f "delims=" %%I in ('where docker 2^>nul') do if not defined DOCKER_EXE set "DOCKER_EXE=%%I"
if not defined DOCKER_EXE if exist "%LOCALAPPDATA%\Programs\DockerDesktop\resources\bin\docker.exe" set "DOCKER_EXE=%LOCALAPPDATA%\Programs\DockerDesktop\resources\bin\docker.exe"
if not defined DOCKER_EXE if exist "%ProgramFiles%\Docker\Docker\resources\bin\docker.exe" set "DOCKER_EXE=%ProgramFiles%\Docker\Docker\resources\bin\docker.exe"

if not defined DOCKER_EXE (
  echo Docker CLI was not found.
  exit /b 1
)

"%DOCKER_EXE%" compose down
