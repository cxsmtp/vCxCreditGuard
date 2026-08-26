@echo off
REM ============================================================================
REM run.bat - build and run CxCreditGuard with Podman on Windows (cmd.exe).
REM
REM   run.bat          build image, (re)start container, tail the startup log
REM   run.bat logs     just tail the running container's logs
REM   run.bat down     stop and remove the container (keeps your data)
REM   run.bat purge    stop/remove the container and delete its data volume
REM
REM Data (SQLite db, master key, initial admin password) lives in the named
REM Podman volume cxcreditguard-data, so it survives rebuilds and restarts. The
REM UI is served at http://localhost:8000.
REM
REM This is the cmd.exe equivalent of run-podman.ps1 - use it when PowerShell's
REM execution policy blocks the .ps1 script. Note that .bat continues a command
REM with ^ at end of line (not \, which is the Unix continuation character), so
REM the podman run below is kept on a single line.
REM ============================================================================
setlocal
cd /d "%~dp0"

set "IMAGE=cxcreditguard:podman"
set "CONTAINER=cxcreditguard"
set "VOLUME=cxcreditguard-data"

where podman >nul 2>nul
if errorlevel 1 (
    echo podman was not found on PATH. Install Podman Desktop and restart this shell.
    exit /b 1
)

if /i "%~1"=="logs" (
    podman logs -f %CONTAINER%
    exit /b %errorlevel%
)

if /i "%~1"=="down"  goto :down
if /i "%~1"=="purge" goto :down
goto :run

:down
echo ==^> Removing container "%CONTAINER%"
podman rm -f %CONTAINER% >nul 2>nul
if /i "%~1"=="purge" (
    echo ==^> Deleting data volume "%VOLUME%"
    podman volume rm -f %VOLUME% >nul 2>nul
    echo All local CxCreditGuard data has been deleted.
)
exit /b 0

:run
echo ==^> Building image "%IMAGE%" (first run downloads base images, be patient)
podman build -f deploy/podman/Dockerfile -t %IMAGE% .
if errorlevel 1 (
    echo Image build failed.
    exit /b 1
)

echo ==^> (Re)starting container "%CONTAINER%"
podman rm -f %CONTAINER% >nul 2>nul
REM podman run auto-creates the named volume if it does not exist yet.
podman run -d --name %CONTAINER% --restart unless-stopped -p 8000:8000 -v %VOLUME%:/app/data %IMAGE%
if errorlevel 1 (
    echo Failed to start the container.
    exit /b 1
)

echo.
echo CxCreditGuard is starting up...
echo   UI:   http://localhost:8000
echo   API:  http://localhost:8000/api
echo   Docs: http://localhost:8000/docs  (development mode only)
echo.
echo Showing the startup log - it includes the one-time initial admin
echo credentials on a fresh volume. Press Ctrl+C to stop tailing.
echo.
podman logs -f %CONTAINER%
endlocal
