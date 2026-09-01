@echo off
REM ===========================================================================
REM  Start the LIMS Central Hub (balance_server.py) in the BACKGROUND.
REM   - Runs hidden: no console window is left open.
REM   - Detached: keeps running after you close this window / log off is fine
REM     for the session (use Task Scheduler for auto-start at boot).
REM   - Logs to hub.out.log and hub.err.log next to this file.
REM  Double-click this file, or run it from a command prompt.
REM ===========================================================================
setlocal
cd /d "%~dp0"

REM Prefer the project virtual-env Python; fall back to system Python.
set "PY=%~dp0.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"

REM Refuse to start a second copy if one is already running.
for /f %%C in ('powershell -NoProfile -Command "@(Get-CimInstance Win32_Process | Where-Object { ($_.Name -eq 'python.exe' -or $_.Name -eq 'pythonw.exe') -and $_.CommandLine -match 'balance_server\.py' }).Count"') do set "RUNNING=%%C"
if not "%RUNNING%"=="0" (
  echo.
  echo   LIMS Central Hub is already running ^(%RUNNING% process^(es^)^).
  echo   URL: http://127.0.0.1:8000    ^(use stop-hub.bat to stop it^)
  echo.
  goto :done
)

echo.
echo   Starting LIMS Central Hub in the background...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%PY%' -ArgumentList 'balance_server.py' -WorkingDirectory '%~dp0' -WindowStyle Hidden -RedirectStandardOutput '%~dp0hub.out.log' -RedirectStandardError '%~dp0hub.err.log'"

echo   Started.
echo   URL : http://127.0.0.1:8000
echo   Logs: %~dp0hub.out.log
echo         %~dp0hub.err.log
echo   Stop: stop-hub.bat
echo.

:done
timeout /t 4 >nul
endlocal
