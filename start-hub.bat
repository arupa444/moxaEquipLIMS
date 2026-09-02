@echo off
REM ===========================================================================
REM  LIMS Central Hub - one-click setup + background start.
REM   1) Creates the virtual environment (.venv) if missing.
REM   2) Installs / updates the Python packages (first run, or when
REM      requirements.txt changes).
REM   3) Starts balance_server.py HIDDEN in the background (no window),
REM      serving http://127.0.0.1:8000. Logs -> hub.out.log / hub.err.log.
REM  Just double-click this file.  Stop it with stop-hub.bat.
REM ===========================================================================
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"
title LIMS Central Hub

set "VENVPY=%~dp0.venv\Scripts\python.exe"
set "STAMP=%~dp0.venv\.deps-installed"
set "TMPF=%TEMP%\lims_hub_%RANDOM%.txt"

REM --- Already running? Don't start a second copy. ------------------------
set "RUNNING=0"
powershell -NoProfile -Command "@((Get-CimInstance Win32_Process) | Where-Object { ($_.Name -eq 'python.exe' -or $_.Name -eq 'pythonw.exe') -and $_.CommandLine -match 'balance_server\.py' }).Count" > "%TMPF%" 2>nul
set /p RUNNING=<"%TMPF%"
del "%TMPF%" >nul 2>&1
if not "%RUNNING%"=="0" if not "%RUNNING%"=="" (
  echo.
  echo   LIMS Central Hub is already running ^(%RUNNING% process^(es^)^).
  echo   URL: http://127.0.0.1:8000     ^(stop with stop-hub.bat^)
  goto :report
)

REM --- Create the virtual environment if it doesn't exist. ----------------
if not exist "%VENVPY%" (
  echo   Creating virtual environment ^(.venv^)...
  set "BASEPY="
  where py >nul 2>&1 && set "BASEPY=py -3"
  if not defined BASEPY ( where python >nul 2>&1 && set "BASEPY=python" )
  if not defined BASEPY (
    echo.
    echo   ERROR: Python is not installed or not on PATH.
    echo   Install Python 3.11 x64 from https://www.python.org/downloads/
    echo   ^(tick "Add python.exe to PATH"^), then run this file again.
    echo.
    pause
    goto :end
  )
  !BASEPY! -m venv ".venv"
  if not exist "%VENVPY%" (
    echo   ERROR: could not create the virtual environment.
    pause
    goto :end
  )
)

REM --- Require Python 3.10+ (the hub uses modern type syntax). ------------
"%VENVPY%" -c "import sys; sys.exit(0 if sys.version_info>=(3,10) else 1)"
if errorlevel 1 (
  echo   ERROR: Python 3.10+ is required. Delete the .venv folder, install
  echo   Python 3.11 x64, then run this file again.
  pause
  goto :end
)

REM --- Install packages only on first run (stamp missing). To force a
REM     reinstall later, delete .venv\.deps-installed and run this again.
set "NEED=0"
if not exist "%STAMP%" set "NEED=1"
if "%NEED%"=="1" (
  echo   Installing/updating packages ^(first run can take a minute^)...
  "%VENVPY%" -m pip install --upgrade pip
  "%VENVPY%" -m pip install -r "%~dp0requirements.txt"
  if errorlevel 1 (
    echo.
    echo   ERROR: package installation failed ^(see messages above^).
    pause
    goto :end
  )
  echo installed > "%STAMP%"
)

REM --- Start the hub hidden, in the background. ---------------------------
echo   Starting LIMS Central Hub in the background...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%VENVPY%' -ArgumentList 'balance_server.py' -WorkingDirectory '%~dp0' -WindowStyle Hidden -RedirectStandardOutput '%~dp0hub.out.log' -RedirectStandardError '%~dp0hub.err.log'"

:report
echo.
echo   LIMS Central Hub is running in the background.
echo   URL : http://127.0.0.1:8000
echo   Logs: %~dp0hub.out.log
echo         %~dp0hub.err.log
echo   Stop: stop-hub.bat
echo.
REM  Portable pause (~5s) that does not need console input:
ping -n 6 127.0.0.1 >nul 2>&1

:end
endlocal
