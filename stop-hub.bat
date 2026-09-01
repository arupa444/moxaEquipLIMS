@echo off
REM ===========================================================================
REM  Stop the LIMS Central Hub (balance_server.py) background process(es).
REM ===========================================================================
setlocal
echo.
echo   Stopping LIMS Central Hub...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p = Get-CimInstance Win32_Process | Where-Object { ($_.Name -eq 'python.exe' -or $_.Name -eq 'pythonw.exe') -and $_.CommandLine -match 'balance_server\.py' }; if ($p) { $p | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }; Write-Host ('   Stopped ' + @($p).Count + ' process(es).') } else { Write-Host '   Nothing running.' }"
echo.
timeout /t 3 >nul
endlocal
