@echo off
title FEKA - Starting All Services
echo ========================================
echo  FEKANOLLEKA PROXY SYSTEM
echo ========================================
echo.
echo [1/5] Starting Proxy Port 1010...
start "Proxy 1010" cmd /c C:\m3sb\scripts\start_proxy_1010.bat
timeout /t 3 /nobreak >nul
echo [2/5] Starting Proxy Port 8882...
start "Proxy 8882" cmd /c C:\m3sb\scripts\start_proxy_8882.bat
timeout /t 3 /nobreak >nul
echo [3/5] Starting Proxy Port 8883...
start "Proxy 8883" cmd /c C:\m3sb\scripts\start_proxy_8883.bat
timeout /t 3 /nobreak >nul
echo [4/5] Starting Telegram Bot...
start "Bot" cmd /c C:\m3sb\scripts\start_bot.bat
timeout /t 2 /nobreak >nul
echo [5/5] Starting API Server...
start "API" cmd /c C:\m3sb\scripts\start_api.bat
timeout /t 2 /nobreak >nul
echo.
echo ========================================
echo  ALL SERVICES STARTED
echo ========================================
pause
