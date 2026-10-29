@echo off
title SENTINEL - Cyber Threat Intelligence Platform
echo ========================================================
echo   SENTINEL // Cyber Threat Intelligence Platform
echo   Launching server and opening browser automatically...
echo ========================================================
echo.

if exist ".venv\Scripts\python.exe" (
    .venv\Scripts\python.exe run.py
) else if exist "venv\Scripts\python.exe" (
    venv\Scripts\python.exe run.py
) else (
    python run.py
)

pause
