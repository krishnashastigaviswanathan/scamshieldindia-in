@echo off
setlocal
cd /d "%~dp0"

set "BACKEND_DIR=%~dp0backend"

if not exist "%BACKEND_DIR%\main.py" (
    echo Error: backend/main.py was not found.
    echo Expected path: %BACKEND_DIR%\main.py
    pause
    exit /b 1
)

where py >nul 2>1
if not errorlevel 1 (
    py -m uvicorn main:app --host 127.0.0.1 --port 8000 --app-dir "%BACKEND_DIR%"
) else (
    python -m uvicorn main:app --host 127.0.0.1 --port 8000 --app-dir "%BACKEND_DIR%"
)

pause
