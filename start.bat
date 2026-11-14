@echo off
echo ============================================
echo   PhishGuard India - Starting Backend...
echo ============================================
echo.
cd /d "C:\Users\HP\.gemini\antigravity\scratch\phishguard-india\backend"
"C:\Users\HP\AppData\Local\Programs\Python\Python315\python.exe" -m uvicorn main:app --host 127.0.0.1 --port 8000
pause
