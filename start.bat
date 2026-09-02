@echo off
echo ============================================
echo  AI-SOC SOAR System — Starting...
echo ============================================
echo.

cd /d "%~dp0"

echo [1/2] Activating virtual environment...
call venv\Scripts\activate.bat

echo [2/2] Starting FastAPI backend on http://127.0.0.1:8000
echo.
echo  Open frontend\index.html in your browser after the server starts.
echo  API Docs available at: http://127.0.0.1:8000/docs
echo.
echo  Press Ctrl+C to stop the server.
echo ============================================

python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
pause
