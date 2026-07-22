@echo off
title K3 SIEM Platform

echo.
echo   Shield  K3 SIEM Platform v2.0
echo.

where node >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js not found. Install from https://nodejs.org
    pause
    exit /b 1
)

echo [OK] Node.js found

echo.
echo [1/3] Installing backend dependencies...
cd backend
call npm install --silent
cd ..

echo [2/3] Installing frontend dependencies...
cd frontend
call npm install --silent
cd ..

node -e "const http=require('http'); const req=http.get('http://127.0.0.1:8123/ping', (res) => process.exit(res.statusCode === 200 ? 0 : 1)); req.on('error', () => process.exit(1)); req.setTimeout(1500, () => { req.destroy(); process.exit(1); });" >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] ClickHouse is not reachable at http://localhost:8123
    echo         Local dev in K3 SIEM requires ClickHouse for events, audit log, and process trees.
    echo.
    echo         Start Docker Desktop or another local ClickHouse service, then run one of:
    echo         docker start k3-clickhouse
    echo         docker run -d --name k3-clickhouse -p 8123:8123 -p 9000:9000 clickhouse/clickhouse-server
    echo.
    pause
    exit /b 1
)

if not exist "backend\data\siem.db" (
    echo [3/3] Seeding database...
    cd backend
    call node src/utils/seed.js
    cd ..
) else (
    echo [3/3] Database already exists
)

echo.
echo Starting K3 SIEM...
echo   Backend  -^>  http://localhost:3001/api
echo   Frontend -^>  http://localhost:3000
echo   Login    -^>  pbasnet / K3@2026
echo.
echo Press Ctrl+C to stop
echo.

start "K3 SIEM Backend" cmd /k "cd backend && node src/index.js"
timeout /t 2 /nobreak > nul
cd frontend && npm start
