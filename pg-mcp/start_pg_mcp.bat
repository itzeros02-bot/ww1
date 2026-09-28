@echo off
chcp 65001 >nul
title pg-mcp PostgreSQL MCP Server
cd /d "%~dp0"

echo ============================================
echo   pg-mcp - PostgreSQL MCP Server (stdio)
echo ============================================
echo.
echo Server runs on stdio - keep this window open
echo while an MCP client is connected.
echo Press Ctrl+C to stop.
echo.

"C:\Users\Administrator\.local\bin\uv.exe" run python -m pg_mcp
pause
