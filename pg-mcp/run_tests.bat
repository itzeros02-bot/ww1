@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul
cd /d "%~dp0"

echo ============================================
echo   pg-mcp test runner
echo ============================================
echo.

where uv >nul 2>nul
if %errorlevel% equ 0 (
    set "PY=uv run python"
    set "PYTEST=uv run pytest"
    set "RUFF=uv run ruff"
) else (
    if exist ".venv\Scripts\python.exe" (
        set "PY=.venv\Scripts\python.exe"
        set "PYTEST=.venv\Scripts\python.exe -m pytest"
        set "RUFF=.venv\Scripts\python.exe -m ruff"
    ) else (
        echo [ERROR] Neither uv nor .venv found. Run: uv sync --extra dev
        exit /b 1
    )
)

if "%1" equ "quick" (
    echo [1/2] Lint...
    %RUFF% check src tests || goto :fail
    echo [2/2] Unit + security tests (no DB required)...
    %PYTEST% tests/unit tests/security -q || goto :fail
) else (
    echo [1/3] Lint...
    %RUFF% check src tests || goto :fail
    echo [2/3] Unit + security tests...
    %PYTEST% tests/unit tests/security -q || goto :fail
    echo [3/3] Integration tests (real PostgreSQL; auto-skips if unreachable)...
    %PYTEST% tests/integration -q || goto :fail
)

echo.
echo [OK] All checks passed.
exit /b 0

:fail
echo.
echo [FAILED] See output above.
exit /b 1
