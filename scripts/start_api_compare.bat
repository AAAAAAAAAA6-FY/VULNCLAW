@echo off
REM ============================================================
REM API Compare Testkit launcher.
REM ALL comments must be plain ASCII English. cmd.exe parses .bat
REM files with system ANSI CP (CP936 on Chinese Windows); UTF-8
REM comments get parsed as commands -> error 9009. Do NOT add Chinese.
REM ============================================================
cd /d "%~dp0.."
set "PROJECT_ROOT=%cd%"

REM 1. Bytecode block (parent-process scope; guarantees children inherit)
set "PYTHONDONTWRITEBYTECODE=1"
set "PYTHONPYCACHEPREFIX="

REM 2. Nuclei / uncover HOME redirect (avoids .config/ at project root)
set "TOOLS_DIR=%PROJECT_ROOT%\_runtime_cache\tools"
if not exist "%TOOLS_DIR%\nuclei"   mkdir "%TOOLS_DIR%\nuclei"   >nul 2>&1
if not exist "%TOOLS_DIR%\uncover" mkdir "%TOOLS_DIR%\uncover" >nul 2>&1
set "HOME=%TOOLS_DIR%"
set "USERPROFILE=%TOOLS_DIR%"
set "NUCLEI_CONFIG_DIR=%TOOLS_DIR%\nuclei"
set "UNCOVER_CONFIG_DIR=%TOOLS_DIR%\uncover"
set "TQDM_DISABLE=1"

REM 3. Force UTF-8 output (stops mojibake)
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"
chcp 65001 >nul

REM Resolve python: prefer project-local venvs; fall back to global
set "PYEXE="
if exist "%PROJECT_ROOT%\.venv\Scripts\python.exe"            set "PYEXE=%PROJECT_ROOT%\.venv\Scripts\python.exe"
if exist "%PROJECT_ROOT%\thirdparty\venv\Scripts\python.exe"  set "PYEXE=%PROJECT_ROOT%\thirdparty\venv\Scripts\python.exe"
if not defined PYEXE set "PYEXE=python"

REM Whitelist-only residual junk cleanup (never touch .venv / thirdparty)
if exist "%PROJECT_ROOT%\__pycache__"   rmdir /s /q "%PROJECT_ROOT%\__pycache__"   >nul 2>&1
if exist "%PROJECT_ROOT%\.pytest_cache" rmdir /s /q "%PROJECT_ROOT%\.pytest_cache" >nul 2>&1
if exist "%PROJECT_ROOT%\.config"       rmdir /s /q "%PROJECT_ROOT%\.config"       >nul 2>&1

echo ============================================================
echo   API Compare Testkit Launcher
echo ============================================================
echo   PROJECT_ROOT = %PROJECT_ROOT%
echo   PYEXE        = %PYEXE%
echo ============================================================
"%PYEXE%" "%PROJECT_ROOT%\scripts\api_compare.py"
set "RC=%ERRORLEVEL%"
echo.
echo === Launcher exit: entry script returned %RC% ===
exit /b %RC%
