@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0.."
set "PROJECT_ROOT=%cd%"
set "PYTHONDONTWRITEBYTECODE=1"
set "PYTHONPYCACHEPREFIX="
set "TOOLS_DIR=%PROJECT_ROOT%\_runtime_cache\tools"
if not exist "%TOOLS_DIR%\nuclei"   mkdir "%TOOLS_DIR%\nuclei"   >nul 2>&1
if not exist "%TOOLS_DIR%\uncover" mkdir "%TOOLS_DIR%\uncover" >nul 2>&1
set "HOME=%TOOLS_DIR%"
set "USERPROFILE=%TOOLS_DIR%"
set "NUCLEI_CONFIG_DIR=%TOOLS_DIR%\nuclei"
set "UNCOVER_CONFIG_DIR=%TOOLS_DIR%\uncover"
set "TQDM_DISABLE=1"
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"
chcp 65001 >nul 2>&1
set "PYEXE="
if exist "%PROJECT_ROOT%\.venv\Scripts\python.exe"        set "PYEXE=%PROJECT_ROOT%\.venv\Scripts\python.exe"
if exist "%PROJECT_ROOT%\thirdparty\venv\Scripts\python.exe" set "PYEXE=%PROJECT_ROOT%\thirdparty\venv\Scripts\python.exe"
if not defined PYEXE set "PYEXE=python"
if exist "%PROJECT_ROOT%\__pycache__"   rmdir /s /q "%PROJECT_ROOT%\__pycache__"   >nul 2>&1
if exist "%PROJECT_ROOT%\.pytest_cache" rmdir /s /q "%PROJECT_ROOT%\.pytest_cache" >nul 2>&1
if exist "%PROJECT_ROOT%\.config"       rmdir /s /q "%PROJECT_ROOT%\.config"       >nul 2>&1
set "ARGS=%*"
if "%ARGS%"=="" (
  echo ============================================================
  echo   Pentest Platform - Debug Mode
  echo ============================================================
  echo   PROJECT_ROOT: %PROJECT_ROOT%
  echo   Python:       %PYEXE%
  echo ============================================================
  echo.
)
"%PYEXE%" -u "%PROJECT_ROOT%\scripts\tools_menu.py" %ARGS%
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" (
  echo Tools menu finished successfully.
) else (
  echo Tools menu exited with RC=%RC%.
)
if "%ARGS%"=="" pause
endlocal & exit /b %RC%
