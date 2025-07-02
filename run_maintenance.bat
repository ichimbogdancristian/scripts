@echo off
:: =====================[ SYSTEM MAINTENANCE RUNNER ]====================
:: Purpose: Download and execute the system maintenance script with proper permissions
:: Usage: Run as Administrator for full functionality
:: ========================================================================

echo =====================[ SYSTEM MAINTENANCE RUNNER ]====================
echo.

:: Check if running as administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script must be run as Administrator!
    echo Right-click and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

echo [INFO] Running as Administrator - OK
echo.

:: Set variables
set SCRIPT_DIR=%~dp0
set TEMP_DIR=%SCRIPT_DIR%temp_download
set SCRIPT_NAME=system_maintenance_simplified.ps1
set GITHUB_URL=https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/%SCRIPT_NAME%

:: Create temporary directory
if not exist "%TEMP_DIR%" (
    mkdir "%TEMP_DIR%"
    echo [INFO] Created temporary directory: %TEMP_DIR%
)

echo [INFO] Downloading latest script from GitHub...
echo Source: %GITHUB_URL%
echo Target: %TEMP_DIR%\%SCRIPT_NAME%
echo.

:: Download the script using PowerShell
powershell.exe -Command "try { Invoke-WebRequest -Uri '%GITHUB_URL%' -OutFile '%TEMP_DIR%\%SCRIPT_NAME%' -UseBasicParsing; Write-Host '[SUCCESS] Script downloaded successfully' -ForegroundColor Green } catch { Write-Host '[ERROR] Failed to download script:' $_.Exception.Message -ForegroundColor Red; exit 1 }"

if %errorlevel% neq 0 (
    echo [ERROR] Failed to download the script from GitHub
    echo Please check:
    echo 1. Internet connection
    echo 2. GitHub URL is correct
    echo 3. Repository is public or you have access
    echo.
    pause
    exit /b 1
)

:: Verify the script was downloaded
if not exist "%TEMP_DIR%\%SCRIPT_NAME%" (
    echo [ERROR] Script file not found after download
    pause
    exit /b 1
)

echo [INFO] Setting PowerShell execution policy...

:: Set execution policy for current session
powershell.exe -Command "Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force; Write-Host '[SUCCESS] Execution policy set to Unrestricted for current session' -ForegroundColor Green"

echo.
echo [INFO] Launching PowerShell maintenance script...
echo Script location: %TEMP_DIR%\%SCRIPT_NAME%
echo.

:: Ask user for script options
echo Available options:
echo 1. Run with basic maintenance (default)
echo 2. Run with change tracking and HTML report
echo 3. Run with change tracking and JSON export
echo 4. Run with change tracking and CSV export
echo 5. Skip bloatware removal
echo 6. Skip essential apps installation
echo 7. Custom options
echo.

set /p choice="Select option (1-7) or press Enter for default: "

:: Set PowerShell parameters based on choice
set PS_PARAMS=
if "%choice%"=="2" set PS_PARAMS=-TrackChanges -GenerateReport
if "%choice%"=="3" set PS_PARAMS=-TrackChanges -GenerateReport -ExportToJson
if "%choice%"=="4" set PS_PARAMS=-TrackChanges -GenerateReport -ExportToCSV
if "%choice%"=="5" set PS_PARAMS=-SkipBloatwareRemoval
if "%choice%"=="6" set PS_PARAMS=-SkipEssentialApps
if "%choice%"=="7" (
    echo.
    echo Enter custom parameters (e.g., -TrackChanges -SkipBloatwareRemoval):
    set /p PS_PARAMS="Parameters: "
)

echo.
echo [INFO] Executing PowerShell script with parameters: %PS_PARAMS%
echo =====================================================

:: Execute the PowerShell script
powershell.exe -ExecutionPolicy Unrestricted -File "%TEMP_DIR%\%SCRIPT_NAME%" %PS_PARAMS%

set SCRIPT_EXIT_CODE=%errorlevel%

echo.
echo =====================================================
if %SCRIPT_EXIT_CODE% equ 0 (
    echo [SUCCESS] System maintenance completed successfully!
) else (
    echo [WARNING] System maintenance completed with warnings/errors (Exit Code: %SCRIPT_EXIT_CODE%^)
)

:: Ask if user wants to keep the downloaded script
echo.
set /p keep_script="Keep downloaded script for future use? (Y/N): "
if /i "%keep_script%"=="N" (
    echo [INFO] Cleaning up temporary files...
    rmdir /s /q "%TEMP_DIR%" 2>nul
    if exist "%TEMP_DIR%" (
        echo [WARNING] Could not delete temporary directory: %TEMP_DIR%
    ) else (
        echo [SUCCESS] Temporary files cleaned up
    )
) else (
    echo [INFO] Script preserved at: %TEMP_DIR%\%SCRIPT_NAME%
    echo You can run it directly next time with:
    echo powershell.exe -ExecutionPolicy Unrestricted -File "%TEMP_DIR%\%SCRIPT_NAME%"
)

echo.
echo [INFO] Execution completed. Press any key to exit...
pause >nul
