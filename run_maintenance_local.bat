@echo off
:: =====================[ LOCAL SYSTEM MAINTENANCE RUNNER ]====================
:: Purpose: Execute the local system maintenance script with proper permissions
:: Usage: Run as Administrator for full functionality
:: ============================================================================

echo =====================[ LOCAL SYSTEM MAINTENANCE RUNNER ]====================
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
set SCRIPT_NAME=system_maintenance_simplified.ps1
set SCRIPT_PATH=%SCRIPT_DIR%%SCRIPT_NAME%

:: Check if the PowerShell script exists
if not exist "%SCRIPT_PATH%" (
    echo [ERROR] Script not found: %SCRIPT_PATH%
    echo Please ensure the PowerShell script is in the same directory as this batch file.
    echo.
    pause
    exit /b 1
)

echo [INFO] Found script: %SCRIPT_NAME%
echo [INFO] Setting PowerShell execution policy...

:: Set execution policy for current session
powershell.exe -Command "Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force; Write-Host '[SUCCESS] Execution policy set to Unrestricted for current session' -ForegroundColor Green"

echo.
echo [INFO] Launching PowerShell maintenance script...
echo.

:: Ask user for script options
echo Available options:
echo 1. Run with basic maintenance (default)
echo 2. Run with change tracking and HTML report
echo 3. Run with change tracking and JSON export
echo 4. Run with change tracking and CSV export
echo 5. Skip bloatware removal
echo 6. Skip essential apps installation
echo 7. Delete temp files after completion
echo 8. Custom options
echo.

set /p choice="Select option (1-8) or press Enter for default: "

:: Set PowerShell parameters based on choice
set PS_PARAMS=
if "%choice%"=="2" set PS_PARAMS=-TrackChanges -GenerateReport
if "%choice%"=="3" set PS_PARAMS=-TrackChanges -GenerateReport -ExportToJson
if "%choice%"=="4" set PS_PARAMS=-TrackChanges -GenerateReport -ExportToCSV
if "%choice%"=="5" set PS_PARAMS=-SkipBloatwareRemoval
if "%choice%"=="6" set PS_PARAMS=-SkipEssentialApps
if "%choice%"=="7" set PS_PARAMS=-DeleteTempFiles
if "%choice%"=="8" (
    echo.
    echo Enter custom parameters (e.g., -TrackChanges -SkipBloatwareRemoval -DeleteTempFiles):
    set /p PS_PARAMS="Parameters: "
)

echo.
echo [INFO] Executing PowerShell script with parameters: %PS_PARAMS%
echo =====================================================

:: Execute the PowerShell script using PowerShell 5 specifically
powershell.exe -Version 5.1 -ExecutionPolicy Unrestricted -File "%SCRIPT_PATH%" %PS_PARAMS%

set SCRIPT_EXIT_CODE=%errorlevel%

echo.
echo =====================================================
if %SCRIPT_EXIT_CODE% equ 0 (
    echo [SUCCESS] System maintenance completed successfully!
) else (
    echo [WARNING] System maintenance completed with warnings/errors (Exit Code: %SCRIPT_EXIT_CODE%^)
)

echo.
echo [INFO] Execution completed. Press any key to exit...
pause >nul
