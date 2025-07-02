@echo off
:: =====================[ ADVANCED SYSTEM MAINTENANCE RUNNER ]====================
:: Purpose: Download from GitHub OR run local system maintenance script
:: Usage: Run as Administrator for full functionality
:: Arguments: 
::   -local : Use local script instead of downloading from GitHub
::   -url <github_url> : Custom GitHub URL
:: ===============================================================================

setlocal enabledelayedexpansion

echo =====================[ ADVANCED SYSTEM MAINTENANCE RUNNER ]====================
echo.

:: Parse command line arguments
set USE_LOCAL=0
set CUSTOM_URL=
set GITHUB_USER=YOUR_USERNAME
set GITHUB_REPO=YOUR_REPO

:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="-local" (
    set USE_LOCAL=1
    shift
    goto :parse_args
)
if /i "%~1"=="-url" (
    set CUSTOM_URL=%~2
    shift
    shift
    goto :parse_args
)
shift
goto :parse_args
:args_done

:: Check if running as administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script must be run as Administrator!
    echo Right-click and select "Run as administrator"
    echo.
    echo Usage examples:
    echo   %~nx0                    ^(Download from GitHub^)
    echo   %~nx0 -local             ^(Use local script^)
    echo   %~nx0 -url https://...   ^(Custom GitHub URL^)
    echo.
    pause
    exit /b 1
)

echo [INFO] Running as Administrator - OK
echo.

:: Set variables
set SCRIPT_DIR=%~dp0
set SCRIPT_NAME=system_maintenance_simplified.ps1
set LOCAL_SCRIPT=%SCRIPT_DIR%%SCRIPT_NAME%
set TEMP_DIR=%SCRIPT_DIR%temp_download
set DOWNLOADED_SCRIPT=%TEMP_DIR%\%SCRIPT_NAME%

:: Determine script source and path
if %USE_LOCAL% equ 1 (
    echo [INFO] Using LOCAL script mode
    set SCRIPT_TO_RUN=%LOCAL_SCRIPT%
    
    if not exist "!SCRIPT_TO_RUN!" (
        echo [ERROR] Local script not found: !SCRIPT_TO_RUN!
        echo Please ensure the PowerShell script is in the same directory.
        pause
        exit /b 1
    )
    echo [SUCCESS] Found local script: %SCRIPT_NAME%
) else (
    echo [INFO] Using GITHUB download mode
    
    :: Set GitHub URL
    if defined CUSTOM_URL (
        set GITHUB_URL=!CUSTOM_URL!
        echo [INFO] Using custom URL: !GITHUB_URL!
    ) else (
        set GITHUB_URL=https://raw.githubusercontent.com/!GITHUB_USER!/!GITHUB_REPO!/main/!SCRIPT_NAME!
        echo [INFO] Using default GitHub URL
        echo [WARNING] Please update GITHUB_USER and GITHUB_REPO variables in this script
        echo Current URL: !GITHUB_URL!
    )
    
    set SCRIPT_TO_RUN=%DOWNLOADED_SCRIPT%
    
    :: Create temporary directory
    if not exist "%TEMP_DIR%" (
        mkdir "%TEMP_DIR%"
        echo [INFO] Created temporary directory
    )
    
    echo [INFO] Downloading script from GitHub...
    
    :: Download the script
    powershell.exe -Command "try { Invoke-WebRequest -Uri '!GITHUB_URL!' -OutFile '!DOWNLOADED_SCRIPT!' -UseBasicParsing; Write-Host '[SUCCESS] Script downloaded successfully' -ForegroundColor Green } catch { Write-Host '[ERROR] Download failed:' $_.Exception.Message -ForegroundColor Red; exit 1 }"
    
    if !errorlevel! neq 0 (
        echo [ERROR] Failed to download script from GitHub
        echo.
        echo Troubleshooting:
        echo 1. Check internet connection
        echo 2. Verify GitHub URL is correct
        echo 3. Ensure repository is public or accessible
        echo 4. Try using -local flag to run local script instead
        echo.
        pause
        exit /b 1
    )
    
    if not exist "!SCRIPT_TO_RUN!" (
        echo [ERROR] Downloaded script not found
        pause
        exit /b 1
    )
)

echo.
echo [INFO] Setting PowerShell execution policy...

:: Set execution policy
powershell.exe -Command "Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force; Write-Host '[SUCCESS] Execution policy set for current session' -ForegroundColor Green"

echo.
echo [INFO] PowerShell script ready: %SCRIPT_TO_RUN%
echo.

:: Interactive options menu
echo ==================[ MAINTENANCE OPTIONS ]==================
echo 1. Basic maintenance (default)
echo 2. Full maintenance with HTML report
echo 3. Full maintenance with JSON export  
echo 4. Full maintenance with CSV export
echo 5. Maintenance without bloatware removal
echo 6. Maintenance without essential apps
echo 7. Quick cleanup (temp files deleted after)
echo 8. Full tracking with all reports
echo 9. Custom parameters
echo 0. Show help for all available parameters
echo ==========================================================
echo.

set /p choice="Select option (0-9) or press Enter for basic: "

:: Set parameters based on choice
set PS_PARAMS=
if "%choice%"=="1" set PS_PARAMS=
if "%choice%"=="2" set PS_PARAMS=-TrackChanges -GenerateReport
if "%choice%"=="3" set PS_PARAMS=-TrackChanges -GenerateReport -ExportToJson
if "%choice%"=="4" set PS_PARAMS=-TrackChanges -GenerateReport -ExportToCSV
if "%choice%"=="5" set PS_PARAMS=-SkipBloatwareRemoval
if "%choice%"=="6" set PS_PARAMS=-SkipEssentialApps
if "%choice%"=="7" set PS_PARAMS=-DeleteTempFiles
if "%choice%"=="8" set PS_PARAMS=-TrackChanges -GenerateReport -ExportToJson -ExportToCSV
if "%choice%"=="9" (
    echo.
    echo Enter custom parameters:
    echo Examples: -TrackChanges -SkipBloatwareRemoval -DeleteTempFiles
    echo           -GenerateReport -ExportToJson -CustomTasksFile "tasks.json"
    set /p PS_PARAMS="Parameters: "
)
if "%choice%"=="0" (
    echo.
    echo ==================[ AVAILABLE PARAMETERS ]==================
    echo -DeleteTempFiles          : Delete temporary files after completion
    echo -SkipBloatwareRemoval     : Skip removal of bloatware applications  
    echo -SkipEssentialApps        : Skip installation of essential apps
    echo -GenerateReport           : Generate maintenance reports
    echo -TrackChanges             : Track system changes before/after
    echo -ExportToJson             : Export data to JSON format
    echo -ExportToCSV              : Export data to CSV format
    echo -CustomTasksFile "file"   : Load custom tasks from JSON file
    echo ============================================================
    echo.
    set /p PS_PARAMS="Enter parameters or press Enter for basic: "
)

echo.
echo [INFO] Executing maintenance script...
echo Script: %SCRIPT_TO_RUN%
echo Parameters: %PS_PARAMS%
echo PowerShell Version: 5.1
echo =====================================================

:: Execute the script with PowerShell 5.1
powershell.exe -Version 5.1 -ExecutionPolicy Unrestricted -NoProfile -File "%SCRIPT_TO_RUN%" %PS_PARAMS%

set SCRIPT_EXIT_CODE=%errorlevel%

echo.
echo =====================================================
if %SCRIPT_EXIT_CODE% equ 0 (
    echo [SUCCESS] System maintenance completed successfully!
) else (
    echo [WARNING] Maintenance completed with warnings/errors (Exit Code: %SCRIPT_EXIT_CODE%^)
)

:: Cleanup for downloaded scripts
if %USE_LOCAL% equ 0 (
    echo.
    set /p keep_script="Keep downloaded script for future use? (Y/N): "
    if /i "!keep_script!"=="N" (
        echo [INFO] Cleaning up temporary files...
        rmdir /s /q "%TEMP_DIR%" 2>nul
        if exist "%TEMP_DIR%" (
            echo [WARNING] Could not delete: %TEMP_DIR%
        ) else (
            echo [SUCCESS] Temporary files cleaned up
        )
    ) else (
        echo [INFO] Script preserved at: %DOWNLOADED_SCRIPT%
        echo [TIP] Next time you can use: %~nx0 -local
    )
)

echo.
echo [INFO] Session completed. Press any key to exit...
pause >nul

endlocal
