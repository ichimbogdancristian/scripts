#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Unified System Maintenance Script with Monolithic Policy Control

.DESCRIPTION
    A comprehensive Windows system maintenance script that follows a monolithic architecture
    with centralized policy control. All tasks are modular, robust, and error-checked.

.PARAMETER Tasks
    Array of task names to execute. If not specified, all tasks will run.

.PARAMETER DeleteTempFiles
    Switch to delete temporary files after execution.

.PARAMETER ReportOnly
    Switch to generate only reports without making system changes.

.EXAMPLE
    .\xxx.ps1
    Runs all maintenance tasks

.EXAMPLE
    .\xxx.ps1 -Tasks @('SystemInventory', 'RemoveBloatware') -DeleteTempFiles
    Runs specific tasks and cleans up temp files

.NOTES
    Version: 1.0
    Author: System Maintenance Policy
    Created: July 2, 2025
    Requires: PowerShell 5.1+, Administrator privileges
#>

param(
    [string[]]$Tasks = @(),
    [switch]$DeleteTempFiles,
    [switch]$ReportOnly
)

# =====================[ SILENT EXECUTION CONFIGURATION ]====================
# Ensure no interactive prompts or popups appear during script execution
$ErrorActionPreference = 'Continue'
$WarningPreference = 'Continue'
$InformationPreference = 'Continue'

# =====================[ SCRIPT MAP FOR NAVIGATION ]====================
<#
NAVIGATION MAP:
Line   50: [UNIFIED POLICY CONTROLLER] - Main execution controller
Line  100: [GLOBALS & INITIALIZATION] - Global variables and initialization
Line  200: [LOGGING SYSTEM] - Centralized logging functions
Line  300: [ERROR HANDLING] - Global error handling and recovery
Line  400: [CENTRAL COORDINATION POLICY] - Task 1: Global lists management
Line  500: [SYSTEM PROTECTION] - Task 2: Restore points and safety
Line  600: [PACKAGE MANAGER SETUP] - Task 3: Winget and Chocolatey
Line  700: [SYSTEM INVENTORY] - Task 4: Hardware/software collection
Line  800: [REMOVE BLOATWARE] - Task 5: Bloatware removal
Line  900: [INSTALL ESSENTIALS] - Task 6: Essential apps installation
Line 1000: [UPGRADE PACKAGES] - Task 7: Package updates
Line 1100: [PRIVACY & TELEMETRY] - Task 8: Privacy configuration
Line 1200: [WINDOWS UPDATE] - Task 9: Windows updates
Line 1300: [RESTORE POINT & CLEANUP] - Task 10: Cleanup operations
Line 1400: [HTML REPORT] - Task 11: Report generation
Line 1500: [REBOOT CHECK] - Task 12: Reboot management
Line 1600: [UTILITY FUNCTIONS] - Helper functions
Line 1700: [MAIN EXECUTION] - Script entry point
#>

# =====================[ UNIFIED POLICY CONTROLLER ]==================== 
# Main controller that orchestrates all tasks with unified policy

function Invoke-SystemMaintenancePolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$TaskList = @(),
        
        [Parameter(Mandatory = $false)]
        [switch]$CleanupTempFiles,
        
        [Parameter(Mandatory = $false)]
        [switch]$ReportOnlyMode
    )

    # Define all available tasks in execution order
    $AllTasks = @(
        'Initialize-CentralCoordinationPolicy',
        'Initialize-SystemProtection',
        'Initialize-PackageManagers',
        'Invoke-SystemInventory',
        'Remove-SystemBloatware',
        'Install-EssentialApplications',
        'Update-SystemPackages',
        'Set-PrivacyTelemetrySettings',
        'Install-WindowsUpdates',
        'Invoke-SystemCleanup',
        'New-HTMLReport',
        'Test-RebootRequirement'
    )

    # Use all tasks if none specified
    if (-not $TaskList -or $TaskList.Count -eq 0) {
        $TaskList = $AllTasks
    }

    # Initialize global context
    $Context = Initialize-GlobalContext -ReportOnly:$ReportOnlyMode
    


    try {
        Write-PolicyLog -Context $Context -Message "=== SYSTEM MAINTENANCE POLICY STARTED ===" -Level 'INFO'
        Write-PolicyLog -Context $Context -Message "Tasks to execute: $($TaskList -join ', ')" -Level 'INFO'
        
        # Execute each task with unified error handling
        foreach ($TaskName in $TaskList) {
            if ($TaskName -in $AllTasks) {
                Invoke-PolicyTask -Context $Context -TaskName $TaskName
            } else {
                Write-PolicyLog -Context $Context -Message "Unknown task: $TaskName" -Level 'WARNING'
            }
        }

        Write-PolicyLog -Context $Context -Message "=== SYSTEM MAINTENANCE POLICY COMPLETED ===" -Level 'SUCCESS'
        
    } catch {
        Write-PolicyLog -Context $Context -Message "Critical error in policy execution: $($_.Exception.Message)" -Level 'ERROR'
        Resolve-CriticalError -Context $Context -Exception $_
    } finally {
        # Always perform cleanup
        Complete-PolicyExecution -Context $Context -DeleteTempFiles:$CleanupTempFiles
    }
}

# =====================[ GLOBALS & INITIALIZATION ]==================== 
# Global variables, constants, and initialization functions

# Global Constants
$Script:SCRIPT_VERSION = "1.0.0"
$Script:SCRIPT_NAME = "Unified System Maintenance Policy"
$Script:TEMP_FOLDER_NAME = "SystemMaintenance_Temp"
$Script:LOG_FILE_NAME = "SystemMaintenance.log"
$Script:TRANSCRIPT_FILE_NAME = "transcript.txt"
$Script:REPORT_FOLDER_NAME = "Reports"

# Global Configuration
$Script:CONFIG = @{
    MaxRestorePoints = 5
    MaxLogSizeMB = 50
    RetryAttempts = 3
    TimeoutSeconds = 300
    ReportGenerationEnabled = $true
    VerboseLogging = $true
}

# Essential Applications List (embedded for reliability)
$Script:ESSENTIAL_APPS = @(
    'Google.Chrome',
    'Mozilla.Firefox',
    'Microsoft.Edge',
    '7zip.7zip',
    'Adobe.Acrobat.Reader.64-bit',
    'Notepad++.Notepad++',
    'Microsoft.WindowsTerminal',
    'WinRAR.WinRAR'
)

function Initialize-GlobalContext {
    [CmdletBinding()]
    param(
        [switch]$ReportOnly
    )

    $Context = @{
        # Core Properties
        StartTime = Get-Date
        ScriptPath = $PSScriptRoot
        ReportOnlyMode = $ReportOnly.IsPresent
        TaskResults = @{
        }
        Errors = @()
        Warnings = @()
        
        # Paths
        TempFolder = $null
        LogPath = $null
        TranscriptPath = $null
        ReportsFolder = $null
        
        # Data Collections
        BloatwareList = @()
        EssentialAppsList = $Script:ESSENTIAL_APPS | ForEach-Object { $_ }
        InstalledApplications = @()
        SystemInventory = @{
        }
        
        # Flags and Status
        RestorePointCreated = $false
        RebootRequired = $false
        PackageManagersReady = $false
        
        # Statistics
        Stats = @{
            BloatwareRemoved = 0
            EssentialsInstalled = 0
            PackagesUpdated = 0
            SpaceFreed = 0
            ErrorsEncountered = 0
            WarningsGenerated = 0
        }
    }

    # Initialize folder structure
    Initialize-FolderStructure -Context $Context
    
    # Initialize logging
    Initialize-LoggingSystem -Context $Context
    
    # Load bloatware list
    Initialize-BloatwareList -Context $Context
    
    return $Context
}

function Initialize-FolderStructure {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    try {
        # Create main temp folder
        $Context.TempFolder = Join-Path $Context.ScriptPath $Script:TEMP_FOLDER_NAME
        if (-not (Test-Path $Context.TempFolder)) {
            New-Item -ItemType Directory -Path $Context.TempFolder -Force | Out-Null
        }

        # Create reports subfolder
        $Context.ReportsFolder = Join-Path $Context.TempFolder $Script:REPORT_FOLDER_NAME
        if (-not (Test-Path $Context.ReportsFolder)) {
            New-Item -ItemType Directory -Path $Context.ReportsFolder -Force | Out-Null
        }

        # Set file paths
        $Context.LogPath = Join-Path $Context.TempFolder $Script:LOG_FILE_NAME
        $Context.TranscriptPath = Join-Path $Context.TempFolder $Script:TRANSCRIPT_FILE_NAME

    } catch {
        Write-Error "Failed to initialize folder structure: $($_.Exception.Message)"
        throw
    }
}

function Initialize-BloatwareList {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    try {
        # Try to load from Bloatware.txt file first
        $bloatwareFile = Join-Path $Context.ScriptPath "Bloatware.txt"
        
        if (Test-Path $bloatwareFile) {
            $Context.BloatwareList = Get-Content $bloatwareFile | 
                Where-Object { $_ -and $_.Trim() -ne '' } |
                ForEach-Object { $_.Trim().Trim("'").Trim('"') } |
                Select-Object -Unique
                
            Write-PolicyLog -Context $Context -Message "Loaded $($Context.BloatwareList.Count) bloatware entries from file" -Level 'INFO'
        } else {
            # Fallback to embedded list
            $Context.BloatwareList = Get-EmbeddedBloatwareList
            Write-PolicyLog -Context $Context -Message "Using embedded bloatware list with $($Context.BloatwareList.Count) entries" -Level 'INFO'
        }
        
    } catch {
        Write-PolicyLog -Context $Context -Message "Error loading bloatware list: $($_.Exception.Message)" -Level 'ERROR' -Task 'COORDINATION'
        $Context.BloatwareList = @()
    }
}

function Get-EmbeddedBloatwareList {
    return @(
        'Acer.AcerCollection',
        'Acer.AcerConfigurationManager',
        'Acer.AcerPortal',
        'Acer.AcerPowerManagement',
        'Acer.AcerQuickAccess',
        'Acer.AcerUEIPFramework',
        'Acer.AcerUserExperienceImprovementProgram',
        'Adobe.AdobeCreativeCloud',
        'Adobe.AdobeExpress',
        'Adobe.AdobeGenuineService',
        'Amazon.AmazonPrimeVideo',
        'ASUS.ASUSGiftBox',
        'ASUS.ASUSLiveUpdate',
        'ASUS.ASUSSplendidVideoEnhancementTechnology',
        'ASUS.ASUSWebStorage',
        'ASUS.ASUSZenAnywhere',
        'ASUS.ASUSZenLink',
        'Astian.Midori',
        'AvantBrowser.AvantBrowser',
        'Avast.AvastFreeAntivirus',
        'AVG.AVGAntiVirusFree',
        'Avira.Avira',
        'Baidu.BaiduBrowser',
        'Baidu.PCAppStore',
        'Basilisk.Basilisk',
        'Bitdefender.Bitdefender',
        'Blisk.Blisk',
        'Booking.com.Booking',
        'BraveSoftware.BraveBrowser',
        'CentBrowser.CentBrowser',
        'Cliqz.Cliqz',
        'Coowon.Coowon',
        'CoolNovo.CoolNovo',
        'CyberLink.MediaSuite',
        'CyberLink.Power2Go',
        'CyberLink.PowerDirector',
        'CyberLink.PowerDVD',
        'CyberLink.YouCam',
        'Dell.CustomerConnect',
        'Dell.DellDigitalDelivery',
        'Dell.DellFoundationServices',
        'Dell.DellHelpAndSupport',
        'Dell.DellMobileConnect',
        'Dell.DellPowerManager',
        'Dell.DellProductRegistration',
        'Dell.DellSupportAssist',
        'Dell.DellUpdate',
        'DigitalPersona.EpicPrivacyBrowser',
        'Disney.DisneyPlus',
        'Dooble.Dooble',
        'DriverPack.DriverPackSolution',
        'ESET.ESETNOD32Antivirus',
        'Evernote.Evernote',
        'ExpressVPN.ExpressVPN',
        'Facebook.Facebook',
        'FenrirInc.Sleipnir',
        'FlashPeak.SlimBrowser',
        'FlashPeak.Slimjet',
        'Foxit.FoxitPDFReader',
        'Gameloft.MarchofEmpires',
        'G5Entertainment.HiddenCity',
        'GhostBrowser.GhostBrowser',
        'Google.YouTube',
        'HP.HP3DDriveGuard',
        'HP.HPAudioSwitch',
        'HP.HPClientSecurityManager',
        'HP.HPConnectionOptimizer',
        'HP.HPDocumentation',
        'HP.HPDropboxPlugin',
        'HP.HPePrintSW',
        'HP.HPJumpStart',
        'HP.HPJumpStartApps',
        'HP.HPJumpStartLaunch',
        'HP.HPRegistrationService',
        'HP.HPSupportSolutionsFramework',
        'HP.HPSureConnect',
        'HP.HPSystemEventUtility',
        'HP.HPWelcome',
        'HewlettPackard.SupportAssistant',
        'Hulu.Hulu',
        'Instagram.Instagram',
        'IOBit.AdvancedSystemCare',
        'IOBit.DriverBooster',
        'KDE.Falkon',
        'Kaspersky.Kaspersky',
        'KeeperSecurity.Keeper',
        'king.com.BubbleWitch',
        'king.com.CandyCrush',
        'king.com.CandyCrushFriends',
        'king.com.CandyCrushSaga',
        'king.com.CandyCrushSodaSaga',
        'king.com.FarmHeroes',
        'king.com.FarmHeroesSaga',
        'Lenovo.AppExplorer',
        'Lenovo.LenovoCompanion',
        'Lenovo.LenovoExperienceImprovement',
        'Lenovo.LenovoFamilyCloud',
        'Lenovo.LenovoHotkeys',
        'Lenovo.LenovoMigrationAssistant',
        'Lenovo.LenovoModernIMController',
        'Lenovo.LenovoServiceBridge',
        'Lenovo.LenovoSolutionCenter',
        'Lenovo.LenovoUtility',
        'Lenovo.LenovoVantage',
        'Lenovo.LenovoVoice',
        'Lenovo.LenovoWiFiSecurity',
        'LinkedIn.LinkedIn',
        'Lunascape.Lunascape',
        'Maxthon.Maxthon',
        'McAfee.LiveSafe',
        'McAfee.Livesafe',
        'McAfee.SafeConnect',
        'McAfee.Security',
        'McAfee.WebAdvisor',
        'Microsoft.3DBuilder',
        'Microsoft.Advertising.Xaml',
        'Microsoft.BingFinance',
        'Microsoft.BingFoodAndDrink',
        'Microsoft.BingHealthAndFitness',
        'Microsoft.BingNews',
        'Microsoft.BingSports',
        'Microsoft.BingTravel',
        'Microsoft.BingWeather',
        'Microsoft.GetHelp',
        'Microsoft.Getstarted',
        'Microsoft.Microsoft3DViewer',
        'Microsoft.MicrosoftOfficeHub',
        'Microsoft.MicrosoftPowerBIForWindows',
        'Microsoft.MicrosoftSolitaireCollection',
        'Microsoft.MinecraftUWP',
        'Microsoft.MixedReality.Portal',
        'Microsoft.NetworkSpeedTest',
        'Microsoft.News',
        'Microsoft.Office.OneNote',
        'Microsoft.Office.Sway',
        'Microsoft.OneConnect',
        'Microsoft.OneDrive',
        'Microsoft.People',
        'Microsoft.Print3D',
        'Microsoft.ScreenSketch',
        'Microsoft.SkypeApp',
        'Microsoft.SoundRecorder',
        'Microsoft.StickyNotes',
        'Microsoft.Wallet',
        'Microsoft.Whiteboard',
        'Microsoft.WindowsFeedback',
        'Microsoft.WindowsFeedbackHub',
        'Microsoft.WindowsMaps',
        'Microsoft.WindowsReadingList',
        'Microsoft.WindowsSoundRecorder',
        'Microsoft.Xbox.TCUI',
        'Microsoft.XboxApp',
        'Microsoft.XboxGameOverlay',
        'Microsoft.XboxGamingOverlay',
        'Microsoft.XboxIdentityProvider',
        'Microsoft.XboxSpeechToTextOverlay',
        'Microsoft.ZuneMusic',
        'Microsoft.ZuneVideo',
        'Mozilla.SeaMonkey',
        'Norton.OnlineBackup',
        'Norton.Security',
        'Opera.Opera',
        'Opera.OperaGX',
        'Orbitum.Orbitum',
        'OtterBrowser.OtterBrowser',
        'PaleMoon.PaleMoon',
        'PCAccelerate.PCAcceleratePro',
        'PCOptimizer.PCOptimizerPro',
        'PicsArt.PicsartPhotoStudio',
        'Piriform.CCleaner',
        'Polarity.Polarity',
        'Power2Go.Power2Go',
        'PowerDirector.PowerDirector',
        'QupZilla.QupZilla',
        'QuteBrowser.QuteBrowser',
        'RandomSaladGamesLLC.SimpleSolitaire',
        'Reimage.ReimageRepair',
        'RoyalRevolt2.RoyalRevolt2',
        'Sleipnir.Sleipnir',
        'SlingTV.Sling',
        'Sogou.SogouExplorer',
        'Spotify.Spotify',
        'SRWare.Iron',
        'Sputnik.Sputnik',
        'Superbird.Superbird',
        'TheTorProject.TorBrowser',
        'ThumbmunkeysLtd.PhototasticCollage',
        'TikTok.TikTok',
        'TorchMediaInc.Torch',
        'TripAdvisor.TripAdvisor',
        'Twitter.Twitter',
        'UCWeb.UCBrowser',
        'VivaldiTechnologies.Vivaldi',
        'Waterfox.Waterfox',
        'WildTangent.WildTangentGamesApp',
        'WildTangent.WildTangentHelper',
        'WPSOffice.WPSOffice',
        'Yandex.YandexBrowser'
    )
}

# =====================[ LOGGING SYSTEM ]==================== 
# Centralized logging functions

function Initialize-LoggingSystem {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    try {
        # Start transcript for complete session recording
        Start-Transcript -Path $Context.TranscriptPath -Append -Force | Out-Null
        
        # Initialize log file with header
        $logHeader = @"
=== SYSTEM MAINTENANCE POLICY LOG ===
Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Script: $Script:SCRIPT_NAME v$Script:SCRIPT_VERSION
Computer: $env:COMPUTERNAME
User: $env:USERNAME
PowerShell: $($PSVersionTable.PSVersion)
============================================

"@
        Add-Content -Path $Context.LogPath -Value $logHeader -Encoding UTF8
        
        Write-PolicyLog -Context $Context -Message "Logging system initialized" -Level 'INFO'
        
    } catch {
        Write-Error "Failed to initialize logging system: $($_.Exception.Message)"
        throw
    }
}

function Write-PolicyLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Context,
        
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS', 'DEBUG')]
        [string]$Level = 'INFO',
        
        [Parameter(Mandatory = $false)]
        [string]$Task = 'SYSTEM'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] [$Task] $Message"
    
    # Write to log file
    try {
        Add-Content -Path $Context.LogPath -Value $logEntry -Encoding UTF8
    } catch {
        # Fallback to console if log file unavailable
        Write-Host $logEntry
    }
    
    # Console output with color coding
    switch ($Level) {
        'ERROR' {
            Write-Host $logEntry -ForegroundColor Red
            $Context.Errors += @{
                Timestamp = $timestamp
                Task = $Task
                Message = $Message
            }
            $Context.Stats.ErrorsEncountered++
        }
        'WARNING' {
            Write-Host $logEntry -ForegroundColor Yellow
            $Context.Warnings += @{
                Timestamp = $timestamp
                Task = $Task
                Message = $Message
            }
            $Context.Stats.WarningsGenerated++
        }
        'SUCCESS' {
            Write-Host $logEntry -ForegroundColor Green
        }
        'DEBUG' {
            if ($Script:CONFIG.VerboseLogging) {
                Write-Host $logEntry -ForegroundColor Cyan
            }
        }
        default {
            Write-Host $logEntry -ForegroundColor White
        }
    }
}

function Write-TaskProgress {
    [CmdletBinding()]
    param(
        [hashtable]$Context,
        [string]$TaskName,
        [string]$Status,
        [int]$PercentComplete = 0
    )
    
    $progressMessage = "[$TaskName] $Status"
    if ($PercentComplete -gt 0) {
        $progressMessage += " ($PercentComplete%)"
    }
    
    Write-PolicyLog -Context $Context -Message $progressMessage -Level 'INFO' -Task $TaskName
    Write-Progress -Activity "System Maintenance" -Status $progressMessage -PercentComplete $PercentComplete
}

function Get-LogSummary {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    $endTime = Get-Date
    $duration = $endTime - $Context.StartTime
    
    return @{
        StartTime = $Context.StartTime
        EndTime = $endTime
        Duration = $duration
        TotalErrors = $Context.Stats.ErrorsEncountered
        TotalWarnings = $Context.Stats.WarningsGenerated
        BloatwareRemoved = $Context.Stats.BloatwareRemoved
        EssentialsInstalled = $Context.Stats.EssentialsInstalled
        PackagesUpdated = $Context.Stats.PackagesUpdated
        SpaceFreed = $Context.Stats.SpaceFreed
        RebootRequired = $Context.RebootRequired
    }
}

# =====================[ ERROR HANDLING ]==================== 
# Global error handling and recovery

function Resolve-CriticalError {
    [CmdletBinding()]
    param(
        [hashtable]$Context,
        [System.Exception]$Exception,
        [string]$TaskName = 'UNKNOWN'
    )
    
    $errorDetails = @{
        TaskName = $TaskName
        Message = $Exception.Message
        StackTrace = $Exception.StackTrace
        Timestamp = Get-Date
        ScriptLineNumber = $Exception.InvocationInfo.ScriptLineNumber
        CommandName = $Exception.InvocationInfo.MyCommand.Name
    }
    
    Write-PolicyLog -Context $Context -Message "CRITICAL ERROR in $TaskName`: $($Exception.Message)" -Level 'ERROR' -Task $TaskName
    Write-PolicyLog -Context $Context -Message "Stack Trace: $($Exception.StackTrace)" -Level 'DEBUG' -Task $TaskName
    
    # Add to context for reporting
    $Context.Errors += $errorDetails
    
    # Attempt recovery based on error type
    switch ($Exception.GetType().Name) {
        'UnauthorizedAccessException' {
            Write-PolicyLog -Context $Context -Message "Access denied - ensure script is running as Administrator" -Level 'WARNING'
        }
        'FileNotFoundException' {
            Write-PolicyLog -Context $Context -Message "Required file missing - check dependencies" -Level 'WARNING'
        }
        'TimeoutException' {
            Write-PolicyLog -Context $Context -Message "Operation timed out - system may be under heavy load" -Level 'WARNING'
        }
        default {
            Write-PolicyLog -Context $Context -Message "Unexpected error type: $($Exception.GetType().Name)" -Level 'WARNING'
        }
    }
}

function Test-SystemRequirements {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    $requirements = @{
        PowerShellVersion = @{ Required = '5.1'; Current = $PSVersionTable.PSVersion.ToString() }
        AdminRights = @{ Required = $true; Current = (Test-IsAdministrator) }
        FreeSpaceGB = @{ Required = 1; Current = (Get-SystemFreeSpace) }
        InternetConnection = @{ Required = $false; Current = (Test-InternetConnection) }
    }
    
    $allRequirementsMet = $true
    
    foreach ($requirement in $requirements.GetEnumerator()) {
        $name = $requirement.Key
        $required = $requirement.Value.Required
        $current = $requirement.Value.Current
        
        $status = switch ($name) {
            'PowerShellVersion' { [version]$current -ge [version]$required }
            'AdminRights' { $current -eq $required }
            'FreeSpaceGB' { $current -ge $required }
            'InternetConnection' { $current -or -not $required }
            default { $true }
        }
        
        if ($status) {
            Write-PolicyLog -Context $Context -Message "$name`: OK ($current)" -Level 'SUCCESS'
        } else {
            Write-PolicyLog -Context $Context -Message "$name`: FAILED (Required: $required, Current: $current)" -Level 'ERROR'
            $allRequirementsMet = $false
        }
    }
    
    return $allRequirementsMet
}

function Test-IsAdministrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SystemFreeSpace {
    try {
        $drive = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $env:SystemDrive }
        return [math]::Round($drive.FreeSpace / 1GB, 2)
    } catch {
        return 0
    }
}

function Test-InternetConnection {
    try {
        $response = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue
        return $response
    } catch {
        return $false
    }
}

function Invoke-PolicyTask {
    [CmdletBinding()]
    param(
        [hashtable]$Context,
        [string]$TaskName
    )
    
    $taskStartTime = Get-Date
    
    try {
        Write-PolicyLog -Context $Context -Message "Starting task: $TaskName" -Level 'INFO' -Task $TaskName
        
        # Execute the task function by direct call
        switch ($TaskName) {
            'Initialize-CentralCoordinationPolicy' { 
                Initialize-CentralCoordinationPolicy -Context $Context 
            }
            'Initialize-SystemProtection' { 
                Initialize-SystemProtection -Context $Context 
            }
            'Initialize-PackageManagers' { 
                Initialize-PackageManagers -Context $Context 
            }
            'Invoke-SystemInventory' { 
                Invoke-SystemInventory -Context $Context 
            }
            'Remove-SystemBloatware' { 
                Remove-SystemBloatware -Context $Context 
            }
            'Install-EssentialApplications' { 
                Install-EssentialApplications -Context $Context 
            }
            'Update-SystemPackages' { 
                Update-SystemPackages -Context $Context 
            }
            'Set-PrivacyTelemetrySettings' { 
                Set-PrivacyTelemetrySettings -Context $Context 
            }
            'Install-WindowsUpdates' { 
                Install-WindowsUpdates -Context $Context 
            }
            'Invoke-SystemCleanup' { 
                Invoke-SystemCleanup -Context $Context 
            }
            'New-HTMLReport' { 
                New-HTMLReport -Context $Context 
            }
            'Test-RebootRequirement' { 
                Test-RebootRequirement -Context $Context 
            }
            default { 
                Write-PolicyLog -Context $Context -Message "Unknown task function: $TaskName" -Level 'ERROR' -Task $TaskName
                throw "Unknown task function: $TaskName"
            }
        }
        
        $taskDuration = (Get-Date) - $taskStartTime
        $Context.TaskResults[$TaskName] = @{
            Status = 'Completed'
            Duration = $taskDuration
            StartTime = $taskStartTime
            EndTime = Get-Date
        }
        
        Write-PolicyLog -Context $Context -Message "Task completed: $TaskName (Duration: $($taskDuration.ToString('mm\:ss')))" -Level 'SUCCESS' -Task $TaskName
        
    } catch {
        $taskDuration = (Get-Date) - $taskStartTime
        $Context.TaskResults[$TaskName] = @{
            Status = 'Failed'
            Duration = $taskDuration
            StartTime = $taskStartTime
            EndTime = Get-Date
            Error = $_.Exception.Message
        }
        
        Resolve-CriticalError -Context $Context -Exception $_.Exception -TaskName $TaskName
        Write-PolicyLog -Context $Context -Message "Task failed: $TaskName - continuing with next task" -Level 'WARNING' -Task $TaskName
    }
}

# =====================[ CENTRAL COORDINATION POLICY ]==================== 
# Task 1: Global lists management

function Initialize-CentralCoordinationPolicy {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    Write-PolicyLog -Context $Context -Message "Initializing Central Coordination Policy" -Level 'INFO' -Task 'COORDINATION'
    
    try {
        # Validate and process bloatware list
        if ($Context.BloatwareList.Count -eq 0) {
            Write-PolicyLog -Context $Context -Message "Warning: No bloatware list loaded" -Level 'WARNING' -Task 'COORDINATION'
        } else {
            # Remove duplicates and validate entries
            $Context.BloatwareList = $Context.BloatwareList | 
                Where-Object { $_ -and $_.Trim() -ne '' } |
                ForEach-Object { $_.Trim() } |
                Select-Object -Unique
            
            Write-PolicyLog -Context $Context -Message "Validated $($Context.BloatwareList.Count) bloatware entries" -Level 'SUCCESS' -Task 'COORDINATION'
        }
        
        # Validate essential apps list
        $Context.EssentialAppsList = $Context.EssentialAppsList | 
            Where-Object { $_ -and $_.Trim() -ne '' } |
            Select-Object -Unique
            
        Write-PolicyLog -Context $Context -Message "Validated $($Context.EssentialAppsList.Count) essential applications" -Level 'SUCCESS' -Task 'COORDINATION'
        
        # Initialize data collection structures
        $Context.SystemInventory = @{
            OS = @{}
            Hardware = @{}
            Disks = @()
            Network = @()
            InstalledApps = @()
            Services = @()
        }
        
        Write-PolicyLog -Context $Context -Message "Central Coordination Policy initialized successfully" -Level 'SUCCESS' -Task 'COORDINATION'
        
    } catch {
        $errorMsg = "Failed to initialize Central Coordination Policy: $($_.Exception.Message)"
        Write-PolicyLog -Context $Context -Message $errorMsg -Level 'ERROR' -Task 'COORDINATION'
        throw
    }
}

function Add-ToBloatwareList {
    [CmdletBinding()]
    param(
        [hashtable]$Context,
        [string[]]$Applications
    )
    
    foreach ($app in $Applications) {
        if ($app -and $app.Trim() -ne '' -and $app -notin $Context.BloatwareList) {
            $Context.BloatwareList += $app.Trim()
            Write-PolicyLog -Context $Context -Message "Added to bloatware list: $app" -Level 'INFO' -Task 'COORDINATION'
        }
    }
}

function Get-BloatwareList {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    return $Context.BloatwareList
}

# =====================[ SYSTEM PROTECTION ]==================== 
# Task 2: Restore points and safety

function Initialize-SystemProtection {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    Write-PolicyLog -Context $Context -Message "Initializing System Protection" -Level 'INFO' -Task 'PROTECTION'
    
    try {
        # Check if System Restore is enabled
        $restoreStatus = Test-SystemRestoreEnabled
        
        if (-not $restoreStatus) {
            Write-PolicyLog -Context $Context -Message "System Restore is disabled - attempting to enable" -Level 'WARNING' -Task 'PROTECTION'
            Enable-SystemRestore -Context $Context
        } else {
            Write-PolicyLog -Context $Context -Message "System Restore is already enabled" -Level 'SUCCESS' -Task 'PROTECTION'
        }
        
        # Create restore point before making changes
        if (-not $Context.ReportOnlyMode) {
            New-SystemRestorePoint -Context $Context -Description "Pre-Maintenance Restore Point"
        } else {
            Write-PolicyLog -Context $Context -Message "Report-only mode: Skipping restore point creation" -Level 'INFO' -Task 'PROTECTION'
        }
        
    } catch {
        $errorMsg = "Failed to initialize system protection: $($_.Exception.Message)"
        Write-PolicyLog -Context $Context -Message $errorMsg -Level 'ERROR' -Task 'PROTECTION'
    }
}

function Test-SystemRestoreEnabled {
    try {
        $restoreStatus = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        return $null -ne $restoreStatus
    } catch {
        return $false
    }
}

function Enable-SystemRestore {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    try {
        # Enable System Restore on system drive
        Enable-ComputerRestore -Drive "$env:SystemDrive"
        Write-PolicyLog -Context $Context -Message "System Restore enabled on $env:SystemDrive" -Level 'SUCCESS' -Task 'PROTECTION'
        
        # Configure restore point settings
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
        Set-ItemProperty -Path $regPath -Name "SystemRestorePointCreationFrequency" -Value 0 -Force
        
    } catch {
        $errorMsg = "Failed to enable System Restore: $($_.Exception.Message)"
        Write-PolicyLog -Context $Context -Message $errorMsg -Level 'ERROR' -Task 'PROTECTION'
        throw
    }
}

function New-SystemRestorePoint {
    [CmdletBinding()]
    param(
        [hashtable]$Context,
        [string]$Description = "System Maintenance Restore Point"
    )
    
    try {
        Write-PolicyLog -Context $Context -Message "Creating restore point: $Description" -Level 'INFO' -Task 'PROTECTION'
        
        # Create the restore point
        Checkpoint-Computer -Description $Description -RestorePointType "MODIFY_SETTINGS"
        $Context.RestorePointCreated = $true
        
        Write-PolicyLog -Context $Context -Message "Restore point created successfully" -Level 'SUCCESS' -Task 'PROTECTION'
        
        # Wait a moment for the restore point to be fully created
        Start-Sleep -Seconds 5
        
    } catch {
        $errorMsg = "Failed to create restore point: $($_.Exception.Message)"
        Write-PolicyLog -Context $Context -Message $errorMsg -Level 'WARNING' -Task 'PROTECTION'
        $Context.RestorePointCreated = $false
    }
}

# =====================[ PACKAGE MANAGER SETUP ]==================== 
# Task 3: Winget and Chocolatey

function Initialize-PackageManagers {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    Write-PolicyLog -Context $Context -Message "Initializing Package Managers" -Level 'INFO' -Task 'PACKAGES'
    
    $packageManagerStatus = @{
        Winget = $false
        Chocolatey = $false
    }
    
    try {
        # Check and setup Winget
        $packageManagerStatus.Winget = Initialize-Winget -Context $Context
        
        # Check and setup Chocolatey
        $packageManagerStatus.Chocolatey = Initialize-Chocolatey -Context $Context
        
        # Set global flag based on at least one package manager being available
        $Context.PackageManagersReady = $packageManagerStatus.Winget -or $packageManagerStatus.Chocolatey
        
        if ($Context.PackageManagersReady) {
            Write-PolicyLog -Context $Context -Message "Package managers initialized successfully" -Level 'SUCCESS' -Task 'PACKAGES'
        } else {
            Write-PolicyLog -Context $Context -Message "No package managers available - some features will be limited" -Level 'WARNING' -Task 'PACKAGES'
        }
        
    } catch {
        $errorMsg = "Failed to initialize package managers: $($_.Exception.Message)"
        Write-PolicyLog -Context $Context -Message $errorMsg -Level 'ERROR' -Task 'PACKAGES'
        $Context.PackageManagersReady = $false
    }
}

function Initialize-Winget {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    try {
        # Check if winget is available
        $wingetCommand = Get-Command winget -ErrorAction SilentlyContinue
        
        if ($wingetCommand) {
            Write-PolicyLog -Context $Context -Message "Winget found - checking version" -Level 'INFO' -Task 'WINGET'
            
            $wingetVersion = & winget --version
            Write-PolicyLog -Context $Context -Message "Winget version: $wingetVersion" -Level 'SUCCESS' -Task 'WINGET'
            
            # Accept source agreements silently
            & winget source update --accept-source-agreements --disable-interactivity 2>&1 | Out-Null
            
            return $true
        } else {
            Write-PolicyLog -Context $Context -Message "Winget not found - attempting installation" -Level 'WARNING' -Task 'WINGET'
            
            if (-not $Context.ReportOnlyMode) {
                Install-Winget -Context $Context
                return $true
            } else {
                Write-PolicyLog -Context $Context -Message "Report-only mode: Skipping winget installation" -Level 'INFO' -Task 'WINGET'
                return $false
            }
        }
        
    } catch {
        $errorMsg = "Error with winget setup: $($_.Exception.Message)"
        Write-PolicyLog -Context $Context -Message $errorMsg -Level 'ERROR' -Task 'WINGET'
        return $false
    }
}

function Install-Winget {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    try {
        Write-PolicyLog -Context $Context -Message "Installing winget from Microsoft Store" -Level 'INFO' -Task 'WINGET'
        
        # Install App Installer (which includes winget) from Microsoft Store
        $appInstallerUri = "ms-windows-store://pdp/?productid=9NBLGGH4NNS1"
        Start-Process $appInstallerUri -WindowStyle Hidden
        
        # Wait for potential installation
        Write-PolicyLog -Context $Context -Message "Waiting for winget installation to complete" -Level 'INFO' -Task 'WINGET'
        Start-Sleep -Seconds 30
        
        # Verify installation
        $wingetCommand = Get-Command winget -ErrorAction SilentlyContinue
        if ($wingetCommand) {
            Write-PolicyLog -Context $Context -Message "Winget installed successfully" -Level 'SUCCESS' -Task 'WINGET'
        } else {
            Write-PolicyLog -Context $Context -Message "Winget installation verification failed" -Level 'WARNING' -Task 'WINGET'
        }
        
    } catch {
        $errorMsg = "Failed to install winget: $($_.Exception.Message)"
        Write-PolicyLog -Context $Context -Message $errorMsg -Level 'ERROR' -Task 'WINGET'
        throw
    }
}

function Initialize-Chocolatey {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    try {
        # Check if chocolatey is available
        $chocoCommand = Get-Command choco -ErrorAction SilentlyContinue
        
        if ($chocoCommand) {
            Write-PolicyLog -Context $Context -Message "Chocolatey found - checking version" -Level 'INFO' -Task 'CHOCO'
            
            $chocoVersion = & choco --version
            Write-PolicyLog -Context $Context -Message "Chocolatey version: $chocoVersion" -Level 'SUCCESS' -Task 'CHOCO'
            
            return $true
        } else {
            Write-PolicyLog -Context $Context -Message "Chocolatey not found - attempting installation" -Level 'WARNING' -Task 'CHOCO'
            
            if (-not $Context.ReportOnlyMode) {
                Install-Chocolatey -Context $Context  # <-- Fix: pass the Context parameter
                return $true
            } else {
                Write-PolicyLog -Context $Context -Message "Report-only mode: Skipping Chocolatey installation" -Level 'INFO' -Task 'CHOCO'
                return $false
            }
        }
        
    } catch {
        $errorMsg = "Error with Chocolatey setup: $($_.Exception.Message)"
        Write-PolicyLog -Context $Context -Message $errorMsg -Level 'ERROR' -Task 'CHOCO'
        return $false
    }
}

# =====================[ SYSTEM INVENTORY ]==================== 
# Task 4: Hardware and software information collection

function Invoke-SystemInventory {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    Write-PolicyLog -Context $Context -Message "Starting System Inventory" -Level 'INFO' -Task 'INVENTORY'
    
    try {
        # Collect OS information
        Write-TaskProgress -Context $Context -TaskName 'INVENTORY' -Status 'Collecting OS information' -PercentComplete 10
        $Context.SystemInventory.OS = Get-OSInformation -Context $Context
        
        # Collect hardware information
        Write-TaskProgress -Context $Context -TaskName 'INVENTORY' -Status 'Collecting hardware information' -PercentComplete 25
        $Context.SystemInventory.Hardware = Get-HardwareInformation -Context $Context
        
        # Collect disk information
        Write-TaskProgress -Context $Context -TaskName 'INVENTORY' -Status 'Collecting disk information' -PercentComplete 40
        $Context.SystemInventory.Disks = Get-DiskInformation -Context $Context
        
        # Collect network information
        Write-TaskProgress -Context $Context -TaskName 'INVENTORY' -Status 'Collecting network information' -PercentComplete 55
        $Context.SystemInventory.Network = Get-NetworkInformation -Context $Context
        
        # Collect installed applications
        Write-TaskProgress -Context $Context -TaskName 'INVENTORY' -Status 'Collecting installed applications' -PercentComplete 70
        $Context.SystemInventory.InstalledApps = Get-InstalledApplications -Context $Context
        
        # Collect services information
        Write-TaskProgress -Context $Context -TaskName 'INVENTORY' -Status 'Collecting services information' -PercentComplete 85
        $Context.SystemInventory.Services = Get-ServicesInformation -Context $Context
        
        Write-TaskProgress -Context $Context -TaskName 'INVENTORY' -Status 'System inventory completed' -PercentComplete 100
        Write-PolicyLog -Context $Context -Message "System inventory completed successfully" -Level 'SUCCESS' -Task 'INVENTORY'
        
        # Save inventory to file
        $inventoryFile = Join-Path $Context.ReportsFolder "SystemInventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $Context.SystemInventory | ConvertTo-Json -Depth 10 | Out-File -FilePath $inventoryFile -Encoding UTF8
        
    } catch {
        $errorMsg = "Failed to complete system inventory: $($_.Exception.Message)"
        Write-PolicyLog -Context $Context -Message $errorMsg -Level 'ERROR' -Task 'INVENTORY'
    }
}

function Get-OSInformation {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    try {
        $osInfo = Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, WindowsBuildLabEx, 
                                                    TotalPhysicalMemory, CsProcessors, CsSystemType
        
        Write-PolicyLog -Context $Context -Message "OS: $($osInfo.WindowsProductName) ($($osInfo.WindowsVersion))" -Level 'INFO' -Task 'INVENTORY'
        return $osInfo
        
    } catch {
        Write-PolicyLog -Context $Context -Message "Failed to collect OS information: $($_.Exception.Message)" -Level 'WARNING' -Task 'INVENTORY'
        return @{
        }
    }
}

function Get-HardwareInformation {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    try {
        $hardware = @{
            Processor = Get-WmiObject -Class Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors
            Memory = Get-WmiObject -Class Win32_PhysicalMemory | Select-Object Capacity, Speed, Manufacturer
            Motherboard = Get-WmiObject -Class Win32_BaseBoard | Select-Object Manufacturer, Product, Version
            BIOS = Get-WmiObject -Class Win32_BIOS | Select-Object Manufacturer, Version, ReleaseDate
        }
        
        $cpuName = $hardware.Processor[0].Name
        $totalRAM = [math]::Round(($hardware.Memory | Measure-Object Capacity -Sum).Sum / 1GB, 2)
        
        Write-PolicyLog -Context $Context -Message "CPU: $cpuName, RAM: ${totalRAM}GB" -Level 'INFO' -Task 'INVENTORY'
        return $hardware
        
    } catch {
        Write-PolicyLog -Context $Context -Message "Failed to collect hardware information: $($_.Exception.Message)" -Level 'WARNING' -Task 'INVENTORY'
        return @{
        }
    }
}

function Get-DiskInformation {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    try {
        $disks = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | ForEach-Object {
            @{
                Drive = $_.DeviceID
                Label = $_.VolumeName
                SizeGB = [math]::Round($_.Size / 1GB, 2)
                FreeSpaceGB = [math]::Round($_.FreeSpace / 1GB, 2)
                PercentFree = [math]::Round(($_.FreeSpace / $_.Size) * 100, 1)
            }
        }
        
        foreach ($disk in $disks) {
            Write-PolicyLog -Context $Context -Message "Disk $($disk.Drive) $($disk.SizeGB)GB ($($disk.PercentFree)% free)" -Level 'INFO' -Task 'INVENTORY'
        }
        
        return $disks
        
    } catch {
        Write-PolicyLog -Context $Context -Message "Failed to collect disk information: $($_.Exception.Message)" -Level 'WARNING' -Task 'INVENTORY'
        return @()
    }
}

function Get-NetworkInformation {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object Name, InterfaceDescription, LinkSpeed
        
        Write-PolicyLog -Context $Context -Message "Found $($adapters.Count) active network adapters" -Level 'INFO' -Task 'INVENTORY'
        return $adapters
        
    } catch {
        Write-PolicyLog -Context $Context -Message "Failed to collect network information: $($_.Exception.Message)" -Level 'WARNING' -Task 'INVENTORY'
        return @()
    }
}

function Get-InstalledApplications {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    try {
        $applications = @()
        
        # Get applications from registry (traditional Win32 apps)
        $registryPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        foreach ($path in $registryPaths) {
            $apps = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | 
                    Where-Object { $_.DisplayName -and $_.DisplayName -notmatch "^(KB|Update)" } |
                    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
            $applications += $apps
        }
        
        # Get modern apps (Store apps)
        $storeApps = Get-AppxPackage | Where-Object { $_.IsFramework -eq $false } |
                     Select-Object @{N='DisplayName';E={$_.Name}}, @{N='DisplayVersion';E={$_.Version}}, @{N='Publisher';E={$_.Publisher}}
        $applications += $storeApps
        
        # Remove duplicates and sort
        $applications = $applications | Sort-Object DisplayName -Unique
        
        Write-PolicyLog -Context $Context -Message "Found $($applications.Count) installed applications" -Level 'INFO' -Task 'INVENTORY'
        return $applications
        
    } catch {
        Write-PolicyLog -Context $Context -Message "Failed to collect installed applications: $($_.Exception.Message)" -Level 'WARNING' -Task 'INVENTORY'
        return @()
    }
}

function Get-ServicesInformation {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    try {
        # Use ErrorAction SilentlyContinue to suppress PermissionDenied errors from Get-Service
        $services = Get-Service -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType, DisplayName
        $runningCount = ($services | Where-Object { $_.Status -eq 'Running' }).Count
        $stoppedCount = ($services | Where-Object { $_.Status -eq 'Stopped' }).Count
        
        Write-PolicyLog -Context $Context -Message "Services: $runningCount running, $stoppedCount stopped" -Level 'INFO' -Task 'INVENTORY'
        return $services
        
    } catch {
        Write-PolicyLog -Context $Context -Message "Failed to collect services information: $($_.Exception.Message)" -Level 'WARNING' -Task 'INVENTORY'
        return @()
    }
}

# =====================[ REMOVE BLOATWARE ]==================== 
# Task 5: Bloatware removal

function Remove-SystemBloatware {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    Write-PolicyLog -Context $Context -Message "Starting Bloatware Removal" -Level 'INFO' -Task 'BLOATWARE'
    
    if ($Context.ReportOnlyMode) {
        Write-PolicyLog -Context $Context -Message "Report-only mode: Bloatware removal will be simulated" -Level 'INFO' -Task 'BLOATWARE'
        return
    }
    
    $removalResults = @{
        Attempted = 0
        Successful = 0
        Failed = 0
        Skipped = 0
        Details = @()
    }
    
    try {
        $installedApps = $Context.SystemInventory.InstalledApps
        $bloatwareList = $Context.BloatwareList
        
        Write-PolicyLog -Context $Context -Message "Checking $($installedApps.Count) installed apps against $($bloatwareList.Count) bloatware entries" -Level 'INFO' -Task 'BLOATWARE'
        
        foreach ($bloatwareApp in $bloatwareList) {
            try {
                $matchingApps = Find-MatchingApplications -InstalledApps $installedApps -SearchPattern $bloatwareApp
                
                foreach ($app in $matchingApps) {
                    $removalResults.Attempted++
                    $removalResult = Remove-Application -Context $Context -Application $app -Method 'Auto'
                    
                    $removalResults.Details += @{
                        Name = $app.DisplayName
                        Method = $removalResult.Method
                        Success = $removalResult.Success
                        Message = $removalResult.Message
                    }
                    
                    if ($removalResult.Success) {
                        $removalResults.Successful++
                        $Context.Stats.BloatwareRemoved++
                        Write-PolicyLog -Context $Context -Message "Successfully removed: $($app.DisplayName)" -Level 'SUCCESS' -Task 'BLOATWARE'
                    } else {
                        $removalResults.Failed++
                        # Reduce log noise for common permission errors
                        if ($removalResult.Message -match "Access denied|requires higher privileges|system-protected") {
                            Write-PolicyLog -Context $Context -Message "Skipped $($app.DisplayName): Protected system app" -Level 'INFO' -Task 'BLOATWARE'
                        } else {
                            Write-PolicyLog -Context $Context -Message "Failed to remove $($app.DisplayName): $($removalResult.Message)" -Level 'WARNING' -Task 'BLOATWARE'
                        }
                    }
                }
                
            } catch {
                $removalResults.Failed++
                Write-PolicyLog -Context $Context -Message "Error processing bloatware $bloatwareApp`: $($_.Exception.Message)" -Level 'WARNING' -Task 'BLOATWARE'
            }
        }
        
        # Save removal report
        $reportFile = Join-Path $Context.ReportsFolder "BloatwareRemoval_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $removalResults | ConvertTo-Json -Depth 5 | Out-File -FilePath $reportFile -Encoding UTF8
        
        Write-PolicyLog -Context $Context -Message "Bloatware removal completed: $($removalResults.Successful) successful, $($removalResults.Failed) failed" -Level 'SUCCESS' -Task 'BLOATWARE'
        
    } catch {
        $errorMsg = "Failed to complete bloatware removal: $($_.Exception.Message)"
        Write-PolicyLog -Context $Context -Message $errorMsg -Level 'ERROR' -Task 'BLOATWARE'
    }
}

function Find-MatchingApplications {
    [CmdletBinding()]
    param(
        [array]$InstalledApps,
        [string]$SearchPattern
    )
    
    return $InstalledApps | Where-Object { 
        $_.DisplayName -like "*$SearchPattern*" -or 
        $_.DisplayName -eq $SearchPattern -or
        ($_.Publisher -and $_.Publisher -like "*$SearchPattern*")
    }
}

function Remove-Application {
    [CmdletBinding()]
    param(
        [hashtable]$Context,
        [object]$Application,
        [string]$Method = 'Auto'
    )
    
    $result = @{
        Success = $false
        Method = 'Unknown'
        Message = ''
    }
    
    try {
        # Try AppX removal first (for Store apps)
        if ($Application.PackageFamilyName -or $Application.DisplayName -match "^Microsoft\.") {
            $result = Remove-AppxApplication -Context $Context -Application $Application
            if ($result.Success) { return $result }
        }
        
        # Try winget removal
        if ($Context.PackageManagersReady) {
            $result = Remove-WingetApplication -Context $Context -Application $Application
            if ($result.Success) { return $result }
        }
        
        # Try registry uninstall string
        $result = Remove-RegistryApplication -Context $Context -Application $Application
        
        return $result
        
    } catch {
        $result.Message = "Exception during removal: $($_.Exception.Message)"
        return $result
    }
}

function Remove-AppxApplication {
    [CmdletBinding()]
    param(
        [hashtable]$Context,
        [object]$Application
    )
    
    $result = @{ Success = $false; Method = 'AppX'; Message = '' }
    
    try {
        $packageName = $Application.DisplayName
        $appxPackage = Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$packageName*" -or $_.PackageFullName -like "*$packageName*" }
        
        if ($appxPackage) {
            # Try to remove the package, but handle permission errors gracefully
            try {
                Remove-AppxPackage -Package $appxPackage.PackageFullName -ErrorAction Stop
                $result.Success = $true
                $result.Message = "Removed via AppX"
            } catch [System.UnauthorizedAccessException] {
                $result.Message = "Access denied - requires higher privileges or package is protected"
            } catch [System.Management.Automation.RuntimeException] {
                if ($_.Exception.Message -match "Access is denied") {
                    $result.Message = "Access denied - package may be system-protected"
                } else {
                    $result.Message = "AppX removal failed: $($_.Exception.Message)"
                }
            }
        } else {
            $result.Message = "No matching AppX package found"
        }
        
    } catch {
        $result.Message = "AppX removal failed: $($_.Exception.Message)"
    }
    
    return $result
}

function Remove-WingetApplication {
    [CmdletBinding()]
    param(
        [hashtable]$Context,
        [object]$Application
    )
    
    $result = @{ Success = $false; Method = 'Winget'; Message = '' }
    
    try {
        $packageName = $Application.DisplayName
        # First try to find the exact package ID
        $searchOutput = & winget search "$packageName" --exact --accept-source-agreements 2>&1
        
        if ($LASTEXITCODE -eq 0 -and $searchOutput -notmatch "No package found") {
            $wingetOutput = & winget uninstall "$packageName" --silent --accept-source-agreements --disable-interactivity 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                $result.Success = $true
                $result.Message = "Removed via winget"
            } elseif ($wingetOutput -match "requires administrator|access.*denied") {
                $result.Message = "Access denied - requires administrator privileges"
            } elseif ($wingetOutput -match "not found|No installed package found") {
                $result.Message = "Package not found in winget"
            } else {
                $result.Message = "Winget removal failed: $($wingetOutput -join ' ')"
            }
        } else {
            $result.Message = "Package not found in winget catalog"
        }
        
    } catch {
        $result.Message = "Winget removal exception: $($_.Exception.Message)"
    }
    
    return $result
}

function Remove-RegistryApplication {
    [CmdletBinding()]
    param(
        [hashtable]$Context,
        [object]$Application
    )
    
    $result = @{ Success = $false; Method = 'Registry'; Message = '' }
    
    try {
        if ($Application.UninstallString) {
            $uninstallString = $Application.UninstallString
            
            # Parse the uninstall command
            if ($uninstallString -match '"([^"]+)"(.*)') {
                $executable = $matches[1]
                $arguments = $matches[2].Trim()
                
                # Add silent flags if possible
                if ($arguments -notmatch "/S|/SILENT|/Q") {
                    $arguments += " /S"
                }
                
                Start-Process -FilePath $executable -ArgumentList $arguments -Wait -NoNewWindow -WindowStyle Hidden
                $result.Success = $true
                $result.Message = "Removed via registry uninstall string"
            } else {
                $result.Message = "Could not parse uninstall string"
            }
        } else {
            $result.Message = "No uninstall string available"
        }
        
    } catch {
        $result.Message = "Registry removal failed: $($_.Exception.Message)"
    }
    
    return $result
}

# =====================[ INSTALL ESSENTIALS ]==================== 
# Task 6: Essential applications installation

function Install-EssentialApplications {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    Write-PolicyLog -Context $Context -Message "Starting Essential Applications Installation" -Level 'INFO' -Task 'ESSENTIALS'
    
    if ($Context.ReportOnlyMode) {
        Write-PolicyLog -Context $Context -Message "Report-only mode: Essential apps installation will be simulated" -Level 'INFO' -Task 'ESSENTIALS'
        return
    }
    
    $installResults = @{
        Attempted = 0
        Successful = 0
        Failed = 0
        AlreadyInstalled = 0
        Details = @()
    }
    
    try {
        $installedApps = $Context.SystemInventory.InstalledApps
        $essentialApps = $Context.EssentialAppsList
        
        Write-PolicyLog -Context $Context -Message "Checking $($essentialApps.Count) essential applications" -Level 'INFO' -Task 'ESSENTIALS'
        
        foreach ($essentialApp in $essentialApps) {
            try {
                $isInstalled = Test-ApplicationInstalled -InstalledApps $installedApps -ApplicationName $essentialApp
                
                if ($isInstalled) {
                    $installResults.AlreadyInstalled++
                    Write-PolicyLog -Context $Context -Message "Already installed: $essentialApp" -Level 'INFO' -Task 'ESSENTIALS'
                } else {
                    $installResults.Attempted++
                    $installResult = Install-Application -Context $Context -ApplicationName $essentialApp
                    
                    $installResults.Details += @{
                        Name = $essentialApp
                        Method = $installResult.Method
                        Success = $installResult.Success
                        Message = $installResult.Message
                    }
                    
                    if ($installResult.Success) {
                        $installResults.Successful++
                        $Context.Stats.EssentialsInstalled++
                        Write-PolicyLog -Context $Context -Message "Successfully installed: $essentialApp" -Level 'SUCCESS' -Task 'ESSENTIALS'
                    } else {
                        $installResults.Failed++
                        Write-PolicyLog -Context $Context -Message "Failed to install $essentialApp`: $($installResult.Message)" -Level 'ERROR' -Task 'ESSENTIALS'
                    }
                }
                
            } catch {
                $installResults.Failed++
                Write-PolicyLog -Context $Context -Message "Error processing essential app $essentialApp`: $($_.Exception.Message)" -Level 'ERROR' -Task 'ESSENTIALS'
            }
        }
        
        # Check for office suite and install LibreOffice if none found
        if (-not (Test-OfficeSuiteInstalled -InstalledApps $installedApps)) {
            Write-PolicyLog -Context $Context -Message "No office suite detected - installing LibreOffice" -Level 'INFO' -Task 'ESSENTIALS'
            $installResult = Install-Application -Context $Context -ApplicationName 'TheDocumentFoundation.LibreOffice'
            
            if ($installResult.Success) {
                $Context.Stats.EssentialsInstalled++
                Write-PolicyLog -Context $Context -Message "LibreOffice installed successfully" -Level 'SUCCESS' -Task 'ESSENTIALS'
            }
        }
        
        # Save installation report
        $reportFile = Join-Path $Context.ReportsFolder "EssentialApps_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $installResults | ConvertTo-Json -Depth 5 | Out-File -FilePath $reportFile -Encoding UTF8
        
        Write-PolicyLog -Context $Context -Message "Essential apps installation completed: $($installResults.Successful) installed, $($installResults.Failed) failed, $($installResults.AlreadyInstalled) already present" -Level 'SUCCESS' -Task 'ESSENTIALS'
        
    } catch {
        $errorMsg = "Failed to complete essential applications installation: $($_.Exception.Message)"
        Write-PolicyLog -Context $Context -Message $errorMsg -Level 'ERROR' -Task 'ESSENTIALS'
    }
}

function Test-ApplicationInstalled {
    [CmdletBinding()]
    param(
        [array]$InstalledApps,
        [string]$ApplicationName
    )
    
    # Escape regex special characters to prevent regex errors
    $escapedAppName = [regex]::Escape($ApplicationName)
    
    return $InstalledApps | Where-Object { 
        $_.DisplayName -like "*$ApplicationName*" -or 
        $_.DisplayName -match $escapedAppName -or
        ($_.Publisher -and $_.Publisher -like "*$ApplicationName*")
    }
}

function Test-OfficeSuiteInstalled {
    [CmdletBinding()]
    param([array]$InstalledApps)
    
    $officeSuites = @('Microsoft Office', 'LibreOffice', 'OpenOffice', 'WPS Office')
    
    foreach ($suite in $officeSuites) {
        if ($InstalledApps | Where-Object { $_.DisplayName -like "*$suite*" }) {
            return $true
        }
    }
    
    return $false
}

function Install-Application {
    [CmdletBinding()]
    param(
        [hashtable]$Context,
        [string]$ApplicationName
    )
    
    $result = @{
        Success = $false
        Method = 'Unknown'
        Message = ''
    }
    
    try {
        # Try winget first
        if ($Context.PackageManagersReady) {
            $result = Install-WingetApplication -Context $Context -ApplicationName $ApplicationName
            if ($result.Success) { return $result }
        }
        
        # Try chocolatey as fallback
        $result = Install-ChocolateyApplication -Context $Context -ApplicationName $ApplicationName
        
        return $result
        
    } catch {
        $result.Message = "Exception during installation: $($_.Exception.Message)"
        return $result
    }
}

function Install-WingetApplication {
    [CmdletBinding()]
    param(
        [hashtable]$Context,
        [string]$ApplicationName
    )
    
    $result = @{ Success = $false; Method = 'Winget'; Message = '' }
    
    try {
        Write-PolicyLog -Context $Context -Message "Installing $ApplicationName via winget" -Level 'INFO' -Task 'INSTALL'
        
        $wingetOutput = & winget install $ApplicationName --silent --accept-source-agreements --accept-package-agreements --disable-interactivity 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            $result.Success = $true
            $result.Message = "Installed via winget"
        } else {
            $result.Message = "Winget installation failed: $wingetOutput"
        }
        
    } catch {
        $result.Message = "Winget installation exception: $($_.Exception.Message)"
    }
    
    return $result
}

function Install-ChocolateyApplication {
    [CmdletBinding()]
    param(
        [hashtable]$Context,
        [string]$ApplicationName
    )
    
    $result = @{ Success = $false; Method = 'Chocolatey'; Message = '' }
    
    try {
        # Convert winget package name to chocolatey equivalent
        $chocoPackage = Convert-ToChocolateyPackageName -WingetName $ApplicationName
        
        Write-PolicyLog -Context $Context -Message "Installing $chocoPackage via Chocolatey" -Level 'INFO' -Task 'INSTALL'
        
        $chocoOutput = & choco install $chocoPackage -y --no-progress 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            $result.Success = $true
            $result.Message = "Installed via Chocolatey"
        } else {
            $result.Message = "Chocolatey installation failed: $chocoOutput"
        }
        
    } catch {
        $result.Message = "Chocolatey installation exception: $($_.Exception.Message)"
    }
    
    return $result
}

function Convert-ToChocolateyPackageName {
    [CmdletBinding()]
    param([string]$WingetName)
    
    # Simple mapping for common packages
    $mapping = @{
        'Google.Chrome' = 'googlechrome'
        'Mozilla.Firefox' = 'firefox'
        '7zip.7zip' = '7zip'
        'VideoLAN.VLC' = 'vlc'
        'Adobe.Acrobat.Reader.64-bit' = 'adobereader'
        'Notepad++.Notepad++' = 'notepadplusplus'
        'Microsoft.VisualStudioCode' = 'vscode'
        'Git.Git' = 'git'
        'Python.Python.3' = 'python'
        'Microsoft.PowerToys' = 'powertoys'
        'TheDocumentFoundation.LibreOffice' = 'libreoffice-fresh'
    }
    
    if ($mapping.ContainsKey($WingetName)) {
        return $mapping[$WingetName]
    }
    
    # Fallback: convert to lowercase and remove dots
    return $WingetName.ToLower().Replace('.', '')
}

# =====================[ UPGRADE PACKAGES ]==================== 
# Task 7: System package updates

function Update-SystemPackages {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    Write-PolicyLog -Context $Context -Message "Starting System Package Updates" -Level 'INFO' -Task 'UPDATES'
    
    if ($Context.ReportOnlyMode) {
        Write-PolicyLog -Context $Context -Message "Report-only mode: Package updates will be simulated" -Level 'INFO' -Task 'UPDATES'
        return
    }
    
    $updateResults = @{
        WingetUpdates = 0
        ChocolateyUpdates = 0
        Failed = 0
        Details = @()
    }
    
    try {
        # Update packages via winget
        if ($Context.PackageManagersReady -and (Get-Command winget -ErrorAction SilentlyContinue)) {
            Write-PolicyLog -Context $Context -Message "Updating packages via winget" -Level 'INFO' -Task 'UPDATES'
            
            try {
                $wingetUpdateOutput = & winget upgrade --all --silent --accept-source-agreements --accept-package-agreements --include-unknown --disable-interactivity 2>&1
                
                if ($LASTEXITCODE -eq 0) {
                    $updateResults.WingetUpdates++
                    Write-PolicyLog -Context $Context -Message "Winget updates completed successfully" -Level 'SUCCESS' -Task 'UPDATES'
                } else {
                    Write-PolicyLog -Context $Context -Message "Winget updates completed with warnings: $wingetUpdateOutput" -Level 'WARNING' -Task 'UPDATES'
                }
                
                $Context.Stats.PackagesUpdated++
                
            } catch {
                $updateResults.Failed++
                Write-PolicyLog -Context $Context -Message "Winget update failed: $($_.Exception.Message)" -Level 'ERROR' -Task 'UPDATES'
            }
        }
        
        # Update packages via chocolatey
        if (Get-Command choco -ErrorAction SilentlyContinue) {
            Write-PolicyLog -Context $Context -Message "Updating packages via Chocolatey" -Level 'INFO' -Task 'UPDATES'
            
            try {
                $chocoUpdateOutput = & choco upgrade all -y --no-progress 2>&1
                
                if ($LASTEXITCODE -eq 0) {
                    $updateResults.ChocolateyUpdates++
                    Write-PolicyLog -Context $Context -Message "Chocolatey updates completed successfully" -Level 'SUCCESS' -Task 'UPDATES'
                } else {
                    Write-PolicyLog -Context $Context -Message "Chocolatey updates completed with warnings: $chocoUpdateOutput" -Level 'WARNING' -Task 'UPDATES'
                }
                
                $Context.Stats.PackagesUpdated++
                
            } catch {
                $updateResults.Failed++
                Write-PolicyLog -Context $Context -Message "Chocolatey update failed: $($_.Exception.Message)" -Level 'ERROR' -Task 'UPDATES'
            }
        }
        
        # Save update report
        $reportFile = Join-Path $Context.ReportsFolder "PackageUpdates_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $updateResults | ConvertTo-Json -Depth 3 | Out-File -FilePath $reportFile -Encoding UTF8
        
        Write-PolicyLog -Context $Context -Message "Package updates completed: Winget: $($updateResults.WingetUpdates), Chocolatey: $($updateResults.ChocolateyUpdates), Failed: $($updateResults.Failed)" -Level 'SUCCESS' -Task 'UPDATES'
        
    } catch {
        $errorMsg = "Failed to complete package updates: $($_.Exception.Message)"
        Write-PolicyLog -Context $Context -Message $errorMsg -Level 'ERROR' -Task 'UPDATES'
    }
}

# =====================[ PRIVACY & TELEMETRY ]==================== 
# Task 8: Privacy configuration and telemetry disabling

function Set-PrivacyTelemetrySettings {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    Write-PolicyLog -Context $Context -Message "Starting Privacy & Telemetry Configuration" -Level 'INFO' -Task 'PRIVACY'
    
    if ($Context.ReportOnlyMode) {
        Write-PolicyLog -Context $Context -Message "Report-only mode: Privacy settings will be simulated" -Level 'INFO' -Task 'PRIVACY'
        return
    }
    
    $privacyResults = @{
        RegistryChanges = 0
        ServicesModified = 0
        TasksDisabled = 0
        Failed = 0
    }
    
    try {
        # Configure registry settings for privacy
        $privacyResults.RegistryChanges = Set-PrivacyRegistrySettings -Context $Context
        
        # Disable telemetry services
        $privacyResults.ServicesModified = Set-TelemetryServices -Context $Context
        
        # Disable telemetry scheduled tasks
        $privacyResults.TasksDisabled = Set-TelemetryTasks -Context $Context
        
        Write-PolicyLog -Context $Context -Message "Privacy configuration completed: $($privacyResults.RegistryChanges) registry changes, $($privacyResults.ServicesModified) services modified, $($privacyResults.TasksDisabled) tasks disabled" -Level 'SUCCESS' -Task 'PRIVACY'
        
    } catch {
        $errorMsg = "Failed to complete privacy configuration: $($_.Exception.Message)"
        Write-PolicyLog -Context $Context -Message $errorMsg -Level 'ERROR' -Task 'PRIVACY'
    }
}

function Set-PrivacyRegistrySettings {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    $changesCount = 0
    
    $privacySettings = @{
        # Disable telemetry
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' = @{
            'AllowTelemetry' = 0
            'DoNotShowFeedbackNotifications' = 1
        }
        
        # Disable advertising ID
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' = @{
            'DisabledByGroupPolicy' = 1
        }
        
        # Disable location tracking
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' = @{
            'DisableLocation' = 1
            'DisableLocationScripting' = 1
        }
        
        # Disable Windows Consumer Features
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' = @{
            'DisableWindowsConsumerFeatures' = 1
            'DisableSoftLanding' = 1
        }
        
        # Disable Cortana
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' = @{
            'AllowCortana' = 0
            'DisableWebSearch' = 1
            'ConnectedSearchUseWeb' = 0
        }
    }
    
    foreach ($registryPath in $privacySettings.Keys) {
        try {
            # Create registry path if it doesn't exist
            if (-not (Test-Path $registryPath)) {
                New-Item -Path $registryPath -Force | Out-Null
            }
            
            $settings = $privacySettings[$registryPath]
            foreach ($setting in $settings.Keys) {
                Set-ItemProperty -Path $registryPath -Name $setting -Value $settings[$setting] -Type DWord -Force
                $changesCount++
                Write-PolicyLog -Context $Context -Message "Set $registryPath\$setting = $($settings[$setting])" -Level 'INFO' -Task 'PRIVACY'
            }
            
        } catch {
            Write-PolicyLog -Context $Context -Message "Failed to configure privacy settings at $registryPath`: $($_.Exception.Message)" -Level 'WARNING' -Task 'PRIVACY'
        }
    }
    
    return $changesCount
}

function Set-TelemetryServices {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    $servicesModified = 0
    
    $telemetryServices = @(
        'DiagTrack',                    # Connected User Experiences and Telemetry
        'dmwappushservice',             # Device Management Wireless Application Protocol
        'WerSvc',                       # Windows Error Reporting Service
        'OneSyncSvc',                   # Microsoft OneDrive Sync Service
        'MessagingService',             # Messaging Service
        'PimIndexMaintenanceSvc',       # Contact Data
        'UserDataSvc',                  # User Data Access
        'UnistoreSvc',                  # User Data Storage
        'BcastDVRUserService',          # GameDVR and Broadcast User Service
        'Fax'                           # Fax Service
    )
    
    foreach ($serviceName in $telemetryServices) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                if ($service.Status -eq 'Running') {
                    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
                }
                Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue
                $servicesModified++
                Write-PolicyLog -Context $Context -Message "Disabled service: $serviceName" -Level 'INFO' -Task 'PRIVACY'
            }
        } catch {
            Write-PolicyLog -Context $Context -Message "Failed to disable service $serviceName`: $($_.Exception.Message)" -Level 'WARNING' -Task 'PRIVACY'
        }
    }
    
    return $servicesModified
}

function Set-TelemetryTasks {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    $tasksDisabled = 0
    
    $telemetryTaskPaths = @(
        '\Microsoft\Windows\Customer Experience Improvement Program\*',
        '\Microsoft\Windows\Application Experience\*',
        '\Microsoft\Windows\Autochk\*',
        '\Microsoft\Windows\CloudExperienceHost\*',
        '\Microsoft\Windows\DiskDiagnostic\*',
        '\Microsoft\Windows\Feedback\*',
        '\Microsoft\Windows\Maintenance\*',
        '\Microsoft\Windows\PI\*',
        '\Microsoft\Windows\Power Efficiency Diagnostics\*',
        '\Microsoft\Windows\Shell\*',
        '\Microsoft\Windows\Windows Error Reporting\*'
    )
    
    foreach ($taskPath in $telemetryTaskPaths) {
        try {
            $tasks = Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue
            foreach ($task in $tasks) {
                if ($task.State -ne 'Disabled') {
                    Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                    $tasksDisabled++
                    Write-PolicyLog -Context $Context -Message "Disabled scheduled task: $($task.TaskPath)$($task.TaskName)" -Level 'INFO' -Task 'PRIVACY'
                }
            }
        } catch {
            Write-PolicyLog -Context $Context -Message "Failed to disable tasks in $taskPath`: $($_.Exception.Message)" -Level 'WARNING' -Task 'PRIVACY'
        }
    }
    
    return $tasksDisabled
}

# =====================[ WINDOWS UPDATE ]==================== 
# Task 9: Windows Update installation

function Install-WindowsUpdates {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    Write-PolicyLog -Context $Context -Message "Starting Windows Updates" -Level 'INFO' -Task 'WINDOWSUPDATE'
    
    if ($Context.ReportOnlyMode) {
        Write-PolicyLog -Context $Context -Message "Report-only mode: Windows updates will be simulated" -Level 'INFO' -Task 'WINDOWSUPDATE'
        return
    }
    
    try {
        # Check if PSWindowsUpdate module is available
        $psWindowsUpdate = Get-Module -ListAvailable -Name PSWindowsUpdate
        
        if (-not $psWindowsUpdate) {
            Write-PolicyLog -Context $Context -Message "Installing PSWindowsUpdate module" -Level 'INFO' -Task 'WINDOWSUPDATE'
            
            # Install NuGet provider if needed
            if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser
            }
            
            # Install PSWindowsUpdate module
            Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber
            Import-Module PSWindowsUpdate -Force
        } else {
            Import-Module PSWindowsUpdate -Force
        }
        
        Write-PolicyLog -Context $Context -Message "Checking for available Windows updates" -Level 'INFO' -Task 'WINDOWSUPDATE'
        
        # Get available updates
        $updates = Get-WindowsUpdate -AcceptAll -IgnoreReboot
        
        if ($updates.Count -gt 0) {
            Write-PolicyLog -Context $Context -Message "Found $($updates.Count) available updates" -Level 'INFO' -Task 'WINDOWSUPDATE'
            
            # Install updates without automatic reboot
            $installResult = Install-WindowsUpdate -AcceptAll -AutoReboot:$false -IgnoreReboot
            
            if ($installResult) {
                Write-PolicyLog -Context $Context -Message "Windows updates installed successfully" -Level 'SUCCESS' -Task 'WINDOWSUPDATE'
                
                # Check if reboot is required
                if (Test-RebootRequired) {
                    $Context.RebootRequired = $true
                    Write-PolicyLog -Context $Context -Message "Reboot required after Windows updates" -Level 'WARNING' -Task 'WINDOWSUPDATE'
                }
            }
        } else {
            Write-PolicyLog -Context $Context -Message "No Windows updates available" -Level 'INFO' -Task 'WINDOWSUPDATE'
        }
        
    } catch {
        $errorMsg = "Failed to install Windows updates: $($_.Exception.Message)"
        Write-PolicyLog -Context $Context -Message $errorMsg -Level 'ERROR' -Task 'WINDOWSUPDATE'
    }
}

function Test-RebootRequired {
    $rebootRequired = $false
    
    # Check various registry locations for pending reboot
    $rebootPaths = @(
        @{
            Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
            Type = 'Path'
        },
        @{
            Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
            Type = 'Path'
        },
        @{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
            Name = 'PendingFileRenameOperations'
            Type = 'Value'
        }
    )
    
    foreach ($check in $rebootPaths) {
        try {
            if ($check.Type -eq 'Path') {
                if (Test-Path $check.Path) {
                    $rebootRequired = $true
                    break
                }
            } elseif ($check.Type -eq 'Value') {
                $value = Get-ItemProperty -Path $check.Path -Name $check.Name -ErrorAction SilentlyContinue
                if ($value -and $value.($check.Name)) {
                    $rebootRequired = $true
                    break
                }
            }
        } catch {
            # Ignore errors in reboot detection
        }
    }
    
    return $rebootRequired
}

# =====================[ RESTORE POINT & CLEANUP ]==================== 
# Task 10: Cleanup operations

function Invoke-SystemCleanup {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    Write-PolicyLog -Context $Context -Message "Starting System Cleanup" -Level 'INFO' -Task 'CLEANUP'
    
    if ($Context.ReportOnlyMode) {
        Write-PolicyLog -Context $Context -Message "Report-only mode: System cleanup will be simulated" -Level 'INFO' -Task 'CLEANUP'
        return
    }
    
    $cleanupResults = @{
        RestorePointsManaged = 0
        TempFilesCleared = 0
        SpaceFreedMB = 0
        EventLogsCleared = 0
        CachesCleared = 0
    }
    
    try {
        # Get initial disk space
        $initialSpace = Get-SystemFreeSpace
        
        # Manage restore points (keep only 5 most recent)
        $cleanupResults.RestorePointsManaged = Limit-RestorePoints -Context $Context
        
        # Clear temporary files
        $cleanupResults.TempFilesCleared = Clear-TemporaryFiles -Context $Context
        
        # Clear system caches
        $cleanupResults.CachesCleared = Clear-SystemCaches -Context $Context
        
        # Clear event logs (optional)
        $cleanupResults.EventLogsCleared = Clear-EventLogs -Context $Context
        
        # Run disk cleanup
        Start-DiskCleanup -Context $Context
        
        # Calculate space freed
        $finalSpace = Get-SystemFreeSpace
        $spaceFreedGB = $finalSpace - $initialSpace
        $cleanupResults.SpaceFreedMB = [math]::Round($spaceFreedGB * 1024, 2)
        $Context.Stats.SpaceFreed = $cleanupResults.SpaceFreedMB
        
        # Save cleanup report
        $reportFile = Join-Path $Context.ReportsFolder "SystemCleanup_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $cleanupResults | ConvertTo-Json -Depth 3 | Out-File -FilePath $reportFile -Encoding UTF8
        
        Write-PolicyLog -Context $Context -Message "System cleanup completed: Freed $($cleanupResults.SpaceFreedMB)MB, Cleared $($cleanupResults.TempFilesCleared) temp files" -Level 'SUCCESS' -Task 'CLEANUP'
        
    } catch {
        $errorMsg = "Failed to complete system cleanup: $($_.Exception.Message)"
        Write-PolicyLog -Context $Context -Message $errorMsg -Level 'ERROR' -Task 'CLEANUP'
    }
}

function Limit-RestorePoints {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    $managed = 0
    
    try {
        $restorePoints = Get-ComputerRestorePoint | Sort-Object CreationTime -Descending
        
        if ($restorePoints.Count -gt $Script:CONFIG.MaxRestorePoints) {
            $pointsToRemove = $restorePoints | Select-Object -Skip $Script:CONFIG.MaxRestorePoints
            
            foreach ($point in $pointsToRemove) {
                try {
                    # Use vssadmin to delete old restore points
                    $shadowId = $point.SequenceNumber
                    & vssadmin delete shadows /shadow=$shadowId /quiet
                    $managed++
                    Write-PolicyLog -Context $Context -Message "Removed old restore point: $($point.Description)" -Level 'INFO' -Task 'CLEANUP'
                } catch {
                    Write-PolicyLog -Context $Context -Message "Failed to remove restore point: $($_.Exception.Message)" -Level 'WARNING' -Task 'CLEANUP'
                }
            }
        }
        
    } catch {
        Write-PolicyLog -Context $Context -Message "Failed to manage restore points: $($_.Exception.Message)" -Level 'WARNING' -Task 'CLEANUP'
    }
    
    return $managed
}

function Clear-TemporaryFiles {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    $filesCleared = 0
    
    $tempPaths = @(
        $env:TEMP,
        $env:TMP,
        "$env:SystemRoot\Temp",
        "$env:SystemRoot\SoftwareDistribution\Download",
        "$env:SystemRoot\Logs",
        "$env:LOCALAPPDATA\Microsoft\Windows\INetCache",
        "$env:LOCALAPPDATA\Temp"
    )
    
    foreach ($tempPath in $tempPaths) {
        if (Test-Path $tempPath) {
            try {
                $files = Get-ChildItem -Path $tempPath -Recurse -Force -ErrorAction SilentlyContinue
                $fileCount = $files.Count
                
                Remove-Item -Path "$tempPath\*" -Recurse -Force -ErrorAction SilentlyContinue
                $filesCleared += $fileCount
                
                Write-PolicyLog -Context $Context -Message "Cleared $fileCount files from $tempPath" -Level 'INFO' -Task 'CLEANUP'
                
            } catch {
                Write-PolicyLog -Context $Context -Message "Failed to clear $tempPath`: $($_.Exception.Message)" -Level 'WARNING' -Task 'CLEANUP'
            }
        }
    }
    
    return $filesCleared
}

function Clear-SystemCaches {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    $cachesCleared = 0
    
    try {
        # Clear DNS cache
        & ipconfig /flushdns | Out-Null
        $cachesCleared++
        Write-PolicyLog -Context $Context -Message "DNS cache cleared" -Level 'INFO' -Task 'CLEANUP'
        
        # Clear Windows Store cache
        & wsreset /nologo
        $cachesCleared++
        Write-PolicyLog -Context $Context -Message "Windows Store cache cleared" -Level 'INFO' -Task 'CLEANUP'
        
    } catch {
        Write-PolicyLog -Context $Context -Message "Failed to clear some caches: $($_.Exception.Message)" -Level 'WARNING' -Task 'CLEANUP'
    }
    
    return $cachesCleared
}

function Clear-EventLogs {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    $logsCleared = 0
    
    try {
        $eventLogs = @('Application', 'Security', 'System', 'Setup')
        
        foreach ($logName in $eventLogs) {
            try {
                $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
                if ($log -and $log.RecordCount -gt 1000) {
                    Clear-WinEvent -LogName $logName -ErrorAction SilentlyContinue
                    $logsCleared++
                    Write-PolicyLog -Context $Context -Message "Cleared event log: $logName" -Level 'INFO' -Task 'CLEANUP'
                }
            } catch {
                # Some logs may not be clearable due to permissions
            }
        }
        
    } catch {
        Write-PolicyLog -Context $Context -Message "Failed to clear event logs: $($_.Exception.Message)" -Level 'WARNING' -Task 'CLEANUP'
    }
    
    return $logsCleared
}

function Start-DiskCleanup {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    try {
        # Run disk cleanup utility
        Write-PolicyLog -Context $Context -Message "Running disk cleanup utility" -Level 'INFO' -Task 'CLEANUP'
        
        # Create disk cleanup settings for reference
        $cleanupItems = @(
            "Temporary Files",
            "Downloaded Program Files", 
            "Recycle Bin",
            "Setup Log Files",
            "Temporary Internet Files",
            "Thumbnails"
        )
        
        Write-PolicyLog -Context $Context -Message "Running cleanup for: $($cleanupItems -join ', ')" -Level 'INFO' -Task 'CLEANUP'
        
        # Use cleanmgr with predefined settings - run silently without UI
        Start-Process -FilePath "cleanmgr" -ArgumentList "/sagerun:1" -Wait -NoNewWindow -WindowStyle Hidden
        
        Write-PolicyLog -Context $Context -Message "Disk cleanup completed" -Level 'SUCCESS' -Task 'CLEANUP'
        
    } catch {
        Write-PolicyLog -Context $Context -Message "Failed to run disk cleanup: $($_.Exception.Message)" -Level 'WARNING' -Task 'CLEANUP'
    }
}

# =====================[ HTML REPORT ]==================== 
# Task 11: Report generation

function New-HTMLReport {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    Write-PolicyLog -Context $Context -Message "Starting HTML Report Generation" -Level 'INFO' -Task 'REPORT'
    
    try {
        $logSummary = Get-LogSummary -Context $Context
        
        # Build HTML content without complex embedded PowerShell
        $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>System Maintenance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        h2 { color: #555; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 10px; text-align: left; border: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        .success { background-color: #d4edda; }
        .error { background-color: #f8d7da; }
        .warning { background-color: #fff3cd; }
    </style>
</head>
<body>

<h1>System Maintenance Report</h1>
<p><strong>Report Date:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
<p><strong>Computer Name:</strong> $env:COMPUTERNAME</p>
<p><strong>User:</strong> $env:USERNAME</p>
<p><strong>PowerShell Version:</strong> $($PSVersionTable.PSVersion)</p>

<h2>Summary</h2>
<table>
    <tr>
        <th>Task</th>
        <th>Status</th>
        <th>Duration</th>
        <th>Details</th>
    </tr>
"@

        # Build task rows
        $taskRows = ""
        $taskResults = $Context.TaskResults.GetEnumerator() | Sort-Object { $_.Value.StartTime }
        foreach ($result in $taskResults) {
            $taskName = $result.Key
            $taskData = $result.Value
            $statusClass = switch ($taskData.Status) { 
                'Completed' { 'success' } 
                'Failed' { 'error' } 
                'Skipped' { 'warning' } 
                default { '' } 
            }
            
            $details = @()
            if ($taskData.Status -eq 'Failed' -and $taskData.Error) {
                $details += "Error: $($taskData.Error)"
            }
            if ($taskData.StartTime) {
                $details += "Started: $($taskData.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
            }
            if ($taskData.EndTime) {
                $details += "Ended: $($taskData.EndTime.ToString('yyyy-MM-dd HH:mm:ss'))"
            }
            $detailsText = $details -join '<br>'
            
            $duration = if ($taskData.Duration) { [math]::Round($taskData.Duration.TotalSeconds, 2) } else { 0 }
            
            $taskRows += @"
    <tr class='$statusClass'>
        <td>$taskName</td>
        <td>$($taskData.Status)</td>
        <td>$duration seconds</td>
        <td>$detailsText</td>
    </tr>
"@
        }

        $htmlFooter = @"
</table>

<h2>Statistics</h2>
<ul>
    <li><strong>Total Errors:</strong> $($logSummary.TotalErrors)</li>
    <li><strong>Total Warnings:</strong> $($logSummary.TotalWarnings)</li>
    <li><strong>Bloatware Removed:</strong> $($logSummary.BloatwareRemoved)</li>
    <li><strong>Essentials Installed:</strong> $($logSummary.EssentialsInstalled)</li>
    <li><strong>Packages Updated:</strong> $($logSummary.PackagesUpdated)</li>
    <li><strong>Space Freed:</strong> $([math]::Round($logSummary.SpaceFreed, 2)) MB</li>
    <li><strong>Reboot Required:</strong> $($logSummary.RebootRequired)</li>
</ul>

<h2>Detailed Logs</h2>
<pre>
$(if (Test-Path $Context.LogPath) { Get-Content -Path $Context.LogPath -Raw } else { "Log file not found" })
</pre>

</body>
</html>
"@
        
        # Combine all parts
        $htmlContent = $htmlHeader + $taskRows + $htmlFooter
        
        # Save HTML report to file
        $reportFile = Join-Path $Context.ReportsFolder "SystemMaintenanceReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        $htmlContent | Out-File -FilePath $reportFile -Encoding UTF8
        
        Write-PolicyLog -Context $Context -Message "HTML report generated: $reportFile" -Level 'SUCCESS' -Task 'REPORT'
        
    } catch {
        $errorMsg = "Failed to generate HTML report: $($_.Exception.Message)"
        Write-PolicyLog -Context $Context -Message $errorMsg -Level 'ERROR' -Task 'REPORT'
    }
}

# =====================[ REBOOT CHECK ]==================== 
# Task 12: Reboot management

function Test-RebootRequirement {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    Write-PolicyLog -Context $Context -Message "Checking Reboot Requirements" -Level 'INFO' -Task 'REBOOT'
    
    try {
        $rebootRequired = Test-RebootRequired
        
        if ($rebootRequired -or $Context.RebootRequired) {
            $Context.RebootRequired = $true
            Write-PolicyLog -Context $Context -Message "System reboot is required" -Level 'WARNING' -Task 'REBOOT'
            
            if (-not $Context.ReportOnlyMode) {
                Show-RebootPrompt -Context $Context
            } else {
                Write-PolicyLog -Context $Context -Message "Report-only mode: Reboot prompt skipped" -Level 'INFO' -Task 'REBOOT'
            }
        } else {
            Write-PolicyLog -Context $Context -Message "No reboot required" -Level 'SUCCESS' -Task 'REBOOT'
        }
        
    } catch {
        $errorMsg = "Failed to check reboot requirements: $($_.Exception.Message)"
        Write-PolicyLog -Context $Context -Message $errorMsg -Level 'ERROR' -Task 'REBOOT'
    }
}

function Show-RebootPrompt {
    [CmdletBinding()]
    param([hashtable]$Context)
    
    try {
        Write-Host "`n" -ForegroundColor Yellow
        Write-Host "=====================[ REBOOT REQUIRED ]=====================" -ForegroundColor Yellow
        Write-Host "System changes require a restart to take full effect." -ForegroundColor Yellow
        Write-Host "It is recommended to restart your computer now." -ForegroundColor Yellow
        Write-Host "==========================================================" -ForegroundColor Yellow
        Write-Host "`n"
        
        $choice = Read-Host "Would you like to restart now? (Y/N)"
        
        if ($choice -match '^[Yy]') {
            Write-PolicyLog -Context $Context -Message "User chose to restart now" -Level 'INFO' -Task 'REBOOT'
            Write-Host "Restarting computer in 10 seconds..." -ForegroundColor Yellow
            Start-Sleep -Seconds 10
            Restart-Computer -Force
        } else {
            Write-PolicyLog -Context $Context -Message "User deferred restart" -Level 'INFO' -Task 'REBOOT'
            Write-Host "Restart deferred. Please restart manually when convenient." -ForegroundColor Yellow
        }
        
    } catch {
        Write-PolicyLog -Context $Context -Message "Failed to show reboot prompt: $($_.Exception.Message)" -Level 'WARNING' -Task 'REBOOT'
    }
}

# =====================[ UTILITY FUNCTIONS ]==================== 
# Helper functions

function Complete-PolicyExecution {
    [CmdletBinding()]
    param(
        [hashtable]$Context,
        [switch]$DeleteTempFiles
    )
    
    try {
        Write-PolicyLog -Context $Context -Message "=== CLEANUP AND FINALIZATION ===" -Level 'INFO'
        
        # Generate final report
        New-HTMLReport -Context $Context
        
        # Stop transcript
        try {
            Stop-Transcript
        } catch {
            # Transcript may not be running
        }
        
        # Display summary
        $summary = Get-LogSummary -Context $Context
        Write-Host "`n" -ForegroundColor Green
        Write-Host "=====================[ EXECUTION SUMMARY ]=====================" -ForegroundColor Green
        Write-Host "Execution Time: $($summary.Duration.ToString('hh\:mm\:ss'))" -ForegroundColor White
        Write-Host "Errors: $($summary.TotalErrors)" -ForegroundColor $(if($summary.TotalErrors -gt 0) { 'Red' } else { 'Green' })
        Write-Host "Warnings: $($summary.TotalWarnings)" -ForegroundColor $(if($summary.TotalWarnings -gt 0) { 'Yellow' } else { 'Green' })
        Write-Host "Bloatware Removed: $($summary.BloatwareRemoved)" -ForegroundColor Green
        Write-Host "Essentials Installed: $($summary.EssentialsInstalled)" -ForegroundColor Green
        Write-Host "Packages Updated: $($summary.PackagesUpdated)" -ForegroundColor Green
        Write-Host "Space Freed: $($summary.SpaceFreed) MB" -ForegroundColor Green
        Write-Host "Reboot Required: $(if($summary.RebootRequired) { 'Yes' } else { 'No' })" -ForegroundColor $(if($summary.RebootRequired) { 'Yellow' } else { 'Green' })
        Write-Host "=============================================================" -ForegroundColor Green
        Write-Host "`n"
        
        # Delete temp files if requested
        if ($DeleteTempFiles.IsPresent) {
            Write-PolicyLog -Context $Context -Message "Cleaning up temporary files..." -Level 'INFO'
            try {
                Remove-Item -Path $Context.TempFolder -Recurse -Force -ErrorAction SilentlyContinue
                Write-PolicyLog -Context $Context -Message "Temporary files cleaned up" -Level 'SUCCESS'
            } catch {
                Write-PolicyLog -Context $Context -Message "Failed to clean up temp files: $($_.Exception.Message)" -Level 'WARNING'
            }
        } else {
            Write-Host "Log files and reports saved to: $($Context.TempFolder)" -ForegroundColor Cyan
        }
        
        Write-PolicyLog -Context $Context -Message "=== SYSTEM MAINTENANCE POLICY EXECUTION COMPLETED ===" -Level 'SUCCESS'
        
    } catch {
        Write-Error "Failed to complete policy execution: $($_.Exception.Message)"
    }
}

# Fix the null comparison issue
function Test-SystemRestoreEnabled {
    try {
        $restoreStatus = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        return $null -ne $restoreStatus
    } catch {
        return $false
    }
}

# =====================[ MAIN EXECUTION ]==================== 
# Script entry point

# Validate system requirements
Write-Host "Validating system requirements..." -ForegroundColor Cyan
if (-not (Test-IsAdministrator)) {
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error "This script requires PowerShell 5.1 or later. Current version: $($PSVersionTable.PSVersion)"
    exit 1
}

# Main execution
try {
    Write-Host "`n" -ForegroundColor Green
    Write-Host "=======================================================================" -ForegroundColor Green
    Write-Host "           $Script:SCRIPT_NAME v$Script:SCRIPT_VERSION" -ForegroundColor Green
    Write-Host "=======================================================================" -ForegroundColor Green
    Write-Host "Starting comprehensive system maintenance..." -ForegroundColor Green
    Write-Host "`n"
    
    # Execute the unified policy
    Invoke-SystemMaintenancePolicy -TaskList $Tasks -CleanupTempFiles:$DeleteTempFiles -ReportOnlyMode:$ReportOnly
    
    Write-Host "System maintenance completed successfully!" -ForegroundColor Green
    
} catch {
    Write-Error "Critical error during script execution: $($_.Exception.Message)"
    Write-Error "Stack Trace: $($_.Exception.StackTrace)"
    exit 1
}

# End of script