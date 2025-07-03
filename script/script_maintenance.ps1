# ==============================================================================
# WINDOWS SYSTEM MAINTENANCE SCRIPT
# ==============================================================================
# 
# PURPOSE: Comprehensive Windows system maintenance with automated tasks
# ARCHITECTURE: Monolithic structure with modular functions
# EXECUTION FLOW: Sequential task execution with error handling and logging
# VERSION: 1.0
# AUTHOR: System Maintenance Script
# DATE: July 2025
# 
# ==============================================================================
# SCRIPT MAP / TABLE OF CONTENTS
# ==============================================================================
# 
# 1. INITIALIZATION & PARAMETERS (Lines 1-120)
#    - Script parameters and switches
#    - Global variables declaration
#    - Path configurations
# 
# 2. UNIFIED CONTROL POLICY (Lines 121-200)
#    - Central coordination policy
#    - Logging system
#    - Error handling
#    - Global initialization
# 
# 3. UTILITY FUNCTIONS (Lines 201-350)
#    - Write-Log: Centralized logging system
#    - Add-Change: System change tracking
#    - Initialize-Environment: Setup temp directories and transcript
#    - Remove-Environment: Cleanup and report generation
# 
# 4. CORE MAINTENANCE FUNCTIONS (Lines 351-900)
#    - New-RestorePoint: Creates system restore point
#    - Install-PackageManagers: Installs winget and Chocolatey
#    - Remove-Bloatware: Removes unwanted Windows apps
#    - Install-EssentialApps: Installs essential software
#    - Update-AllPackages: Updates all installed packages
#    - Optimize-Privacy: Configures privacy settings
#    - Install-WindowsUpdates: Installs Windows updates
#    - Invoke-DiskCleanup: Cleans temporary files
#    - Test-RebootRequired: Checks if reboot is needed
# 
# 5. SYSTEM MONITORING & TRACKING (Lines 901-1100)
#    - Get-SystemSnapshot: Captures system state
#    - Test-SystemProblems: Identifies system issues
#    - Compare-SystemSnapshots: Detects changes
#    - Export-SystemData: Generates reports
# 
# 6. MAIN EXECUTION CONTROLLER (Lines 1101-1200)
#    - Start-SystemMaintenance: Orchestrates all tasks
#    - Task loop execution with progress tracking
#    - Error handling and summary reporting
# 
# 7. REPORTING & EXPORT FUNCTIONS (Lines 1201-1300)
#    - New-HTMLReport: Creates HTML reports
#    - Import-CustomTasks: Loads custom tasks
#    - Export formats: JSON, CSV, HTML
# 
# ==============================================================================

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Skip removal of bloatware applications")]
    [switch]$SkipBloatwareRemoval,
    
    [Parameter(HelpMessage = "Skip installation of essential applications")]
    [switch]$SkipEssentialApps,
    
    [Parameter(HelpMessage = "Skip Windows Updates installation")]
    [switch]$SkipWindowsUpdates,
    
    [Parameter(HelpMessage = "Skip disk cleanup operations")]
    [switch]$SkipDiskCleanup,
    
    [Parameter(HelpMessage = "Skip privacy optimization")]
    [switch]$SkipPrivacyOptimization,
    
    [Parameter(HelpMessage = "Generate detailed HTML report")]
    [switch]$GenerateReport,
    
    [Parameter(HelpMessage = "Track system changes during execution")]
    [switch]$TrackChanges,
    
    [Parameter(HelpMessage = "Export results to JSON format")]
    [switch]$ExportToJson,
    
    [Parameter(HelpMessage = "Export results to CSV format")]
    [switch]$ExportToCsv,
    
    [Parameter(HelpMessage = "Delete temporary files after execution")]
    [switch]$DeleteTempFiles,
    
    [Parameter(HelpMessage = "Path to custom tasks JSON file")]
    [string]$CustomTasksFile,
    
    [Parameter(HelpMessage = "Specify custom output directory")]
    [string]$OutputDirectory = "$env:TEMP\SystemMaintenance",
    
    [Parameter(HelpMessage = "Run in silent mode without interactive prompts")]
    [switch]$SilentMode
)

# ==============================================================================
# UNIFIED CONTROL POLICY - CENTRAL COORDINATION
# ==============================================================================

# Global Script Variables
$Script:Config = @{
    TempFolder = $OutputDirectory
    LogPath = "$OutputDirectory\SystemMaintenance.log"
    TranscriptPath = "$OutputDirectory\SystemMaintenance_Transcript.log"
    SystemChanges = @()
    SystemProblems = @()
    BeforeSnapshot = @{}
    AfterSnapshot = @{}
    CustomTasks = @()
    TaskResults = @{}
    StartTime = Get-Date
    IsElevated = $false
    ErrorActionPreference = 'Continue'
    WarningPreference = 'Continue'
    VerbosePreference = 'Continue'
}

# Central Task Registry
$Script:MaintenanceTasks = @(
    @{
        Name = "CreateRestorePoint"
        DisplayName = "Create System Restore Point"
        Function = "New-RestorePoint"
        Enabled = $true
        Priority = 1
        Category = "Safety"
        Description = "Creates a system restore point before making changes"
    },
    @{
        Name = "InstallPackageManagers"
        DisplayName = "Install Package Managers"
        Function = "Install-PackageManagers"
        Enabled = $true
        Priority = 2
        Category = "Prerequisites"
        Description = "Installs winget and Chocolatey package managers"
    },
    @{
        Name = "RemoveBloatware"
        DisplayName = "Remove Bloatware"
        Function = "Remove-Bloatware"
        Enabled = (-not $SkipBloatwareRemoval)
        Priority = 3
        Category = "Cleanup"
        Description = "Removes unnecessary pre-installed applications"
    },
    @{
        Name = "InstallEssentialApps"
        DisplayName = "Install Essential Applications"
        Function = "Install-EssentialApps"
        Enabled = (-not $SkipEssentialApps)
        Priority = 4
        Category = "Installation"
        Description = "Installs commonly needed applications"
    },
    @{
        Name = "UpdatePackages"
        DisplayName = "Update All Packages"
        Function = "Update-AllPackages"
        Enabled = $true
        Priority = 5
        Category = "Updates"
        Description = "Updates all installed packages"
    },
    @{
        Name = "OptimizePrivacy"
        DisplayName = "Optimize Privacy Settings"
        Function = "Optimize-Privacy"
        Enabled = (-not $SkipPrivacyOptimization)
        Priority = 6
        Category = "Privacy"
        Description = "Configures Windows privacy settings"
    },
    @{
        Name = "InstallWindowsUpdates"
        DisplayName = "Install Windows Updates"
        Function = "Install-WindowsUpdates"
        Enabled = (-not $SkipWindowsUpdates)
        Priority = 7
        Category = "Updates"
        Description = "Installs available Windows updates"
    },
    @{
        Name = "DiskCleanup"
        DisplayName = "Disk Cleanup"
        Function = "Invoke-DiskCleanup"
        Enabled = (-not $SkipDiskCleanup)
        Priority = 8
        Category = "Cleanup"
        Description = "Cleans temporary files and frees disk space"
    },
    @{
        Name = "CheckReboot"
        DisplayName = "Check Reboot Requirement"
        Function = "Test-RebootRequired"
        Enabled = $true
        Priority = 9
        Category = "System"
        Description = "Checks if system restart is needed"
    }
)

# ==============================================================================
# UNIFIED LOGGING SYSTEM
# ==============================================================================

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO",
        
        [Parameter()]
        [string]$Category = "General",
        
        [Parameter()]
        [switch]$NoConsole,
        
        [Parameter()]
        [switch]$NoFile
    )
    
    process {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] [$Level] [$Category] $Message"
        
        # Console output with color coding
        if (-not $NoConsole) {
            $color = switch ($Level) {
                "SUCCESS" { "Green" }
                "WARNING" { "Yellow" }
                "ERROR" { "Red" }
                "INFO" { "White" }
                "DEBUG" { "Gray" }
                default { "White" }
            }
            Write-Host $logEntry -ForegroundColor $color
        }
        
        # File logging
        if (-not $NoFile) {
            try {
                # Ensure the directory exists before writing to log file
                $logDirectory = Split-Path -Path $Script:Config.LogPath -Parent
                if (-not (Test-Path $logDirectory)) {
                    New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
                }
                $logEntry | Out-File -FilePath $Script:Config.LogPath -Append -Encoding UTF8
            }
            catch {
                Write-Warning "Failed to write to log file: $_"
            }
        }
    }
}

# ==============================================================================
# UNIFIED ERROR HANDLING
# ==============================================================================

function Invoke-SafeOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter()]
        [string]$OperationName = "Unknown Operation",
        
        [Parameter()]
        [string]$Category = "General",
        
        [Parameter()]
        [switch]$ContinueOnError,
        
        [Parameter()]
        [scriptblock]$OnError
    )
    
    try {
        Write-Log "Starting: $OperationName" -Level "INFO" -Category $Category
        $result = & $ScriptBlock
        Write-Log "Completed: $OperationName" -Level "SUCCESS" -Category $Category
        return $result
    }
    catch {
        $errorMessage = "Failed: $OperationName - $($_.Exception.Message)"
        Write-Log $errorMessage -Level "ERROR" -Category $Category
        
        # Track error in system changes
        Add-Change -Type "Error" -Category $Category -Description $errorMessage -Details $_.Exception
        
        if ($OnError) {
            & $OnError
        }
        
        if (-not $ContinueOnError) {
            throw
        }
        
        return $null
    }
}

# ==============================================================================
# SYSTEM CHANGE TRACKING
# ==============================================================================

function Add-Change {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Type,
        
        [Parameter(Mandatory = $true)]
        [string]$Category,
        
        [Parameter(Mandatory = $true)]
        [string]$Description,
        
        [Parameter()]
        [object]$Details
    )
    
    $change = @{
        Timestamp = Get-Date
        Type = $Type
        Category = $Category
        Description = $Description
        Details = $Details
    }
    
    $Script:Config.SystemChanges += $change
    
    Write-Log "System Change: [$Type] [$Category] $Description" -Level "INFO" -Category "ChangeTracking"
}

# ==============================================================================
# ENVIRONMENT INITIALIZATION
# ==============================================================================

function Initialize-Environment {
    [CmdletBinding()]
    param()
    
    Write-Log "Initializing system maintenance environment" -Level "INFO" -Category "Initialization"
    
    # Check administrator privileges
    $Script:Config.IsElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    
    if (-not $Script:Config.IsElevated) {
        Write-Log "WARNING: Not running as administrator. Some operations may fail." -Level "WARNING" -Category "Initialization"
    }
    
    # Create temporary directory
    if (-not (Test-Path $Script:Config.TempFolder)) {
        New-Item -Path $Script:Config.TempFolder -ItemType Directory -Force | Out-Null
        Write-Log "Created temporary directory: $($Script:Config.TempFolder)" -Level "INFO" -Category "Initialization"
    }
    
    # Start transcript
    try {
        # Ensure the directory exists before starting transcript
        $transcriptDirectory = Split-Path -Path $Script:Config.TranscriptPath -Parent
        if (-not (Test-Path $transcriptDirectory)) {
            New-Item -Path $transcriptDirectory -ItemType Directory -Force | Out-Null
        }
        Start-Transcript -Path $Script:Config.TranscriptPath -Force
        Write-Log "Started PowerShell transcript" -Level "INFO" -Category "Initialization"
    }
    catch {
        Write-Log "Failed to start transcript: $_" -Level "WARNING" -Category "Initialization"
    }
    
    # Load custom tasks if specified
    if ($CustomTasksFile -and (Test-Path $CustomTasksFile)) {
        Import-CustomTasks -Path $CustomTasksFile
    }
    
    # Capture initial system snapshot if tracking is enabled
    if ($TrackChanges) {
        $Script:Config.BeforeSnapshot = Get-SystemSnapshot
        Write-Log "Captured initial system snapshot" -Level "INFO" -Category "Initialization"
    }
    
    # Configure cleanmgr for silent operation
    Initialize-CleanMgrSettings
    
    Write-Log "Environment initialization completed" -Level "SUCCESS" -Category "Initialization"
}

function Remove-Environment {
    [CmdletBinding()]
    param()
    
    Write-Log "Cleaning up environment" -Level "INFO" -Category "Cleanup"
    
    # Capture final system snapshot if tracking is enabled
    if ($TrackChanges) {
        $Script:Config.AfterSnapshot = Get-SystemSnapshot
        Write-Log "Captured final system snapshot" -Level "INFO" -Category "Cleanup"
    }
    
    # Generate reports if requested
    if ($GenerateReport) {
        New-HTMLReport
    }
    
    if ($ExportToJson) {
        Export-SystemData -Format "JSON"
    }
    
    if ($ExportToCsv) {
        Export-SystemData -Format "CSV"
    }
    
    # Stop transcript
    try {
        Stop-Transcript
        Write-Log "Stopped PowerShell transcript" -Level "INFO" -Category "Cleanup"
    }
    catch {
        Write-Log "Failed to stop transcript: $_" -Level "WARNING" -Category "Cleanup"
    }
    
    # Delete temporary files if requested
    if ($DeleteTempFiles) {
        try {
            Remove-Item -Path $Script:Config.TempFolder -Recurse -Force
            Write-Log "Deleted temporary files" -Level "INFO" -Category "Cleanup"
        }
        catch {
            Write-Log "Failed to delete temporary files: $_" -Level "WARNING" -Category "Cleanup"
        }
    }
    
    Write-Log "Environment cleanup completed" -Level "SUCCESS" -Category "Cleanup"
}

# ==============================================================================
# CORE MAINTENANCE FUNCTIONS
# ==============================================================================

function New-RestorePoint {
    [CmdletBinding()]
    param()
    
    return Invoke-SafeOperation -OperationName "Create System Restore Point" -Category "Safety" -ContinueOnError -ScriptBlock {
        # Enable System Restore if disabled
        Enable-ComputerRestore -Drive "C:\"
        
        # Create restore point
        $restorePointName = "System Maintenance - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        Checkpoint-Computer -Description $restorePointName -RestorePointType "MODIFY_SETTINGS"
        
        Add-Change -Type "SystemChange" -Category "Safety" -Description "Created system restore point" -Details $restorePointName
        
        return @{
            Success = $true
            RestorePointName = $restorePointName
        }
    }
}

function Install-PackageManagers {
    [CmdletBinding()]
    param()
    
    return Invoke-SafeOperation -OperationName "Install Package Managers" -Category "Prerequisites" -ContinueOnError -ScriptBlock {
        $results = @{
            WinGet = $false
            Chocolatey = $false
        }
        
        # Check and install winget
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            Write-Log "Installing winget..." -Level "INFO" -Category "Prerequisites"
            # Install winget via Microsoft Store or GitHub
            $wingetInstaller = "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
            $tempPath = "$($Script:Config.TempFolder)\winget.msixbundle"
            
            Invoke-WebRequest -Uri $wingetInstaller -OutFile $tempPath -UseBasicParsing
            Add-AppxPackage -Path $tempPath -ForceApplicationShutdown
            
            $results.WinGet = $true
            Add-Change -Type "Installation" -Category "Prerequisites" -Description "Installed winget package manager"
        }
        else {
            Write-Log "winget is already installed" -Level "INFO" -Category "Prerequisites"
            $results.WinGet = $true
        }
        
        # Check and install Chocolatey
        if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
            Write-Log "Installing Chocolatey..." -Level "INFO" -Category "Prerequisites"
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
            
            $results.Chocolatey = $true
            Add-Change -Type "Installation" -Category "Prerequisites" -Description "Installed Chocolatey package manager"
        }
        else {
            Write-Log "Chocolatey is already installed" -Level "INFO" -Category "Prerequisites"
            $results.Chocolatey = $true
        }
        
        return $results
    }
}

function Remove-Bloatware {
    [CmdletBinding()]
    param()
    
    return Invoke-SafeOperation -OperationName "Remove Bloatware" -Category "Cleanup" -ContinueOnError -ScriptBlock {
        $bloatwareList = @(
            "Microsoft.3DBuilder",
            "Microsoft.BingFinance",
            "Microsoft.BingNews",
            "Microsoft.BingSports",
            "Microsoft.BingWeather",
            "Microsoft.Getstarted",
            "Microsoft.MicrosoftOfficeHub",
            "Microsoft.MicrosoftSolitaireCollection",
            "Microsoft.People",
            "Microsoft.SkypeApp",
            "Microsoft.WindowsAlarms",
            "Microsoft.WindowsCamera",
            "Microsoft.WindowsMaps",
            "Microsoft.WindowsPhone",
            "Microsoft.WindowsSoundRecorder",
            "Microsoft.Xbox.TCUI",
            "Microsoft.XboxApp",
            "Microsoft.XboxGameOverlay",
            "Microsoft.XboxGamingOverlay",
            "Microsoft.XboxIdentityProvider",
            "Microsoft.XboxSpeechToTextOverlay",
            "Microsoft.ZuneMusic",
            "Microsoft.ZuneVideo"
        )
        
        $removedApps = @()
        
        foreach ($app in $bloatwareList) {
            $package = Get-AppxPackage -Name $app -ErrorAction SilentlyContinue
            if ($package) {
                Write-Log "Removing $app..." -Level "INFO" -Category "Cleanup"
                Remove-AppxPackage -Package $package.PackageFullName -ErrorAction SilentlyContinue
                $removedApps += $app
                Add-Change -Type "Removal" -Category "Cleanup" -Description "Removed bloatware application" -Details $app
            }
        }
        
        return @{
            Success = $true
            RemovedApps = $removedApps
            RemovedCount = $removedApps.Count
        }
    }
}

function Install-EssentialApps {
    [CmdletBinding()]
    param()
    
    return Invoke-SafeOperation -OperationName "Install Essential Applications" -Category "Installation" -ContinueOnError -ScriptBlock {
        $essentialApps = @(
            @{ Name = 'Adobe Acrobat Reader'; Winget = 'Adobe.Acrobat.Reader.64-bit'; Choco = 'adobereader' },
            @{ Name = 'Google Chrome'; Winget = 'Google.Chrome'; Choco = 'googlechrome' },
            @{ Name = 'Microsoft Edge'; Winget = 'Microsoft.Edge'; Choco = 'microsoft-edge' },
            @{ Name = 'Total Commander'; Winget = 'Ghisler.TotalCommander'; Choco = 'totalcommander' },
            @{ Name = 'PowerShell 7'; Winget = 'Microsoft.Powershell'; Choco = 'powershell' },
            @{ Name = 'Windows Terminal'; Winget = 'Microsoft.WindowsTerminal'; Choco = 'microsoft-windows-terminal' },
            @{ Name = 'WinRAR'; Winget = 'RARLab.WinRAR'; Choco = 'winrar' },
            @{ Name = '7-Zip'; Winget = '7zip.7zip'; Choco = '7zip' },
            @{ Name = 'Notepad++'; Winget = 'Notepad++.Notepad++'; Choco = 'notepadplusplus' },
            @{ Name = 'PDF24 Creator'; Winget = 'PDF24.PDF24Creator'; Choco = 'pdf24' },
            @{ Name = 'Java 8 Update'; Winget = 'Oracle.JavaRuntimeEnvironment'; Choco = 'javaruntime' }
            )
        
        $installedApps = @()
        $failedApps = @()
        
        foreach ($app in $essentialApps) {
            Write-Log "Installing $($app.Name)..." -Level "INFO" -Category "Installation"
            
            # Try winget first
            $wingetSuccess = $false
            if (Get-Command winget -ErrorAction SilentlyContinue) {
                try {
                    $wingetProcess = Start-Process -FilePath "winget" -ArgumentList "install", "--id", $app.WinGetId, "--silent", "--accept-source-agreements", "--accept-package-agreements", "--disable-interactivity" -WindowStyle Hidden -PassThru -Wait -NoNewWindow
                    if ($wingetProcess.ExitCode -eq 0) {
                        $wingetSuccess = $true
                    }
                }
                catch {
                    Write-Log "winget installation failed for $($app.Name)" -Level "WARNING" -Category "Installation"
                }
            }
            
            # Fall back to Chocolatey
            if (-not $wingetSuccess -and (Get-Command choco -ErrorAction SilentlyContinue)) {
                try {
                    $chocoProcess = Start-Process -FilePath "choco" -ArgumentList "install", $app.ChocoId, "-y", "--no-progress" -WindowStyle Hidden -PassThru -Wait -NoNewWindow
                    if ($chocoProcess.ExitCode -eq 0) {
                        $installedApps += $app.Name
                        Add-Change -Type "Installation" -Category "Installation" -Description "Installed essential application" -Details $app.Name
                    } else {
                        $failedApps += $app.Name
                    }
                }
                catch {
                    Write-Log "Chocolatey installation failed for $($app.Name)" -Level "WARNING" -Category "Installation"
                    $failedApps += $app.Name
                }
            }
            elseif ($wingetSuccess) {
                $installedApps += $app.Name
                Add-Change -Type "Installation" -Category "Installation" -Description "Installed essential application" -Details $app.Name
            }
            else {
                $failedApps += $app.Name
            }
        }
        
        return @{
            Success = $true
            InstalledApps = $installedApps
            FailedApps = $failedApps
            InstalledCount = $installedApps.Count
        }
    }
}

function Update-AllPackages {
    [CmdletBinding()]
    param()
    
    return Invoke-SafeOperation -OperationName "Update All Packages" -Category "Updates" -ContinueOnError -ScriptBlock {
        $results = @{
            WinGetUpdates = 0
            ChocolateyUpdates = 0
        }
        
        # Update winget packages
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Write-Log "Updating winget packages..." -Level "INFO" -Category "Updates"
            try {
                $wingetProcess = Start-Process -FilePath "winget" -ArgumentList "upgrade", "--all", "--silent", "--disable-interactivity" -WindowStyle Hidden -PassThru -Wait -NoNewWindow
                if ($wingetProcess.ExitCode -eq 0) {
                    $results.WinGetUpdates = 1  # Simplified count since we can't easily parse output
                    Add-Change -Type "Update" -Category "Updates" -Description "Updated winget packages" -Details $results.WinGetUpdates
                }
            }
            catch {
                Write-Log "winget update failed: $_" -Level "WARNING" -Category "Updates"
            }
        }
        
        # Update Chocolatey packages
        if (Get-Command choco -ErrorAction SilentlyContinue) {
            Write-Log "Updating Chocolatey packages..." -Level "INFO" -Category "Updates"
            try {
                $chocoProcess = Start-Process -FilePath "choco" -ArgumentList "upgrade", "all", "-y", "--no-progress" -WindowStyle Hidden -PassThru -Wait -NoNewWindow
                if ($chocoProcess.ExitCode -eq 0) {
                    $results.ChocolateyUpdates = 1  # Simplified count since we can't easily parse output
                    Add-Change -Type "Update" -Category "Updates" -Description "Updated Chocolatey packages" -Details $results.ChocolateyUpdates
                }
            }
            catch {
                Write-Log "Chocolatey update failed: $_" -Level "WARNING" -Category "Updates"
            }
        }
        
        return $results
    }
}

function Optimize-Privacy {
    [CmdletBinding()]
    param()
    
    return Invoke-SafeOperation -OperationName "Optimize Privacy Settings" -Category "Privacy" -ContinueOnError -ScriptBlock {
        $privacySettings = @(
            @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SystemPaneSuggestionsEnabled"; Value = 0 },
            @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SilentInstalledAppsEnabled"; Value = 0 },
            @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "PreInstalledAppsEnabled"; Value = 0 },
            @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "PreInstalledAppsEverEnabled"; Value = 0 },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name = "DisableWindowsConsumerFeatures"; Value = 1 },
            @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "AllowTelemetry"; Value = 0 },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry"; Value = 0 }
        )
        
        $appliedSettings = 0
        
        foreach ($setting in $privacySettings) {
            try {
                if (-not (Test-Path $setting.Path)) {
                    New-Item -Path $setting.Path -Force | Out-Null
                }
                Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type DWord
                $appliedSettings++
                Write-Log "Applied privacy setting: $($setting.Path)\$($setting.Name)" -Level "INFO" -Category "Privacy"
            }
            catch {
                Write-Log "Failed to apply privacy setting: $($setting.Path)\$($setting.Name)" -Level "WARNING" -Category "Privacy"
            }
        }
        
        Add-Change -Type "Configuration" -Category "Privacy" -Description "Applied privacy settings" -Details $appliedSettings
        
        return @{
            Success = $true
            AppliedSettings = $appliedSettings
        }
    }
}

function Install-WindowsUpdates {
    [CmdletBinding()]
    param()
    
    return Invoke-SafeOperation -OperationName "Install Windows Updates" -Category "Updates" -ContinueOnError -ScriptBlock {
        # Install PSWindowsUpdate module if not present
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-Log "Installing PSWindowsUpdate module..." -Level "INFO" -Category "Updates"
            Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
        }
        
        Import-Module PSWindowsUpdate
        
        # Get available updates
        $updates = Get-WUList
        Write-Log "Found $($updates.Count) available updates" -Level "INFO" -Category "Updates"
        
        if ($updates.Count -gt 0) {
            # Install updates without automatic reboot
            $installResult = Install-WindowsUpdate -AcceptAll -AutoReboot:$false -Verbose
            
            Add-Change -Type "Update" -Category "Updates" -Description "Installed Windows updates" -Details $updates.Count
            
            return @{
                Success = $true
                UpdatesInstalled = $updates.Count
                RebootRequired = $installResult.RebootRequired
            }
        }
        else {
            return @{
                Success = $true
                UpdatesInstalled = 0
                RebootRequired = $false
            }
        }
    }
}

function Invoke-DiskCleanup {
    [CmdletBinding()]
    param()
    
    return Invoke-SafeOperation -OperationName "Disk Cleanup" -Category "Cleanup" -ContinueOnError -ScriptBlock {
        # Get initial disk space
        $beforeSpace = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "C:" } | Select-Object -ExpandProperty FreeSpace
        
        # Clean temporary directories
        $tempPaths = @(
            "$env:TEMP\*",
            "$env:WINDIR\Temp\*",
            "$env:LOCALAPPDATA\Temp\*",
            "$env:USERPROFILE\AppData\Local\Microsoft\Windows\Temporary Internet Files\*"
        )
        
        $deletedFiles = 0
        foreach ($path in $tempPaths) {
            try {
                $files = Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                $deletedFiles += $files.Count
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            }
            catch {
                Write-Log "Failed to clean path: $path" -Level "WARNING" -Category "Cleanup"
            }
        }
        
        # Run Windows Disk Cleanup silently
        try {
            # Use cleanmgr with sageset to configure silent cleanup
            $cleanmgrProcess = Start-Process -FilePath "cleanmgr" -ArgumentList "/sagerun:1" -WindowStyle Hidden -PassThru -Wait -NoNewWindow
            if ($cleanmgrProcess.ExitCode -eq 0) {
                Write-Log "Windows Disk Cleanup completed successfully" -Level "INFO" -Category "Cleanup"
            } else {
                Write-Log "Windows Disk Cleanup completed with exit code: $($cleanmgrProcess.ExitCode)" -Level "WARNING" -Category "Cleanup"
            }
        }
        catch {
            Write-Log "Failed to run Windows Disk Cleanup: $_" -Level "WARNING" -Category "Cleanup"
        }
        
        # Get final disk space
        $afterSpace = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "C:" } | Select-Object -ExpandProperty FreeSpace
        $spaceFreed = $afterSpace - $beforeSpace
        
        Add-Change -Type "Cleanup" -Category "Cleanup" -Description "Performed disk cleanup" -Details "$([math]::Round($spaceFreed / 1GB, 2)) GB freed"
        
        return @{
            Success = $true
            SpaceFreedGB = [math]::Round($spaceFreed / 1GB, 2)
            DeletedFiles = $deletedFiles
        }
    }
}

function Test-RebootRequired {
    [CmdletBinding()]
    param()
    
    return Invoke-SafeOperation -OperationName "Check Reboot Requirement" -Category "System" -ContinueOnError -ScriptBlock {
        $rebootRequired = $false
        $reasons = @()
        
        # Check registry for reboot indicators
        $rebootPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
            "HKLM:\SOFTWARE\Microsoft\ServerManager\CurrentRebootAttempts"
        )
        
        foreach ($path in $rebootPaths) {
            if (Test-Path $path) {
                $rebootRequired = $true
                $reasons += $path
            }
        }
        
        # Check for pending file operations
        $pendingFileOps = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($pendingFileOps) {
            $rebootRequired = $true
            $reasons += "Pending file operations"
        }
        
        if ($rebootRequired) {
            Write-Log "System reboot is required" -Level "WARNING" -Category "System"
            Add-Change -Type "SystemChange" -Category "System" -Description "Reboot required" -Details $reasons
            
            if (-not $SilentMode) {
                $response = Read-Host "A system reboot is required. Reboot now? (Y/N)"
                if ($response -eq "Y" -or $response -eq "y") {
                    Write-Log "Initiating system reboot..." -Level "INFO" -Category "System"
                    Restart-Computer -Force
                }
            } else {
                Write-Log "Reboot required but running in silent mode - skipping reboot prompt" -Level "INFO" -Category "System"
            }
        }
        else {
            Write-Log "No reboot required" -Level "INFO" -Category "System"
        }
        
        return @{
            Success = $true
            RebootRequired = $rebootRequired
            Reasons = $reasons
        }
    }
}

# ==============================================================================
# SYSTEM MONITORING & TRACKING
# ==============================================================================

function Get-SystemSnapshot {
    [CmdletBinding()]
    param()
    
    return Invoke-SafeOperation -OperationName "Capture System Snapshot" -Category "Monitoring" -ContinueOnError -ScriptBlock {
        $snapshot = @{
            Timestamp = Get-Date
            OS = Get-CimInstance -ClassName Win32_OperatingSystem
            Hardware = Get-CimInstance -ClassName Win32_ComputerSystem
            DiskSpace = Get-CimInstance -ClassName Win32_LogicalDisk
            Services = Get-Service | Where-Object { $_.Status -eq "Running" }
            InstalledSoftware = Get-CimInstance -ClassName Win32_Product
            StartupPrograms = Get-CimInstance -ClassName Win32_StartupCommand
            NetworkAdapters = Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.NetEnabled -eq $true }
            EventLogs = Get-WinEvent -FilterHashtable @{LogName='System'; Level=2,3; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 50 -ErrorAction SilentlyContinue
        }
        
        return $snapshot
    }
}

function Test-SystemProblems {
    [CmdletBinding()]
    param()
    
    return Invoke-SafeOperation -OperationName "Identify System Problems" -Category "Monitoring" -ContinueOnError -ScriptBlock {
        $problems = @()
        
        # Check disk space
        $diskSpace = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
        foreach ($disk in $diskSpace) {
            $freePercentage = ($disk.FreeSpace / $disk.Size) * 100
            if ($freePercentage -lt 10) {
                $problems += @{
                    Type = "DiskSpace"
                    Severity = "Critical"
                    Description = "Low disk space on drive $($disk.DeviceID)"
                    FreePercentage = [math]::Round($freePercentage, 2)
                }
            }
            elseif ($freePercentage -lt 20) {
                $problems += @{
                    Type = "DiskSpace"
                    Severity = "Warning"
                    Description = "Low disk space on drive $($disk.DeviceID)"
                    FreePercentage = [math]::Round($freePercentage, 2)
                }
            }
        }
        
        # Check failed services
        $failedServices = Get-Service | Where-Object { $_.Status -eq "Stopped" -and $_.StartType -eq "Automatic" }
        foreach ($service in $failedServices) {
            $problems += @{
                Type = "Service"
                Severity = "Warning"
                Description = "Automatic service is stopped"
                ServiceName = $service.Name
                DisplayName = $service.DisplayName
            }
        }
        
        # Check system errors
        $systemErrors = Get-WinEvent -FilterHashtable @{LogName='System'; Level=2; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 10 -ErrorAction SilentlyContinue
        foreach ($systemError in $systemErrors) {
            $problems += @{
                Type = "SystemError"
                Severity = "Error"
                Description = $systemError.LevelDisplayName
                TimeCreated = $systemError.TimeCreated
                Id = $systemError.Id
                Message = $systemError.Message
            }
        }
        
        $Script:Config.SystemProblems = $problems
        
        return @{
            Success = $true
            ProblemsFound = $problems.Count
            Problems = $problems
        }
    }
}

function Compare-SystemSnapshots {
    [CmdletBinding()]
    param()
    
    if (-not $Script:Config.BeforeSnapshot -or -not $Script:Config.AfterSnapshot) {
        Write-Log "System snapshots not available for comparison" -Level "WARNING" -Category "Monitoring"
        return @{ Success = $false }
    }
    
    return Invoke-SafeOperation -OperationName "Compare System Snapshots" -Category "Monitoring" -ContinueOnError -ScriptBlock {
        $changes = @{
            DiskSpaceChanges = @()
            ServiceChanges = @()
            SoftwareChanges = @()
        }
        
        # Compare disk space
        $beforeDisks = $Script:Config.BeforeSnapshot.DiskSpace
        $afterDisks = $Script:Config.AfterSnapshot.DiskSpace
        
        foreach ($afterDisk in $afterDisks) {
            $beforeDisk = $beforeDisks | Where-Object { $_.DeviceID -eq $afterDisk.DeviceID }
            if ($beforeDisk) {
                $spaceDiff = $afterDisk.FreeSpace - $beforeDisk.FreeSpace
                if ([math]::Abs($spaceDiff) -gt 100MB) {
                    $changes.DiskSpaceChanges += @{
                        Drive = $afterDisk.DeviceID
                        SpaceChangeGB = [math]::Round($spaceDiff / 1GB, 2)
                    }
                }
            }
        }
        
        # Compare services
        $beforeServices = $Script:Config.BeforeSnapshot.Services.Name
        $afterServices = $Script:Config.AfterSnapshot.Services.Name
        
        $stoppedServices = $beforeServices | Where-Object { $_ -notin $afterServices }
        $startedServices = $afterServices | Where-Object { $_ -notin $beforeServices }
        
        foreach ($service in $stoppedServices) {
            $changes.ServiceChanges += @{
                ServiceName = $service
                Change = "Stopped"
            }
        }
        
        foreach ($service in $startedServices) {
            $changes.ServiceChanges += @{
                ServiceName = $service
                Change = "Started"
            }
        }
        
        # Compare installed software
        $beforeSoftware = $Script:Config.BeforeSnapshot.InstalledSoftware.Name
        $afterSoftware = $Script:Config.AfterSnapshot.InstalledSoftware.Name
        
        $removedSoftware = $beforeSoftware | Where-Object { $_ -notin $afterSoftware }
        $installedSoftware = $afterSoftware | Where-Object { $_ -notin $beforeSoftware }
        
        foreach ($software in $removedSoftware) {
            $changes.SoftwareChanges += @{
                SoftwareName = $software
                Change = "Removed"
            }
        }
        
        foreach ($software in $installedSoftware) {
            $changes.SoftwareChanges += @{
                SoftwareName = $software
                Change = "Installed"
            }
        }
        
        return @{
            Success = $true
            Changes = $changes
        }
    }
}

function Export-SystemData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("JSON", "CSV", "XML")]
        [string]$Format
    )
    
    return Invoke-SafeOperation -OperationName "Export System Data to $Format" -Category "Reporting" -ContinueOnError -ScriptBlock {
        $exportData = @{
            Timestamp = Get-Date
            ExecutionTime = (Get-Date) - $Script:Config.StartTime
            SystemChanges = $Script:Config.SystemChanges
            SystemProblems = $Script:Config.SystemProblems
            TaskResults = $Script:Config.TaskResults
            BeforeSnapshot = $Script:Config.BeforeSnapshot
            AfterSnapshot = $Script:Config.AfterSnapshot
        }
        
        $fileName = "SystemMaintenance_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        $filePath = "$($Script:Config.TempFolder)\$fileName"
        
        switch ($Format) {
            "JSON" {
                $filePath += ".json"
                $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding UTF8
            }
            "CSV" {
                $filePath += ".csv"
                $exportData.SystemChanges | Export-Csv -Path $filePath -NoTypeInformation
            }
            "XML" {
                $filePath += ".xml"
                $exportData | Export-Clixml -Path $filePath
            }
        }
        
        Write-Log "Exported system data to: $filePath" -Level "INFO" -Category "Reporting"
        
        return @{
            Success = $true
            FilePath = $filePath
        }
    }
}

function Initialize-CleanMgrSettings {
    [CmdletBinding()]
    param()
    
    # Configure cleanmgr to run silently by setting up sageset:1
    $cleanmgrKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
    $cleanupItems = @(
        "Temporary Files",
        "Recycle Bin",
        "Temporary Internet Files",
        "Thumbnails",
        "Memory Dump Files",
        "Windows Error Reporting Archive Files",
        "Windows Error Reporting Queue Files",
        "Windows Error Reporting System Archive Files",
        "Windows Error Reporting System Queue Files",
        "Downloaded Program Files",
        "WebClient/Publisher Temporary Files"
    )
    
    foreach ($item in $cleanupItems) {
        $itemPath = "$cleanmgrKey\$item"
        if (Test-Path $itemPath) {
            try {
                Set-ItemProperty -Path $itemPath -Name "StateFlags0001" -Value 2 -Type DWord -ErrorAction SilentlyContinue
            }
            catch {
                # Ignore errors for items that don't support this setting
            }
        }
    }
    
    Write-Log "Configured cleanmgr for silent operation" -Level "INFO" -Category "Initialization"
}

# ==============================================================================
# MAIN EXECUTION CONTROLLER
# ==============================================================================

function Start-SystemMaintenance {
    [CmdletBinding()]
    param()
    
    Write-Log "Starting Windows System Maintenance Script" -Level "INFO" -Category "Controller"
    Write-Log "Execution started at: $($Script:Config.StartTime)" -Level "INFO" -Category "Controller"
    
    try {
        # Initialize environment
        Initialize-Environment
        
        # Get enabled tasks
        $enabledTasks = $Script:MaintenanceTasks | Where-Object { $_.Enabled } | Sort-Object Priority
        $totalTasks = $enabledTasks.Count
        $completedTasks = 0
        
        Write-Log "Total tasks to execute: $totalTasks" -Level "INFO" -Category "Controller"
        
        # Execute tasks
        foreach ($task in $enabledTasks) {
            $completedTasks++
            $percentComplete = [math]::Round(($completedTasks / $totalTasks) * 100, 0)
            
            Write-Log "[$completedTasks/$totalTasks] ($percentComplete%) Executing: $($task.DisplayName)" -Level "INFO" -Category "Controller"
            
            try {
                $taskResult = & $task.Function
                $Script:Config.TaskResults[$task.Name] = $taskResult
                
                if ($taskResult.Success) {
                    Write-Log "Task completed successfully: $($task.DisplayName)" -Level "SUCCESS" -Category "Controller"
                }
                else {
                    Write-Log "Task completed with issues: $($task.DisplayName)" -Level "WARNING" -Category "Controller"
                }
            }
            catch {
                Write-Log "Task failed: $($task.DisplayName) - $($_.Exception.Message)" -Level "ERROR" -Category "Controller"
                $Script:Config.TaskResults[$task.Name] = @{
                    Success = $false
                    Error = $_.Exception.Message
                }
            }
        }
        
        # Run system problem detection
        Test-SystemProblems
        
        # Compare snapshots if tracking is enabled
        if ($TrackChanges) {
            Compare-SystemSnapshots
        }
        
        # Generate summary
        $executionTime = (Get-Date) - $Script:Config.StartTime
        $successfulTasks = ($Script:Config.TaskResults.Values | Where-Object { $_.Success }).Count
        $failedTasks = $totalTasks - $successfulTasks
        $totalChanges = $Script:Config.SystemChanges.Count
        $totalProblems = $Script:Config.SystemProblems.Count
        
        Write-Log "=== MAINTENANCE SUMMARY ===" -Level "SUCCESS" -Category "Controller"
        Write-Log "Execution time: $($executionTime.ToString('hh\:mm\:ss'))" -Level "INFO" -Category "Controller"
        Write-Log "Successful tasks: $successfulTasks" -Level "INFO" -Category "Controller"
        Write-Log "Failed tasks: $failedTasks" -Level "INFO" -Category "Controller"
        Write-Log "System changes tracked: $totalChanges" -Level "INFO" -Category "Controller"
        Write-Log "System problems found: $totalProblems" -Level "INFO" -Category "Controller"
        
        if ($totalProblems -gt 0) {
            Write-Log "Critical problems detected - review system status" -Level "WARNING" -Category "Controller"
        }
        
        Write-Log "Log file location: $($Script:Config.LogPath)" -Level "INFO" -Category "Controller"
        Write-Log "Output directory: $($Script:Config.TempFolder)" -Level "INFO" -Category "Controller"
        
    }
    catch {
        Write-Log "Critical error in main execution: $($_.Exception.Message)" -Level "ERROR" -Category "Controller"
        throw
    }
    finally {
        # Cleanup environment
        Remove-Environment
    }
}

# ==============================================================================
# REPORTING & EXPORT FUNCTIONS
# ==============================================================================

function New-HTMLReport {
    [CmdletBinding()]
    param()
    
    return Invoke-SafeOperation -OperationName "Generate HTML Report" -Category "Reporting" -ContinueOnError -ScriptBlock {
        $htmlPath = "$($Script:Config.TempFolder)\SystemMaintenance_Report.html"
        
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>System Maintenance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 10px; border-radius: 5px; }
        .section { margin: 20px 0; }
        .success { color: green; }
        .warning { color: orange; }
        .error { color: red; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>System Maintenance Report</h1>
        <p>Generated: $(Get-Date)</p>
        <p>Execution Time: $((Get-Date) - $Script:Config.StartTime)</p>
    </div>
    
    <div class="section">
        <h2>Task Results</h2>
        <table>
            <tr><th>Task</th><th>Status</th><th>Details</th></tr>
"@
        
        foreach ($task in $Script:MaintenanceTasks) {
            $result = $Script:Config.TaskResults[$task.Name]
            if ($result) {
                $status = if ($result.Success) { "SUCCESS" } else { "FAILED" }
                $statusClass = if ($result.Success) { "success" } else { "error" }
                $details = if ($result.Error) { $result.Error } else { "Completed successfully" }
                
                $html += "<tr><td>$($task.DisplayName)</td><td class='$statusClass'>$status</td><td>$details</td></tr>"
            }
        }
        
        $html += @"
        </table>
    </div>
    
    <div class="section">
        <h2>System Changes</h2>
        <table>
            <tr><th>Timestamp</th><th>Type</th><th>Category</th><th>Description</th></tr>
"@
        
        foreach ($change in $Script:Config.SystemChanges) {
            $html += "<tr><td>$($change.Timestamp)</td><td>$($change.Type)</td><td>$($change.Category)</td><td>$($change.Description)</td></tr>"
        }
        
        $html += @"
        </table>
    </div>
    
    <div class="section">
        <h2>System Problems</h2>
        <table>
            <tr><th>Type</th><th>Severity</th><th>Description</th></tr>
"@
        
        foreach ($problem in $Script:Config.SystemProblems) {
            $severityClass = switch ($problem.Severity) {
                "Critical" { "error" }
                "Warning" { "warning" }
                default { "" }
            }
            $html += "<tr><td>$($problem.Type)</td><td class='$severityClass'>$($problem.Severity)</td><td>$($problem.Description)</td></tr>"
        }
        
        $html += @"
        </table>
    </div>
</body>
</html>
"@
        
        $html | Out-File -FilePath $htmlPath -Encoding UTF8
        
        Write-Log "HTML report generated: $htmlPath" -Level "INFO" -Category "Reporting"
        
        return @{
            Success = $true
            ReportPath = $htmlPath
        }
    }
}

function Import-CustomTasks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    return Invoke-SafeOperation -OperationName "Import Custom Tasks" -Category "Configuration" -ContinueOnError -ScriptBlock {
        $customTasks = Get-Content -Path $Path | ConvertFrom-Json
        
        foreach ($task in $customTasks) {
            $Script:Config.CustomTasks += $task
            Write-Log "Imported custom task: $($task.Name)" -Level "INFO" -Category "Configuration"
        }
        
        return @{
            Success = $true
            ImportedTasks = $customTasks.Count
        }
    }
}

# ==============================================================================
# SCRIPT EXECUTION ENTRY POINT
# ==============================================================================

# Execute the main maintenance function
Start-SystemMaintenance