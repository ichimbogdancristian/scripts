# =====================[ SIMPLIFIED SYSTEM MAINTENANCE SCRIPT ]====================
# Purpose: Comprehensive Windows system maintenance with simplified structure
# Usage: Run as Administrator for full functionality
# ==================================================================================

param(
    [switch]$DeleteTempFiles,
    [switch]$SkipBloatwareRemoval,
    [switch]$SkipEssentialApps,
    [switch]$GenerateReport,
    [switch]$TrackChanges,
    [switch]$ExportToJson,
    [switch]$ExportToCSV,
    [string]$CustomTasksFile
)

# =====================[ GLOBAL VARIABLES ]====================
$Script:TempFolder = Join-Path $PSScriptRoot "SystemMaintenance_Temp"
$Script:LogPath = Join-Path $Script:TempFolder "SystemMaintenance.log"
$Script:ReportsFolder = Join-Path $Script:TempFolder "Reports"
$Script:SystemChanges = @()
$Script:SystemProblems = @()
$Script:BeforeSnapshot = @{}
$Script:AfterSnapshot = @{}
$Script:CustomTasks = @()

# =====================[ UTILITY FUNCTIONS ]====================
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARNING','ERROR','SUCCESS')]
        [string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "[$timestamp] [$Level] $Message"
    
    # Ensure log directory exists
    if (-not (Test-Path (Split-Path $Script:LogPath))) {
        New-Item -ItemType Directory -Path (Split-Path $Script:LogPath) -Force | Out-Null
    }
    
    Add-Content -Path $Script:LogPath -Value $entry -Encoding UTF8
    
    $color = switch ($Level) {
        'INFO' { 'White' }
        'WARNING' { 'Yellow' }
        'ERROR' { 'Red' }
        'SUCCESS' { 'Green' }
    }
    Write-Host $entry -ForegroundColor $color
}

function Add-Change {
    param(
        [string]$Type,
        [string]$Category,
        [string]$Description,
        [hashtable]$Details = @{}
    )
    
    $change = @{
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Type = $Type
        Category = $Category
        Description = $Description
    }
    
    foreach ($key in $Details.Keys) {
        $change[$key] = $Details[$key]
    }
    
    $Script:SystemChanges += $change
    Write-Log "Change tracked: $Description" -Level 'INFO'
}

function Initialize-Environment {
    if (-not (Test-Path $Script:TempFolder)) {
        New-Item -ItemType Directory -Path $Script:TempFolder -Force | Out-Null
    }
    if (-not (Test-Path $Script:ReportsFolder)) {
        New-Item -ItemType Directory -Path $Script:ReportsFolder -Force | Out-Null
    }
    
    Write-Log "Environment initialized. Temp folder: $Script:TempFolder" -Level 'SUCCESS'
    Start-Transcript -Path (Join-Path $Script:TempFolder 'transcript.txt') -Append
    
    # Load custom tasks if specified
    if ($CustomTasksFile) {
        $Script:CustomTasks = Import-CustomTasks -TaskFile $CustomTasksFile
    }
    
    # Capture initial system snapshot if tracking is enabled
    if ($TrackChanges) {
        Write-Log "Capturing initial system snapshot..." -Level 'INFO'
        $Script:BeforeSnapshot = Get-SystemSnapshot
        Test-SystemProblems | Out-Null  # Initial problems scan
    }
}

function Remove-Environment {
    # Capture final system snapshot if tracking is enabled
    if ($TrackChanges) {
        Write-Log "Capturing final system snapshot..." -Level 'INFO'
        $Script:AfterSnapshot = Get-SystemSnapshot
        
        # Compare snapshots to detect changes
        if ($Script:BeforeSnapshot -and $Script:AfterSnapshot) {
            Compare-SystemSnapshots -Before $Script:BeforeSnapshot -After $Script:AfterSnapshot | Out-Null
        }
        
        # Final problems scan
        Test-SystemProblems | Out-Null
    }
    
    # Generate reports if requested
    if ($GenerateReport) {
        Write-Log "Generating system reports..." -Level 'INFO'
        if ($ExportToJson) {
            Export-SystemData -Format "JSON" | Out-Null
        }
        if ($ExportToCSV) {
            Export-SystemData -Format "CSV" | Out-Null
        }
        if (-not $ExportToJson -and -not $ExportToCSV) {
            # Default to HTML report
            Export-SystemData -Format "HTML" | Out-Null
        }
    }
    
    try { Stop-Transcript | Out-Null } catch { }
    
    if ($DeleteTempFiles -and (Test-Path $Script:TempFolder)) {
        try {
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            Remove-Item -Path $Script:TempFolder -Recurse -Force -ErrorAction Stop
            Write-Log "Temporary files deleted successfully." -Level 'SUCCESS'
        } catch {
            Write-Log "Failed to delete temporary files: $_" -Level 'WARNING'
        }
    } else {
        Write-Log "Temporary files preserved at: $Script:TempFolder" -Level 'INFO'
        if ($GenerateReport) {
            Write-Log "Reports available at: $Script:ReportsFolder" -Level 'INFO'
        }
    }
}

# =====================[ CORE MAINTENANCE FUNCTIONS ]====================

function New-RestorePoint {
    Write-Log "Creating system restore point..." -Level 'INFO'
    try {
        # Enable System Restore if not enabled
        $srStatus = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        if (-not $srStatus) {
            Enable-ComputerRestore -Drive "C:" -ErrorAction Stop
            Write-Log "System Restore enabled." -Level 'SUCCESS'
        }
        
        Checkpoint-Computer -Description "System Maintenance Script" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Log "Restore point created successfully." -Level 'SUCCESS'
        return $true
    } catch {
        Write-Log "Failed to create restore point: $_" -Level 'ERROR'
        return $false
    }
}

function Install-PackageManagers {
    Write-Log "Setting up package managers..." -Level 'INFO'
    
    # Check and install winget
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Log "Installing winget..." -Level 'INFO'
        try {
            $appInstallerUrl = "https://aka.ms/getwinget"
            $wingetInstaller = Join-Path $Script:TempFolder "AppInstaller.msixbundle"
            Invoke-WebRequest -Uri $appInstallerUrl -OutFile $wingetInstaller -UseBasicParsing
            Add-AppxPackage -Path $wingetInstaller
            Write-Log "Winget installed successfully." -Level 'SUCCESS'
        } catch {
            Write-Log "Failed to install winget: $_" -Level 'ERROR'
        }
    } else {
        Write-Log "Winget already installed." -Level 'SUCCESS'
    }
    
    # Check and install Chocolatey
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Log "Installing Chocolatey..." -Level 'INFO'
        try {
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
            Write-Log "Chocolatey installed successfully." -Level 'SUCCESS'
        } catch {
            Write-Log "Failed to install Chocolatey: $_" -Level 'ERROR'
        }
    } else {
        Write-Log "Chocolatey already installed." -Level 'SUCCESS'
    }
}

function Remove-Bloatware {
    if ($SkipBloatwareRemoval) {
        Write-Log "Bloatware removal skipped by user request." -Level 'INFO'
        return
    }
    
    Write-Log "Removing bloatware applications..." -Level 'INFO'
    
    $BloatwareList = @(
        'Microsoft.3DBuilder', 'Microsoft.BingFinance', 'Microsoft.BingNews', 'Microsoft.BingSports',
        'Microsoft.BingWeather', 'Microsoft.GetHelp', 'Microsoft.Getstarted', 'Microsoft.MixedReality.Portal',
        'Microsoft.Microsoft3DViewer', 'Microsoft.MicrosoftOfficeHub', 'Microsoft.MicrosoftSolitaireCollection',
        'Microsoft.NetworkSpeedTest', 'Microsoft.News', 'Microsoft.Office.Sway', 'Microsoft.OneConnect',
        'Microsoft.People', 'Microsoft.Print3D', 'Microsoft.SkypeApp', 'Microsoft.Wallet',
        'Microsoft.WindowsFeedback', 'Microsoft.WindowsMaps', 'Microsoft.Xbox.TCUI', 'Microsoft.XboxApp',
        'Microsoft.XboxGameOverlay', 'Microsoft.XboxGamingOverlay', 'Microsoft.XboxIdentityProvider',
        'Microsoft.XboxSpeechToTextOverlay', 'Microsoft.ZuneMusic', 'Microsoft.ZuneVideo',
        'king.com.*', 'CandyCrush*', 'Facebook*', 'Instagram*', 'Twitter*', 'TikTok*', 'Netflix*'
    )
    
    $removedCount = 0
    $removedApps = @()
    foreach ($app in $BloatwareList) {
        try {
            $packages = Get-AppxPackage -Name $app -AllUsers -ErrorAction SilentlyContinue
            if ($packages) {
                foreach ($package in $packages) {
                    Remove-AppxPackage -Package $package.PackageFullName -ErrorAction Stop
                    $removedCount++
                    $removedApps += $package.Name
                    Write-Log "Removed: $($package.Name)" -Level 'SUCCESS'
                    
                    # Track the change
                    Add-Change -Type "Software Removed" -Category "Bloatware" -Description "Removed bloatware: $($package.Name)" -Details @{
                        AppName = $package.Name
                        PackageFullName = $package.PackageFullName
                    }
                }
            }
        } catch {
            Write-Log "Failed to remove $app`: $_" -Level 'WARNING'
        }
    }
    
    Write-Log "Bloatware removal completed. Removed $removedCount applications." -Level 'SUCCESS'
}

function Install-EssentialApps {
    if ($SkipEssentialApps) {
        Write-Log "Essential apps installation skipped by user request." -Level 'INFO'
        return
    }
    
    Write-Log "Installing essential applications..." -Level 'INFO'
    
    $EssentialApps = @(
        @{ Name = 'Google Chrome'; Winget = 'Google.Chrome'; Choco = 'googlechrome' },
        @{ Name = 'Adobe Acrobat Reader'; Winget = 'Adobe.Acrobat.Reader.64-bit'; Choco = 'adobereader' },
        @{ Name = '7-Zip'; Winget = '7zip.7zip'; Choco = '7zip' },
        @{ Name = 'Notepad++'; Winget = 'Notepad++.Notepad++'; Choco = 'notepadplusplus' },
        @{ Name = 'PowerShell 7'; Winget = 'Microsoft.Powershell'; Choco = 'powershell' },
        @{ Name = 'Windows Terminal'; Winget = 'Microsoft.WindowsTerminal'; Choco = 'microsoft-windows-terminal' }
    )
    
    $installedCount = 0
    foreach ($app in $EssentialApps) {
        Write-Log "Installing $($app.Name)..." -Level 'INFO'
        
        # Try winget first
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            try {
                $result = winget install --id $app.Winget --accept-source-agreements --accept-package-agreements --silent 2>&1
                if ($result -match 'Successfully installed' -or $result -match 'No applicable update found') {
                    Write-Log "$($app.Name) installed/updated via winget." -Level 'SUCCESS'
                    $installedCount++
                    
                    # Track the change
                    Add-Change -Type "Software Installed" -Category "Essential Apps" -Description "Installed essential app: $($app.Name)" -Details @{
                        AppName = $app.Name
                        InstallMethod = "winget"
                        PackageId = $app.Winget
                    }
                    continue
                }
            } catch { }
        }
        
        # Try chocolatey as fallback
        if (Get-Command choco -ErrorAction SilentlyContinue) {
            try {
                $result = choco install $app.Choco -y 2>&1
                if ($result -match 'successfully installed' -or $result -match 'already installed') {
                    Write-Log "$($app.Name) installed via Chocolatey." -Level 'SUCCESS'
                    $installedCount++
                    
                    # Track the change
                    Add-Change -Type "Software Installed" -Category "Essential Apps" -Description "Installed essential app: $($app.Name)" -Details @{
                        AppName = $app.Name
                        InstallMethod = "chocolatey"
                        PackageId = $app.Choco
                    }
                } else {
                    Write-Log "Failed to install $($app.Name)" -Level 'WARNING'
                }
            } catch {
                Write-Log "Failed to install $($app.Name): $_" -Level 'WARNING'
            }
        }
    }
    
    Write-Log "Essential apps installation completed. Installed/Updated $installedCount applications." -Level 'SUCCESS'
}

function Update-AllPackages {
    Write-Log "Updating all installed packages..." -Level 'INFO'
    
    # Update winget packages
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        try {
            Write-Log "Updating packages via winget..." -Level 'INFO'
            winget upgrade --all --accept-source-agreements --accept-package-agreements --silent | Out-Null
            Write-Log "Winget updates completed." -Level 'SUCCESS'
        } catch {
            Write-Log "Winget update failed: $_" -Level 'WARNING'
        }
    }
    
    # Update chocolatey packages
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        try {
            Write-Log "Updating packages via Chocolatey..." -Level 'INFO'
            choco upgrade all -y | Out-Null
            Write-Log "Chocolatey updates completed." -Level 'SUCCESS'
        } catch {
            Write-Log "Chocolatey update failed: $_" -Level 'WARNING'
        }
    }
}

function Optimize-Privacy {
    Write-Log "Optimizing privacy settings..." -Level 'INFO'
    
    $PrivacySettings = @{
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' = @{
            'AllowTelemetry' = 0
        }
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy' = @{
            'TailoredExperiencesWithDiagnosticDataEnabled' = 0
        }
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' = @{
            'AllowTelemetry' = 0
        }
    }
    
    foreach ($regPath in $PrivacySettings.Keys) {
        try {
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            foreach ($setting in $PrivacySettings[$regPath].GetEnumerator()) {
                Set-ItemProperty -Path $regPath -Name $setting.Key -Value $setting.Value -Force
                Write-Log "Set $($setting.Key) = $($setting.Value)" -Level 'SUCCESS'
            }
        } catch {
            Write-Log "Failed to set privacy setting in $regPath`: $_" -Level 'WARNING'
        }
    }
}

function Install-WindowsUpdates {
    Write-Log "Installing Windows Updates..." -Level 'INFO'
    
    # Check if PSWindowsUpdate module is available
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        try {
            Install-Module PSWindowsUpdate -Force -Scope CurrentUser
            Write-Log "PSWindowsUpdate module installed." -Level 'SUCCESS'
        } catch {
            Write-Log "Failed to install PSWindowsUpdate module: $_" -Level 'WARNING'
            return
        }
    }
    
    try {
        Import-Module PSWindowsUpdate
        $updates = Get-WUList
        if ($updates) {
            Write-Log "Found $($updates.Count) updates. Installing..." -Level 'INFO'
            Install-WindowsUpdate -AcceptAll -AutoReboot:$false
            Write-Log "Windows updates installed successfully." -Level 'SUCCESS'
        } else {
            Write-Log "No Windows updates available." -Level 'INFO'
        }
    } catch {
        Write-Log "Windows Update failed: $_" -Level 'WARNING'
    }
}

function Invoke-DiskCleanup {
    Write-Log "Performing disk cleanup..." -Level 'INFO'
    
    try {
        # Clean temporary files
        $tempPaths = @(
            "$env:TEMP\*",
            "$env:LOCALAPPDATA\Temp\*",
            "C:\Windows\Temp\*",
            "C:\Windows\Prefetch\*"
        )
        
        $cleanedSize = 0
        foreach ($tempPath in $tempPaths) {
            try {
                $items = Get-ChildItem -Path $tempPath -Recurse -Force -ErrorAction SilentlyContinue
                $size = ($items | Measure-Object -Property Length -Sum).Sum
                $cleanedSize += $size
                Remove-Item -Path $tempPath -Recurse -Force -ErrorAction SilentlyContinue
            } catch { }
        }
        
        # Run disk cleanup
        Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1" -Wait -NoNewWindow -ErrorAction SilentlyContinue
        
        $cleanedSizeMB = [math]::Round($cleanedSize / 1MB, 2)
        Write-Log "Disk cleanup completed. Freed approximately $cleanedSizeMB MB." -Level 'SUCCESS'
    } catch {
        Write-Log "Disk cleanup failed: $_" -Level 'WARNING'
    }
}

function Test-RebootRequired {
    Write-Log "Checking if reboot is required..." -Level 'INFO'
    
    $rebootRequired = $false
    
    # Check various registry keys that indicate reboot requirement
    $rebootKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations'
    )
    
    foreach ($key in $rebootKeys) {
        if (Test-Path $key) {
            $rebootRequired = $true
            break
        }
    }
    
    if ($rebootRequired) {
        Write-Log "Reboot is required to complete the maintenance tasks." -Level 'WARNING'
        $response = Read-Host "Do you want to reboot now? (Y/N)"
        if ($response -match '^[Yy]') {
            Write-Log "Rebooting system..." -Level 'INFO'
            Restart-Computer -Force
        } else {
            Write-Log "Reboot deferred. Please reboot manually when convenient." -Level 'WARNING'
        }
    } else {
        Write-Log "No reboot required." -Level 'SUCCESS'
    }
}

# =====================[ MAIN EXECUTION ]====================
function Start-SystemMaintenance {
    Write-Host "=====================[ SYSTEM MAINTENANCE SCRIPT ]===================="
    Write-Log "System maintenance started by $env:USERNAME on $env:COMPUTERNAME" -Level 'INFO'
    
    Initialize-Environment
    
    # Built-in tasks
    $tasks = @(
        @{ Name = "Create Restore Point"; Function = { New-RestorePoint } },
        @{ Name = "Setup Package Managers"; Function = { Install-PackageManagers } },
        @{ Name = "Remove Bloatware"; Function = { Remove-Bloatware } },
        @{ Name = "Install Essential Apps"; Function = { Install-EssentialApps } },
        @{ Name = "Update All Packages"; Function = { Update-AllPackages } },
        @{ Name = "Optimize Privacy"; Function = { Optimize-Privacy } },
        @{ Name = "Install Windows Updates"; Function = { Install-WindowsUpdates } },
        @{ Name = "Disk Cleanup"; Function = { Invoke-DiskCleanup } },
        @{ Name = "Check Reboot Required"; Function = { Test-RebootRequired } }
    )
    
    # Add custom tasks if loaded
    foreach ($customTask in $Script:CustomTasks) {
        $tasks += @{ 
            Name = $customTask.Name
            Function = $customTask.ScriptBlock 
            Category = $customTask.Category
        }
        Write-Log "Added custom task: $($customTask.Name)" -Level 'INFO'
    }
    
    $completedTasks = 0
    $totalTasks = $tasks.Count
    
    foreach ($task in $tasks) {
        try {
            Write-Host "`n--- $($task.Name) ---" -ForegroundColor Cyan
            & $task.Function
            $completedTasks++
            
            # Track task completion
            Add-Change -Type "Task Completed" -Category "Maintenance" -Description "Completed task: $($task.Name)" -Details @{
                TaskName = $task.Name
                TaskCategory = if ($task.Category) { $task.Category } else { "Built-in" }
            }
            
        } catch {
            Write-Log "Task '$($task.Name)' failed: $_" -Level 'ERROR'
            
            # Track task failure
            Add-Change -Type "Task Failed" -Category "Maintenance" -Description "Failed task: $($task.Name) - $_" -Details @{
                TaskName = $task.Name
                ErrorMessage = $_.ToString()
            }
        }
        
        $progress = [math]::Round(($completedTasks / $totalTasks) * 100)
        Write-Progress -Activity "System Maintenance" -Status "Progress: $progress%" -PercentComplete $progress
    }
    
    Write-Progress -Activity "System Maintenance" -Completed
    Write-Log "System maintenance completed. $completedTasks of $totalTasks tasks completed successfully." -Level 'SUCCESS'
    
    # Display summary if tracking is enabled
    if ($TrackChanges) {
        Write-Host "`n--- MAINTENANCE SUMMARY ---" -ForegroundColor Green
        Write-Host "Changes detected: $($Script:SystemChanges.Count)" -ForegroundColor Yellow
        Write-Host "Problems found: $($Script:SystemProblems.Count)" -ForegroundColor Yellow
        
        if ($Script:SystemProblems.Count -gt 0) {
            Write-Host "`nCritical Problems:" -ForegroundColor Red
            $Script:SystemProblems | Where-Object { $_.Severity -eq "High" } | ForEach-Object {
                Write-Host "  • $($_.Description)" -ForegroundColor Red
            }
        }
    }
    
    Remove-Environment
    
    Write-Host "`n=====================[ MAINTENANCE COMPLETED ]===================="
    Write-Host "Log file: $Script:LogPath" -ForegroundColor Cyan
    if (-not $DeleteTempFiles) {
        Write-Host "Temp files: $Script:TempFolder" -ForegroundColor Cyan
        if ($GenerateReport) {
            Write-Host "Reports: $Script:ReportsFolder" -ForegroundColor Cyan
        }
    }
}

# =====================[ SCRIPT EXECUTION ]====================
# Check if running as administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script should be run as Administrator for full functionality."
    $response = Read-Host "Continue anyway? (Y/N)"
    if ($response -notmatch '^[Yy]') {
        exit 1
    }
}

# Start the maintenance process
Start-SystemMaintenance

# =====================[ SYSTEM TRACKING & MONITORING FUNCTIONS ]====================

function Get-SystemSnapshot {
    Write-Log "Capturing system snapshot..." -Level 'INFO'
    
    $snapshot = @{
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        
        # System Information
        OSInfo = @{
            Version = [System.Environment]::OSVersion.VersionString
            Architecture = $env:PROCESSOR_ARCHITECTURE
            ComputerName = $env:COMPUTERNAME
            UserName = $env:USERNAME
            LastBootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
        }
        
        # Hardware Information
        Hardware = @{
            TotalRAM = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
            Processor = (Get-CimInstance Win32_Processor).Name
            DiskSpace = @{
            }
        }
        
        # Disk Information
        DiskInfo = @{
        }
        
        # Network Information
        NetworkAdapters = @()
        
        # Installed Software
        InstalledSoftware = @()
        
        # Windows Services
        Services = @{
        }
        
        # Startup Programs
        StartupPrograms = @()
        
        # System Problems
        Problems = @()
    }
    
    # Get disk information
    Get-WmiObject -Class Win32_LogicalDisk | ForEach-Object {
        if ($_.DriveType -eq 3) {  # Fixed drives only
            $snapshot.DiskInfo[$_.DeviceID] = @{
                Size = [math]::Round($_.Size / 1GB, 2)
                FreeSpace = [math]::Round($_.FreeSpace / 1GB, 2)
                UsedSpace = [math]::Round(($_.Size - $_.FreeSpace) / 1GB, 2)
                PercentFree = [math]::Round(($_.FreeSpace / $_.Size) * 100, 1)
            }
        }
    }
    
    # Get network adapters
    Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
        $snapshot.NetworkAdapters += @{
            Name = $_.Name
            InterfaceDescription = $_.InterfaceDescription
            LinkSpeed = $_.LinkSpeed
            MacAddress = $_.MacAddress
        }
    }
    
    # Get installed software (simplified)
    $snapshot.InstalledSoftware = @(
        Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne '' } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
        Sort-Object DisplayName
    )
    
    # Get services status
    Get-Service | Where-Object { $_.Name -match '^(Windows|Microsoft|Intel|AMD|NVIDIA)' } | ForEach-Object {
        $snapshot.Services[$_.Name] = $_.Status.ToString()
    }
    
    # Get startup programs
    $snapshot.StartupPrograms = @(
        Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue |
        Select-Object Name, Command, Location
    )
    
    return $snapshot
}

function Test-SystemProblems {
    Write-Log "Scanning for system problems..." -Level 'INFO'
    $problems = @()
    
    # Check disk space
    Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | ForEach-Object {
        $percentFree = ($_.FreeSpace / $_.Size) * 100
        if ($percentFree -lt 10) {
            $problems += @{
                Type = "Low Disk Space"
                Severity = "High"
                Description = "Drive $($_.DeviceID) has only $([math]::Round($percentFree, 1))% free space"
                Drive = $_.DeviceID
                FreePercent = [math]::Round($percentFree, 1)
            }
        } elseif ($percentFree -lt 20) {
            $problems += @{
                Type = "Low Disk Space"
                Severity = "Medium"
                Description = "Drive $($_.DeviceID) has only $([math]::Round($percentFree, 1))% free space"
                Drive = $_.DeviceID
                FreePercent = [math]::Round($percentFree, 1)
            }
        }
    }
    
    # Check for failed services
    Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -eq 'Stopped' } | ForEach-Object {
        $problems += @{
            Type = "Service Issue"
            Severity = "Medium"
            Description = "Automatic service '$($_.Name)' is stopped"
            ServiceName = $_.Name
            Status = $_.Status.ToString()
        }
    }
    
    # Check Windows Update errors
    try {
        $updateErrors = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WindowsUpdateClient/Operational'; Level=2} -MaxEvents 10 -ErrorAction SilentlyContinue
        if ($updateErrors) {
            $problems += @{
                Type = "Windows Update Error"
                Severity = "Medium"
                Description = "Recent Windows Update errors found ($($updateErrors.Count) errors)"
                ErrorCount = $updateErrors.Count
            }
        }
    } catch { }
    
    # Check system errors
    try {
        $systemErrors = Get-WinEvent -FilterHashtable @{LogName='System'; Level=2} -MaxEvents 5 -ErrorAction SilentlyContinue
        if ($systemErrors) {
            $problems += @{
                Type = "System Error"
                Severity = "High"
                Description = "Recent system errors found ($($systemErrors.Count) errors)"
                ErrorCount = $systemErrors.Count
            }
        }
    } catch { }
    
    # Check memory usage
    $totalRAM = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
    $availableRAM = (Get-CimInstance Win32_OperatingSystem).AvailablePhysicalMemory
    $usedPercent = (($totalRAM - $availableRAM) / $totalRAM) * 100
    
    if ($usedPercent -gt 85) {
        $problems += @{
            Type = "High Memory Usage"
            Severity = "Medium"
            Description = "Memory usage is at $([math]::Round($usedPercent, 1))%"
            MemoryUsagePercent = [math]::Round($usedPercent, 1)
        }
    }
    
    $Script:SystemProblems = $problems
    Write-Log "Found $($problems.Count) system problems." -Level 'INFO'
    return $problems
}

function Compare-SystemSnapshots {
    param(
        [hashtable]$Before,
        [hashtable]$After
    )
    
    Write-Log "Comparing system snapshots..." -Level 'INFO'
    $changes = @()
    
    # Compare disk space
    foreach ($drive in $Before.DiskInfo.Keys) {
        if ($After.DiskInfo.ContainsKey($drive)) {
            $beforeSpace = $Before.DiskInfo[$drive].FreeSpace
            $afterSpace = $After.DiskInfo[$drive].FreeSpace
            $spaceDiff = $afterSpace - $beforeSpace
            
            if ([math]::Abs($spaceDiff) -gt 0.1) {  # More than 100MB difference
                $changes += @{
                    Type = "Disk Space Change"
                    Category = "Storage"
                    Description = "Drive $drive free space changed by $([math]::Round($spaceDiff, 2)) GB"
                    Drive = $drive
                    BeforeGB = $beforeSpace
                    AfterGB = $afterSpace
                    ChangeGB = $spaceDiff
                }
            }
        }
    }
    
    # Compare installed software
    $beforeSoftware = $Before.InstalledSoftware | ForEach-Object { $_.DisplayName }
    $afterSoftware = $After.InstalledSoftware | ForEach-Object { $_.DisplayName }
    
    # New software
    $newSoftware = $afterSoftware | Where-Object { $_ -notin $beforeSoftware }
    foreach ($software in $newSoftware) {
        $changes += @{
            Type = "Software Installed"
            Category = "Software"
            Description = "Installed: $software"
            SoftwareName = $software
        }
    }
    
    # Removed software
    $removedSoftware = $beforeSoftware | Where-Object { $_ -notin $afterSoftware }
    foreach ($software in $removedSoftware) {
        $changes += @{
            Type = "Software Removed"
            Category = "Software"
            Description = "Removed: $software"
            SoftwareName = $software
        }
    }
    
    # Compare services
    foreach ($serviceName in $Before.Services.Keys) {
        if ($After.Services.ContainsKey($serviceName)) {
            if ($Before.Services[$serviceName] -ne $After.Services[$serviceName]) {
                $changes += @{
                    Type = "Service Status Change"
                    Category = "Services"
                    Description = "Service $serviceName changed from $($Before.Services[$serviceName]) to $($After.Services[$serviceName])"
                    ServiceName = $serviceName
                    BeforeStatus = $Before.Services[$serviceName]
                    AfterStatus = $After.Services[$serviceName]
                }
            }
        }
    }
    
    $Script:SystemChanges = $changes
    Write-Log "Detected $($changes.Count) system changes." -Level 'INFO'
    return $changes
}

function Export-SystemData {
    param(
        [string]$Format = "JSON"  # JSON, CSV, HTML
    )
    
    if (-not (Test-Path $Script:ReportsFolder)) {
        New-Item -ItemType Directory -Path $Script:ReportsFolder -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $exportData = @{
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        BeforeSnapshot = $Script:BeforeSnapshot
        AfterSnapshot = $Script:AfterSnapshot
        SystemChanges = $Script:SystemChanges
        SystemProblems = $Script:SystemProblems
        MaintenanceLog = if (Test-Path $Script:LogPath) { Get-Content $Script:LogPath } else { @() }
    }
    
    switch ($Format.ToUpper()) {
        "JSON" {
            $jsonFile = Join-Path $Script:ReportsFolder "SystemReport_$timestamp.json"
            $exportData | ConvertTo-Json -Depth 10 | Out-File $jsonFile -Encoding UTF8
            Write-Log "System data exported to JSON: $jsonFile" -Level 'SUCCESS'
            return $jsonFile
        }
        "CSV" {
            # Export changes to CSV
            $csvFile = Join-Path $Script:ReportsFolder "SystemChanges_$timestamp.csv"
            $Script:SystemChanges | Export-Csv $csvFile -NoTypeInformation -Encoding UTF8
            
            # Export problems to CSV
            $problemsCsvFile = Join-Path $Script:ReportsFolder "SystemProblems_$timestamp.csv"
            $Script:SystemProblems | Export-Csv $problemsCsvFile -NoTypeInformation -Encoding UTF8
            
            Write-Log "System data exported to CSV: $csvFile and $problemsCsvFile" -Level 'SUCCESS'
            return @($csvFile, $problemsCsvFile)
        }
        "HTML" {
            $htmlFile = Join-Path $Script:ReportsFolder "SystemReport_$timestamp.html"
            $htmlContent = Generate-HTMLReport -Data $exportData
            $htmlContent | Out-File $htmlFile -Encoding UTF8
            Write-Log "System data exported to HTML: $htmlFile" -Level 'SUCCESS'
            return $htmlFile
        }
    }
}

function Generate-HTMLReport {
    param([hashtable]$Data)
    
    $changesHtml = ""
    foreach ($change in $Data.SystemChanges) {
        $changesHtml += "<tr><td>$($change.Timestamp)</td><td>$($change.Type)</td><td>$($change.Category)</td><td>$($change.Description)</td></tr>"
    }
    
    $problemsHtml = ""
    foreach ($problem in $Data.SystemProblems) {
        $severityClass = switch ($problem.Severity) {
            "High" { "severity-high" }
            "Medium" { "severity-medium" }
            "Low" { "severity-low" }
            default { "" }
        }
        $problemsHtml += "<tr class='$severityClass'><td>$($problem.Type)</td><td>$($problem.Severity)</td><td>$($problem.Description)</td></tr>"
    }
    
    return @"
<!DOCTYPE html>
<html>
<head>
    <title>System Maintenance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; text-align: center; }
        .section { margin: 20px 0; }
        .section h2 { background: #34495e; color: white; padding: 10px; margin: 0; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #f2f2f2; }
        .severity-high { background: #ffebee; }
        .severity-medium { background: #fff3e0; }
        .severity-low { background: #e8f5e8; }
        .timestamp { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>System Maintenance Report</h1>
        <p class="timestamp">Generated: $($Data.Timestamp)</p>
    </div>
    
    <div class="section">
        <h2>System Changes</h2>
        <table>
            <tr><th>Timestamp</th><th>Type</th><th>Category</th><th>Description</th></tr>
            $changesHtml
        </table>
    </div>
    
    <div class="section">
        <h2>System Problems</h2>
        <table>
            <tr><th>Type</th><th>Severity</th><th>Description</th></tr>
            $problemsHtml
        </table>
    </div>
</body>
</html>
"@
}

function Import-CustomTasks {
    param([string]$TaskFile)
    
    if (-not $TaskFile -or -not (Test-Path $TaskFile)) {
        Write-Log "Custom tasks file not found or not specified." -Level 'WARNING'
        return @()
    }
    
    try {
        $customTasks = @()
        $taskContent = Get-Content $TaskFile -Raw | ConvertFrom-Json
        
        foreach ($task in $taskContent) {
            if ($task.Name -and $task.ScriptBlock) {
                $customTasks += @{
                    Name = $task.Name
                    Description = $task.Description
                    ScriptBlock = [ScriptBlock]::Create($task.ScriptBlock)
                    Category = $task.Category
                }
                Write-Log "Loaded custom task: $($task.Name)" -Level 'INFO'
            }
        }
        
        Write-Log "Loaded $($customTasks.Count) custom tasks from $TaskFile" -Level 'SUCCESS'
        return $customTasks
    } catch {
        Write-Log "Failed to import custom tasks: $_" -Level 'ERROR'
        return @()
    }
}

# =====================[ ENHANCED MAINTENANCE FUNCTIONS ]====================
