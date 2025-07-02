# =====================================================================================
# UNIFIED SYSTEM MAINTENANCE POLICY FRAMEWORK
# =====================================================================================
# Version: 2.0
# Purpose: Unified framework for modular system maintenance tasks with extensive logging
# Architecture: Policy-driven, modular, robust error handling, standardized logging
# =====================================================================================

#Requires -Version 5.1
#Requires -RunAsAdministrator

using namespace System.Collections.Generic
using namespace System.IO

# =====================================================================================
# GLOBAL POLICY CONFIGURATION
# =====================================================================================
$Global:SystemMaintenancePolicy = @{
    Version = '2.0'
    RequiredPowerShellVersion = '5.1'
    MaxConcurrentTasks = 1
    DefaultTimeoutMinutes = 30
    LogRetentionDays = 30
    EnableVerboseLogging = $true
    EnablePerformanceMetrics = $true
    EnableAutoReboot = $false
}

# =====================================================================================
# CENTRAL COORDINATION POLICY CONTROLLER
# =====================================================================================
class SystemMaintenancePolicyController {
    [hashtable]$Context
    [List[TaskDefinition]]$RegisteredTasks
    [string]$SessionId
    
    SystemMaintenancePolicyController() {
        $this.SessionId = (Get-Date).ToString('yyyyMMdd_HHmmss') + '_' + (Get-Random -Maximum 9999).ToString('D4')
        $this.RegisteredTasks = [List[TaskDefinition]]::new()
        $this.InitializeContext()
    }
    
    [void] InitializeContext() {
        $this.Context = @{
            SessionId = $this.SessionId
            StartTime = Get-Date
            TempFolder = Join-Path $PSScriptRoot "SystemMaintenance_$($this.SessionId)"
            TaskFolders = @{}
            TaskLogs = @{}
            TaskResults = @{}
            GlobalLogPath = $null
            ErrorCount = 0
            WarningCount = 0
            SuccessCount = 0
            Performance = @{}
        }
        
        $this.InitializeEnvironment()
    }
    
    [void] InitializeEnvironment() {
        # Create main temp folder structure
        if (-not (Test-Path $this.Context.TempFolder)) {
            New-Item -ItemType Directory -Path $this.Context.TempFolder -Force | Out-Null
        }
        
        # Create logs directory
        $logsFolder = Join-Path $this.Context.TempFolder 'Logs'
        if (-not (Test-Path $logsFolder)) {
            New-Item -ItemType Directory -Path $logsFolder -Force | Out-Null
        }
        
        # Initialize global log
        $this.Context.GlobalLogPath = Join-Path $logsFolder "GlobalSession_$($this.SessionId).log"
        
        # Start transcript
        $transcriptPath = Join-Path $logsFolder "Transcript_$($this.SessionId).txt"
        Start-Transcript -Path $transcriptPath -Append -ErrorAction SilentlyContinue
        
        $this.WriteGlobalLog("INIT", "INFO", "System Maintenance Policy Controller initialized")
        $this.WriteGlobalLog("INIT", "INFO", "Session ID: $($this.SessionId)")
        $this.WriteGlobalLog("INIT", "INFO", "Temp folder: $($this.Context.TempFolder)")
    }
    
    [void] RegisterTask([TaskDefinition]$task) {
        $this.RegisteredTasks.Add($task)
        $this.WriteGlobalLog("REGISTER", "INFO", "Task registered: $($task.Name)")
    }
    
    [void] ExecuteAllTasks() {
        $this.WriteGlobalLog("EXECUTION", "INFO", "Starting execution of $($this.RegisteredTasks.Count) registered tasks")
        
        foreach ($task in $this.RegisteredTasks) {
            $this.ExecuteTask($task)
        }
        
        $this.GenerateExecutionSummary()
        $this.Cleanup()
    }
    
    [void] ExecuteTask([TaskDefinition]$task) {
        $taskStartTime = Get-Date
        $this.WriteGlobalLog("EXECUTION", "INFO", "Starting task: $($task.Name)")
        
        try {
            # Create task-specific folder and log
            $taskFolder = $this.CreateTaskFolder($task.Name)
            $taskLogPath = Join-Path $taskFolder "$($task.Name.Replace(' ', '_'))_$($this.SessionId).log"
            
            $this.Context.TaskFolders[$task.Name] = $taskFolder
            $this.Context.TaskLogs[$task.Name] = $taskLogPath
            
            # Initialize task log with standardized structure
            $taskLogger = [TaskLogger]::new($taskLogPath, $task.Name, $this.SessionId)
            $taskLogger.StartTaskLog($task.Description, $task.Dependencies)
            
            # Execute the task
            $taskContext = $this.Context.Clone()
            $taskContext.CurrentTask = $task.Name
            $taskContext.TaskLogger = $taskLogger
            $taskContext.TaskFolder = $taskFolder
            
            & $task.ScriptBlock -Context $taskContext
            
            $taskLogger.CompleteTaskLog("SUCCESS", "Task completed successfully")
            $this.Context.SuccessCount++
            $this.WriteGlobalLog("EXECUTION", "SUCCESS", "Task completed: $($task.Name)")
            
        } catch {
            $this.Context.ErrorCount++
            $errorMessage = "Task failed: $($task.Name) - Error: $_"
            $this.WriteGlobalLog("EXECUTION", "ERROR", $errorMessage)
            
            if ($taskLogger) {
                $taskLogger.CompleteTaskLog("ERROR", $errorMessage)
            }
        } finally {
            $taskDuration = (Get-Date) - $taskStartTime
            $this.Context.Performance[$task.Name] = @{
                Duration = $taskDuration
                StartTime = $taskStartTime
                EndTime = Get-Date
            }
        }
    }
    
    [string] CreateTaskFolder([string]$taskName) {
        $sanitizedName = $taskName -replace '[^\w\-_]', '_'
        $taskFolder = Join-Path $this.Context.TempFolder "Tasks\$sanitizedName"
        
        if (-not (Test-Path $taskFolder)) {
            New-Item -ItemType Directory -Path $taskFolder -Force | Out-Null
        }
        
        return $taskFolder
    }
    
    [void] WriteGlobalLog([string]$section, [string]$level, [string]$message) {
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
        $entry = "[$timestamp] [$section] [$level] $message"
        
        Add-Content -Path $this.Context.GlobalLogPath -Value $entry -Encoding UTF8
        
        # Console output with color coding
        $color = switch ($level) {
            'INFO'    { 'Cyan' }
            'SUCCESS' { 'Green' }
            'WARNING' { 'Yellow' }
            'ERROR'   { 'Red' }
            default   { 'White' }
        }
        
        Write-Host $entry -ForegroundColor $color
    }
    
    [void] GenerateExecutionSummary() {
        $summaryPath = Join-Path $this.Context.TempFolder "ExecutionSummary_$($this.SessionId).html"
        $totalDuration = (Get-Date) - $this.Context.StartTime
        
        $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>System Maintenance Execution Summary</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 10px; border-radius: 5px; }
        .task { margin: 10px 0; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        .success { background-color: #d4edda; }
        .error { background-color: #f8d7da; }
        .metrics { background-color: #e7f3ff; padding: 10px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>System Maintenance Execution Summary</h1>
        <p><strong>Session ID:</strong> $($this.SessionId)</p>
        <p><strong>Start Time:</strong> $($this.Context.StartTime)</p>
        <p><strong>Duration:</strong> $($totalDuration.ToString())</p>
        <p><strong>Total Tasks:</strong> $($this.RegisteredTasks.Count)</p>
        <p><strong>Successful:</strong> $($this.Context.SuccessCount)</p>
        <p><strong>Errors:</strong> $($this.Context.ErrorCount)</p>
        <p><strong>Warnings:</strong> $($this.Context.WarningCount)</p>
    </div>
    
    <h2>Task Performance Metrics</h2>
    <div class="metrics">
"@
        
        foreach ($task in $this.RegisteredTasks) {
            $perf = $this.Context.Performance[$task.Name]
            if ($perf) {
                $htmlContent += "<p><strong>$($task.Name):</strong> $($perf.Duration.TotalSeconds.ToString('F2'))s</p>"
            }
        }
        
        $htmlContent += @"
    </div>
    
    <h2>Task Details</h2>
"@
        
        foreach ($task in $this.RegisteredTasks) {
            $status = if ($this.Context.TaskResults.ContainsKey($task.Name)) { "success" } else { "error" }
            $htmlContent += @"
    <div class="task $status">
        <h3>$($task.Name)</h3>
        <p><strong>Description:</strong> $($task.Description)</p>
        <p><strong>Log File:</strong> $($this.Context.TaskLogs[$task.Name])</p>
    </div>
"@
        }
        
        $htmlContent += "</body></html>"
        
        Set-Content -Path $summaryPath -Value $htmlContent -Encoding UTF8
        $this.WriteGlobalLog("SUMMARY", "INFO", "Execution summary generated: $summaryPath")
    }
    
    [void] Cleanup() {
        try {
            Stop-Transcript -ErrorAction SilentlyContinue
            $this.WriteGlobalLog("CLEANUP", "INFO", "Policy controller cleanup completed")
        } catch {
            Write-Warning "Cleanup warning: $_"
        }
    }
}

# =====================================================================================
# TASK DEFINITION CLASS
# =====================================================================================
class TaskDefinition {
    [string]$Name
    [string]$Description
    [string[]]$Dependencies
    [scriptblock]$ScriptBlock
    [int]$TimeoutMinutes
    [bool]$CriticalTask
    
    TaskDefinition([string]$name, [string]$description, [scriptblock]$scriptBlock) {
        $this.Name = $name
        $this.Description = $description
        $this.ScriptBlock = $scriptBlock
        $this.Dependencies = @()
        $this.TimeoutMinutes = $Global:SystemMaintenancePolicy.DefaultTimeoutMinutes
        $this.CriticalTask = $false
    }
}

# =====================================================================================
# EXTENSIVE TASK LOGGING CLASS
# =====================================================================================
class TaskLogger {
    [string]$LogPath
    [string]$TaskName
    [string]$SessionId
    [datetime]$StartTime
    [List[string]]$LogSections
    
    TaskLogger([string]$logPath, [string]$taskName, [string]$sessionId) {
        $this.LogPath = $logPath
        $this.TaskName = $taskName
        $this.SessionId = $sessionId
        $this.StartTime = Get-Date
        $this.LogSections = [List[string]]::new()
    }
    
    [void] StartTaskLog([string]$description, [string[]]$dependencies) {
        $this.WriteLogSection("HEADER", @"
================================================================================
TASK EXECUTION LOG - STANDARDIZED STRUCTURE v2.0
================================================================================
Task Name: $($this.TaskName)
Description: $description
Session ID: $($this.SessionId)
Start Time: $($this.StartTime.ToString('yyyy-MM-dd HH:mm:ss.fff'))
Computer: $($env:COMPUTERNAME)
User: $($env:USERNAME)
PowerShell Version: $($PSVersionTable.PSVersion)
Dependencies: $($dependencies -join ', ')
================================================================================
"@)
    }
    
    [void] WriteLogSection([string]$sectionName, [string]$content) {
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
        $section = @"

[$timestamp] ========== $sectionName ==========
$content
========== END $sectionName ==========

"@
        
        Add-Content -Path $this.LogPath -Value $section -Encoding UTF8
        $this.LogSections.Add($sectionName)
    }
    
    [void] LogStep([string]$stepName, [string]$details, [string]$level = "INFO") {
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
        $stepLog = "[$timestamp] [$level] [STEP: $stepName] $details"
        Add-Content -Path $this.LogPath -Value $stepLog -Encoding UTF8
    }
    
    [void] LogStateSnapshot([string]$stateName, [hashtable]$stateData) {
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
        $stateContent = "[$timestamp] [STATE: $stateName]`n"
        
        foreach ($key in $stateData.Keys) {
            $stateContent += "  $key`: $($stateData[$key])`n"
        }
        
        Add-Content -Path $this.LogPath -Value $stateContent -Encoding UTF8
    }
    
    [void] LogError([string]$errorMessage, [System.Management.Automation.ErrorRecord]$errorRecord = $null) {
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
        $errorLog = @"
[$timestamp] [ERROR] $errorMessage
"@
        
        if ($errorRecord) {
            $errorLog += @"

Error Details:
  Exception: $($errorRecord.Exception.Message)
  Script Line: $($errorRecord.InvocationInfo.ScriptLineNumber)
  Position: $($errorRecord.InvocationInfo.PositionMessage)
  Stack Trace: $($errorRecord.ScriptStackTrace)
"@
        }
        
        Add-Content -Path $this.LogPath -Value $errorLog -Encoding UTF8
    }
    
    [void] CompleteTaskLog([string]$status, [string]$summary) {
        $endTime = Get-Date
        $duration = $endTime - $this.StartTime
        
        $this.WriteLogSection("TASK_COMPLETION", @"
Task Status: $status
End Time: $($endTime.ToString('yyyy-MM-dd HH:mm:ss.fff'))
Total Duration: $($duration.ToString())
Summary: $summary
Log Sections Created: $($this.LogSections.Count) [$($this.LogSections -join ', ')]
================================================================================
TASK LOG COMPLETED
================================================================================
"@)
    }
}

# =====================================================================================
# STANDARDIZED TASK TEMPLATE FUNCTIONS
# =====================================================================================
function New-TaskDefinition {
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        
        [Parameter(Mandatory)]
        [string]$Description,
        
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,
        
        [string[]]$Dependencies = @(),
        
        [int]$TimeoutMinutes = 30,
        
        [bool]$CriticalTask = $false
    )
    
    $task = [TaskDefinition]::new($Name, $Description, $ScriptBlock)
    $task.Dependencies = $Dependencies
    $task.TimeoutMinutes = $TimeoutMinutes
    $task.CriticalTask = $CriticalTask
    
    return $task
}

# =====================================================================================
# ROBUST TASK IMPLEMENTATIONS
# =====================================================================================

# Task 1: Central Coordination Policy
$Task1_CentralCoordinationPolicy = New-TaskDefinition -Name "Central Coordination Policy" -Description "Establish centralized lists and coordination policies" -ScriptBlock {
    param([hashtable]$Context)
    
    $logger = $Context.TaskLogger
    
    try {
        $logger.WriteLogSection("INITIALIZATION", "Starting Central Coordination Policy task")
        
        # Pre-execution state
        $preState = @{
            TaskFolder = $Context.TaskFolder
            SystemInfo = Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, TotalPhysicalMemory
        }
        $logger.LogStateSnapshot("PRE_EXECUTION", $preState)
        
        # Step 1: Create bloatware list
        $logger.LogStep("BLOATWARE_LIST_CREATION", "Creating comprehensive bloatware list")
        
        $bloatwareList = @(
            'Microsoft.BingWeather', 'Microsoft.GetHelp', 'Microsoft.Getstarted',
            'Microsoft.Microsoft3DViewer', 'Microsoft.MicrosoftSolitaireCollection',
            'Microsoft.ZuneMusic', 'Microsoft.ZuneVideo', 'king.com.CandyCrushSaga'
        ) | Sort-Object -Unique
        
        $bloatwareListPath = Join-Path $Context.TaskFolder 'Bloatware_list.txt'
        $bloatwareList | ConvertTo-Json | Set-Content -Path $bloatwareListPath -Encoding UTF8
        
        $logger.LogStep("BLOATWARE_LIST_SAVED", "Bloatware list saved with $($bloatwareList.Count) entries")
        
        # Step 2: Create essential apps list
        $logger.LogStep("ESSENTIAL_APPS_LIST_CREATION", "Creating essential applications list")
        
        $essentialApps = @(
            @{ Name = 'Google Chrome'; Winget = 'Google.Chrome'; Choco = 'googlechrome' },
            @{ Name = '7-Zip'; Winget = '7zip.7zip'; Choco = '7zip' },
            @{ Name = 'Notepad++'; Winget = 'Notepad++.Notepad++'; Choco = 'notepadplusplus' }
        )
        
        $essentialAppsPath = Join-Path $Context.TaskFolder 'EssentialApps_list.txt'
        $essentialApps | ConvertTo-Json | Set-Content -Path $essentialAppsPath -Encoding UTF8
        
        $logger.LogStep("ESSENTIAL_APPS_LIST_SAVED", "Essential apps list saved with $($essentialApps.Count) entries")
        
        # Post-execution state
        $postState = @{
            BloatwareListPath = $bloatwareListPath
            BloatwareCount = $bloatwareList.Count
            EssentialAppsPath = $essentialAppsPath
            EssentialAppsCount = $essentialApps.Count
            TaskFolderSize = (Get-ChildItem $Context.TaskFolder -Recurse | Measure-Object -Property Length -Sum).Sum
        }
        $logger.LogStateSnapshot("POST_EXECUTION", $postState)
        
    } catch {
        $logger.LogError("Task execution failed", $_)
        throw
    }
}

# Task 2: System Protection
$Task2_SystemProtection = New-TaskDefinition -Name "System Protection" -Description "Enable System Restore and create restoration checkpoint" -ScriptBlock {
    param([hashtable]$Context)
    
    $logger = $Context.TaskLogger
    
    try {
        $logger.WriteLogSection("INITIALIZATION", "Starting System Protection task")
        
        # Pre-execution state
        $preState = @{
            RestorePointsBefore = (Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Measure-Object).Count
            SystemDrive = $env:SystemDrive
        }
        $logger.LogStateSnapshot("PRE_EXECUTION", $preState)
        
        # Step 1: Check System Restore status
        $logger.LogStep("RESTORE_STATUS_CHECK", "Checking if System Restore is enabled")
        
        $restoreEnabled = $false
        $restorePoints = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        
        if ($restorePoints) {
            $restoreEnabled = $true
            $logger.LogStep("RESTORE_STATUS_VERIFIED", "System Restore is already enabled")
        } else {
            $logger.LogStep("RESTORE_ENABLEMENT", "Enabling System Restore on $($env:SystemDrive)")
            Enable-ComputerRestore -Drive $env:SystemDrive -ErrorAction Stop
            $restoreEnabled = $true
            $logger.LogStep("RESTORE_ENABLED", "System Restore enabled successfully")
        }
        
        # Step 2: Create restore point
        if ($restoreEnabled) {
            $logger.LogStep("RESTORE_POINT_CREATION", "Creating system restore point")
            $restorePointName = "SystemMaintenance_$($Context.SessionId)"
            Checkpoint-Computer -Description $restorePointName -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
            $logger.LogStep("RESTORE_POINT_CREATED", "Restore point '$restorePointName' created successfully")
        }
        
        # Post-execution state
        $postState = @{
            RestorePointsAfter = (Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Measure-Object).Count
            RestoreEnabled = $restoreEnabled
            LatestRestorePoint = (Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Select-Object -First 1).Description
        }
        $logger.LogStateSnapshot("POST_EXECUTION", $postState)
        
    } catch {
        $logger.LogError("Task execution failed", $_)
        throw
    }
}

# Task 3: Package Manager Setup
$Task3_PackageManagerSetup = New-TaskDefinition -Name "Package Manager Setup" -Description "Install and configure package managers (winget and Chocolatey)" -ScriptBlock {
    param([hashtable]$Context)
    
    $logger = $Context.TaskLogger
    
    try {
        $logger.WriteLogSection("INITIALIZATION", "Starting Package Manager Setup task")
        
        # Pre-execution state
        $preState = @{
            WingetAvailable = [bool](Get-Command winget -ErrorAction SilentlyContinue)
            ChocolateyAvailable = [bool](Get-Command choco -ErrorAction SilentlyContinue)
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        }
        $logger.LogStateSnapshot("PRE_EXECUTION", $preState)
        
        # Step 1: Setup winget
        $logger.LogStep("WINGET_CHECK", "Checking winget availability")
        if (-not $preState.WingetAvailable) {
            $logger.LogStep("WINGET_INSTALLATION", "Installing winget via App Installer")
            try {
                $appInstallerUrl = "https://aka.ms/getwinget"
                $wingetInstaller = Join-Path $Context.TaskFolder "AppInstaller.msixbundle"
                Invoke-WebRequest -Uri $appInstallerUrl -OutFile $wingetInstaller -UseBasicParsing
                Add-AppxPackage -Path $wingetInstaller
                $logger.LogStep("WINGET_INSTALLED", "Winget installation completed successfully")
            } catch {
                $logger.LogError("Failed to install winget", $_)
            }
        } else {
            $logger.LogStep("WINGET_EXISTS", "Winget already available")
        }
        
        # Step 2: Setup Chocolatey
        $logger.LogStep("CHOCOLATEY_CHECK", "Checking Chocolatey availability")
        if (-not $preState.ChocolateyAvailable) {
            $logger.LogStep("CHOCOLATEY_INSTALLATION", "Installing Chocolatey")
            try {
                Set-ExecutionPolicy Bypass -Scope Process -Force
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
                $chocoScript = 'Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString("https://community.chocolatey.org/install.ps1"))'
                powershell -NoProfile -ExecutionPolicy Bypass -Command $chocoScript
                $logger.LogStep("CHOCOLATEY_INSTALLED", "Chocolatey installation completed successfully")
            } catch {
                $logger.LogError("Failed to install Chocolatey", $_)
            }
        } else {
            $logger.LogStep("CHOCOLATEY_EXISTS", "Chocolatey already available")
        }
        
        # Post-execution state
        $postState = @{
            WingetAvailable = [bool](Get-Command winget -ErrorAction SilentlyContinue)
            ChocolateyAvailable = [bool](Get-Command choco -ErrorAction SilentlyContinue)
            PackageManagersReady = $true
        }
        $logger.LogStateSnapshot("POST_EXECUTION", $postState)
        
    } catch {
        $logger.LogError("Task execution failed", $_)
        throw
    }
}

# Task 4: System Inventory
$Task4_SystemInventory = New-TaskDefinition -Name "System Inventory" -Description "Collect comprehensive system information and installed software inventory" -ScriptBlock {
    param([hashtable]$Context)
    
    $logger = $Context.TaskLogger
    
    try {
        $logger.WriteLogSection("INITIALIZATION", "Starting System Inventory task")
        
        # Create inventory directory
        $inventoryPath = Join-Path $Context.TaskFolder 'inventory'
        if (-not (Test-Path $inventoryPath)) {
            New-Item -ItemType Directory -Path $inventoryPath -Force | Out-Null
        }
        
        # Pre-execution state
        $preState = @{
            InventoryPath = $inventoryPath
            DiskSpace = (Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace
        }
        $logger.LogStateSnapshot("PRE_EXECUTION", $preState)
        
        # Step 1: Collect OS information
        $logger.LogStep("OS_INFO_COLLECTION", "Collecting operating system information")
        try {
            Get-ComputerInfo | Out-File (Join-Path $inventoryPath 'os_info.txt')
            $logger.LogStep("OS_INFO_SAVED", "OS information saved successfully")
        } catch {
            $logger.LogError("Failed to collect OS information", $_)
        }
        
        # Step 2: Collect hardware information
        $logger.LogStep("HARDWARE_INFO_COLLECTION", "Collecting hardware information")
        try {
            Get-WmiObject -Class Win32_ComputerSystem | Out-File (Join-Path $inventoryPath 'hardware_info.txt')
            $logger.LogStep("HARDWARE_INFO_SAVED", "Hardware information saved successfully")
        } catch {
            $logger.LogError("Failed to collect hardware information", $_)
        }
        
        # Step 3: Collect disk information
        $logger.LogStep("DISK_INFO_COLLECTION", "Collecting disk information")
        try {
            Get-PSDrive | Where-Object {$_.Provider -like '*FileSystem*'} | Out-File (Join-Path $inventoryPath 'disk_info.txt')
            $logger.LogStep("DISK_INFO_SAVED", "Disk information saved successfully")
        } catch {
            $logger.LogError("Failed to collect disk information", $_)
        }
        
        # Step 4: Collect network information
        $logger.LogStep("NETWORK_INFO_COLLECTION", "Collecting network information")
        try {
            Get-NetIPAddress | Out-File (Join-Path $inventoryPath 'network_info.txt')
            $logger.LogStep("NETWORK_INFO_SAVED", "Network information saved successfully")
        } catch {
            $logger.LogError("Failed to collect network information", $_)
        }
        
        # Step 5: Collect installed programs
        $logger.LogStep("INSTALLED_PROGRAMS_COLLECTION", "Collecting installed programs inventory")
        try {
            $installedProgramsList = @()
            
            # Registry-based installed programs (64-bit and 32-bit)
            $installedProgramsList += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue
            $installedProgramsList += Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue
            
            # AppX packages
            $installedProgramsList += Get-AppxPackage -AllUsers | Select-Object -ExpandProperty Name
            
            # Winget-managed packages
            if (Get-Command winget -ErrorAction SilentlyContinue) {
                $wingetList = winget list --source winget 2>$null | Select-Object -Skip 1
                $installedProgramsList += $wingetList | ForEach-Object { $_.Split(' ')[0] }
            }
            
            # Clean and save the list
            $installedProgramsList = $installedProgramsList | Where-Object { $_ -and $_.Trim() -ne '' } | Sort-Object -Unique
            $installedProgramsList | ConvertTo-Json | Set-Content -Path (Join-Path $inventoryPath 'installed_programs.json') -Encoding UTF8
            
            $logger.LogStep("INSTALLED_PROGRAMS_SAVED", "Installed programs list saved with $($installedProgramsList.Count) entries")
        } catch {
            $logger.LogError("Failed to collect installed programs", $_)
        }
        
        # Post-execution state
        $postState = @{
            InventoryFilesCreated = (Get-ChildItem $inventoryPath -File | Measure-Object).Count
            TotalInventorySize = (Get-ChildItem $inventoryPath -Recurse | Measure-Object -Property Length -Sum).Sum
        }
        $logger.LogStateSnapshot("POST_EXECUTION", $postState)
        
    } catch {
        $logger.LogError("Task execution failed", $_)
        throw
    }
}

# Task 5: Remove Bloatware
$Task5_RemoveBloatware = New-TaskDefinition -Name "Remove Bloatware" -Description "Remove unwanted bloatware applications from the system" -ScriptBlock {
    param([hashtable]$Context)
    
    $logger = $Context.TaskLogger
    
    try {
        $logger.WriteLogSection("INITIALIZATION", "Starting Remove Bloatware task")
        
        # Load bloatware list from Task 1
        $bloatwareListPath = Join-Path (Join-Path $Context.TempFolder "Tasks\Central_Coordination_Policy") 'Bloatware_list.txt'
        $bloatwareList = @()
        
        if (Test-Path $bloatwareListPath) {
            try {
                $bloatwareList = Get-Content $bloatwareListPath | ConvertFrom-Json
            } catch {
                # Fallback to default list
                $bloatwareList = @(
                    'Microsoft.BingWeather', 'Microsoft.GetHelp', 'Microsoft.Getstarted',
                    'Microsoft.Microsoft3DViewer', 'Microsoft.MicrosoftSolitaireCollection',
                    'Microsoft.ZuneMusic', 'Microsoft.ZuneVideo', 'king.com.CandyCrushSaga'
                )
            }
        }
        
        # Pre-execution state
        $preState = @{
            BloatwareTargets = $bloatwareList.Count
            InstalledAppsBefore = (Get-AppxPackage -AllUsers | Measure-Object).Count
        }
        $logger.LogStateSnapshot("PRE_EXECUTION", $preState)
        
        $removedCount = 0
        $errorCount = 0
        
        # Remove bloatware applications
        foreach ($bloat in $bloatwareList) {
            $logger.LogStep("REMOVE_BLOATWARE", "Processing removal of: $bloat")
            
            try {
                # Try AppX removal first
                $appxPackage = Get-AppxPackage -AllUsers | Where-Object { $_.Name -like "*$bloat*" }
                if ($appxPackage) {
                    Remove-AppxPackage -Package $appxPackage.PackageFullName -AllUsers -ErrorAction Stop
                    $removedCount++
                    $logger.LogStep("BLOATWARE_REMOVED", "Successfully removed AppX package: $bloat")
                    continue
                }
                
                # Try winget removal
                if (Get-Command winget -ErrorAction SilentlyContinue) {
                    $wingetResult = winget uninstall --id $bloat --exact --silent --accept-source-agreements 2>&1
                    if ($wingetResult -notmatch 'No installed package found') {
                        $removedCount++
                        $logger.LogStep("BLOATWARE_REMOVED", "Successfully removed via winget: $bloat")
                        continue
                    }
                }
                
                $logger.LogStep("BLOATWARE_NOT_FOUND", "Bloatware not found on system: $bloat")
                
            } catch {
                $errorCount++
                $logger.LogError("Failed to remove bloatware: $bloat", $_)
            }
        }
        
        # Post-execution state
        $postState = @{
            BloatwareRemoved = $removedCount
            RemovalErrors = $errorCount
            InstalledAppsAfter = (Get-AppxPackage -AllUsers | Measure-Object).Count
        }
        $logger.LogStateSnapshot("POST_EXECUTION", $postState)
        
    } catch {
        $logger.LogError("Task execution failed", $_)
        throw
    }
}

# Task 6: Install Essential Applications
$Task6_InstallEssentialApps = New-TaskDefinition -Name "Install Essential Applications" -Description "Install essential applications needed for system productivity" -ScriptBlock {
    param([hashtable]$Context)
    
    $logger = $Context.TaskLogger
    
    try {
        $logger.WriteLogSection("INITIALIZATION", "Starting Install Essential Applications task")
        
        # Load essential apps list from Task 1
        $essentialAppsListPath = Join-Path (Join-Path $Context.TempFolder "Tasks\Central_Coordination_Policy") 'EssentialApps_list.txt'
        $essentialApps = @()
        
        if (Test-Path $essentialAppsListPath) {
            try {
                $essentialApps = Get-Content $essentialAppsListPath | ConvertFrom-Json
            } catch {
                # Fallback to default list
                $essentialApps = @(
                    @{ Name = 'Google Chrome'; Winget = 'Google.Chrome'; Choco = 'googlechrome' },
                    @{ Name = '7-Zip'; Winget = '7zip.7zip'; Choco = '7zip' },
                    @{ Name = 'Notepad++'; Winget = 'Notepad++.Notepad++'; Choco = 'notepadplusplus' }
                )
            }
        }
        
        # Pre-execution state  
        $preState = @{
            EssentialAppsTargets = $essentialApps.Count
            WingetAvailable = [bool](Get-Command winget -ErrorAction SilentlyContinue)
            ChocolateyAvailable = [bool](Get-Command choco -ErrorAction SilentlyContinue)
        }
        $logger.LogStateSnapshot("PRE_EXECUTION", $preState)
        
        $installedCount = 0
        $errorCount = 0
        
        # Install essential applications
        foreach ($app in $essentialApps) {
            $logger.LogStep("INSTALL_ESSENTIAL_APP", "Processing installation of: $($app.Name)")
            
            try {
                $installed = $false
                
                # Try winget installation first
                if ($preState.WingetAvailable -and $app.Winget) {
                    try {
                        $wingetResult = winget install --id $app.Winget --exact --silent --accept-source-agreements --accept-package-agreements 2>&1
                        if ($wingetResult -notmatch 'No package found') {
                            $installed = $true
                            $installedCount++
                            $logger.LogStep("APP_INSTALLED", "Successfully installed via winget: $($app.Name)")
                        }
                    } catch {
                        $logger.LogError("Winget installation failed for $($app.Name)", $_)
                    }
                }
                
                # Try Chocolatey if winget failed
                if (-not $installed -and $preState.ChocolateyAvailable -and $app.Choco) {
                    try {
                        $chocoResult = choco install $app.Choco -y 2>&1
                        if ($chocoResult -notmatch 'not found') {
                            $installed = $true
                            $installedCount++
                            $logger.LogStep("APP_INSTALLED", "Successfully installed via Chocolatey: $($app.Name)")
                        }
                    } catch {
                        $logger.LogError("Chocolatey installation failed for $($app.Name)", $_)
                    }
                }
                
                if (-not $installed) {
                    $errorCount++
                    $logger.LogStep("APP_INSTALL_FAILED", "Failed to install: $($app.Name)")
                }
                
            } catch {
                $errorCount++
                $logger.LogError("Failed to install essential app: $($app.Name)", $_)
            }
        }
        
        # Post-execution state
        $postState = @{
            AppsInstalled = $installedCount
            InstallationErrors = $errorCount
            InstallationSuccessRate = if ($essentialApps.Count -gt 0) { ($installedCount / $essentialApps.Count) * 100 } else { 0 }
        }
        $logger.LogStateSnapshot("POST_EXECUTION", $postState)
        
    } catch {
        $logger.LogError("Task execution failed", $_)
        throw
    }
}

# Task 7: Upgrade All Packages
$Task7_UpgradeAllPackages = New-TaskDefinition -Name "Upgrade All Packages" -Description "Update all installed packages to their latest versions" -ScriptBlock {
    param([hashtable]$Context)
    
    $logger = $Context.TaskLogger
    
    try {
        $logger.WriteLogSection("INITIALIZATION", "Starting Upgrade All Packages task")
        
        # Pre-execution state
        $preState = @{
            WingetAvailable = [bool](Get-Command winget -ErrorAction SilentlyContinue)
            ChocolateyAvailable = [bool](Get-Command choco -ErrorAction SilentlyContinue)
        }
        $logger.LogStateSnapshot("PRE_EXECUTION", $preState)
        
        $upgradeCount = 0
        $errorCount = 0
        
        # Step 1: Upgrade winget packages
        if ($preState.WingetAvailable) {
            $logger.LogStep("WINGET_UPGRADE", "Upgrading packages via winget")
            try {
                $wingetUpgradeResult = winget upgrade --all --accept-source-agreements --accept-package-agreements --silent 2>&1
                $upgradeCount++
                $logger.LogStep("WINGET_UPGRADE_COMPLETED", "Winget package upgrades completed")
            } catch {
                $errorCount++
                $logger.LogError("Winget upgrade failed", $_)
            }
        }
        
        # Step 2: Upgrade Chocolatey packages
        if ($preState.ChocolateyAvailable) {
            $logger.LogStep("CHOCOLATEY_UPGRADE", "Upgrading packages via Chocolatey")
            try {
                $chocoUpgradeResult = choco upgrade all -y 2>&1
                $upgradeCount++
                $logger.LogStep("CHOCOLATEY_UPGRADE_COMPLETED", "Chocolatey package upgrades completed")
            } catch {
                $errorCount++
                $logger.LogError("Chocolatey upgrade failed", $_)
            }
        }
        
        # Post-execution state
        $postState = @{
            UpgradeOperations = $upgradeCount
            UpgradeErrors = $errorCount
        }
        $logger.LogStateSnapshot("POST_EXECUTION", $postState)
        
    } catch {
        $logger.LogError("Task execution failed", $_)
        throw
    }
}

# Task 8: Privacy and Telemetry
$Task8_PrivacyAndTelemetry = New-TaskDefinition -Name "Privacy and Telemetry" -Description "Configure privacy settings and disable telemetry" -ScriptBlock {
    param([hashtable]$Context)
    
    $logger = $Context.TaskLogger
    
    try {
        $logger.WriteLogSection("INITIALIZATION", "Starting Privacy and Telemetry task")
        
        # Pre-execution state
        $preState = @{
            TelemetryLevel = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue).AllowTelemetry
        }
        $logger.LogStateSnapshot("PRE_EXECUTION", $preState)
        
        $settingsChanged = 0
        $errorCount = 0
        
        # Step 1: Disable telemetry
        $logger.LogStep("DISABLE_TELEMETRY", "Disabling Windows telemetry")
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Force
            $settingsChanged++
            $logger.LogStep("TELEMETRY_DISABLED", "Telemetry disabled successfully")
        } catch {
            $errorCount++
            $logger.LogError("Failed to disable telemetry", $_)
        }
        
        # Step 2: Disable advertising ID
        $logger.LogStep("DISABLE_ADVERTISING_ID", "Disabling advertising ID")
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Force
            $settingsChanged++
            $logger.LogStep("ADVERTISING_ID_DISABLED", "Advertising ID disabled successfully")
        } catch {
            $errorCount++
            $logger.LogError("Failed to disable advertising ID", $_)
        }
        
        # Step 3: Disable location tracking
        $logger.LogStep("DISABLE_LOCATION_TRACKING", "Disabling location tracking")
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Force
            $settingsChanged++
            $logger.LogStep("LOCATION_TRACKING_DISABLED", "Location tracking disabled successfully")
        } catch {
            $errorCount++
            $logger.LogError("Failed to disable location tracking", $_)
        }
        
        # Post-execution state
        $postState = @{
            SettingsChanged = $settingsChanged
            ConfigurationErrors = $errorCount
            TelemetryLevelAfter = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue).AllowTelemetry
        }
        $logger.LogStateSnapshot("POST_EXECUTION", $postState)
        
    } catch {
        $logger.LogError("Task execution failed", $_)
        throw
    }
}

# Task 9: Windows Update
$Task9_WindowsUpdate = New-TaskDefinition -Name "Windows Update" -Description "Check for and install Windows updates" -ScriptBlock {
    param([hashtable]$Context)
    
    $logger = $Context.TaskLogger
    
    try {
        $logger.WriteLogSection("INITIALIZATION", "Starting Windows Update task")
        
        # Pre-execution state
        $preState = @{
            PSWindowsUpdateAvailable = [bool](Get-Module -ListAvailable -Name PSWindowsUpdate)
            LastUpdateCheck = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect" -Name "LastSuccessTime" -ErrorAction SilentlyContinue).LastSuccessTime
        }
        $logger.LogStateSnapshot("PRE_EXECUTION", $preState)
        
        # Step 1: Install PSWindowsUpdate module if needed
        if (-not $preState.PSWindowsUpdateAvailable) {
            $logger.LogStep("INSTALL_PSWINDOWSUPDATE", "Installing PSWindowsUpdate module")
            try {
                Install-Module -Name PSWindowsUpdate -Force -SkipPublisherCheck
                $logger.LogStep("PSWINDOWSUPDATE_INSTALLED", "PSWindowsUpdate module installed successfully")
            } catch {
                $logger.LogError("Failed to install PSWindowsUpdate module", $_)
                return
            }
        }
        
        # Step 2: Check for updates
        $logger.LogStep("CHECK_UPDATES", "Checking for Windows updates")
        try {
            $updates = Get-WUList -MicrosoftUpdate
            $logger.LogStep("UPDATES_FOUND", "Found $($updates.Count) available updates")
            
            # Step 3: Install updates if any are found
            if ($updates.Count -gt 0) {
                $logger.LogStep("INSTALL_UPDATES", "Installing Windows updates")
                $installResult = Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot:$false
                $logger.LogStep("UPDATES_INSTALLED", "Windows updates installation completed")
            }
        } catch {
            $logger.LogError("Windows update check/installation failed", $_)
        }
        
        # Post-execution state
        $postState = @{
            UpdatesAvailable = if ($updates) { $updates.Count } else { 0 }
            UpdatesInstalled = if ($installResult) { $installResult.Count } else { 0 }
            RebootRequired = [bool](Get-WUIsPendingReboot -ErrorAction SilentlyContinue)
        }
        $logger.LogStateSnapshot("POST_EXECUTION", $postState)
        
    } catch {
        $logger.LogError("Task execution failed", $_)
        throw
    }
}

# Task 10: Disk Cleanup
$Task10_DiskCleanup = New-TaskDefinition -Name "Disk Cleanup" -Description "Perform comprehensive disk cleanup and optimization" -ScriptBlock {
    param([hashtable]$Context)
    
    $logger = $Context.TaskLogger
    
    try {
        $logger.WriteLogSection("INITIALIZATION", "Starting Disk Cleanup task")
        
        # Pre-execution state
        $preState = @{
            FreeSpaceBefore = (Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace
            TempFolderSize = if (Test-Path $env:TEMP) { (Get-ChildItem $env:TEMP -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum } else { 0 }
        }
        $logger.LogStateSnapshot("PRE_EXECUTION", $preState)
        
        $cleanupOperations = 0
        $errorCount = 0
        
        # Step 1: Clean temporary files
        $logger.LogStep("CLEAN_TEMP_FILES", "Cleaning temporary files")
        try {
            if (Test-Path $env:TEMP) {
                Get-ChildItem $env:TEMP -Recurse -Force | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                $cleanupOperations++
                $logger.LogStep("TEMP_FILES_CLEANED", "Temporary files cleaned successfully")
            }
        } catch {
            $errorCount++
            $logger.LogError("Failed to clean temporary files", $_)
        }
        
        # Step 2: Clean Windows Update cache
        $logger.LogStep("CLEAN_UPDATE_CACHE", "Cleaning Windows Update cache")
        try {
            Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
            if (Test-Path "C:\Windows\SoftwareDistribution\Download") {
                Get-ChildItem "C:\Windows\SoftwareDistribution\Download" -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                $cleanupOperations++
                $logger.LogStep("UPDATE_CACHE_CLEANED", "Windows Update cache cleaned successfully")
            }
            Start-Service -Name wuauserv -ErrorAction SilentlyContinue
        } catch {
            $errorCount++
            $logger.LogError("Failed to clean Windows Update cache", $_)
        }
        
        # Step 3: Run disk cleanup utility
        $logger.LogStep("RUN_DISK_CLEANUP", "Running Windows disk cleanup utility")
        try {
            Start-Process cleanmgr -ArgumentList "/sagerun:1" -Wait -NoNewWindow
            $cleanupOperations++
            $logger.LogStep("DISK_CLEANUP_COMPLETED", "Disk cleanup utility completed")
        } catch {
            $errorCount++
            $logger.LogError("Failed to run disk cleanup utility", $_)
        }
        
        # Post-execution state
        $postState = @{
            FreeSpaceAfter = (Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace
            CleanupOperations = $cleanupOperations
            CleanupErrors = $errorCount
            SpaceReclaimed = $null
        }
        $postState.SpaceReclaimed = $postState.FreeSpaceAfter - $preState.FreeSpaceBefore
        $logger.LogStateSnapshot("POST_EXECUTION", $postState)
        
    } catch {
        $logger.LogError("Task execution failed", $_)
        throw
    }
}

# Task 11: Generate System Report
$Task11_GenerateSystemReport = New-TaskDefinition -Name "Generate System Report" -Description "Generate comprehensive system maintenance report" -ScriptBlock {
    param([hashtable]$Context)
    
    $logger = $Context.TaskLogger
    
    try {
        $logger.WriteLogSection("INITIALIZATION", "Starting Generate System Report task")
        
        # Pre-execution state
        $preState = @{
            ReportFolder = $Context.TaskFolder
        }
        $logger.LogStateSnapshot("PRE_EXECUTION", $preState)
        
        # Step 1: Generate HTML report
        $logger.LogStep("GENERATE_HTML_REPORT", "Generating HTML system report")
        try {
            $reportPath = Join-Path $Context.TaskFolder "SystemMaintenanceReport.html"
            $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>System Maintenance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .section { margin: 15px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .success { background-color: #d4edda; }
        .warning { background-color: #fff3cd; }
        .error { background-color: #f8d7da; }
    </style>
</head>
<body>
    <div class="header">
        <h1>System Maintenance Report</h1>
        <p><strong>Generated:</strong> $(Get-Date)</p>
        <p><strong>Computer:</strong> $($env:COMPUTERNAME)</p>
        <p><strong>User:</strong> $($env:USERNAME)</p>
    </div>
    
    <div class="section success">
        <h2>System Information</h2>
        <p><strong>OS Version:</strong> $([System.Environment]::OSVersion.VersionString)</p>
        <p><strong>PowerShell Version:</strong> $($PSVersionTable.PSVersion)</p>
        <p><strong>Free Disk Space:</strong> $([math]::Round((Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace / 1GB, 2)) GB</p>
    </div>
    
    <div class="section">
        <h2>Maintenance Tasks Completed</h2>
        <p>System maintenance has been completed successfully. All logs are available in the task folders for detailed review.</p>
    </div>
</body>
</html>
"@
            Set-Content -Path $reportPath -Value $htmlContent -Encoding UTF8
            $logger.LogStep("HTML_REPORT_GENERATED", "HTML report generated successfully at: $reportPath")
        } catch {
            $logger.LogError("Failed to generate HTML report", $_)
        }
        
        # Post-execution state
        $postState = @{
            ReportGenerated = Test-Path $reportPath
            ReportPath = $reportPath
        }
        $logger.LogStateSnapshot("POST_EXECUTION", $postState)
        
    } catch {
        $logger.LogError("Task execution failed", $_)
        throw
    }
}

# Task 12: System Reboot Check
$Task12_SystemRebootCheck = New-TaskDefinition -Name "System Reboot Check" -Description "Check if system reboot is required and prompt user" -ScriptBlock {
    param([hashtable]$Context)
    
    $logger = $Context.TaskLogger
    
    try {
        $logger.WriteLogSection("INITIALIZATION", "Starting System Reboot Check task")
        
        # Pre-execution state
        $preState = @{
            PendingReboot = $false
        }
        
        # Check for pending reboot
        $rebootRequired = $false
        
        # Check Windows Update reboot flag
        if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue) {
            $rebootRequired = $true
        }
        
        # Check pending file rename operations
        if (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue) {
            $rebootRequired = $true
        }
        
        $preState.PendingReboot = $rebootRequired
        $logger.LogStateSnapshot("PRE_EXECUTION", $preState)
        
        # Step 1: Check reboot requirement
        $logger.LogStep("CHECK_REBOOT_REQUIREMENT", "Checking if system reboot is required")
        
        if ($rebootRequired) {
            $logger.LogStep("REBOOT_REQUIRED", "System reboot is required")
            
            if (-not $Global:SystemMaintenancePolicy.EnableAutoReboot) {
                $logger.LogStep("PROMPT_USER_REBOOT", "Prompting user for reboot decision")
                Write-Host "`n⚠️  SYSTEM REBOOT REQUIRED" -ForegroundColor Yellow
                Write-Host "Some changes require a system restart to take effect." -ForegroundColor Yellow
                Write-Host "Do you want to restart now? [Y/N]" -NoNewline -ForegroundColor Yellow
                $response = Read-Host " "
                
                if ($response -match '^[Yy]') {
                    $logger.LogStep("USER_APPROVED_REBOOT", "User approved system reboot")
                    Restart-Computer -Force
                } else {
                    $logger.LogStep("USER_DECLINED_REBOOT", "User declined system reboot")
                    Write-Host "System restart postponed. Please restart manually when convenient." -ForegroundColor Yellow
                }
            } else {
                $logger.LogStep("AUTO_REBOOT", "Automatic reboot enabled - restarting system")
                Restart-Computer -Force
            }
        } else {
            $logger.LogStep("NO_REBOOT_REQUIRED", "No system reboot is required")
        }
        
        # Post-execution state
        $postState = @{
            RebootRequired = $rebootRequired
            AutoRebootEnabled = $Global:SystemMaintenancePolicy.EnableAutoReboot
        }
        $logger.LogStateSnapshot("POST_EXECUTION", $postState)
        
    } catch {
        $logger.LogError("Task execution failed", $_)
        throw
    }
}

# =====================================================================================
# MAIN EXECUTION FUNCTION
# =====================================================================================
function Start-SystemMaintenance {
    param(
        [switch]$DeleteTempFiles,
        [string[]]$TasksToRun = @(),
        [switch]$GenerateReport = $true
    )
    
    try {
        # Initialize the policy controller
        $controller = [SystemMaintenancePolicyController]::new()
        
        # Register all tasks
        $controller.RegisterTask($Task1_CentralCoordinationPolicy)
        $controller.RegisterTask($Task2_SystemProtection)
        $controller.RegisterTask($Task3_PackageManagerSetup)
        $controller.RegisterTask($Task4_SystemInventory)
        $controller.RegisterTask($Task5_RemoveBloatware)
        $controller.RegisterTask($Task6_InstallEssentialApps)
        $controller.RegisterTask($Task7_UpgradeAllPackages)
        $controller.RegisterTask($Task8_PrivacyAndTelemetry)
        $controller.RegisterTask($Task9_WindowsUpdate)
        $controller.RegisterTask($Task10_DiskCleanup)
        $controller.RegisterTask($Task11_GenerateSystemReport)
        $controller.RegisterTask($Task12_SystemRebootCheck)
        
        # Execute all registered tasks
        $controller.ExecuteAllTasks()
        
        # Show results location
        Write-Host "`n=================================================================================" -ForegroundColor Green
        Write-Host "SYSTEM MAINTENANCE COMPLETED" -ForegroundColor Green
        Write-Host "=================================================================================" -ForegroundColor Green
        Write-Host "Session ID: $($controller.SessionId)" -ForegroundColor Cyan
        Write-Host "Results Location: $($controller.Context.TempFolder)" -ForegroundColor Cyan
        Write-Host "Global Log: $($controller.Context.GlobalLogPath)" -ForegroundColor Cyan
        Write-Host "=================================================================================" -ForegroundColor Green
        
        # Optional cleanup
        if ($DeleteTempFiles) {
            $controller.WriteGlobalLog("CLEANUP", "INFO", "Deleting temporary files as requested")
            Remove-Item -Path $controller.Context.TempFolder -Recurse -Force -ErrorAction SilentlyContinue
        }
        
    } catch {
        Write-Error "System maintenance failed: $_"
        throw
    }
}

# =====================================================================================
# SCRIPT EXECUTION ENTRY POINT
# =====================================================================================
if ($MyInvocation.InvocationName -ne '.') {
    # Script is being executed directly, not dot-sourced
    Start-SystemMaintenance -GenerateReport
}
