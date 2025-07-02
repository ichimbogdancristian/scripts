# =====================[ CENTRAL COORDINATION POLICY ]=====================
function Invoke-CentralCoordinationPolicy {
    <#
        Reviews script structure, execution logic, and timeline.
        Ensures all tasks are executed, errors are logged, and script is maintainable.
    #>
    Write-Host "[INFO] Central Coordination Policy enforced."
    # --- Centralized Temp Folder Creation ---
    $Script:TempFolder = Join-Path $env:TEMP "SystemMaintenance_$(Get-Random)"
    if (-not (Test-Path $Script:TempFolder)) {
        New-Item -ItemType Directory -Path $Script:TempFolder -Force | Out-Null
    }
    # --- Unified and Unique Bloatware List ---
    $Script:BloatwareList = @(
        'Microsoft.Microsoft3DViewer', 'king.com.CandyCrushSaga', 'king.com.CandyCrushFriends',
        'king.com.CandyCrushSodaSaga', 'king.com.BubbleWitch3Saga', 'king.com.FarmHeroesSaga',
        'Microsoft.XboxApp', 'Microsoft.XboxGamingOverlay', 'Microsoft.XboxGameOverlay',
        'Microsoft.Xbox.TCUI', 'Microsoft.XboxSpeechToTextOverlay', 'Microsoft.XboxIdentityProvider',
        'Microsoft.ZuneMusic', 'Microsoft.ZuneVideo', 'Microsoft.Office.OneNote', 'Microsoft.SkypeApp',
        'Microsoft.MicrosoftSolitaireCollection', 'Microsoft.BingWeather', 'Microsoft.BingNews',
        'Microsoft.BingFinance', 'Microsoft.BingSports', 'Microsoft.BingFoodAndDrink',
        'Microsoft.BingHealthAndFitness', 'Microsoft.BingTravel', 'Microsoft.People',
        'Microsoft.MixedReality.Portal', 'Microsoft.GetHelp', 'Microsoft.Getstarted',
        'Microsoft.MicrosoftOfficeHub', 'Microsoft.WindowsFeedbackHub', 'Microsoft.WindowsMaps',
        'Microsoft.SoundRecorder', 'Microsoft.ScreenSketch', 'Microsoft.MicrosoftStickyNotes',
        'Microsoft.3DBuilder', 'Microsoft.Advertising.Xaml', 'Microsoft.Messaging',
        'Microsoft.MicrosoftPowerBIForWindows', 'Microsoft.News', 'Microsoft.Office.Sway',
        'Microsoft.OneConnect', 'Microsoft.Print3D', 'Microsoft.Wallet', 'Microsoft.Whiteboard',
        'Microsoft.WindowsReadingList', 'Microsoft.WindowsFeedback', 'Microsoft.WindowsSoundRecorder',
        'Microsoft.NetworkSpeedTest',
        'WildTangent', 'McAfee', 'Norton', 'CyberLink', 'ExpressVPN', 'Booking.com', 'Keeper', 'Dropbox',
        'Amazon', 'HP JumpStart', 'HP Support Assistant', 'Dell Customer Connect', 'Lenovo Vantage',
        'Lenovo App Explorer', 'Asus GiftBox', 'Candy Crush', 'Spotify', 'Disney+', 'Facebook',
        'Twitter', 'LinkedIn', 'Booking', 'eBay', 'Netflix', 'Farm Heroes', 'March of Empires', 'Sling',
        'Phototastic', 'PicsArt', 'Adobe Express', 'Simple Solitaire', 'Bubble Witch', 'Hidden City',
        'Minecraft', 'Royal Revolt', 'Dolby', 'Power2Go', 'PowerDirector', 'WildTangent Games',
        'Keeper Password Manager', 'TripAdvisor', 'WPS Office', 'Evernote', 'Foxit', 'Opera', 'Opera GX',
        'Vivaldi', 'Brave', 'Tor Browser', 'UC Browser', 'Baidu Browser', 'Yandex Browser', 'Comodo Dragon',
        'SRWare Iron', 'Maxthon', 'Pale Moon', 'Waterfox', 'Slimjet', 'Cent Browser', 'Coc Coc',
        'Avant Browser', 'SeaMonkey', 'Epic Privacy Browser', 'Sleipnir', 'Dooble', 'Otter Browser',
        'Falkon', 'Midori', 'QuteBrowser', 'K-Meleon', 'Lunascape', '360 Browser', 'Basilisk', 'Polarity',
        'Ghost Browser', 'Coowon', 'Orbitum', 'Sputnik', 'Sogou Explorer', 'SlimBrowser', 'Blisk',
        'Cliqz', 'Torch', 'Superbird', 'CoolNovo', 'QupZilla', 'Acer Collection',
        'Acer Configuration Manager', 'Acer Portal', 'Acer Power Management', 'Acer Quick Access',
        'Acer UEIP Framework', 'Acer User Experience Improvement Program', 'ASUS Live Update',
        'ASUS GiftBox', 'ASUS Splendid Video Enhancement Technology', 'ASUS WebStorage', 'ASUS ZenAnywhere',
        'ASUS ZenLink', 'Dell Digital Delivery', 'Dell Foundation Services', 'Dell Help & Support',
        'Dell Mobile Connect', 'Dell Power Manager', 'Dell Product Registration', 'Dell SupportAssist',
        'Dell Update', 'HP 3D DriveGuard', 'HP Audio Switch', 'HP Client Security Manager',
        'HP Connection Optimizer', 'HP Documentation', 'HP Dropbox Plugin', 'HP ePrint SW',
        'HP JumpStart Apps', 'HP JumpStart Launch', 'HP Registration Service',
        'HP Support Solutions Framework', 'HP Sure Connect', 'HP System Event Utility', 'HP Welcome',
        'Lenovo Companion', 'Lenovo Experience Improvement', 'Lenovo Family Cloud',
        'Lenovo Hotkeys', 'Lenovo Migration Assistant', 'Lenovo Modern IM Controller', 'Lenovo Service Bridge',
        'Lenovo Solution Center', 'Lenovo Utility', 'Lenovo Voice', 'Lenovo WiFi Security',
        'WildTangent Helper', 'CyberLink PowerDVD', 'CyberLink YouCam',
        'CyberLink Media Suite', 'McAfee LiveSafe', 'McAfee Security', 'McAfee Safe Connect', 'McAfee WebAdvisor', 'Norton Security', 
        'Norton Online Backup', 'Avast Free Antivirus', 'AVG Antivirus', 'Avira', 'Kaspersky', 'Bitdefender',
        'ESET', 'CCleaner', 'Driver Booster', 'DriverPack', 'PC App Store', 'PC Accelerate', 'PC Optimizer',
        'Reimage Repair', 'Advanced SystemCare', 'Adobe Creative Cloud', 'Adobe Genuine Service',
        'OneDrive', 'Hulu', 'Amazon Prime Video', 'Instagram', 
        'TikTok', 'Power2Go', 'PowerDirector',  'YouTube'
    ) | Sort-Object -Unique
    # Write unified bloatware list to temp transcript file
    $bloatwareListPath = Join-Path $Script:TempFolder 'Bloatware_list.txt'
    $Script:BloatwareList | ForEach-Object { $_ | ConvertTo-Json -Compress } | Out-File $bloatwareListPath -Encoding UTF8
    # --- Centralized Essential Apps List ---
    $Script:EssentialApps = @(
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
        @{ Name = 'Java 8 Update'; Winget = 'Oracle.JavaRuntimeEnvironment'; Choco = 'javaruntime' },
        @{ Name = 'Mail and Calendar'; Winget = 'Microsoft.WindowsCommunicationsApps'; Choco = '' },
        @{ Name = 'Phone Link'; Winget = 'Microsoft.YourPhone'; Choco = '' },
        @{ Name = 'Windows Calculator'; Winget = 'Microsoft.WindowsCalculator'; Choco = '' },
        @{ Name = 'Windows Camera'; Winget = 'Microsoft.WindowsCamera'; Choco = '' },
        @{ Name = 'Microsoft Teams'; Winget = 'Microsoft.Teams'; Choco = 'microsoft-teams' },
        @{ Name = 'Zoom'; Winget = 'Zoom.Zoom'; Choco = 'zoom' }
    )
    $essentialAppsListPath = Join-Path $Script:TempFolder 'EssentialApps_list.txt'
    $Script:EssentialApps | ForEach-Object { $_ | ConvertTo-Json -Compress } | Out-File $essentialAppsListPath -Encoding UTF8
}

# =====================[ GLOBALS & INITIALIZATION ]========================

# Global error log path
$Script:ErrorLogPath = Join-Path $env:TEMP "SystemMaintenance_ErrorLog.txt"
# Global task report path
$Script:TaskReportPath = Join-Path $env:TEMP "SystemMaintenance_TaskReport.txt"

# Logs errors with timestamp, function, and message
function Write-ErrorLog {
    param(
        [string]$Function,
        [string]$Message
    )
    $entry = "[{0}] [{1}] {2}" -f (Get-Date -Format 'HH:mm:ss'), $Function, $Message
    Add-Content -Path $Script:ErrorLogPath -Value $entry -Encoding UTF8
}

# Logs task/subtask status (start, success, error) with timestamp
function Write-TaskReport {
    param(
        [string]$TaskName,
        [string]$Status, # START, SUCCESS, ERROR
        [string]$Message = ""
    )
    $entry = "[{0}] [{1}] {2} {3}" -f (Get-Date -Format 'HH:mm:ss'), $Status, $TaskName, $Message
    Add-Content -Path $Script:TaskReportPath -Value $entry -Encoding UTF8
}

# Admin rights check
function Test-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error "[FATAL] This script must be run as Administrator. Exiting."
        exit 
    }
}

function Initialize-Environment {
    if (-not $Script:TempFolder) {
        $Script:TempFolder = Join-Path $env:TEMP "SystemMaintenance_$(Get-Random)"
    }
    if (-not (Test-Path $Script:TempFolder)) {
        New-Item -ItemType Directory -Path $Script:TempFolder -Force | Out-Null
    }
    $Script:TranscriptFile = Join-Path $Script:TempFolder 'transcript_log.txt'
    Start-Transcript -Path $Script:TranscriptFile -Append
    Write-Host "[INFO] Temp folder created: $Script:TempFolder"
}

function Remove-Environment {
    Stop-Transcript | Out-Null
    Remove-Item -Path $Script:TempFolder -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[INFO] Temp folder deleted."
}

# =====================[ ERROR HANDLING ]==================================
function Invoke-Task {
    param(
    [Parameter(Mandatory)]
    [string]$TaskName,
    [Parameter(Mandatory)]
    [scriptblock]$TaskScript
    )
    Write-Host "[TASK] $TaskName"
    try {
        & $TaskScript
        Write-Host "[SUCCESS] $TaskName"
    } catch {
        Write-Warning "[ERROR] $TaskName failed: $_"
        Write-ErrorLog -Function "Invoke-Task:$TaskName" -Message $_
    }
}

# =====================[ TASK 1: SYSTEM PROTECTION ]=====================
# -- Subtask 1.1: System Restore Protection
function Test-SystemRestore {
    $transcript = @()
    $startTime = Get-Date
    $transcript += "[{0}] [START] System Restore Protection" -f ($startTime.ToString('HH:mm:ss'))
    Write-TaskReport -TaskName "System Restore Protection" -Status "START"
    try {
        $restoreEnabled = $false
        $osDrive = "C:"
        $transcript += "[{0}] Checking if System Restore is enabled on {1}" -f ((Get-Date).ToString('HH:mm:ss')), $osDrive
        $srStatus = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        if ($srStatus) {
            $restoreEnabled = $true
            $transcript += "[{0}] System Restore is already enabled." -f ((Get-Date).ToString('HH:mm:ss'))
        } else {
            $transcript += "[{0}] Enabling System Restore on {1}..." -f ((Get-Date).ToString('HH:mm:ss')), $osDrive
            Enable-ComputerRestore -Drive $osDrive -ErrorAction Stop
            $restoreEnabled = $true
            $transcript += "[{0}] System Restore enabled." -f ((Get-Date).ToString('HH:mm:ss'))
        }
        if ($restoreEnabled) {
            $transcript += "[{0}] Creating a system restore point..." -f ((Get-Date).ToString('HH:mm:ss'))
            Checkpoint-Computer -Description "System Maintenance Script" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
            $transcript += "[{0}] System restore point created." -f ((Get-Date).ToString('HH:mm:ss'))
        } else {
            $transcript += "[{0}] [WARN] Could not enable System Restore on {1}." -f ((Get-Date).ToString('HH:mm:ss')), $osDrive
        }
        $transcript += "[{0}] [SUCCESS] System Restore Protection" -f ((Get-Date).ToString('HH:mm:ss'))
        Write-TaskReport -TaskName "System Restore Protection" -Status "SUCCESS"
    } catch {
        $transcript += "[{0}] [ERROR] System Restore check/creation failed: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $_
        Write-ErrorLog -Function "Test-SystemRestore" -Message $_
        Write-TaskReport -TaskName "System Restore Protection" -Status "ERROR" -Message $_
    }
    $endTime = Get-Date
    $transcript += "[{0}] [END] System Restore Protection" -f ($endTime.ToString('HH:mm:ss'))
    $outPath = Join-Path $Script:TempFolder 'Task1_SystemProtection_log.txt'
    $transcript | Out-File $outPath -Encoding UTF8
}

# =====================[ TASK 2: PACKAGE MANAGER SETUP ]==================
# -- Subtask 2.1: Ensure Winget & Chocolatey
function Test-PackageManagers {
    $transcript = @()
    $startTime = Get-Date
    $transcript += "[{0}] [START] Package Manager Setup" -f ($startTime.ToString('HH:mm:ss'))
    Write-TaskReport -TaskName "Package Manager Setup" -Status "START"
    try {
        $winget = Get-Command winget -ErrorAction SilentlyContinue
        if (-not $winget) {
            $transcript += "[{0}] winget not found. Attempting to install..." -f ((Get-Date).ToString('HH:mm:ss'))
            Invoke-WebRequest -Uri "https://aka.ms/getwinget" -OutFile "$Script:TempFolder\AppInstaller.msixbundle" -UseBasicParsing
            Add-AppxPackage -Path "$Script:TempFolder\AppInstaller.msixbundle"
            $transcript += "[{0}] winget installed." -f ((Get-Date).ToString('HH:mm:ss'))
        } else {
            $transcript += "[{0}] winget found. Upgrading winget..." -f ((Get-Date).ToString('HH:mm:ss'))
            winget upgrade --id Microsoft.Winget.Source --accept-source-agreements --accept-package-agreements --silent
            $transcript += "[{0}] winget upgraded." -f ((Get-Date).ToString('HH:mm:ss'))
        }
        $choco = Get-Command choco -ErrorAction SilentlyContinue
        if (-not $choco) {
            $transcript += "[{0}] Chocolatey not found. Installing..." -f ((Get-Date).ToString('HH:mm:ss'))
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
            $transcript += "[{0}] Chocolatey installed." -f ((Get-Date).ToString('HH:mm:ss'))
        } else {
            $transcript += "[{0}] Chocolatey found. Upgrading Chocolatey..." -f ((Get-Date).ToString('HH:mm:ss'))
            choco upgrade chocolatey -y
            $transcript += "[{0}] Chocolatey upgraded." -f ((Get-Date).ToString('HH:mm:ss'))
        }
        $transcript += "[{0}] [SUCCESS] Package Manager Setup" -f ((Get-Date).ToString('HH:mm:ss'))
        Write-TaskReport -TaskName "Package Manager Setup" -Status "SUCCESS"
    } catch {
        $transcript += "[{0}] [ERROR] Package manager check/installation failed: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $_
        Write-ErrorLog -Function "Test-PackageManagers" -Message $_
        Write-TaskReport -TaskName "Package Manager Setup" -Status "ERROR" -Message $_
    }
    $endTime = Get-Date
    $transcript += "[{0}] [END] Package Manager Setup" -f ($endTime.ToString('HH:mm:ss'))
    $outPath = Join-Path $Script:TempFolder 'Task2_PackageManagerSetup_log.txt'
    $transcript | Out-File $outPath -Encoding UTF8
}

# =====================[ TASK 3: SYSTEM INVENTORY ]=======================
# -- Subtask 3.1: Collect System Inventory
function Get-Inventory {
    $transcript = @()
    $startTime = Get-Date
    $transcript += "[{0}] [START] System Inventory" -f ($startTime.ToString('HH:mm:ss'))
    Write-TaskReport -TaskName "System Inventory" -Status "START"
    try {
        $inventoryPath = Join-Path $Script:TempFolder 'inventory'
        New-Item -ItemType Directory -Path $inventoryPath -Force | Out-Null
        $transcript += "[{0}] Collecting OS info..." -f ((Get-Date).ToString('HH:mm:ss'))
        Get-ComputerInfo | Out-File (Join-Path $inventoryPath 'os_info.txt')
        $transcript += "[{0}] Collecting hardware info..." -f ((Get-Date).ToString('HH:mm:ss'))
        Get-WmiObject -Class Win32_ComputerSystem | Out-File (Join-Path $inventoryPath 'hardware_info.txt')
        $transcript += "[{0}] Collecting disk info..." -f ((Get-Date).ToString('HH:mm:ss'))
        Get-PSDrive | Where-Object {$_.Provider -like '*FileSystem*'} | Out-File (Join-Path $inventoryPath 'disk_info.txt')
        $transcript += "[{0}] Collecting network info..." -f ((Get-Date).ToString('HH:mm:ss'))
        Get-NetIPAddress | Out-File (Join-Path $inventoryPath 'network_info.txt')
        $Script:InstalledProgramsList = @()
        $Script:InstalledProgramsList += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue
        $Script:InstalledProgramsList += Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue
        $Script:InstalledProgramsList += Get-AppxPackage -AllUsers | Select-Object -ExpandProperty Name
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            $wingetList = winget list --source winget | Select-Object -Skip 1
            $Script:InstalledProgramsList += $wingetList | ForEach-Object { $_.Split(' ')[0] }
        }
    $Script:InstalledProgramsList = $Script:InstalledProgramsList | Where-Object { $_ -and $_.Trim() -ne '' }
    $installedProgramsPath = Join-Path $inventoryPath 'installed_programs.txt'
    $Script:InstalledProgramsList | ForEach-Object { $_ | ConvertTo-Json -Compress } | Out-File $installedProgramsPath
    $installedProgramsDiffPath = Join-Path $Script:TempFolder 'InstalledPrograms_list.txt'
    $Script:InstalledProgramsList | ForEach-Object { $_ | ConvertTo-Json -Compress } | Out-File $installedProgramsDiffPath -Encoding UTF8
        $transcript += "[{0}] Inventory collected in {1}" -f ((Get-Date).ToString('HH:mm:ss')), $inventoryPath
        $transcript += "[{0}] [SUCCESS] System Inventory" -f ((Get-Date).ToString('HH:mm:ss'))
        Write-TaskReport -TaskName "System Inventory" -Status "SUCCESS"
    } catch {
        $transcript += "[{0}] [ERROR] Inventory collection failed: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $_
        Write-ErrorLog -Function "Get-Inventory" -Message $_
        Write-TaskReport -TaskName "System Inventory" -Status "ERROR" -Message $_
    }
    $endTime = Get-Date
    $transcript += "[{0}] [END] System Inventory" -f ($endTime.ToString('HH:mm:ss'))
    $outPath = Join-Path $Script:TempFolder 'Task3_SystemInventory_log.txt'
    $transcript | Out-File $outPath -Encoding UTF8
}

# =====================[ TASK 4: DEBLOATING & APP MANAGEMENT ]============
# -- Subtask 4.1: Remove Bloatware

function Uninstall-Bloatware {
    $transcript = @()
    $startTime = Get-Date
    $transcript += "[{0}] [START] Remove Bloatware" -f ($startTime.ToString('HH:mm:ss'))
    Write-TaskReport -TaskName "Remove Bloatware" -Status "START"
    try {
        $transcript += "[{0}] Scanning for bloatware apps to remove..." -f ((Get-Date).ToString('HH:mm:ss'))
        Write-Progress -Activity "Bloatware Removal" -Status "Initializing..." -PercentComplete 0
        $bloatwareListPath = Join-Path $Script:TempFolder 'Bloatware_list.txt'
        $bloatwareList = Get-Content $bloatwareListPath | Where-Object { $_ -and $_.Trim() -ne '' } | ForEach-Object { $_ | ConvertFrom-Json }
        $installedProgramsDiffPath = Join-Path $Script:TempFolder 'InstalledPrograms_list.txt'
        $installed = Get-Content $installedProgramsDiffPath | Where-Object { $_ -and $_.Trim() -ne '' } | ForEach-Object { $_ | ConvertFrom-Json }

        # --- Create diff list: only bloatware that is actually installed ---
        $bloatwareToRemove = @()
        foreach ($bloat in $bloatwareList) {
            if ($installed | Where-Object { $_.ToLower().Contains($bloat.ToLower()) }) {
                $bloatwareToRemove += $bloat
            }
        }
        $diffListPath = Join-Path $Script:TempFolder 'BloatwareDiff_list.txt'
        $bloatwareToRemove | ForEach-Object { $_ | ConvertTo-Json -Compress } | Out-File $diffListPath -Encoding UTF8
        $transcript += "[{0}] Diff list created. Only installed bloatware will be processed. Diff list saved to {1}." -f ((Get-Date).ToString('HH:mm:ss')), $diffListPath

        $total = $bloatwareToRemove.Count
        $current = 0
        $removed = @()
        foreach ($bloat in $bloatwareToRemove) {
            $current++
            Write-Progress -Activity "Bloatware Removal" -Status ("Uninstalling: {0} ({1}/{2})" -f $bloat, $current, $total) -PercentComplete ([int](($current / $total) * 100))
            $bloatMatches = $installed | Where-Object { $_ -and $_.ToLower().Contains($bloat.ToLower()) }
            foreach ($match in $bloatMatches) {
                try {
                    # 1. Try AppX removal
                    $pkg = Get-AppxPackage -AllUsers | Where-Object { $_.Name -eq $bloat }
                    if ($pkg) {
                        $transcript += "[{0}] Removing AppX package: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $bloat
                        Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                        $transcript += "[{0}] Removed AppX package: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $bloat
                        $removed += $bloat
                        continue
                    }
                    # 2. Try winget uninstall
                    if (Get-Command winget -ErrorAction SilentlyContinue) {
                        $wingetResult = winget uninstall --exact --silent --accept-source-agreements --accept-package-agreements --id "$match" 2>&1
                        if ($wingetResult -notmatch 'No installed package found') {
                            $transcript += "[{0}] Uninstalled via winget: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $match
                            $removed += $match
                            continue
                        }
                    }
                    # 3. Try WMI uninstall
                    $wmic = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -eq $match }
                    if ($wmic) {
                        $wmic.Uninstall() | Out-Null
                        $transcript += "[{0}] Uninstalled via WMI: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $match
                        $removed += $match
                        continue
                    }
                    # 4. Try Uninstall-Package (PowerShell PackageManagement)
                    if (Get-Command Uninstall-Package -ErrorAction SilentlyContinue) {
                        try {
                            Uninstall-Package -Name $match -Force -ErrorAction Stop
                            $transcript += "[{0}] Uninstalled via Uninstall-Package: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $match
                            $removed += $match
                            continue
                        } catch {}
                    }
                    $transcript += "[{0}] [WARN] Could not uninstall {1} using any method." -f ((Get-Date).ToString('HH:mm:ss')), $match
                } catch {
                    $transcript += "[{0}] [WARN] Failed to uninstall {1}: {2}" -f ((Get-Date).ToString('HH:mm:ss')), $match, $_
                }
            }
        }
        Write-Progress -Activity "Bloatware Removal" -Status "Complete" -Completed
        $transcript += "[{0}] Bloatware removal complete. Diff list saved to {1}." -f ((Get-Date).ToString('HH:mm:ss')), $diffListPath
        $transcript += "[{0}] [SUCCESS] Remove Bloatware" -f ((Get-Date).ToString('HH:mm:ss'))
        Write-TaskReport -TaskName "Remove Bloatware" -Status "SUCCESS"
    } catch {
        $transcript += "[{0}] [ERROR] Bloatware removal failed: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $_
        Write-ErrorLog -Function "Uninstall-Bloatware" -Message $_
        Write-TaskReport -TaskName "Remove Bloatware" -Status "ERROR" -Message $_
    }
    $endTime = Get-Date
    $transcript += "[{0}] [END] Remove Bloatware" -f ($endTime.ToString('HH:mm:ss'))
    $outPath = Join-Path $Script:TempFolder 'Task4_DebloatAndAppMgmt_log.txt'
    $transcript | Out-File $outPath -Encoding UTF8
}

# -- Subtask 4.2: Install Essential Apps
function Install-EssentialApps {
    $transcript = @()
    $startTime = Get-Date
    $transcript += "[{0}] [START] Install Essential Apps" -f ($startTime.ToString('HH:mm:ss'))
    Write-TaskReport -TaskName "Install Essential Apps" -Status "START"
    try {
        $essentialAppsListPath = Join-Path $Script:TempFolder 'EssentialApps_list.txt'
        $essentialApps = Get-Content $essentialAppsListPath | ForEach-Object { $_ | ConvertFrom-Json }
        $installedProgramsDiffPath = Join-Path $Script:TempFolder 'InstalledPrograms_list.txt'
        $installed = Get-Content $installedProgramsDiffPath | Where-Object { $_ -and $_.Trim() -ne '' } | ForEach-Object { $_ | ConvertFrom-Json }
        $officeInstalled = $false
        $officeNames = @('Microsoft Office', 'Office16', 'Office15', 'Office14', 'Office12', 'Office11', 'Office10', 'Office09', 'Office08', 'Office07', 'Office 365')
        foreach ($name in $officeNames) {
            if ($installed | Where-Object { $_ -like "*$name*" }) {
                $officeInstalled = $true
                break
            }
        }
        $libreInstalled = $false
        $libreNames = @('LibreOffice')
        foreach ($name in $libreNames) {
            if ($installed | Where-Object { $_ -like "*$name*" }) {
                $libreInstalled = $true
                break
            }
        }
        if (-not $libreInstalled) {
            if (-not $officeInstalled) {
                $essentialApps += @{ Name = 'LibreOffice'; Winget = 'TheDocumentFoundation.LibreOffice'; Choco = 'libreoffice-fresh' }
                $transcript += "[{0}] LibreOffice added to essential apps list." -f ((Get-Date).ToString('HH:mm:ss'))
            } else {
                $transcript += "[{0}] Microsoft Office is installed. Skipping LibreOffice installation." -f ((Get-Date).ToString('HH:mm:ss'))
            }
        } else {
            $transcript += "[{0}] LibreOffice is already installed. Skipping." -f ((Get-Date).ToString('HH:mm:ss'))
        }
        # --- Create diff list: only essential apps that are NOT installed ---
        $appsToInstall = @()
        foreach ($app in $essentialApps) {
            $isInstalled = $installed | Where-Object { $_ -and $_ -like "*$($app.Name)*" }
            if (-not $isInstalled) {
                $appsToInstall += $app
            }
        }
        $diffListPath = Join-Path $Script:TempFolder 'EssentialAppsDiff_list.txt'
        $appsToInstall | ForEach-Object { $_ | ConvertTo-Json -Compress } | Out-File $diffListPath -Encoding UTF8
        $transcript += "[{0}] Diff list created. Only missing essential apps will be processed. Diff list saved to {1}." -f ((Get-Date).ToString('HH:mm:ss')), $diffListPath

        $essTotal = $appsToInstall.Count
        $essCurrent = 0
        foreach ($app in $appsToInstall) {
            $essCurrent++
            Write-Progress -Activity "Essential Apps Installation" -Status ("Installing: {0} ({1}/{2})" -f $app.Name, $essCurrent, $essTotal) -PercentComplete ([int](($essCurrent / $essTotal) * 100))
            $transcript += "[{0}] Installing {1}..." -f ((Get-Date).ToString('HH:mm:ss')), $app.Name
            $installedVia = $null
            $retryCount = 0
            $maxRetries = 3
            $retryDelay = 90 # seconds
            $installSucceeded = $false
            while (-not $installSucceeded -and $retryCount -lt $maxRetries) {
                $retryCount++
                if ($app.Winget -and (Get-Command winget -ErrorAction SilentlyContinue)) {
                    try {
                        $wingetResult = winget install --id $($app.Winget) --accept-source-agreements --accept-package-agreements --silent -e 2>&1
                        if ($wingetResult -match 'Installer failed with exit code: 1618') {
                        $transcript += "[{0}] [WARN] Windows Installer is busy (exit code 1618) for {1}. Attempt {2}/3. Retrying in {3} seconds..." -f ((Get-Date).ToString('HH:mm:ss')), $app.Name, $retryCount, $retryDelay
                            Start-Sleep -Seconds $retryDelay
                            continue
                        }
                        $installedVia = 'winget'
                        $installSucceeded = $true
                    } catch {
                        $transcript += "[{0}] [WARN] winget failed for {1}: {2}" -f ((Get-Date).ToString('HH:mm:ss')), $app.Name, $_
                    }
                }
                if (-not $installSucceeded -and $app.Choco -and (Get-Command choco -ErrorAction SilentlyContinue)) {
                    try {
                        $chocoResult = choco install $($app.Choco) -y 2>&1
                        if ($chocoResult -match '1618') {
                        $transcript += "[{0}] [WARN] Windows Installer is busy (exit code 1618) for {1} via choco. Attempt {2}/3. Retrying in {3} seconds..." -f ((Get-Date).ToString('HH:mm:ss')), $app.Name, $retryCount, $retryDelay
                            Start-Sleep -Seconds $retryDelay
                            continue
                        }
                        $installedVia = 'choco'
                        $installSucceeded = $true
                    } catch {
                        $transcript += "[{0}] [WARN] choco failed for {1}: {2}" -f ((Get-Date).ToString('HH:mm:ss')), $app.Name, $_
                    }
                }
                break
            }
            if ($installSucceeded -and $installedVia) {
                $transcript += "[{0}] Installed {1} via {2}." -f ((Get-Date).ToString('HH:mm:ss')), $app.Name, $installedVia
            } elseif (-not $installSucceeded) {
                $transcript += "[{0}] [ERROR] Could not install {1} after {2} attempts due to Windows Installer being busy (exit code 1618). Skipping." -f ((Get-Date).ToString('HH:mm:ss')), $app.Name, $maxRetries
            } elseif (-not $installedVia) {
                $transcript += "[{0}] [ERROR] Could not install {1} via winget or choco." -f ((Get-Date).ToString('HH:mm:ss')), $app.Name
            }
        }
        Write-Progress -Activity "Essential Apps Installation" -Status "All essential apps processed" -Completed
        $transcript += "[{0}] Essential apps installation complete. Diff list saved to {1}." -f ((Get-Date).ToString('HH:mm:ss')), $diffListPath
        $transcript += "[{0}] [SUCCESS] Install Essential Apps" -f ((Get-Date).ToString('HH:mm:ss'))
        Write-TaskReport -TaskName "Install Essential Apps" -Status "SUCCESS"
    } catch {
        $transcript += "[{0}] [ERROR] Essential apps installation failed: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $_
        Write-ErrorLog -Function "Install-EssentialApps" -Message $_
        Write-TaskReport -TaskName "Install Essential Apps" -Status "ERROR" -Message $_
    }
    $endTime = Get-Date
    $transcript += "[{0}] [END] Install Essential Apps" -f ($endTime.ToString('HH:mm:ss'))
    $outPath = Join-Path $Script:TempFolder 'Task4_DebloatAndAppMgmt_log.txt'
    $transcript | Out-File $outPath -Encoding UTF8
}

# =====================[ TASK 5: PRIVACY & TELEMETRY ]====================
# -- Subtask 5.1: Disable Telemetry


function Disable-Telemetry {
    $transcript = @()
    $startTime = Get-Date
    $transcript += "[{0}] [START] Disable Telemetry" -f ($startTime.ToString('HH:mm:ss'))
    Write-TaskReport -TaskName "Disable Telemetry" -Status "START"
    try {
        $transcript += "[{0}] Disabling Windows telemetry and data collection..." -f ((Get-Date).ToString('HH:mm:ss'))
        $regPaths = @(
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'
        )
        foreach ($path in $regPaths) {
            if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
            Set-ItemProperty -Path $path -Name AllowTelemetry -Value 0 -Force
            $transcript += "[{0}] Set AllowTelemetry=0 in {1}" -f ((Get-Date).ToString('HH:mm:ss')), $path
        }
        $services = @(
            'DiagTrack',
            'dmwappushservice'
        )
        foreach ($svc in $services) {
            if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
                Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                Set-Service -Name $svc -StartupType Disabled
                $transcript += "[{0}] Disabled service: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $svc
            }
        }
        # Enhanced Telemetry Blocking
        $telemetryHosts = @(
            'vortex.data.microsoft.com',
            'settings-win.data.microsoft.com',
            'telemetry.microsoft.com',
            'watson.telemetry.microsoft.com',
            'telecommand.telemetry.microsoft.com',
            'oca.telemetry.microsoft.com',
            'sqm.telemetry.microsoft.com',
            'wes.df.telemetry.microsoft.com',
            'services.wes.df.telemetry.microsoft.com',
            'statsfe2.ws.microsoft.com',
            'corpext.msitadfs.glbdns2.microsoft.com',
            'compatexchange.cloudapp.net',
            'a-0001.a-msedge.net',
            'a-0002.a-msedge.net',
            'a-0003.a-msedge.net',
            'a-0004.a-msedge.net',
            'a-0005.a-msedge.net'
        )

        # Try to block telemetry hosts via Windows Firewall (in addition to hosts file, for reliability)
        foreach ($telemetryHost in $telemetryHosts) {
            try {
                $ruleName = "Block Telemetry - $telemetryHost"
                # Only add firewall rule if $telemetryHost is an IP address or valid keyword
                if ($telemetryHost -match '^(\d{1,3}\.){3}\d{1,3}$' -or $telemetryHost -match '^(LocalSubnet|DNS|DHCP|WINS|DefaultGateway|Internet|Intranet|IntranetRemoteAccess|PlayToDevice)$') {
                    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
                        New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block -RemoteAddress $telemetryHost -Enabled True | Out-Null
                $transcript += "[{0}] Added firewall rule to block: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $telemetryHost
                    } else {
                $transcript += "[{0}] Firewall rule already exists for: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $telemetryHost
                    }
                } else {
                $transcript += "[{0}] Skipped firewall rule for hostname (not IP): {1}" -f ((Get-Date).ToString('HH:mm:ss')), $telemetryHost
                }
            } catch {
                $transcript += "[{0}] [WARN] Could not add firewall rule for {1}: {2}" -f ((Get-Date).ToString('HH:mm:ss')), $telemetryHost, $_
            }
        }

        # Try to block telemetry hosts in hosts file (with retry logic)
        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        foreach ($telemetryHost in $telemetryHosts) {
            $maxRetries = 5
            $retryDelay = 10
            $attempt = 0
            $success = $false
            while (-not $success -and $attempt -lt $maxRetries) {
                $attempt++
                try {
                    if (-not (Select-String -Path $hostsPath -Pattern $telemetryHost -Quiet)) {
                        Add-Content -Path $hostsPath -Value "0.0.0.0 $telemetryHost"
                        $transcript += "[{0}] Blocked telemetry host in hosts file: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $telemetryHost
                    }
                    $success = $true
                } catch {
                    if ($_.Exception.Message -like '*because it is being used by another process*' -or $_.Exception.Message -like '*The process cannot access the file*') {
                        if ($attempt -lt $maxRetries) {
                            $transcript += "[{0}] [WARN] Hosts file is locked (attempt {1}/{2}) for {3}. Retrying in {4} seconds..." -f ((Get-Date).ToString('HH:mm:ss')), $attempt, $maxRetries, $telemetryHost, $retryDelay
                            Start-Sleep -Seconds $retryDelay
                        } else {
                            $transcript += "[{0}] [WARN] Could not modify hosts file for {1} after {2} attempts: {3}" -f ((Get-Date).ToString('HH:mm:ss')), $telemetryHost, $maxRetries, $_
                        }
                    } else {
                        $transcript += "[{0}] [WARN] Could not modify hosts file for {1}: {2}" -f ((Get-Date).ToString('HH:mm:ss')), $telemetryHost, $_
                        break
                    }
                }
            }
        }

        $transcript += "[{0}] [SUCCESS] Disable Telemetry" -f ((Get-Date).ToString('HH:mm:ss'))
        Write-TaskReport -TaskName "Disable Telemetry" -Status "SUCCESS"
    } catch {
        $transcript += "[{0}] [ERROR] Telemetry disabling failed: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $_
        Write-ErrorLog -Function "Disable-Telemetry" -Message $_
        Write-TaskReport -TaskName "Disable Telemetry" -Status "ERROR" -Message $_
    }
    $endTime = Get-Date
    $transcript += "[{0}] [END] Disable Telemetry" -f ($endTime.ToString('HH:mm:ss'))
    $outPath = Join-Path $Script:TempFolder 'Task5_PrivacyTelemetry_log.txt'
    $transcript | Out-File $outPath -Encoding UTF8
}

# =====================[ TASK 6: UPDATES & MAINTENANCE ]==================
# -- Subtask 6.1: Windows Update & Upgrade
function Update-Windows {
    $transcript = @()
    $startTime = Get-Date
    $transcript += "[{0}] [START] Windows Update & Upgrade" -f ($startTime.ToString('HH:mm:ss'))
    Write-TaskReport -TaskName "Windows Update & Upgrade" -Status "START"
    try {
        $transcript += "[{0}] Starting Windows Update & Upgrade..." -f ((Get-Date).ToString('HH:mm:ss'))
        Write-Progress -Activity "Windows Update" -Status "Initializing..." -PercentComplete 0
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            try {
                Install-PackageProvider -Name NuGet -Force -Scope CurrentUser -ErrorAction SilentlyContinue
                Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber -ErrorAction SilentlyContinue
                $transcript += "[{0}] PSWindowsUpdate module installed." -f ((Get-Date).ToString('HH:mm:ss'))
            } catch {
                $transcript += "[{0}] [WARN] Could not install PSWindowsUpdate module: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $_
            }
        }
        Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
        try {
            Write-Progress -Activity "Windows Update" -Status "Checking and installing updates..." -PercentComplete 50
            Get-WindowsUpdate -AcceptAll -Install -AutoReboot -ErrorAction Stop
            $transcript += "[{0}] Windows Update completed." -f ((Get-Date).ToString('HH:mm:ss'))
        } catch {
            $transcript += "[{0}] [WARN] Get-WindowsUpdate failed: {1}. Trying wuauclt..." -f ((Get-Date).ToString('HH:mm:ss')), $_
            Write-Progress -Activity "Windows Update" -Status "Triggering wuauclt..." -PercentComplete 80
            wuauclt /detectnow /updatenow
            $transcript += "[{0}] Triggered Windows Update via wuauclt. Please check Windows Update manually if needed." -f ((Get-Date).ToString('HH:mm:ss'))
        }
        Write-Progress -Activity "Windows Update" -Status "Complete" -Completed
        $transcript += "[{0}] [SUCCESS] Windows Update & Upgrade" -f ((Get-Date).ToString('HH:mm:ss'))
        Write-TaskReport -TaskName "Windows Update & Upgrade" -Status "SUCCESS"
    } catch {
        $transcript += "[{0}] [ERROR] Windows Update & Upgrade failed: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $_
        Write-ErrorLog -Function "Update-Windows" -Message $_
        Write-TaskReport -TaskName "Windows Update & Upgrade" -Status "ERROR" -Message $_
    }
    $endTime = Get-Date
    $transcript += "[{0}] [END] Windows Update & Upgrade" -f ($endTime.ToString('HH:mm:ss'))
    $outPath = Join-Path $Script:TempFolder 'Task6_UpdatesMaintenance_log.txt'
    $transcript | Out-File $outPath -Encoding UTF8
}

# -- Subtask 6.2: Winget Upgrade All
function Update-AllPackages {
    $transcript = @()
    $startTime = Get-Date
    $transcript += "[{0}] [START] Upgrade All Packages" -f ($startTime.ToString('HH:mm:ss'))
    Write-TaskReport -TaskName "Upgrade All Packages" -Status "START"
    try {
        $transcript += "[{0}] Running: winget upgrade --all --include-unknown --accept-source-agreements --accept-package-agreements --silent" -f ((Get-Date).ToString('HH:mm:ss'))
        Write-Progress -Activity "Winget Upgrade" -Status "Upgrading all packages..." -PercentComplete 0
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            $output = winget upgrade --all --include-unknown --accept-source-agreements --accept-package-agreements --silent 2>&1
            $transcript += $output
            Write-Progress -Activity "Winget Upgrade" -Status "All packages processed" -Completed
            $transcript += "[{0}] All packages processed via winget." -f ((Get-Date).ToString('HH:mm:ss'))
            $transcript += "[{0}] [SUCCESS] Upgrade All Packages" -f ((Get-Date).ToString('HH:mm:ss'))
            Write-TaskReport -TaskName "Upgrade All Packages" -Status "SUCCESS"
        } else {
            Write-Progress -Activity "Winget Upgrade" -Status "winget not found. Skipping." -Completed
            $transcript += "[{0}] [WARN] winget not found. Skipping package upgrade." -f ((Get-Date).ToString('HH:mm:ss'))
        }
    } catch {
        $transcript += "[{0}] [ERROR] Winget upgrade all failed: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $_
        Write-ErrorLog -Function "Update-AllPackages" -Message $_
        Write-TaskReport -TaskName "Upgrade All Packages" -Status "ERROR" -Message $_
    }
    $endTime = Get-Date
    $transcript += "[{0}] [END] Upgrade All Packages" -f ($endTime.ToString('HH:mm:ss'))
    $outPath = Join-Path $Script:TempFolder 'Task6_UpdatesMaintenance_log.txt'
    $transcript | Out-File $outPath -Encoding UTF8
}

# =====================[ TASK 7: CLEANUP ]===============================
# -- Subtask 7.1: Browser Cache/Cookies Cleanup
function Clear-BrowserData {
    $transcript = @()
    $startTime = Get-Date
    $transcript += "[{0}] [START] Cleanup Browser Data" -f ($startTime.ToString('HH:mm:ss'))
    Write-TaskReport -TaskName "Cleanup Browser Data" -Status "START"
    try {
        $transcript += "[{0}] Cleaning browser cache and cookies..." -f ((Get-Date).ToString('HH:mm:ss'))
        $userProfiles = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object {
            try {
                $profilePath = (Get-ItemProperty $_.PsPath).ProfileImagePath
                if ($profilePath -and (Test-Path $profilePath)) { $profilePath }
            } catch {}
        } | Where-Object { $_ -and (Test-Path $_) }
        $browsers = @(
            @{ Name = 'Edge'; Paths = @('AppData\Local\Microsoft\Edge\User Data\Default\Cache', 'AppData\Local\Microsoft\Edge\User Data\Default\Cookies') },
            @{ Name = 'Chrome'; Paths = @('AppData\Local\Google\Chrome\User Data\Default\Cache', 'AppData\Local\Google\Chrome\User Data\Default\Cookies') },
            @{ Name = 'Firefox'; Paths = @('AppData\Local\Mozilla\Firefox\Profiles') }
        )
        $totalProfiles = ($userProfiles | Measure-Object).Count
        $profileIdx = 0
        foreach ($profile in $userProfiles) {
            $profileIdx++
            $totalBrowsers = ($browsers | Measure-Object).Count
            $browserIdx = 0
            foreach ($browser in $browsers) {
                $browserIdx++
                $pathIdx = 0
                foreach ($relPath in $browser.Paths) {
                    $pathIdx++
                    $progressPercent = [int](($profileIdx / $totalProfiles) * 100)
                    Write-Progress -Activity "Browser Data Cleanup" -Status ("Profile {0}/{1}, {2} {3}/{4}" -f $profileIdx, $totalProfiles, $browser.Name, $browserIdx, $totalBrowsers) -PercentComplete $progressPercent
                    $fullPath = Join-Path $profile $relPath
                    if (Test-Path $fullPath) {
                        try {
                            $procName = $browser.Name
                            $isRunning = Get-Process -Name $procName -ErrorAction SilentlyContinue
                            if ($isRunning) {
                                $transcript += "[{0}] [WARN] {1} is running. Some files may not be deleted." -f ((Get-Date).ToString('HH:mm:ss')), $browser.Name
                            }
                            if ($relPath -like '*Cache*') {
                                Remove-Item -Path $fullPath -Recurse -Force -ErrorAction SilentlyContinue
                                $transcript += "[{0}] Cleared cache for {1} in {2}." -f ((Get-Date).ToString('HH:mm:ss')), $browser.Name, $profile
                            } elseif ($relPath -like '*Cookies*') {
                                Remove-Item -Path $fullPath -Force -ErrorAction SilentlyContinue
                                $transcript += "[{0}] Cleared cookies for {1} in {2}." -f ((Get-Date).ToString('HH:mm:ss')), $browser.Name, $profile
                            } elseif ($browser.Name -eq 'Firefox' -and (Test-Path $fullPath)) {
                                Get-ChildItem $fullPath -Directory | ForEach-Object {
                                    $cache2 = Join-Path $_.FullName 'cache2'
                                    $cookies = Join-Path $_.FullName 'cookies.sqlite'
                                    if (Test-Path $cache2) {
                                        try {
                                            Remove-Item -Path $cache2 -Recurse -Force -ErrorAction SilentlyContinue
                                            $transcript += "[{0}] Cleared Firefox cache2 in {1}." -f ((Get-Date).ToString('HH:mm:ss')), $_.FullName
                                        } catch {
                                            $transcript += "[{0}] [WARN] Failed to clear Firefox cache2 in {1}: {2}" -f ((Get-Date).ToString('HH:mm:ss')), $_.FullName, $_
                                        }
                                    }
                                    if (Test-Path $cookies) {
                                        try {
                                            Remove-Item -Path $cookies -Force -ErrorAction SilentlyContinue
                                            $transcript += "[{0}] Cleared Firefox cookies in {1}." -f ((Get-Date).ToString('HH:mm:ss')), $_.FullName
                                        } catch {
                                            $transcript += "[{0}] [WARN] Failed to clear Firefox cookies in {1}: {2}" -f ((Get-Date).ToString('HH:mm:ss')), $_.FullName, $_
                                        }
                                    }
                                }
                            }
                        } catch {
                            $transcript += "[{0}] [WARN] Failed to clear {1} for {2} in {3}: {4}" -f ((Get-Date).ToString('HH:mm:ss')), $relPath, $browser.Name, $profile, $_
                        }
                    }
                }
            }
        }
        Write-Progress -Activity "Browser Data Cleanup" -Status "Complete" -Completed
        $transcript += "[{0}] [SUCCESS] Browser cache and cookies cleanup complete." -f ((Get-Date).ToString('HH:mm:ss'))
        Write-TaskReport -TaskName "Cleanup Browser Data" -Status "SUCCESS"
    } catch {
        $transcript += "[{0}] [ERROR] Browser data cleanup failed: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $_
        Write-ErrorLog -Function "Clear-BrowserData" -Message $_
        Write-TaskReport -TaskName "Cleanup Browser Data" -Status "ERROR" -Message $_
    }
    $endTime = Get-Date
    $transcript += "[{0}] [END] Cleanup Browser Data" -f ($endTime.ToString('HH:mm:ss'))
    $outPath = Join-Path $Script:TempFolder 'Task7_Cleanup_log.txt'
    $transcript | Out-File $outPath -Encoding UTF8
}

    # -- Subtask 7.2: DNS CACHE CLEANUP (was 7.3)
function Clear-DnsCache {
    $transcript = @()
    $startTime = Get-Date
    $transcript += "[{0}] [START] Clear DNS Cache" -f ($startTime.ToString('HH:mm:ss'))
    Write-TaskReport -TaskName "Clear DNS Cache" -Status "START"
    try {
        $transcript += "[{0}] Clearing DNS client cache..." -f ((Get-Date).ToString('HH:mm:ss'))
        if (Get-Command Clear-DnsClientCache -ErrorAction SilentlyContinue) {
            Clear-DnsClientCache
            $transcript += "[{0}] DNS client cache cleared." -f ((Get-Date).ToString('HH:mm:ss'))
        } else {
            $transcript += "[{0}] [WARN] Clear-DnsClientCache cmdlet not available on this system. Skipping DNS cache cleanup." -f ((Get-Date).ToString('HH:mm:ss'))
        }
        $transcript += "[{0}] [SUCCESS] Clear DNS Cache" -f ((Get-Date).ToString('HH:mm:ss'))
        Write-TaskReport -TaskName "Clear DNS Cache" -Status "SUCCESS"
    } catch {
        $transcript += "[{0}] [ERROR] DNS cache cleanup failed: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $_
        Write-ErrorLog -Function "Clear-DnsCache" -Message $_
        Write-TaskReport -TaskName "Clear DNS Cache" -Status "ERROR" -Message $_
    }
    $endTime = Get-Date
    $transcript += "[{0}] [END] Clear DNS Cache" -f ($endTime.ToString('HH:mm:ss'))
    $outPath = Join-Path $Script:TempFolder 'Task7_Cleanup_log.txt'
    $transcript | Out-File $outPath -Encoding UTF8 -Append
}

# =====================[ TASK 8: LOGGING & RESTORE POINTS ]===============
# -- Subtask 8.1: Event Viewer & CBS Log Survey
function Get-LogSurvey {
    $transcript = @()
    $startTime = Get-Date
    $transcript += "[{0}] [START] Survey Logs" -f ($startTime.ToString('HH:mm:ss'))
    Write-TaskReport -TaskName "Survey Logs" -Status "START"
    try {
        $transcript += "[{0}] Surveying Event Viewer and CBS logs for last 48h errors..." -f ((Get-Date).ToString('HH:mm:ss'))
        Write-Progress -Activity "Log Survey" -Status "Collecting logs..." -PercentComplete 0
        $logPath = Join-Path $Script:TempFolder 'log_survey_log.txt'
        $since = (Get-Date).AddHours(-48)
        $systemErrors = $null
        $appErrors = $null
        try {
            Write-Progress -Activity "Log Survey" -Status "Collecting system/application logs..." -PercentComplete 30
            Import-Module Microsoft.PowerShell.Diagnostics -ErrorAction Stop
            $systemErrors = Get-WinEvent -FilterHashtable @{LogName='System'; Level=2; StartTime=$since} -ErrorAction Stop | Select-Object TimeCreated, Id, LevelDisplayName, Message
            $appErrors = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2; StartTime=$since} -ErrorAction Stop | Select-Object TimeCreated, Id, LevelDisplayName, Message
        } catch {
            $transcript += "[{0}] [WARN] Get-WinEvent failed (likely due to missing temp files or permissions). Falling back to Get-EventLog." -f ((Get-Date).ToString('HH:mm:ss'))
            try {
                $systemErrors = Get-EventLog -LogName System -EntryType Error -After $since -ErrorAction Stop | Select-Object TimeGenerated, EventID, EntryType, Message
                $appErrors = Get-EventLog -LogName Application -EntryType Error -After $since -ErrorAction Stop | Select-Object TimeGenerated, EventID, EntryType, Message
            } catch {
                $transcript += "[{0}] [WARN] Get-EventLog also failed: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $_
            }
        }
        Write-Progress -Activity "Log Survey" -Status "Writing system/application logs..." -PercentComplete 60
        "==== System Log Errors (Last 48h) ====" | Out-File $logPath
        if ($systemErrors) { $systemErrors | Format-Table -AutoSize | Out-File $logPath -Append } else { "(No system errors found or log unavailable)" | Out-File $logPath -Append }
        "==== Application Log Errors (Last 48h) ====" | Out-File $logPath -Append
        if ($appErrors) { $appErrors | Format-Table -AutoSize | Out-File $logPath -Append } else { "(No application errors found or log unavailable)" | Out-File $logPath -Append }
        $cbsLog = "$env:windir\Logs\CBS\CBS.log"
        if (Test-Path $cbsLog) {
            Write-Progress -Activity "Log Survey" -Status "Scanning CBS.log..." -PercentComplete 80
            $cbsLines = Get-Content $cbsLog | Select-String -Pattern 'error' -SimpleMatch
            $recentCbs = $cbsLines | Where-Object {
                if ($_.Line -match '\[(\d{4}-\d{2}-\d{2})') {
                    $logDate = $matches[1]
                    try {
                        return ([datetime]$logDate -ge $since)
                    } catch { return $false }
                } else {
                    return $false
                }
            }
            "==== CBS.log Errors (Last 48h) ====" | Out-File $logPath -Append
            if ($recentCbs) { $recentCbs | ForEach-Object { $_.Line } | Out-File $logPath -Append } else { "(No CBS.log errors found)" | Out-File $logPath -Append }
        }
        Write-Progress -Activity "Log Survey" -Status "Complete" -Completed
        $transcript += "[{0}] Log survey complete. Results in {1}." -f ((Get-Date).ToString('HH:mm:ss')), $logPath
        $transcript += "[{0}] [SUCCESS] Survey Logs" -f ((Get-Date).ToString('HH:mm:ss'))
        Write-TaskReport -TaskName "Survey Logs" -Status "SUCCESS"
    } catch {
        $transcript += "[{0}] [ERROR] Log survey failed: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $_
        Write-ErrorLog -Function "Get-LogSurvey" -Message $_
        Write-TaskReport -TaskName "Survey Logs" -Status "ERROR" -Message $_
    }
    $endTime = Get-Date
    $transcript += "[{0}] [END] Survey Logs" -f ($endTime.ToString('HH:mm:ss'))
    $outPath = Join-Path $Script:TempFolder 'Task8_LoggingRestore_log.txt'
    $transcript | Out-File $outPath -Encoding UTF8
}

# -- Subtask 8.2: Restore Points Validation
function Protect-RestorePoints {
    $transcript = @()
    $startTime = Get-Date
    $transcript += "[{0}] [START] Validate Restore Points" -f ($startTime.ToString('HH:mm:ss'))
    Write-TaskReport -TaskName "Validate Restore Points" -Status "START"
    try {
        $transcript += "[{0}] Validating and pruning restore points..." -f ((Get-Date).ToString('HH:mm:ss'))
        Write-Progress -Activity "Restore Points" -Status "Collecting restore points..." -PercentComplete 0
        $restorePoints = Get-ComputerRestorePoint | Sort-Object -Property CreationTime -Descending
        $logPath = Join-Path $Script:TempFolder 'restore_points_log.txt'
        $initialCount = $restorePoints.Count
        if ($restorePoints.Count -gt 5) {
            $toRemove = $restorePoints | Select-Object -Skip 5
            $totalToRemove = $toRemove.Count
            $removed = 0
            foreach ($rp in $toRemove) {
                $removed++
                $percent = [int](($removed / $totalToRemove) * 100)
                Write-Progress -Activity "Restore Points" -Status ("Deleting old restore point {0}/{1}" -f $removed, $totalToRemove) -PercentComplete $percent
                try {
                    vssadmin delete shadows /for=C: /oldest /quiet | Out-Null
                    $transcript += "[{0}] Deleted old restore point: {1} [{2}]" -f ((Get-Date).ToString('HH:mm:ss')), $rp.Description, $rp.CreationTime
                } catch {
                    $transcript += "[{0}] [WARN] Could not delete restore point: {1} [{2}]" -f ((Get-Date).ToString('HH:mm:ss')), $rp.Description, $rp.CreationTime
                }
            }
        }
        Write-Progress -Activity "Restore Points" -Status "Writing summary..." -PercentComplete 90
        $remaining = Get-ComputerRestorePoint | Sort-Object -Property CreationTime -Descending | Select-Object -First 5
        $finalCount = ($remaining | Measure-Object).Count
        $transcript += "[{0}] Restore points before: {1}, after: {2}." -f ((Get-Date).ToString('HH:mm:ss')), $initialCount, $finalCount
        "==== Latest 5 Restore Points ====" | Out-File $logPath
        $remaining | Format-Table SequenceNumber, Description, CreationTime, EventType, RestorePointType -AutoSize | Out-File $logPath -Append
        Write-Progress -Activity "Restore Points" -Status "Complete" -Completed
        $transcript += "[{0}] Restore points validation complete. Details in {1}." -f ((Get-Date).ToString('HH:mm:ss')), $logPath
        $transcript += "[{0}] [SUCCESS] Validate Restore Points" -f ((Get-Date).ToString('HH:mm:ss'))
        Write-TaskReport -TaskName "Validate Restore Points" -Status "SUCCESS"
    } catch {
        $transcript += "[{0}] [ERROR] Restore points validation failed: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $_
        Write-ErrorLog -Function "Protect-RestorePoints" -Message $_
        Write-TaskReport -TaskName "Validate Restore Points" -Status "ERROR" -Message $_
    }
    $endTime = Get-Date
    $transcript += "[{0}] [END] Validate Restore Points" -f ($endTime.ToString('HH:mm:ss'))
    $outPath = Join-Path $Script:TempFolder 'Task8_LoggingRestore_log.txt'
    $transcript | Out-File $outPath -Encoding UTF8 -Append
}

# =====================[ TASK 9: FULL DISK CLEANUP ]===========================
# -- Subtask 9.1: Full Disk Cleanup (moved from 7.2)
function Optimize-Disk {
    $transcript = @()
    $startTime = Get-Date
    $transcript += "[{0}] [START] Full Disk Cleanup" -f ($startTime.ToString('HH:mm:ss'))
    Write-TaskReport -TaskName "Full Disk Cleanup" -Status "START"
    try {
        $transcript += "[{0}] Starting full disk cleanup..." -f ((Get-Date).ToString('HH:mm:ss'))
        $cleanupTasks = @(
            @{ Name = 'Temporary Setup Files'; Path = "$env:SystemRoot\Panther"; Pattern = '*' },
            @{ Name = 'Old Chkdsk files'; Path = "$env:SystemRoot"; Pattern = 'chk*.chk' },
            @{ Name = 'Setup Log files'; Path = "$env:SystemRoot"; Pattern = '*.log' },
            @{ Name = 'Windows Update Cleanup'; Path = "$env:SystemRoot\SoftwareDistribution\Download"; Pattern = '*' },
            @{ Name = 'Microsoft Defender Antivirus'; Path = "$env:ProgramData\Microsoft\Windows Defender\Scans\History"; Pattern = '*' },
            @{ Name = 'Downloaded Program Files'; Path = "$env:SystemRoot\Downloaded Program Files"; Pattern = '*' },
            @{ Name = 'Feedback Hub Archive log files'; Path = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe\LocalState"; Pattern = '*.log' },
            @{ Name = 'Temporary internet files'; Path = "$env:SystemRoot\inetpub\temp"; Pattern = '*' },
            @{ Name = 'System error memory dump files'; Path = "$env:SystemRoot"; Pattern = '*.dmp' },
            @{ Name = 'System error minidump files'; Path = "$env:SystemRoot\Minidump"; Pattern = '*.dmp' },
            @{ Name = 'Language Resource Files'; Path = "$env:SystemRoot\System32\%LANG%"; Pattern = '*' },
            @{ Name = 'Recycle Bin'; Path = "$env:SystemDrive\$Recycle.Bin"; Pattern = '*' },
            @{ Name = 'RetailDemo Office Content'; Path = "$env:SystemRoot\System32\RetailDemo"; Pattern = '*' },
            @{ Name = 'Temporary files'; Path = "$env:TEMP"; Pattern = '*' },
            @{ Name = 'Thumbnails'; Path = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"; Pattern = 'thumbcache_*.db' },
            @{ Name = 'User file history'; Path = "$env:SystemDrive\FileHistory"; Pattern = '*' }
        )
        $total = $cleanupTasks.Count
        $current = 0
        foreach ($task in $cleanupTasks) {
            $current++
            $name = $task.Name
            $path = $ExecutionContext.InvokeCommand.ExpandString($task.Path)
            $pattern = $task.Pattern
            Write-Progress -Activity "Disk Cleanup" -Status ("Cleaning: {0} ({1}/{2})" -f $name, $current, $total) -PercentComplete ([int](($current / $total) * 100))
            if (Test-Path $path) {
                try {
                    Remove-Item -Path (Join-Path $path $pattern) -Recurse -Force -ErrorAction SilentlyContinue
                    $transcript += "[{0}] Cleaned: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $name
                } catch {
                    $transcript += "[{0}] [WARN] Failed to clean {1}: {2}" -f ((Get-Date).ToString('HH:mm:ss')), $name, $_
                }
            } else {
                $transcript += "[{0}] Skipped (not found): {1}" -f ((Get-Date).ToString('HH:mm:ss')), $name
            }
        }
        Write-Progress -Activity "Disk Cleanup" -Completed
        $userProfiles = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object {
            try {
                $profilePath = (Get-ItemProperty $_.PsPath).ProfileImagePath
                if ($profilePath -and (Test-Path $profilePath)) { $profilePath }
            } catch {}
        } | Where-Object { $_ -and (Test-Path $_) }
        foreach ($profile in $userProfiles) {
            $userTemp = Join-Path $profile 'AppData\Local\Temp'
            if (Test-Path $userTemp) {
                try {
                    Remove-Item -Path "$userTemp\*" -Recurse -Force -ErrorAction SilentlyContinue
                    $transcript += "[{0}] Temp files cleaned for {1}." -f ((Get-Date).ToString('HH:mm:ss')), $profile
                } catch {
                    $transcript += "[{0}] [WARN] Failed to clean temp for {1}: {2}" -f ((Get-Date).ToString('HH:mm:ss')), $profile, $_
                }
            }
        }
        $transcript += "[{0}] [SUCCESS] Full disk cleanup complete." -f ((Get-Date).ToString('HH:mm:ss'))
        Write-TaskReport -TaskName "Full Disk Cleanup" -Status "SUCCESS"
    } catch {
        $transcript += "[{0}] [ERROR] Disk cleanup failed: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $_
        Write-ErrorLog -Function "Optimize-Disk" -Message $_
        Write-TaskReport -TaskName "Full Disk Cleanup" -Status "ERROR" -Message $_
    }
    $endTime = Get-Date
    $transcript += "[{0}] [END] Full Disk Cleanup" -f ($endTime.ToString('HH:mm:ss'))
    $outPath = Join-Path $Script:TempFolder 'Task9_FullDiskCleanup_log.txt'
    $transcript | Out-File $outPath -Encoding UTF8
}





# =====================[ TASK 10: CREATE TRANSCRIPT ]===========================

# -- Task 10: Create HTML Transcript in Dark Mode --
function Export-Transcript {
    try {
        $transcriptPath = Join-Path $PSScriptRoot 'System_Maintenance.html'
        $htmlHeader = @"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <title>System Maintenance Transcript</title>
    <style>
        body { background: #181a1b; color: #e8e6e3; font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; }
        .container { max-width: 450px; margin: 2em auto; background: #23272e; border-radius: 8px; box-shadow: 0 0 10px #0008; padding: 2em; }
        h1, h2, h3 { color: #7fd1b9; }
        .task { border-left: 5px solid #7fd1b9; margin: 2em 0; padding: 1em; background: #22262c; border-radius: 6px; }
        .timestamp { color: #b3b3b3; font-size: 0.95em; }
        .status-success { color: #7fd1b9; font-weight: bold; }
        .status-error { color: #ff6f6f; font-weight: bold; }
        .status-warning { color: #ffd166; font-weight: bold; }
        .subtask { margin-left: 1.5em; }
        pre { background: #181a1b; color: #e8e6e3; padding: 1em; border-radius: 4px; overflow-x: auto; }
        .file-section { margin: 1em 0; border-top: 1px solid #444; padding-top: 1em; }
    </style>
</head>
<body>
<div class='container'>
    <h1>System Maintenance Transcript</h1>
    <p class='timestamp'>Generated: $(Get-Date -Format 'dd-MM-yyyy HH:mm:ss')</p>
"@
        $htmlFooter = @"
</div>
</body>
</html>
"@
        $htmlBody = ""

        # Collect all task logs from temp folder
        $taskLogs = Get-ChildItem -Path $Script:TempFolder -File -Filter '*_log.txt' -ErrorAction SilentlyContinue
        foreach ($log in $taskLogs) {
            $logContent = Get-Content $log.FullName -Raw
            $taskName = [System.IO.Path]::GetFileNameWithoutExtension($log.Name)
            $logMatches = [regex]::Matches($logContent, '\[(.*?)\] \[(.*?)\](.*?)((\r?\n)+|$)')
            $htmlBody += "<div class='task'><h2>$taskName</h2>"
            foreach ($m in $logMatches) {
                $timestamp = $m.Groups[1].Value
                $status = $m.Groups[2].Value.ToUpper()
                $msg = $m.Groups[3].Value.Trim()
                $statusClass = switch ($status) {
                    'SUCCESS' { 'status-success' }
                    'ERROR'   { 'status-error' }
                    'WARN'    { 'status-warning' }
                    default   { '' }
                }
                $htmlBody += "<div><span class='timestamp'>[$timestamp]</span> <span class='$statusClass'>[$status]</span> <span class='subtask'>$msg</span></div>"
            }
            $htmlBody += "<div class='file-section'><h3>Raw Log</h3><pre>$( [System.Web.HttpUtility]::HtmlEncode($logContent) )</pre></div>"
            $htmlBody += "</div>"
        }

        # Append other temp files (not logs) for reference
        $otherFiles = Get-ChildItem -Path $Script:TempFolder -File | Where-Object { $_.Name -notlike '*_log.txt' -and $_.Name -ne 'system_maintenance_transcript.html' }
        foreach ($file in $otherFiles) {
            $fileContent = Get-Content $file.FullName -Raw
            $htmlBody += "<div class='file-section'><h3>File: $($file.Name)</h3><pre>$( [System.Web.HttpUtility]::HtmlEncode($fileContent) )</pre></div>"
        }

        # Write the HTML transcript
        Set-Content -Path $transcriptPath -Value ($htmlHeader + $htmlBody + $htmlFooter) -Encoding UTF8
        Write-Host "[INFO] HTML transcript created at $transcriptPath"
    } catch {
        Write-Host "[ERROR] Failed to create HTML transcript: $_"
    }
}







# =====================[ TASK 11: FINALIZATION ]===========================
# -- Task 11.1: Reboot Prompt
function Request-RebootIfNeeded {
    try {
        $pendingReboot = $false
        # Check for common reboot-pending indicators
        $rebootKeys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
            'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations'
        )
        foreach ($key in $rebootKeys) {
            if (Test-Path $key) {
                $pendingReboot = $true
                break
            }
        }
        if ($pendingReboot) {
            Write-Host "[INFO] A system reboot is required to complete maintenance tasks."
            $choice = Read-Host "Do you want to reboot now? (Y/N)"
            if ($choice -match '^(Y|y)') {
                Write-Host "[INFO] Rebooting system..."
                Restart-Computer -Force
            } else {
                Write-Host "[INFO] Please remember to reboot your system later."
            }
        } else {
            Write-Host "[INFO] No reboot is required."
        }
    } catch {
        Write-Host "[ERROR] Failed to check or request reboot: $_"
    }
}

# =====================[ MAIN EXECUTION ]==================================

try {
    Test-Admin
    Invoke-CentralCoordinationPolicy
    Initialize-Environment

    Invoke-Task 'System Restore Protection' { Test-SystemRestore }
    Invoke-Task 'Ensure Package Managers' { Test-PackageManagers }
    Invoke-Task 'Inventory' { Get-Inventory }
    Invoke-Task 'Remove Bloatware' { Uninstall-Bloatware }
    Invoke-Task 'Install Essential Apps' { Install-EssentialApps }
    Invoke-Task 'Disable Telemetry' { Disable-Telemetry }
    Invoke-Task 'Windows Update & Upgrade' { Update-Windows }
    Invoke-Task 'Upgrade All Packages' { Update-AllPackages }
    Invoke-Task 'Cleanup Browser Data' { Clear-BrowserData }
    Invoke-Task 'Clear DNS Cache' { Clear-DnsCache }
    Invoke-Task 'Survey Logs' { Get-LogSurvey }
    Invoke-Task 'Validate Restore Points' { Protect-RestorePoints }
    Invoke-Task 'Create Transcript' { Export-Transcript }
    Invoke-Task 'Prompt Reboot If Needed' { Request-RebootIfNeeded }

} finally {
    Remove-Environment
}
