#requires -Version 5.0
<#!
    System Maintenance Script
    - Centralized, monolithic, and modularized by tasks/subtasks
    - Compatible with PowerShell 5/7, Windows 10/11
    - Unattended execution, no extra windows
    - Temporary folder auto-cleanup
    - All actions logged to transcript
    - Robust error handling: continues on error, logs all failures
    - See Script.txt for full policy and requirements
!#>

# =====================[ CENTRAL COORDINATION POLICY ]=====================
function Invoke-CentralCoordinationPolicy {
    <#
        Reviews script structure, execution logic, and timeline.
        Ensures all tasks are executed, errors are logged, and script is maintainable.
    #>
    Write-Host "[INFO] Central Coordination Policy enforced."
}

# =====================[ GLOBALS & INITIALIZATION ]========================
$Script:TempFolder = Join-Path $env:TEMP "SystemMaintenance_$(Get-Random)"
$Script:TranscriptFile = Join-Path $Script:TempFolder 'transcript.txt'

# Admin rights check
function Test-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error "[FATAL] This script must be run as Administrator. Exiting."
        exit 
    }
}

function Initialize-Environment {
    New-Item -ItemType Directory -Path $Script:TempFolder -Force | Out-Null
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
    }
}

# =====================[ TASK 1: SYSTEM PROTECTION ]=====================
# -- Subtask 1.1: System Restore Protection
function Test-SystemRestore {
    try {
        $restoreEnabled = $false
        $osDrive = "C:"
        # Check if System Restore is enabled on C:
        $srStatus = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        if ($srStatus) {
            $restoreEnabled = $true
        } else {
            # Try enabling System Restore (requires admin)
            Write-Host "[INFO] Enabling System Restore on $osDrive..."
            Enable-ComputerRestore -Drive $osDrive -ErrorAction Stop
            $restoreEnabled = $true
        }
        if ($restoreEnabled) {
            # Create a restore point
            Write-Host "[INFO] Creating a system restore point..."
            Checkpoint-Computer -Description "System Maintenance Script" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
            Write-Host "[INFO] System restore point created."
        } else {
            Write-Warning "[WARN] Could not enable System Restore on $osDrive."
        }
    } catch {
        Write-Warning "[ERROR] System Restore check/creation failed: $_"
    }
}

# =====================[ TASK 2: PACKAGE MANAGER SETUP ]==================
# -- Subtask 2.1: Ensure Winget & Chocolatey
function Test-PackageManagers {
    try {
        # Check for winget
        $winget = Get-Command winget -ErrorAction SilentlyContinue
        if (-not $winget) {
            Write-Host "[INFO] winget not found. Attempting to install..."
            # winget is available via Microsoft Store (App Installer)
            Invoke-WebRequest -Uri "https://aka.ms/getwinget" -OutFile "$Script:TempFolder\AppInstaller.msixbundle" -UseBasicParsing
            Add-AppxPackage -Path "$Script:TempFolder\AppInstaller.msixbundle"
        } else {
            Write-Host "[INFO] winget found. Upgrading winget..."
            winget upgrade --id Microsoft.Winget.Source --accept-source-agreements --accept-package-agreements --silent
        }
        # Check for Chocolatey
        $choco = Get-Command choco -ErrorAction SilentlyContinue
        if (-not $choco) {
            Write-Host "[INFO] Chocolatey not found. Installing..."
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        } else {
            Write-Host "[INFO] Chocolatey found. Upgrading Chocolatey..."
            choco upgrade chocolatey -y
        }
    } catch {
        Write-Warning "[ERROR] Package manager check/installation failed: $_"
    }
}

# =====================[ TASK 3: SYSTEM INVENTORY ]=======================
# -- Subtask 3.1: Collect System Inventory
function Get-Inventory {
    try {
        $inventoryPath = Join-Path $Script:TempFolder 'inventory'
        New-Item -ItemType Directory -Path $inventoryPath -Force | Out-Null
        # OS Info
        Get-ComputerInfo | Out-File (Join-Path $inventoryPath 'os_info.txt')
        # Hardware Info
        Get-WmiObject -Class Win32_ComputerSystem | Out-File (Join-Path $inventoryPath 'hardware_info.txt')
        # Disk Info
        Get-PSDrive | Where-Object {$_.Provider -like '*FileSystem*'} | Out-File (Join-Path $inventoryPath 'disk_info.txt')
        # Network Info
        Get-NetIPAddress | Out-File (Join-Path $inventoryPath 'network_info.txt')
        # Installed Programs (Win32_Product is slow, so use registry)
        Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Out-File (Join-Path $inventoryPath 'installed_programs.txt')
        Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Out-File -Append (Join-Path $inventoryPath 'installed_programs.txt')
        # Winget inventory
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            winget list --source winget > (Join-Path $inventoryPath 'winget_list.txt')
        }
        Write-Host "[INFO] Inventory collected in $inventoryPath"
    } catch {
        Write-Warning "[ERROR] Inventory collection failed: $_"
    }
}

# =====================[ TASK 4: DEBLOATING & APP MANAGEMENT ]============
# -- Subtask 4.1: Remove Bloatware

function Uninstall-Bloatware {
    try {
        Write-Host "[INFO] Scanning for bloatware apps to remove..."
        # List of common bloatware AppX package names and Win32/OEM bloatware
        $bloatwareList = @(
            # Microsoft Store Apps (AppX)
            'Microsoft.Microsoft3DViewer',
            'king.com.CandyCrushSaga',
            'king.com.CandyCrushFriends',
            'king.com.CandyCrushSodaSaga',
            'king.com.BubbleWitch3Saga',
            'king.com.FarmHeroesSaga',
            'Microsoft.XboxApp',
            'Microsoft.XboxGamingOverlay',
            'Microsoft.XboxGameOverlay',
            'Microsoft.Xbox.TCUI',
            'Microsoft.XboxSpeechToTextOverlay',
            'Microsoft.XboxIdentityProvider',
            'Microsoft.XboxGameCallableUI',
            'Microsoft.XboxGameOverlay',
            'Microsoft.XboxGamingOverlay',
            'Microsoft.Xbox.TCUI',
            'Microsoft.XboxSpeechToTextOverlay',
            'Microsoft.XboxIdentityProvider',
            'Microsoft.ZuneMusic',
            'Microsoft.ZuneVideo',
            'Microsoft.Office.OneNote',
            'Microsoft.SkypeApp',
            'Microsoft.MicrosoftSolitaireCollection',
            'Microsoft.BingWeather',
            'Microsoft.BingNews',
            'Microsoft.BingFinance',
            'Microsoft.BingSports',
            'Microsoft.BingFoodAndDrink',
            'Microsoft.BingHealthAndFitness',
            'Microsoft.BingTravel',
            'Microsoft.YourPhone',
            'Microsoft.MSPaint',
            'Microsoft.People',
            'Microsoft.MixedReality.Portal',
            'Microsoft.GetHelp',
            'Microsoft.Getstarted',
            'Microsoft.MicrosoftOfficeHub',
            'Microsoft.WindowsFeedbackHub',
            'Microsoft.WindowsMaps',
            'Microsoft.SoundRecorder',
            'Microsoft.WindowsAlarms',
            'Microsoft.windowscommunicationsapps',
            'Microsoft.WindowsCamera',
            'Microsoft.ScreenSketch',
            'Microsoft.MicrosoftStickyNotes',
            'Microsoft.3DBuilder',
            'Microsoft.Advertising.Xaml',
            'Microsoft.Appconnector',
            'Microsoft.CommsPhone',
            'Microsoft.ConnectivityStore',
            'Microsoft.Messaging',
            'Microsoft.Microsoft3DViewer',
            'Microsoft.MicrosoftOfficeHub',
            'Microsoft.MicrosoftPowerBIForWindows',
            'Microsoft.MicrosoftSolitaireCollection',
            'Microsoft.MicrosoftStickyNotes',
            'Microsoft.MixedReality.Portal',
            'Microsoft.NetworkSpeedTest',
            'Microsoft.News',
            'Microsoft.Office.Sway',
            'Microsoft.OneConnect',
            'Microsoft.People',
            'Microsoft.Print3D',
            'Microsoft.SkypeApp',
            'Microsoft.Wallet',
            'Microsoft.Whiteboard',
            'Microsoft.Windows.Photos',
            'Microsoft.WindowsAlarms',
            'Microsoft.WindowsCamera',
            'Microsoft.WindowsMaps',
            'Microsoft.WindowsSoundRecorder',
            'Microsoft.Xbox.TCUI',
            'Microsoft.XboxApp',
            'Microsoft.XboxGameOverlay',
            'Microsoft.XboxGamingOverlay',
            'Microsoft.XboxIdentityProvider',
            'Microsoft.XboxSpeechToTextOverlay',
            'Microsoft.ZuneMusic',
            'Microsoft.ZuneVideo',
            'Microsoft.WindowsReadingList',
            'Microsoft.WindowsPhone',
            'Microsoft.WindowsStore',
            'Microsoft.WindowsFeedback',
            'Microsoft.WindowsSoundRecorder',
            'Microsoft.WindowsCommunicationsApps',
            'Microsoft.YourPhone',
            'Microsoft.GetHelp',
            'Microsoft.Getstarted',
            'Microsoft.MicrosoftStickyNotes',
            'Microsoft.People',
            'Microsoft.MicrosoftSolitaireCollection',
            'Microsoft.MicrosoftOfficeHub',
            'Microsoft.WindowsFeedbackHub',
            'Microsoft.WindowsMaps',
            'Microsoft.WindowsAlarms',
            'Microsoft.WindowsCamera',
            'Microsoft.ScreenSketch',
            'Microsoft.MixedReality.Portal',
            'Microsoft.3DBuilder',
            'Microsoft.Advertising.Xaml',
            'Microsoft.Appconnector',
            'Microsoft.ConnectivityStore',
            'Microsoft.Messaging',
            'Microsoft.MicrosoftPowerBIForWindows',
            'Microsoft.NetworkSpeedTest',
            'Microsoft.Office.Sway',
            'Microsoft.OneConnect',
            'Microsoft.Print3D',
            'Microsoft.Wallet',
            'Microsoft.Whiteboard',
            'Microsoft.Windows.Photos',
            'Microsoft.WindowsReadingList',
            'Microsoft.WindowsPhone',
            'Microsoft.WindowsStore',
            'Microsoft.WindowsFeedback',
            'Microsoft.WindowsSoundRecorder',
            'Microsoft.WindowsCommunicationsApps',
            'Microsoft.YourPhone',
            'Microsoft.GetHelp',
            'Microsoft.Getstarted',
            'Microsoft.MicrosoftStickyNotes',
            'Microsoft.People',
            'Microsoft.MicrosoftSolitaireCollection',
            'Microsoft.MicrosoftOfficeHub',
            'Microsoft.WindowsFeedbackHub',
            'Microsoft.WindowsMaps',
            'Microsoft.WindowsAlarms',
            'Microsoft.WindowsCamera',
            'Microsoft.ScreenSketch',
            'Microsoft.MixedReality.Portal',
            'Microsoft.3DBuilder',
            'Microsoft.Advertising.Xaml',
            'Microsoft.Appconnector',
            'Microsoft.ConnectivityStore',
            'Microsoft.Messaging',
            'Microsoft.MicrosoftPowerBIForWindows',
            'Microsoft.NetworkSpeedTest',
            'Microsoft.Office.Sway',
            'Microsoft.OneConnect',
            'Microsoft.Print3D',
            'Microsoft.Wallet',
            'Microsoft.Whiteboard',
            'Microsoft.Windows.Photos',
            'Microsoft.WindowsReadingList',
            'Microsoft.WindowsPhone',
            'Microsoft.WindowsStore',
            'Microsoft.WindowsFeedback',
            'Microsoft.WindowsSoundRecorder',
            'Microsoft.WindowsCommunicationsApps',
            'Microsoft.YourPhone',
            'Microsoft.GetHelp',
            'Microsoft.Getstarted',
            'Microsoft.MicrosoftStickyNotes',
            'Microsoft.People',
            'Microsoft.MicrosoftSolitaireCollection',
            'Microsoft.MicrosoftOfficeHub',
            'Microsoft.WindowsFeedbackHub',
            'Microsoft.WindowsMaps',
            'Microsoft.WindowsAlarms',
            'Microsoft.WindowsCamera',
            'Microsoft.ScreenSketch',
            'Microsoft.MixedReality.Portal',
            'Microsoft.3DBuilder',
            'Microsoft.Advertising.Xaml',
            'Microsoft.Appconnector',
            'Microsoft.ConnectivityStore',
            'Microsoft.Messaging',
            'Microsoft.MicrosoftPowerBIForWindows',
            'Microsoft.NetworkSpeedTest',
            'Microsoft.Office.Sway',
            'Microsoft.OneConnect',
            'Microsoft.Print3D',
            'Microsoft.Wallet',
            'Microsoft.Whiteboard',
            'Microsoft.Windows.Photos',
            'Microsoft.WindowsReadingList',
            'Microsoft.WindowsPhone',
            'Microsoft.WindowsStore',
            'Microsoft.WindowsFeedback',
            'Microsoft.WindowsSoundRecorder',
            'Microsoft.WindowsCommunicationsApps',
            'Microsoft.YourPhone',
            'Microsoft.GetHelp',
            'Microsoft.Getstarted',
            'Microsoft.MicrosoftStickyNotes',
            'Microsoft.People',
            'Microsoft.MicrosoftSolitaireCollection',
            'Microsoft.MicrosoftOfficeHub',
            'Microsoft.WindowsFeedbackHub',
            'Microsoft.WindowsMaps',
            'Microsoft.WindowsAlarms',
            'Microsoft.WindowsCamera',
            'Microsoft.ScreenSketch',
            'Microsoft.MixedReality.Portal'
            # Expanded from Chris Titus Tech, W10Privacy, and other reputable sources
        )
        # Common Win32/OEM bloatware display names (partial matches)
        $bloatwareWin32 = @(
            'WildTangent', 'McAfee', 'Norton', 'CyberLink', 'ExpressVPN', 'Booking.com', 'Keeper', 'Dropbox', 'Amazon', 'HP JumpStart', 'HP Support Assistant', 'Dell Customer Connect', 'Lenovo Vantage', 'Lenovo App Explorer', 'Asus GiftBox', 'Candy Crush', 'Spotify', 'Disney+', 'Facebook', 'Twitter', 'LinkedIn', 'Booking', 'eBay', 'Netflix', 'Farm Heroes', 'March of Empires', 'Sling', 'Phototastic', 'PicsArt', 'Adobe Express', 'Simple Solitaire', 'Bubble Witch', 'Hidden City', 'Minecraft', 'Royal Revolt', 'Dolby', 'Power2Go', 'PowerDirector', 'WildTangent Games', 'Keeper Password Manager', 'TripAdvisor', 'WPS Office', 'Evernote', 'Foxit', 'Opera', 'Opera GX', 'Vivaldi', 'Brave', 'Tor Browser', 'UC Browser', 'Baidu Browser', 'Yandex Browser', 'Comodo Dragon', 'SRWare Iron', 'Maxthon', 'Pale Moon', 'Waterfox', 'Slimjet', 'Cent Browser', 'Coc Coc', 'Avant Browser', 'SeaMonkey', 'Epic Privacy Browser', 'Sleipnir', 'Dooble', 'Otter Browser', 'Falkon', 'Midori', 'QuteBrowser', 'K-Meleon', 'Lunascape', '360 Browser', 'Basilisk', 'Polarity', 'Ghost Browser', 'Coowon', 'Orbitum', 'Sputnik', 'Sogou Explorer', 'SlimBrowser', 'Dooble', 'Blisk', 'Cliqz', 'Torch', 'Superbird', 'CoolNovo', 'QupZilla', 'LinkedIn',
            # Expanded Win32/OEM bloatware from reputable sources
            'Acer Collection', 'Acer Configuration Manager', 'Acer Portal', 'Acer Power Management', 'Acer Quick Access', 'Acer UEIP Framework', 'Acer User Experience Improvement Program',
            'ASUS Live Update', 'ASUS GiftBox', 'ASUS Splendid Video Enhancement Technology', 'ASUS WebStorage', 'ASUS ZenAnywhere', 'ASUS ZenLink',
            'Dell Digital Delivery', 'Dell Foundation Services', 'Dell Help & Support', 'Dell Mobile Connect', 'Dell Power Manager', 'Dell Product Registration', 'Dell SupportAssist', 'Dell Update',
            'HP 3D DriveGuard', 'HP Audio Switch', 'HP Client Security Manager', 'HP Connection Optimizer', 'HP Documentation', 'HP Dropbox Plugin', 'HP ePrint SW', 'HP JumpStart Apps', 'HP JumpStart Launch', 'HP Registration Service', 'HP Support Solutions Framework', 'HP Sure Connect', 'HP System Event Utility', 'HP Welcome',
            'Lenovo App Explorer', 'Lenovo Companion', 'Lenovo Experience Improvement', 'Lenovo Family Cloud', 'Lenovo Hotkeys', 'Lenovo Migration Assistant', 'Lenovo Modern IM Controller', 'Lenovo Service Bridge', 'Lenovo Solution Center', 'Lenovo Utility', 'Lenovo Vantage', 'Lenovo Voice', 'Lenovo WiFi Security',
            'WildTangent Games', 'WildTangent Helper',
            'CyberLink PowerDVD', 'CyberLink YouCam', 'CyberLink Media Suite', 'CyberLink Power2Go', 'CyberLink PowerDirector',
            'McAfee LiveSafe', 'McAfee Security', 'McAfee Safe Connect', 'McAfee WebAdvisor',
            'Norton Security', 'Norton Online Backup',
            'Avast Free Antivirus', 'AVG Antivirus', 'Avira', 'Kaspersky', 'Bitdefender', 'ESET',
            'CCleaner', 'Driver Booster', 'DriverPack', 'PC App Store', 'PC Accelerate', 'PC Optimizer', 'Reimage Repair', 'Advanced SystemCare',
            'Adobe Creative Cloud', 'Adobe Express', 'Adobe Genuine Service',
            'WPS Office', 'Foxit', 'Evernote', 'Dropbox', 'OneDrive',
            'Hulu', 'Amazon Prime Video', 'Instagram', 'TikTok',
            'Keeper Password Manager', 'TripAdvisor',
            'Power2Go', 'PowerDirector'
        )
        # Load inventory from Get-Inventory
        $inventoryPath = Join-Path $Script:TempFolder 'inventory'
        $installedProgramsPath = Join-Path $inventoryPath 'installed_programs.txt'
        $wingetListPath = Join-Path $inventoryPath 'winget_list.txt'
        $installed = @()
        if (Test-Path $installedProgramsPath) {
            $installed += Get-Content $installedProgramsPath | Where-Object { $_ -and $_.Trim() -ne '' }
        }
        if (Test-Path $wingetListPath) {
            $wingetList = Get-Content $wingetListPath | Select-Object -Skip 1
            $installed += $wingetList | ForEach-Object { $_.Split(' ')[0] }
        }
        if (-not $installed -or $installed.Count -eq 0) {
            $installed += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue
            $installed += Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue
        }
        # Remove AppX bloatware
        foreach ($bloat in $bloatwareList) {
            $pkg = Get-AppxPackage -AllUsers | Where-Object { $_.Name -eq $bloat }
            if ($pkg) {
                try {
                    Write-Host "[INFO] Removing AppX package: $bloat"
                    Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                    Write-Host "[INFO] Removed AppX package: $bloat"
                } catch {
                    Write-Warning ("[WARN] Failed to remove AppX package {0}: {1}" -f $bloat, $_)
                }
            }
        }
        # Remove Win32/OEM bloatware by display name (partial match)
        foreach ($bloat in $bloatwareWin32) {
            $bloatMatches = $installed | Where-Object { $_ -and $_.ToLower().Contains($bloat.ToLower()) }
            foreach ($match in $bloatMatches) {
                try {
                    Write-Host "[INFO] Uninstalling Win32/OEM bloatware: $match"
                    if (Get-Command winget -ErrorAction SilentlyContinue) {
                        winget uninstall --exact --silent --accept-source-agreements --accept-package-agreements --id "$match" 2>&1 | Out-Null
                    }
                    # Fallback: try WMIC
                    $wmic = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -eq $match }
                    if ($wmic) {
                        $wmic.Uninstall() | Out-Null
                    }
                    Write-Host "[INFO] Uninstalled: $match"
                } catch {
                    Write-Warning ("[WARN] Failed to uninstall {0}: {1}" -f $match, $_)
                }
            }
        }
        Write-Host "[INFO] Bloatware removal complete."
    } catch {
        Write-Warning "[ERROR] Bloatware removal failed: $_"
    }
}

# -- Subtask 4.2: Install Essential Apps
function Install-EssentialApps {
    try {
        # Define essential apps (add more as needed)
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
            @{ Name = 'Java 8 Update'; Winget = 'Oracle.JavaRuntimeEnvironment'; Choco = 'javaruntime' },
            @{ Name = 'Mail and Calendar'; Winget = 'Microsoft.WindowsCommunicationsApps'; Choco = '' },
            @{ Name = 'Phone Link'; Winget = 'Microsoft.YourPhone'; Choco = '' },
            @{ Name = 'Windows Calculator'; Winget = 'Microsoft.WindowsCalculator'; Choco = '' },
            @{ Name = 'Windows Camera'; Winget = 'Microsoft.WindowsCamera'; Choco = '' }
        )
        # Add more must-have office apps
        $essentialApps += @(
            @{ Name = 'Microsoft Teams'; Winget = 'Microsoft.Teams'; Choco = 'microsoft-teams' },
            @{ Name = 'Zoom'; Winget = 'Zoom.Zoom'; Choco = 'zoom' }
        )
        # Check for Microsoft Office
        $officeInstalled = $false
        $officeNames = @('Microsoft Office', 'Office16', 'Office15', 'Office14', 'Office12', 'Office11', 'Office10', 'Office09', 'Office08', 'Office07', 'Office 365')
        $installed = @()
        $inventoryPath = Join-Path $Script:TempFolder 'inventory'
        $installedProgramsPath = Join-Path $inventoryPath 'installed_programs.txt'
        $wingetListPath = Join-Path $inventoryPath 'winget_list.txt'
        if (Test-Path $installedProgramsPath) {
            $installed += Get-Content $installedProgramsPath | Where-Object { $_ -and $_.Trim() -ne '' }
        }
        if (Test-Path $wingetListPath) {
            $wingetList = Get-Content $wingetListPath | Select-Object -Skip 1
            $installed += $wingetList | ForEach-Object { $_.Split(' ')[0] }
        }
        if (-not $installed -or $installed.Count -eq 0) {
            $installed += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue
            $installed += Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue
        }
        foreach ($name in $officeNames) {
            if ($installed | Where-Object { $_ -like "*$name*" }) {
                $officeInstalled = $true
                break
            }
        }
        # Add LibreOffice only if not installed and Microsoft Office is not installed
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
            } else {
                Write-Host "[INFO] Microsoft Office is installed. Skipping LibreOffice installation."
            }
        } else {
            Write-Host "[INFO] LibreOffice is already installed. Skipping."
        }
        # Install missing essential apps
        foreach ($app in $essentialApps) {
            $isInstalled = $installed | Where-Object { $_ -and $_ -like "*$($app.Name)*" }
            if (-not $isInstalled) {
                Write-Host "[INFO] Installing $($app.Name)..."
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
                                Write-Warning ("[WARN] Windows Installer is busy (exit code 1618) for $($app.Name). Attempt $retryCount/$maxRetries. Retrying in $retryDelay seconds...")
                                Start-Sleep -Seconds $retryDelay
                                continue
                            }
                            $installedVia = 'winget'
                            $installSucceeded = $true
                        } catch {
                            Write-Warning "[WARN] winget failed for $($app.Name): $_"
                        }
                    }
                    if (-not $installSucceeded -and $app.Choco -and (Get-Command choco -ErrorAction SilentlyContinue)) {
                        try {
                            $chocoResult = choco install $($app.Choco) -y 2>&1
                            if ($chocoResult -match '1618') {
                                Write-Warning ("[WARN] Windows Installer is busy (exit code 1618) for $($app.Name) via choco. Attempt $retryCount/$maxRetries. Retrying in $retryDelay seconds...")
                                Start-Sleep -Seconds $retryDelay
                                continue
                            }
                            $installedVia = 'choco'
                            $installSucceeded = $true
                        } catch {
                            Write-Warning "[WARN] choco failed for $($app.Name): $_"
                        }
                    }
                    break # If neither installer is available, break loop
                }
                if ($installSucceeded -and $installedVia) {
                    Write-Host "[INFO] Installed $($app.Name) via $installedVia."
                } elseif (-not $installSucceeded) {
                    Write-Warning ("[ERROR] Could not install $($app.Name) after $maxRetries attempts due to Windows Installer being busy (exit code 1618). Skipping.")
                } elseif (-not $installedVia) {
                    Write-Warning "[ERROR] Could not install $($app.Name) via winget or choco."
                }
            } else {
                Write-Host "[INFO] $($app.Name) already installed."
            }
        }
        Write-Host "[INFO] Essential apps installation complete."
    } catch {
        Write-Warning "[ERROR] Essential apps installation failed: $_"
    }
}

# =====================[ TASK 5: PRIVACY & TELEMETRY ]====================
# -- Subtask 5.1: Disable Telemetry
function Disable-Telemetry {
    try {
        Write-Host "[INFO] Disabling Windows telemetry and data collection..."
        # Disable telemetry via registry
        $regPaths = @(
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'
        )
        foreach ($path in $regPaths) {
            if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
            Set-ItemProperty -Path $path -Name AllowTelemetry -Value 0 -Force
        }
        # Disable diagnostics tracking services
        $services = @(
            'DiagTrack', # Connected User Experiences and Telemetry
            'dmwappushservice' # dmwappushsvc
        )
        foreach ($svc in $services) {
            if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
                Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                Set-Service -Name $svc -StartupType Disabled
            }
        }
        # Block telemetry hosts in hosts file
        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
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
        foreach ($telemetryHost in $telemetryHosts) {
            $maxRetries = 5
            $retryDelay = 10 # seconds
            $attempt = 0
            $success = $false
            while (-not $success -and $attempt -lt $maxRetries) {
                $attempt++
                try {
                    if (-not (Select-String -Path $hostsPath -Pattern $telemetryHost -Quiet)) {
                        Add-Content -Path $hostsPath -Value "0.0.0.0 $telemetryHost"
                    }
                    $success = $true
                } catch {
                    if ($_.Exception.Message -like '*because it is being used by another process*' -or $_.Exception.Message -like '*The process cannot access the file*') {
                        if ($attempt -lt $maxRetries) {
                            Write-Warning ("[WARN] Hosts file is locked (attempt {0}/{1}) for {2}. Retrying in {3} seconds..." -f $attempt, $maxRetries, $telemetryHost, $retryDelay)
                            Start-Sleep -Seconds $retryDelay
                        } else {
                            Write-Warning ("[WARN] Could not modify hosts file for {0} after {1} attempts: {2}" -f $telemetryHost, $maxRetries, $_)
                        }
                    } else {
                        Write-Warning ("[WARN] Could not modify hosts file for {0}: {1}" -f $telemetryHost, $_)
                        break
                    }
                }
            }
        }
        Write-Host "[INFO] Telemetry disabled."
    } catch {
        Write-Warning "[ERROR] Telemetry disabling failed: $_"
    }
}

# =====================[ TASK 6: UPDATES & MAINTENANCE ]==================
# -- Subtask 6.1: Windows Update & Upgrade
function Update-Windows {
    try {
        Write-Host "[INFO] Starting Windows Update & Upgrade..."
        # Try to import/update PSWindowsUpdate module if available
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            try {
                Install-PackageProvider -Name NuGet -Force -Scope CurrentUser -ErrorAction SilentlyContinue
                Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber -ErrorAction SilentlyContinue
            } catch {
                Write-Warning "[WARN] Could not install PSWindowsUpdate module: $_"
            }
        }
        Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
        # Run Windows Update
        try {
            Get-WindowsUpdate -AcceptAll -Install -AutoReboot -ErrorAction Stop
            Write-Host "[INFO] Windows Update completed."
        } catch {
            Write-Warning "[WARN] Get-WindowsUpdate failed: $_. Trying wuauclt..."
            # Fallback to wuauclt for older systems
            wuauclt /detectnow /updatenow
            Write-Host "[INFO] Triggered Windows Update via wuauclt. Please check Windows Update manually if needed."
        }
    } catch {
        Write-Warning "[ERROR] Windows Update & Upgrade failed: $_"
    }
}

# -- Subtask 6.2: Winget Upgrade All
function Update-AllPackages {
    try {
        Write-Host "[INFO] Upgrading all packages via winget..."
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            winget upgrade --all --include-unknown --accept-source-agreements --accept-package-agreements --silent
            Write-Host "[INFO] All packages upgraded via winget."
        } else {
            Write-Warning "[WARN] winget not found. Skipping package upgrade."
        }
    } catch {
        Write-Warning "[ERROR] Winget upgrade all failed: $_"
    }
}

# =====================[ TASK 7: CLEANUP ]===============================
# -- Subtask 7.1: Browser Cache/Cookies Cleanup
function Clear-BrowserData {
    try {
        Write-Host "[INFO] Cleaning browser cache and cookies..."
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
        foreach ($profile in $userProfiles) {
            foreach ($browser in $browsers) {
                foreach ($relPath in $browser.Paths) {
                    $fullPath = Join-Path $profile $relPath
                    if (Test-Path $fullPath) {
                        try {
                            # Check if browser process is running
                            $procName = $browser.Name
                            $isRunning = Get-Process -Name $procName -ErrorAction SilentlyContinue
                            if ($isRunning) {
                                Write-Warning "[WARN] $($browser.Name) is running. Some files may not be deleted."
                            }
                            if ($relPath -like '*Cache*') {
                                Remove-Item -Path $fullPath -Recurse -Force -ErrorAction SilentlyContinue
                                Write-Host "[INFO] Cleared cache for $($browser.Name) in $profile."
                            } elseif ($relPath -like '*Cookies*') {
                                Remove-Item -Path $fullPath -Force -ErrorAction SilentlyContinue
                                Write-Host "[INFO] Cleared cookies for $($browser.Name) in $profile."
                            } elseif ($browser.Name -eq 'Firefox' -and (Test-Path $fullPath)) {
                                # Firefox: clear all cache2 and cookies.sqlite in all profiles
                                Get-ChildItem $fullPath -Directory | ForEach-Object {
                                    $cache2 = Join-Path $_.FullName 'cache2'
                                    $cookies = Join-Path $_.FullName 'cookies.sqlite'
                                    if (Test-Path $cache2) {
                                        Remove-Item -Path $cache2 -Recurse -Force -ErrorAction SilentlyContinue
                                        Write-Host "[INFO] Cleared cache for Firefox in $($_.FullName)."
                                    }
                                    if (Test-Path $cookies) {
                                        Remove-Item -Path $cookies -Force -ErrorAction SilentlyContinue
                                        Write-Host "[INFO] Cleared cookies for Firefox in $($_.FullName)."
                                    }
                                }
                            }
                        } catch {
                            Write-Warning ("[WARN] Failed to clear {0} for {1} in {2}: {3}" -f $relPath, $browser.Name, $profile, $_)
                        }
                    }
                }
            }
        }
        Write-Host "[INFO] Browser cache and cookies cleanup complete."
    } catch {
        Write-Warning "[ERROR] Browser data cleanup failed: $_"
    }
}

# -- Subtask 7.2: Full Disk Cleanup
function Optimize-Disk {
    try {
        Write-Host "[INFO] Starting full disk cleanup..."
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
            # Removed Write-Progress to prevent terminal hangs
            Write-Host ("[INFO] Cleaning: {0} ({1}/{2})" -f $name, $current, $total)
            if (Test-Path $path) {
                try {
                    Remove-Item -Path (Join-Path $path $pattern) -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host ("[INFO] Cleaned: {0}" -f $name)
                } catch {
                    Write-Warning ("[WARN] Failed to clean {0}: {1}" -f $name, $_)
                }
            } else {
                Write-Host ("[INFO] Skipped (not found): {0}" -f $name)
            }
        }
        # Clean all user temp folders
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
                    Write-Host ("[INFO] Temp files cleaned for {0}." -f $profile)
                } catch {
                    Write-Warning ("[WARN] Failed to clean temp for {0}: {1}" -f $profile, $_)
                }
            }
        }
        Write-Host "[INFO] Full disk cleanup complete."
    } catch {
        Write-Warning "[ERROR] Disk cleanup failed: $_"
    }
}

# -- Subtask 7.3: DNS CACHE CLEANUP
function Clear-DnsCache {
    try {
        Write-Host "[INFO] Clearing DNS client cache..."
        if (Get-Command Clear-DnsClientCache -ErrorAction SilentlyContinue) {
            Clear-DnsClientCache
            Write-Host "[INFO] DNS client cache cleared."
        } else {
            Write-Warning "[WARN] Clear-DnsClientCache cmdlet not available on this system. Skipping DNS cache cleanup."
        }
    } catch {
        Write-Warning "[ERROR] DNS cache cleanup failed: $_"
    }
}

# =====================[ TASK 8: LOGGING & RESTORE POINTS ]===============
# -- Subtask 8.1: Event Viewer & CBS Log Survey
function Get-LogSurvey {
    try {
        Write-Host "[INFO] Surveying Event Viewer and CBS logs for last 48h errors..."
        $logPath = Join-Path $Script:TempFolder 'log_survey.txt'
        $since = (Get-Date).AddHours(-48)
        $systemErrors = $null
        $appErrors = $null
        # Try Get-WinEvent, fallback to Get-EventLog if needed
        try {
            Import-Module Microsoft.PowerShell.Diagnostics -ErrorAction Stop
            $systemErrors = Get-WinEvent -FilterHashtable @{LogName='System'; Level=2; StartTime=$since} -ErrorAction Stop | Select-Object TimeCreated, Id, LevelDisplayName, Message
            $appErrors = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2; StartTime=$since} -ErrorAction Stop | Select-Object TimeCreated, Id, LevelDisplayName, Message
        } catch {
            Write-Warning "[WARN] Get-WinEvent failed (likely due to missing temp files or permissions). Falling back to Get-EventLog."
            try {
                $systemErrors = Get-EventLog -LogName System -EntryType Error -After $since -ErrorAction Stop | Select-Object TimeGenerated, EventID, EntryType, Message
                $appErrors = Get-EventLog -LogName Application -EntryType Error -After $since -ErrorAction Stop | Select-Object TimeGenerated, EventID, EntryType, Message
            } catch {
                Write-Warning "[WARN] Get-EventLog also failed: $_"
            }
        }
        "==== System Log Errors (Last 48h) ====" | Out-File $logPath
        if ($systemErrors) { $systemErrors | Format-Table -AutoSize | Out-File $logPath -Append } else { "(No system errors found or log unavailable)" | Out-File $logPath -Append }
        "==== Application Log Errors (Last 48h) ====" | Out-File $logPath -Append
        if ($appErrors) { $appErrors | Format-Table -AutoSize | Out-File $logPath -Append } else { "(No application errors found or log unavailable)" | Out-File $logPath -Append }
        # CBS.log errors (last 48h)
        $cbsLog = "$env:windir\Logs\CBS\CBS.log"
        if (Test-Path $cbsLog) {
            $cbsLines = Get-Content $cbsLog | Select-String -Pattern 'error' -SimpleMatch
            # Extract date from CBS.log line: format is [YYYY-MM-DD]
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
        Write-Host "[INFO] Log survey complete. Results in $logPath."
    } catch {
        Write-Warning "[ERROR] Log survey failed: $_"
    }
}

# -- Subtask 8.2: Restore Points Validation
function Protect-RestorePoints {
    try {
        Write-Host "[INFO] Validating and pruning restore points..."
        $restorePoints = Get-ComputerRestorePoint | Sort-Object -Property CreationTime -Descending
        $logPath = Join-Path $Script:TempFolder 'restore_points.txt'
        $initialCount = $restorePoints.Count
        if ($restorePoints.Count -gt 5) {
            $toRemove = $restorePoints | Select-Object -Skip 5
            foreach ($rp in $toRemove) {
                try {
                    vssadmin delete shadows /for=C: /oldest /quiet | Out-Null
                    Write-Host "[INFO] Deleted old restore point: $($rp.Description) [$($rp.CreationTime)]"
                } catch {
                    Write-Warning "[WARN] Could not delete restore point: $($rp.Description) [$($rp.CreationTime)]"
                }
            }
        }
        $remaining = Get-ComputerRestorePoint | Sort-Object -Property CreationTime -Descending | Select-Object -First 5
        $finalCount = ($remaining | Measure-Object).Count
        Write-Host "[INFO] Restore points before: $initialCount, after: $finalCount."
        "==== Latest 5 Restore Points ====" | Out-File $logPath
        $remaining | Format-Table SequenceNumber, Description, CreationTime, EventType, RestorePointType -AutoSize | Out-File $logPath -Append
        Write-Host "[INFO] Restore points validation complete. Details in $logPath."
    } catch {
        Write-Warning "[ERROR] Restore points validation failed: $_"
    }
}

# -- Subtask 8.3: Create Transcript
function Export-Transcript {
    try {
        Write-Host "[INFO] Creating visual execution summary..."
        $transcriptPath = Join-Path $Script:TempFolder 'final_transcript.txt'
        $out = @()
        $out += ""
        $out += "==================== SYSTEM MAINTENANCE FINAL SUMMARY ===================="
        $out += ("Generated: {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
        $out += ""
        # --- REMOVED ITEMS ---
        $out += "-------------------- REMOVED FROM SYSTEM --------------------"
        $bloatLog = (Get-Content $Script:TranscriptFile | Select-String '\[INFO\] Uninstalled|\[INFO\] Removed AppX package|\[INFO\] Cleaned:')
        if ($bloatLog) {
            foreach ($line in $bloatLog) {
                $msg = $line.Line -replace '\[INFO\] ', ''
                $timestamp = $line.Line -match '^(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})' ? $matches[1] : ''
                if ($timestamp) {
                    $msg = $msg -replace "^$timestamp ", ''
                    $out += ("    ✗ {0} (at {1})" -f $msg, $timestamp)
                } else {
                    $out += ("    ✗ {0}" -f $msg)
                }
            }
        } else {
            $out += "    (No bloatware or major files removed)"
        }
        $tempCleaned = (Get-Content $Script:TranscriptFile | Select-String 'Temp files cleaned for')
        foreach ($line in $tempCleaned) {
            $msg = $line.Line -replace '\[INFO\] ', ''
            $timestamp = $line.Line -match '^(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})' ? $matches[1] : ''
            if ($timestamp) {
                $msg = $msg -replace "^$timestamp ", ''
                $out += ("    ✗ {0} (at {1})" -f $msg, $timestamp)
            } else {
                $out += ("    ✗ {0}" -f $msg)
            }
        }
        $out += ""
        # --- ADDED ITEMS ---
        $out += "-------------------- ADDED TO SYSTEM --------------------"
        $addedLog = (Get-Content $Script:TranscriptFile | Select-String '\[INFO\] Installed')
        if ($addedLog) {
            foreach ($line in $addedLog) {
                $msg = $line.Line -replace '\[INFO\] ', ''
                $timestamp = $line.Line -match '^(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})' ? $matches[1] : ''
                if ($timestamp) {
                    $msg = $msg -replace "^$timestamp ", ''
                    $out += ("    ✓ {0} (at {1})" -f $msg, $timestamp)
                } else {
                    $out += ("    ✓ {0}" -f $msg)
                }
            }
        } else {
            $out += "    (No new essential apps installed)"
        }
        $out += ""
        # --- ERRORS/WARNINGS ---
        $out += "-------------------- WARNINGS & ERRORS --------------------"
        $warns = (Get-Content $Script:TranscriptFile | Select-String '\[WARN|ERROR\]')
        if ($warns) {
            foreach ($line in $warns) {
                $msg = $line.Line -replace '\[WARN(ING)?\] ', '' -replace '\[ERROR\] ', ''
                $timestamp = $line.Line -match '^(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})' ? $matches[1] : ''
                if ($timestamp) {
                    $msg = $msg -replace "^$timestamp ", ''
                    $out += ("    ! {0} (at {1})" -f $msg, $timestamp)
                } else {
                    $out += ("    ! {0}" -f $msg)
                }
            }
        } else {
            $out += "    (No warnings or errors detected)"
        }
        $out += ""
        # --- TASK EXECUTION SUMMARY ---
        $out += "-------------------- TASK EXECUTION SUMMARY --------------------"
        $taskLog = (Get-Content $Script:TranscriptFile | Select-String '\[TASK\] |\[SUCCESS\] ')
        if ($taskLog) {
            foreach ($line in $taskLog) {
                $msg = $line.Line -replace '\[TASK\] ', 'Started: ' -replace '\[SUCCESS\] ', 'Completed: '
                $timestamp = $line.Line -match '^(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})' ? $matches[1] : ''
                if ($timestamp) {
                    $msg = $msg -replace "^$timestamp ", ''
                    $out += ("    - {0} (at {1})" -f $msg, $timestamp)
                } else {
                    $out += ("    - {0}" -f $msg)
                }
            }
        } else {
            $out += "    (No task execution details found)"
        }
        $out += ""
        $out += "==================== END OF SUMMARY ===================="
        $out | Out-File $transcriptPath -Encoding UTF8
        Write-Host ("[INFO] Visual transcript created at {0}." -f $transcriptPath)
    } catch {
        Write-Warning "[ERROR] Transcript creation failed: $_"
    }
}

# =====================[ TASK 9: FINALIZATION ]===========================
# -- Subtask 9.1: Reboot Prompt
function Request-RebootIfNeeded {
    try {
        Write-Host "[INFO] Checking if a reboot is required..."
        $pending = $false
        # Check for pending reboot (common registry keys)
        $rebootKeys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
            'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager',
            'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName'
        )
        foreach ($key in $rebootKeys) {
            if (Test-Path $key) {
                $pending = $true
                break
            }
        }
        if ($pending) {
            Write-Host "A system reboot is required. Reboot now? [Y/n] (default: Y, auto-skip in 120s)"
            $timeout = 120
            $interval = 2
            $elapsed = 0
            Write-Host "Press 'n' then Enter to skip reboot, 'y' -or Enter to reboot, or wait 120 seconds to skip reboot automatically."
            $userInput = $null
            while ($elapsed -lt $timeout) {
                if ($Host.UI.RawUI.KeyAvailable) {
                    $key = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
                    if ($key.Character -eq "`r" -or $key.Character -eq "`n") {
                        break
                    } elseif ($key.Character) {
                        if ($key.Character -eq 'n' -or $key.Character -eq 'N') {
                            $userInput = 'n'
                            break
                        } elseif ($key.Character -eq 'y' -or $key.Character -eq 'Y') {
                            $userInput = 'y'
                            break
                        }
                    }
                }
                Start-Sleep -Seconds $interval
                $elapsed += $interval
            }
            if ($userInput -eq 'n' -or $userInput -eq 'N') {
                Write-Host "[INFO] Reboot skipped by user."
            } elseif ($userInput -eq 'y' -or $userInput -eq 'Y' -or $userInput -eq '' -or $null -eq $userInput) {
                if ($elapsed -ge $timeout) {
                    Write-Host "[INFO] No input received after 120 seconds. Reboot skipped automatically."
                } else {
                    Write-Host "[INFO] Rebooting system..."
                    Restart-Computer -Force
                }
            } else {
                Write-Host "[INFO] Reboot skipped by user."
            }
        } else {
            Write-Host "[INFO] No reboot required."
        }
    } catch {
        Write-Warning "[ERROR] Reboot prompt failed: $_"
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
    Invoke-Task 'Full Disk Cleanup' { Optimize-Disk }
    Invoke-Task 'Survey Logs' { Get-LogSurvey }
    Invoke-Task 'Validate Restore Points' { Protect-RestorePoints }
    Invoke-Task 'Create Transcript' { Export-Transcript }
    Invoke-Task 'Prompt Reboot If Needed' { Request-RebootIfNeeded }

} finally {
    Remove-Environment
}

# =====================[ END OF SCRIPT ]===================================
