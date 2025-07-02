# =====================[ SYSTEM MAINTENANCE POLICY CONTROLLER ]====================
# All tasks must:
# - Accept a [hashtable]$Context parameter for shared state and logging
# - Use Write-Log -Context $Context for all logging
# - Be robust, modular, and not rely on global variables
# - Handle errors with try/catch and log failures
# - Not exit or break the main script flow (let the controller handle task order)
# - Clean up any temp files they create in $Context.TempFolder if needed
#
# The controller will:
# - Initialize $Context and environment
# - Run all tasks in order, passing $Context
# - Log all errors and successes
# - Remove environment at the end
#
# =====================[ END POLICY CONTROLLER HEADER ]====================

function Invoke-SystemMaintenancePolicy {
    param(
        [ScriptBlock[]]$Tasks
    )
    $Context = @{}
    Initialize-Environment -Context $Context
    $taskIndex = 0
    foreach ($Task in $Tasks) {
        # Skip null or empty tasks
        if (-not $Task) {
            Write-Host "Skipping null/empty task at index $($taskIndex + 1)"
            continue
        }
        
        $taskIndex++
        try {
            $Context.TaskName = ($Task.ToString() -replace 'function ', '').Trim()
        } catch {
            $Context.TaskName = "UnknownTask$taskIndex"
            Write-Host "Warning: Could not determine task name for task $taskIndex, using $($Context.TaskName)"
        }
        $Context.TaskLogPath = Join-Path $Context.TempFolder ("Task${taskIndex}_${Context.TaskName}_log.txt")
        try {
            Write-TaskLog -Context $Context -Message "Starting $($Context.TaskName)" -Level 'INFO'
            & $Task -Context $Context
            Write-TaskLog -Context $Context -Message "$($Context.TaskName) completed successfully." -Level 'SUCCESS'
        } catch {
            Write-TaskLog -Context $Context -Message "Task failed: $_" -Level 'ERROR'
        }
    }
    Remove-Environment -Context $Context
}

# =====================[ INITIALIZATION & CLEANUP ]====================
function Initialize-Environment {
    param([hashtable]$Context)
    $Context.TempFolder = Join-Path $PSScriptRoot "SystemMaintenance_$(Get-Random)"
    if (-not (Test-Path $Context.TempFolder)) {
        New-Item -ItemType Directory -Path $Context.TempFolder -Force | Out-Null
    }
    $Context.LogPath = Join-Path $Context.TempFolder 'SystemMaintenance.log'
    Start-Transcript -Path (Join-Path $Context.TempFolder 'transcript_log.txt') -Append
    Write-Log -Context $Context -Message "Temp folder created: $($Context.TempFolder)" -Level 'INFO'
}

function Remove-Environment {
    param([hashtable]$Context)
    Stop-Transcript | Out-Null
}

# =====================[ LOGGING SYSTEM ]====================
function Write-Log {
    param(
        [hashtable]$Context,
        [string]$Message,
        [ValidateSet('INFO','WARNING','ERROR','SUCCESS')]
        [string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "[$timestamp] [$Level] $Message"
    $logPath = $Context.LogPath
    Add-Content -Path $logPath -Value $entry -Encoding UTF8
    
    # Enhanced color compatibility for different PowerShell versions and terminals
    $colorMap = @{
        'INFO'    = @{ Color = 'Cyan'; Fallback = 'White' }
        'SUCCESS' = @{ Color = 'Green'; Fallback = 'White' }
        'WARNING' = @{ Color = 'Yellow'; Fallback = 'White' }
        'ERROR'   = @{ Color = 'Red'; Fallback = 'White' }
    }
    
    $selectedColor = $colorMap[$Level]
    if (-not $selectedColor) {
        $selectedColor = @{ Color = 'White'; Fallback = 'White' }
    }
    
    # Check if advanced color support is available (PowerShell 7+ or modern Windows Terminal)
    $supportsAdvancedColors = $false
    try {
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $supportsAdvancedColors = $true
        } elseif ($Host.Name -eq 'ConsoleHost' -and [Environment]::OSVersion.Version.Major -ge 10) {
            # Windows 10+ with Windows PowerShell might support ANSI
            $supportsAdvancedColors = $true
        }
    } catch {
        $supportsAdvancedColors = $false
    }
    
    if ($supportsAdvancedColors) {
        # Use ANSI escape sequences for rich colors
        $reset = "`e[0m"
        $ansiColor = switch ($Level) {
            'INFO'    { "`e[38;2;102;204;255m" }  # Light blue
            'SUCCESS' { "`e[38;2;0;200;83m" }     # Green
            'WARNING' { "`e[38;2;246;133;55m" }   # Orange
            'ERROR'   { "`e[38;2;255;71;87m" }    # Red
            default   { "`e[38;2;255;255;255m" }  # White
        }
        Write-Host "$ansiColor$entry$reset"
    } else {
        # Fallback to basic PowerShell colors for compatibility
        try {
            Write-Host $entry -ForegroundColor $selectedColor.Color
        } catch {
            # Ultimate fallback if even basic colors fail
            Write-Host $entry -ForegroundColor $selectedColor.Fallback
        }
    }
}

function Write-TaskLog {
    param(
        [hashtable]$Context,
        [string]$Message,
        [ValidateSet('INFO','WARNING','ERROR','SUCCESS')]
        [string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "[$timestamp] [$Level] [$($Context.TaskName)] $Message"
    Add-Content -Path $Context.TaskLogPath -Value $entry -Encoding UTF8
}

# =====================[ MODULAR TASKS ]====================
# =====================[ TASK 1: CENTRAL COORDINATION POLICY ]====================
function Invoke-Task1_CentralCoordinationPolicy {
    param([hashtable]$Context)
    Write-Host "=====================[ TASK 1: CENTRAL COORDINATION POLICY ]===================="
    Write-Log -Context $Context -Message "=====================[ TASK 1: CENTRAL COORDINATION POLICY ]====================" -Level 'INFO'
    Write-TaskLog -Context $Context -Message "Task 1: Central Coordination Policy enforced." -Level 'INFO'
    Write-Log -Context $Context -Message "Task 1: Central Coordination Policy enforced." -Level 'INFO'
    # --- Centralized Temp Folder Creation ---
    $Script:TempFolder = Join-Path $PSScriptRoot "SystemMaintenance_$(Get-Random)"
    if (-not (Test-Path $Script:TempFolder)) {
        New-Item -ItemType Directory -Path $Script:TempFolder -Force | Out-Null
    }
    # --- Centralized Error Log and Task Report Path ---
    $Script:ErrorLogPath = Join-Path $Script:TempFolder "SystemMaintenance_ErrorLog.txt"
    $Script:TaskReportPath = Join-Path $Script:TempFolder "SystemMaintenance_TaskReport.txt"
    # --- Unified and Unique Bloatware List ---
    $Script:BloatwareList = @('Acer.AcerCollection', 'Acer.AcerConfigurationManager', 'Acer.AcerPortal',
'Acer.AcerPowerManagement', 'Acer.AcerQuickAccess', 'Acer.AcerUEIPFramework', 'Acer.AcerUserExperienceImprovementProgram',
'Adobe.AdobeCreativeCloud', 'Adobe.AdobeExpress', 'Adobe.AdobeGenuineService', 'Amazon.AmazonPrimeVideo',
'ASUS.ASUSGiftBox', 'ASUS.ASUSLiveUpdate', 'ASUS.ASUSSplendidVideoEnhancementTechnology', 'ASUS.ASUSWebStorage',
'ASUS.ASUSZenAnywhere', 'ASUS.ASUSZenLink', 'Astian.Midori', 'AvantBrowser.AvantBrowser', 'Avast.AvastFreeAntivirus',
'AVG.AVGAntiVirusFree', 'Avira.Avira', 'Baidu.BaiduBrowser', 'Baidu.PCAppStore', 'Basilisk.Basilisk',
'Bitdefender.Bitdefender', 'Blisk.Blisk', 'Booking.com.Booking', 'BraveSoftware.BraveBrowser',
'CentBrowser.CentBrowser', 'Cliqz.Cliqz', 'Coowon.Coowon', 'CoolNovo.CoolNovo', 'CyberLink.MediaSuite',
'CyberLink.Power2Go', 'CyberLink.PowerDirector', 'CyberLink.PowerDVD', 'CyberLink.YouCam', 'Dell.CustomerConnect',
'Dell.DellDigitalDelivery', 'Dell.DellFoundationServices', 'Dell.DellHelpAndSupport', 'Dell.DellMobileConnect',
'Dell.DellPowerManager', 'Dell.DellProductRegistration', 'Dell.DellSupportAssist', 'Dell.DellUpdate',
'DigitalPersona.EpicPrivacyBrowser', 'Disney.DisneyPlus', 'Dooble.Dooble', 'DriverPack.DriverPackSolution',
'ESET.ESETNOD32Antivirus', 'Evernote.Evernote', 'ExpressVPN.ExpressVPN', 'Facebook.Facebook',
'FenrirInc.Sleipnir', 'FlashPeak.SlimBrowser', 'FlashPeak.Slimjet', 'Foxit.FoxitPDFReader',
'Gameloft.MarchofEmpires', 'G5Entertainment.HiddenCity', 'GhostBrowser.GhostBrowser', 'Google.YouTube',
'HP.HP3DDriveGuard', 'HP.HPAudioSwitch', 'HP.HPClientSecurityManager', 'HP.HPConnectionOptimizer',
'HP.HPDocumentation', 'HP.HPDropboxPlugin', 'HP.HPePrintSW', 'HP.HPJumpStart', 'HP.HPJumpStartApps',
'HP.HPJumpStartLaunch', 'HP.HPRegistrationService', 'HP.HPSupportSolutionsFramework', 'HP.HPSureConnect',
'HP.HPSystemEventUtility', 'HP.HPWelcome', 'HewlettPackard.SupportAssistant', 'Hulu.Hulu', 'Instagram.Instagram',
'IOBit.AdvancedSystemCare', 'IOBit.DriverBooster', 'KDE.Falkon', 'Kaspersky.Kaspersky', 'KeeperSecurity.Keeper',
'king.com.BubbleWitch', 'king.com.CandyCrush', 'king.com.CandyCrushFriends', 'king.com.CandyCrushSaga',
'king.com.CandyCrushSodaSaga', 'king.com.FarmHeroes', 'king.com.FarmHeroesSaga', 'Lenovo.AppExplorer',
'Lenovo.LenovoCompanion', 'Lenovo.LenovoExperienceImprovement', 'Lenovo.LenovoFamilyCloud',
'Lenovo.LenovoHotkeys', 'Lenovo.LenovoMigrationAssistant', 'Lenovo.LenovoModernIMController',
'Lenovo.LenovoServiceBridge', 'Lenovo.LenovoSolutionCenter', 'Lenovo.LenovoUtility', 'Lenovo.LenovoVantage',
'Lenovo.LenovoVoice', 'Lenovo.LenovoWiFiSecurity', 'LinkedIn.LinkedIn', 'Lunascape.Lunascape',
'Maxthon.Maxthon', 'McAfee.LiveSafe', 'McAfee.Livesafe', 'McAfee.SafeConnect', 'McAfee.Security',
'McAfee.WebAdvisor', 'Microsoft.3DBuilder', 'Microsoft.Advertising.Xaml', 'Microsoft.BingFinance',
'Microsoft.BingFoodAndDrink', 'Microsoft.BingHealthAndFitness', 'Microsoft.BingNews', 'Microsoft.BingSports',
'Microsoft.BingTravel', 'Microsoft.BingWeather', 'Microsoft.GetHelp', 'Microsoft.Getstarted',
'Microsoft.Microsoft3DViewer', 'Microsoft.MicrosoftOfficeHub', 'Microsoft.MicrosoftPowerBIForWindows',
'Microsoft.MicrosoftSolitaireCollection', 'Microsoft.MinecraftUWP', 'Microsoft.MixedReality.Portal',
'Microsoft.NetworkSpeedTest', 'Microsoft.News', 'Microsoft.Office.OneNote', 'Microsoft.Office.Sway',
'Microsoft.OneConnect', 'Microsoft.OneDrive', 'Microsoft.People', 'Microsoft.Print3D', 'Microsoft.ScreenSketch',
'Microsoft.SkypeApp', 'Microsoft.SoundRecorder', 'Microsoft.StickyNotes', 'Microsoft.Wallet',
'Microsoft.Whiteboard', 'Microsoft.WindowsFeedback', 'Microsoft.WindowsFeedbackHub', 'Microsoft.WindowsMaps',
'Microsoft.WindowsReadingList', 'Microsoft.WindowsSoundRecorder', 'Microsoft.Xbox.TCUI', 'Microsoft.XboxApp',
'Microsoft.XboxGameOverlay', 'Microsoft.XboxGamingOverlay', 'Microsoft.XboxIdentityProvider',
'Microsoft.XboxSpeechToTextOverlay', 'Microsoft.ZuneMusic', 'Microsoft.ZuneVideo', 'Mozilla.SeaMonkey',
'Norton.OnlineBackup', 'Norton.Security', 'Opera.Opera', 'Opera.OperaGX', 'Orbitum.Orbitum',
'OtterBrowser.OtterBrowser', 'PaleMoon.PaleMoon', 'PCAccelerate.PCAcceleratePro', 'PCOptimizer.PCOptimizerPro',
'PicsArt.PicsartPhotoStudio', 'Piriform.CCleaner', 'Polarity.Polarity', 'Power2Go.Power2Go',
'PowerDirector.PowerDirector', 'QupZilla.QupZilla', 'QuteBrowser.QuteBrowser', 'RandomSaladGamesLLC.SimpleSolitaire',
'Reimage.ReimageRepair', 'RoyalRevolt2.RoyalRevolt2', 'Sleipnir.Sleipnir', 'SlingTV.Sling',
'Sogou.SogouExplorer', 'Spotify.Spotify', 'SRWare.Iron', 'Sputnik.Sputnik', 'Superbird.Superbird',
'TheTorProject.TorBrowser', 'ThumbmunkeysLtd.PhototasticCollage', 'TikTok.TikTok', 'TorchMediaInc.Torch',
'TripAdvisor.TripAdvisor', 'Twitter.Twitter', 'UCWeb.UCBrowser', 'VivaldiTechnologies.Vivaldi',
'Waterfox.Waterfox', 'WildTangent.WildTangentGamesApp', 'WildTangent.WildTangentHelper', 'WPSOffice.WPSOffice',
'Yandex.YandexBrowser'

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
        @{ Name = 'Java 8 Update'; Winget = 'Oracle.JavaRuntimeEnvironment'; Choco = 'javaruntime' }
    )
    $essentialAppsListPath = Join-Path $Script:TempFolder 'EssentialApps_list.txt'
    $Script:EssentialApps | ForEach-Object { $_ | ConvertTo-Json -Compress } | Out-File $essentialAppsListPath -Encoding UTF8
}
# =====================[ END TASK 1 ]====================

# =====================[ TASK 2: SYSTEM PROTECTION ]====================
function Invoke-Task2_SystemProtection {
    param([hashtable]$Context)
    Write-Host "=====================[ TASK 2: SYSTEM PROTECTION ]===================="
    Write-Log -Context $Context -Message "=====================[ TASK 2: SYSTEM PROTECTION ]====================" -Level 'INFO'
    Write-TaskLog -Context $Context -Message "Task 2: System Protection started." -Level 'INFO'
    Write-Log -Context $Context -Message "Task 2: System Protection started." -Level 'INFO'
    $restoreEnabled = $false
    $osDrive = "C:"
    try {
        Write-Host "[System Protection] Checking if System Restore is enabled on $osDrive..."
        Write-Log -Context $Context -Message "Task 2: Checking if System Restore is enabled on $osDrive" -Level 'INFO'
        $srStatus = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        if ($srStatus) {
            $restoreEnabled = $true
            Write-Host "[System Protection] System Restore is already enabled."
            Write-Log -Context $Context -Message "System Restore is already enabled." -Level 'INFO'
        } else {
            Write-Host "[System Protection] Enabling System Restore on $osDrive..."
            Write-Log -Context $Context -Message "Enabling System Restore on $osDrive..." -Level 'INFO'
            Enable-ComputerRestore -Drive $osDrive -ErrorAction Stop
            $restoreEnabled = $true
            Write-Host "[System Protection] System Restore enabled."
            Write-Log -Context $Context -Message "System Restore enabled." -Level 'SUCCESS'
        }
        if ($restoreEnabled) {
            Write-Host "[System Protection] Creating a system restore point..."
            Write-Log -Context $Context -Message "Creating a system restore point..." -Level 'INFO'
            Checkpoint-Computer -Description "System Maintenance Script" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
            Write-Host "[System Protection] System restore point created."
            Write-Log -Context $Context -Message "System restore point created." -Level 'SUCCESS'
        } else {
            Write-Host "[System Protection] Could not enable System Restore on $osDrive."
            Write-Log -Context $Context -Message "Could not enable System Restore on $osDrive." -Level 'WARNING'
        }
    } catch {
        Write-Log -Context $Context -Message "Task 2: System Protection failed: $_" -Level 'ERROR'
    }
    Write-TaskLog -Context $Context -Message "Task 2 completed." -Level 'SUCCESS'
}
# =====================[ END TASK 2 ]====================

# =====================[ TASK 3: PACKAGE MANAGER SETUP ]====================
function Invoke-Task3_PackageManagerSetup {
    param([hashtable]$Context)
    Write-Host "=====================[ TASK 3: PACKAGE MANAGER SETUP ]===================="
    Write-Log -Context $Context -Message "=====================[ TASK 3: PACKAGE MANAGER SETUP ]====================" -Level 'INFO'
    Write-TaskLog -Context $Context -Message "Task 3: Package Manager Setup started." -Level 'INFO'
    Write-Log -Context $Context -Message "Task 3: Package Manager Setup started." -Level 'INFO'
    try {
        # --- Check and install winget ---
        $winget = Get-Command winget -ErrorAction SilentlyContinue
        if (-not $winget) {
            Write-Log -Context $Context -Message "winget not installed. Attempting installation..." -Level 'WARNING'
            try {
                $appInstallerUrl = "https://aka.ms/getwinget"
                $wingetInstaller = Join-Path $Context.TempFolder "AppInstaller.msixbundle"
                Invoke-WebRequest -Uri $appInstallerUrl -OutFile $wingetInstaller -UseBasicParsing
                Add-AppxPackage -Path $wingetInstaller
                Write-Log -Context $Context -Message "winget installed via App Installer package." -Level 'SUCCESS'
            } catch {
                Write-Log -Context $Context -Message "Failed to install winget: $_" -Level 'ERROR'
            }
        } else {
            Write-Log -Context $Context -Message "winget installed." -Level 'SUCCESS'
            # Try to update winget
            try {
                $updateResult = winget upgrade --id Microsoft.DesktopAppInstaller --accept-source-agreements --accept-package-agreements --silent -e 2>&1
                if ($updateResult -match 'No applicable update found' -or $updateResult -match 'No installed package found') {
                    Write-Log -Context $Context -Message "winget is up to date." -Level 'INFO'
                } elseif ($updateResult -match 'Successfully installed' -or $updateResult -match 'Successfully upgraded') {
                    Write-Log -Context $Context -Message "winget updated successfully." -Level 'SUCCESS'
                } else {
                    Write-Log -Context $Context -Message "winget update output: $updateResult" -Level 'INFO'
                }
            } catch {
                Write-Log -Context $Context -Message "Failed to update winget: $_" -Level 'WARNING'
            }
        }

        # --- Check and install Chocolatey ---
        $choco = Get-Command choco -ErrorAction SilentlyContinue
        if (-not $choco) {
            Write-Log -Context $Context -Message "Chocolatey not installed. Attempting installation..." -Level 'WARNING'
            try {
                Set-ExecutionPolicy Bypass -Scope Process -Force
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
                $chocoScript = 'Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString("https://community.chocolatey.org/install.ps1"))'
                powershell -NoProfile -ExecutionPolicy Bypass -Command $chocoScript
                Write-Log -Context $Context -Message "Chocolatey installed via official script." -Level 'SUCCESS'
            } catch {
                Write-Log -Context $Context -Message "Failed to install Chocolatey: $_" -Level 'ERROR'
            }
        } else {
            Write-Log -Context $Context -Message "Chocolatey installed." -Level 'SUCCESS'
            # Try to update Chocolatey
            try {
                $updateResult = choco upgrade chocolatey -y 2>&1
                if ($updateResult -match '0 upgrades' -or $updateResult -match 'Chocolatey v') {
                    Write-Log -Context $Context -Message "Chocolatey is up to date." -Level 'INFO'
                } elseif ($updateResult -match 'Upgraded') {
                    Write-Log -Context $Context -Message "Chocolatey updated successfully." -Level 'SUCCESS'
                } else {
                    Write-Log -Context $Context -Message "Chocolatey update output: $updateResult" -Level 'INFO'
                }
            } catch {
                Write-Log -Context $Context -Message "Failed to update Chocolatey: $_" -Level 'WARNING'
            }
        }
    } catch {
        Write-Log -Context $Context -Message "Task 3: Package manager check/installation failed: $_" -Level 'ERROR'
    }
    Write-TaskLog -Context $Context -Message "Task 3 completed." -Level 'SUCCESS'
}
# =====================[ END TASK 3 ]====================

# =====================[ TASK 4: SYSTEM INVENTORY ]====================
function Invoke-Task4_SystemInventory {
    param([hashtable]$Context)
    Write-Host "=====================[ TASK 4: SYSTEM INVENTORY ]===================="
    Write-Log -Context $Context -Message "=====================[ TASK 4: SYSTEM INVENTORY ]====================" -Level 'INFO'
    Write-TaskLog -Context $Context -Message "Task 4: System Inventory started." -Level 'INFO'
    Write-Log -Context $Context -Message "Task 4: System Inventory started." -Level 'INFO'
    try {
        $inventoryPath = Join-Path $Script:TempFolder 'inventory'
        New-Item -ItemType Directory -Path $inventoryPath -Force | Out-Null
        Write-Host "[System Inventory] Collecting OS info..."
        Write-Log -Context $Context -Message "Task 4: Collecting OS info..." -Level 'INFO'
        Get-ComputerInfo | Out-File (Join-Path $inventoryPath 'os_info.txt')
        Write-Host "[System Inventory] Collecting hardware info..."
        Write-Log -Context $Context -Message "Collecting hardware info..." -Level 'INFO'
        Get-WmiObject -Class Win32_ComputerSystem | Out-File (Join-Path $inventoryPath 'hardware_info.txt')
        Write-Host "[System Inventory] Collecting disk info..."
        Write-Log -Context $Context -Message "Collecting disk info..." -Level 'INFO'
        Get-PSDrive | Where-Object {$_.Provider -like '*FileSystem*'} | Out-File (Join-Path $inventoryPath 'disk_info.txt')
        Write-Host "[System Inventory] Collecting network info..."
        Write-Log -Context $Context -Message "Collecting network info..." -Level 'INFO'
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
        Write-Host "[System Inventory] Installed programs list saved to $installedProgramsPath"
        Write-Log -Context $Context -Message "Task 4: Inventory collected in $inventoryPath" -Level 'SUCCESS'
    } catch {
        Write-Log -Context $Context -Message "Task 4: System Inventory failed: $_" -Level 'ERROR'
    }
    Write-TaskLog -Context $Context -Message "Task 4 completed." -Level 'SUCCESS'
}
# =====================[ END TASK 4 ]====================

# =====================[ TASK 5: REMOVE BLOATWARE ]====================
function Invoke-Task5_RemoveBloatware {
    param([hashtable]$Context)
    Write-Host "=====================[ TASK 5: REMOVE BLOATWARE ]===================="
    Write-Log -Context $Context -Message "=====================[ TASK 5: REMOVE BLOATWARE ]====================" -Level 'INFO'
    Write-TaskLog -Context $Context -Message "Task 5: Remove Bloatware started." -Level 'INFO'
    Write-Log -Context $Context -Message "Task 5: Remove Bloatware started." -Level 'INFO'
    $removed = @()
    try {
        # --- Generate InstalledPrograms_list.txt at the start of Task 5 ---
        $installedProgramsDiffPath = Join-Path $Script:TempFolder 'InstalledPrograms_list.txt'
        $installedPrograms = @()
        $installedPrograms += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue
        $installedPrograms += Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue
        $installedPrograms += Get-AppxPackage -AllUsers | Select-Object -ExpandProperty Name
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            $wingetList = winget list --source winget | Select-Object -Skip 1
            $installedPrograms += $wingetList | ForEach-Object { $_.Split(' ')[0] }
        }
        $installedPrograms = $installedPrograms | Where-Object { $_ -and $_.Trim() -ne '' }
        $installedPrograms | ForEach-Object { $_ | ConvertTo-Json -Compress } | Out-File $installedProgramsDiffPath -Encoding UTF8

        # --- Compare to Bloatware_list.txt and create BloatwareDiff_list.txt ---
        Write-Log -Context $Context -Message "Scanning for bloatware apps to remove..." -Level 'INFO'
        $bloatwareListPath = Join-Path $Script:TempFolder 'Bloatware_list.txt'
        $bloatwareList = @()
        try {
            $bloatwareList = Get-Content $bloatwareListPath -Raw | ConvertFrom-Json
        } catch {
            $bloatwareList = Get-Content $bloatwareListPath | Where-Object { $_ -and $_.Trim() -ne '' } | ForEach-Object { $_ | ConvertFrom-Json }
        }
        $installed = @()
        try {
            $installed = Get-Content $installedProgramsDiffPath -Raw | ConvertFrom-Json
        } catch {
            $installed = Get-Content $installedProgramsDiffPath | Where-Object { $_ -and $_.Trim() -ne '' } | ForEach-Object { $_ | ConvertFrom-Json }
        }
        $bloatwareToRemove = @()
        foreach ($bloat in $bloatwareList) {
            if ($installed | Where-Object { $_.ToLower().Contains($bloat.ToLower()) }) {
                $bloatwareToRemove += $bloat
            }
        }
        $diffListPath = Join-Path $Script:TempFolder 'BloatwareDiff_list.txt'
        $bloatwareToRemove | ConvertTo-Json | Out-File $diffListPath -Encoding UTF8
        Write-Log -Context $Context -Message "Diff list created. Only installed bloatware will be processed. Diff list saved to $diffListPath" -Level 'INFO'
        Write-Log -Context $Context -Message ("Diff list contents: {0}" -f ($bloatwareToRemove -join ', ')) -Level 'INFO'

        # --- Robust bloatware mapping for special cases ---
        $BloatwareSpecialCases = @{
            'Clipchamp' = @{ AppX = 'Clipchamp.Clipchamp'; Winget = $null };
            'LinkedIn'  = @{ AppX = 'Microsoft.LinkedIn'; Winget = $null };
            'Vivaldi'   = @{ AppX = $null; Winget = 'VivaldiTechnologies.Vivaldi' };
        }
        foreach ($key in $BloatwareSpecialCases.Keys) {
            $case = $BloatwareSpecialCases[$key]
            if ($case.AppX) {
                $pkg = Get-AppxPackage -AllUsers | Where-Object { $_.Name -eq $case.AppX }
                if ($pkg) {
                    Write-Log -Context $Context -Message "Removing AppX package: $($case.AppX)" -Level 'INFO'
                    try {
                        Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                        Write-Log -Context $Context -Message "Removed AppX package: $($case.AppX)" -Level 'SUCCESS'
                    } catch {
                        Write-Log -Context $Context -Message "Failed to remove AppX package: $($case.AppX) - $_" -Level 'WARNING'
                    }
                }
            }
            if ($case.Winget -and (Get-Command winget -ErrorAction SilentlyContinue)) {
                $wingetResult = winget uninstall --id $($case.Winget) --exact --silent --accept-source-agreements --accept-package-agreements 2>&1
                if ($wingetResult -notmatch 'No installed package found') {
                    Write-Log -Context $Context -Message "Uninstalled via winget: $($case.Winget)" -Level 'SUCCESS'
                } else {
                    Write-Log -Context $Context -Message "Winget could not uninstall: $($case.Winget)" -Level 'WARNING'
                }
            }
        }

        $total = $bloatwareToRemove.Count
        $current = 0
        foreach ($bloat in $bloatwareToRemove) {
            $current++
            Write-Progress -Activity "Bloatware Removal" -Status ("Uninstalling: {0} ({1}/{2})" -f $bloat, $current, $total) -PercentComplete ([int](($current / $total) * 100))
            Write-Log -Context $Context -Message ("Uninstalling: {0} ({1}/{2})" -f $bloat, $current, $total) -Level 'INFO'
            $bloatMatches = $installed | Where-Object { $_ -and $_.ToLower().Contains($bloat.ToLower()) }
            foreach ($match in $bloatMatches) {
                $uninstallSuccess = $false
                $methodsTried = @()

                # 1. Try AppX removal (use robust mapping if available)
                if (-not $uninstallSuccess) {
                    $appxName = if ($BloatwareSpecialCases.ContainsKey($bloat) -and $BloatwareSpecialCases[$bloat].AppX) { $BloatwareSpecialCases[$bloat].AppX } else { $bloat }
                    $pkg = Get-AppxPackage -AllUsers | Where-Object { $_.Name -eq $appxName }
                    if ($pkg) {
                        $methodsTried += 'AppX'
                        try {
                            Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                            Write-Log -Context $Context -Message "Removed AppX package: $appxName" -Level 'SUCCESS'
                            $uninstallSuccess = $true
                        } catch {
                            Write-Log -Context $Context -Message ("Failed to remove AppX package: {0} - {1}" -f $appxName, $_) -Level 'WARNING'
                        }
                    }
                }

                # 2. Try winget uninstall
                if (-not $uninstallSuccess) {
                    $wingetId = if ($BloatwareSpecialCases.ContainsKey($bloat) -and $BloatwareSpecialCases[$bloat].Winget) { $BloatwareSpecialCases[$bloat].Winget } else { $match }
                    if ($wingetId -and (Get-Command winget -ErrorAction SilentlyContinue)) {
                        $methodsTried += 'winget'
                        try {
                            $wingetResult = winget uninstall --id "$wingetId" --exact --silent --accept-source-agreements --accept-package-agreements 2>&1
                            if ($wingetResult -notmatch 'No installed package found') {
                                Write-Log -Context $Context -Message "Uninstalled via winget: $wingetId" -Level 'SUCCESS'
                                $uninstallSuccess = $true
                            } else {
                                Write-Log -Context $Context -Message "Winget could not uninstall: $wingetId" -Level 'WARNING'
                            }
                        } catch {
                            Write-Log -Context $Context -Message ("winget uninstall failed for {0}: {1}" -f $wingetId, $_) -Level 'WARNING'
                        }
                    }
                }

                # 3. Try WMI uninstall
                if (-not $uninstallSuccess) {
                    $wmic = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -eq $match }
                    if ($wmic) {
                        $methodsTried += 'WMI'
                        try {
                            $wmic.Uninstall() | Out-Null
                            Write-Log -Context $Context -Message "Uninstalled via WMI: $match" -Level 'SUCCESS'
                            $uninstallSuccess = $true
                        } catch {
                            Write-Log -Context $Context -Message ("WMI uninstall failed for {0}: {1}" -f $match, $_) -Level 'WARNING'
                        }
                    }
                }

                # 4. Try Uninstall-Package (PowerShell PackageManagement)
                if (-not $uninstallSuccess -and (Get-Command Uninstall-Package -ErrorAction SilentlyContinue)) {
                    $methodsTried += 'Uninstall-Package'
                    try {
                        Uninstall-Package -Name $match -Force -ErrorAction Stop
                        Write-Log -Context $Context -Message "Uninstalled via Uninstall-Package: $match" -Level 'SUCCESS'
                        $uninstallSuccess = $true
                    } catch {
                        Write-Log -Context $Context -Message ("Uninstall-Package failed for {0}: {1}" -f $match, $_) -Level 'WARNING'
                    }
                }

                # 5. Try registry uninstall string
                if (-not $uninstallSuccess) {
                    $regPaths = @(
                        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
                    )
                    foreach ($regPath in $regPaths) {
                        $regApps = Get-ItemProperty $regPath -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.DisplayName -like "*$match*" }
                        foreach ($regApp in $regApps) {
                            if ($regApp.UninstallString) {
                                $methodsTried += 'RegistryString'
                                try {
                                    $uninstallCmd = $regApp.UninstallString
                                    if ($uninstallCmd -notmatch '/quiet|/silent') {
                                        $uninstallCmd += ' /quiet'
                                    }
                                    Write-Log -Context $Context -Message "Attempting registry uninstall: $uninstallCmd" -Level 'INFO'
                                    Start-Process -FilePath "cmd.exe" -ArgumentList "/c $uninstallCmd" -Wait -NoNewWindow
                                    Write-Log -Context $Context -Message "Uninstalled via registry string: $match" -Level 'SUCCESS'
                                    $uninstallSuccess = $true
                                } catch {
                                    Write-Log -Context $Context -Message ("Registry uninstall failed for {0}: {1}" -f $match, $_) -Level 'WARNING'
                                }
                            }
                        }
                    }
                }

                if ($uninstallSuccess) {
                    $removed += $match
                } else {
                    Write-Log -Context $Context -Message ("Could not uninstall {0} using any method. Methods tried: {1}" -f $match, ($methodsTried -join ', ')) -Level 'WARNING'
                }
            }
        }
        Write-Progress -Activity "Bloatware Removal" -Status "Complete" -Completed
        Write-Log -Context $Context -Message "Bloatware removal complete. Diff list saved to $diffListPath" -Level 'SUCCESS'
        # --- Delete InstalledPrograms_list.txt after removal ---
        if (Test-Path $installedProgramsDiffPath) {
            Remove-Item $installedProgramsDiffPath -Force
            Write-Log -Context $Context -Message "Deleted temp file: $installedProgramsDiffPath" -Level 'INFO'
        }
    } catch {
        Write-Log -Context $Context -Message "Task 5: Bloatware removal failed: $_" -Level 'ERROR'
    }
    Write-TaskLog -Context $Context -Message "Task 5 completed." -Level 'SUCCESS'
}
# =====================[ END TASK 5 ]====================

# =====================[ TASK 6: INSTALL ESSENTIAL APPLICATIONS ]====================
function Invoke-Task6_InstallEssentialApps {
    param([hashtable]$Context)
    Write-Host "=====================[ TASK 6: INSTALL ESSENTIAL APPLICATIONS ]===================="
    Write-Log -Context $Context -Message "=====================[ TASK 6: INSTALL ESSENTIAL APPLICATIONS ]====================" -Level 'INFO'
    Write-TaskLog -Context $Context -Message "Task 6: Install Essential Applications started." -Level 'INFO'
    Write-Log -Context $Context -Message "Task 6: Install Essential Applications started." -Level 'INFO'
    Write-Host "[Essential Apps] Checking installed programs and preparing list..."
    try {
        # --- Generate InstalledPrograms_list.txt at the start of Task 6 ---
        $installedProgramsDiffPath = Join-Path $Script:TempFolder 'InstalledPrograms_list.txt'
        $installedPrograms = @()
        $installedPrograms += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue
        $installedPrograms += Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue
        $installedPrograms += Get-AppxPackage -AllUsers | Select-Object -ExpandProperty Name
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            $wingetList = winget list --source winget | Select-Object -Skip 1
            $installedPrograms += $wingetList | ForEach-Object { $_.Split(' ')[0] }
        }
        $installedPrograms = $installedPrograms | Where-Object { $_ -and $_.Trim() -ne '' }
        $installedPrograms | ForEach-Object { $_ | ConvertTo-Json -Compress } | Out-File $installedProgramsDiffPath -Encoding UTF8

        $essentialAppsListPath = Join-Path $Script:TempFolder 'EssentialApps_list.txt'
        $essentialApps = Get-Content $essentialAppsListPath | ForEach-Object { $_ | ConvertFrom-Json }
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
                Write-Log -Context $Context -Message "LibreOffice added to essential apps list." -Level 'INFO'
            } else {
                Write-Log -Context $Context -Message "Microsoft Office is installed. Skipping LibreOffice installation." -Level 'INFO'
            }
        } else {
            Write-Log -Context $Context -Message "LibreOffice is already installed. Skipping." -Level 'INFO'
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
        Write-Host ("[Essential Apps] The following apps will be installed: {0}" -f ($appsToInstall | ForEach-Object { $_.Name } | Sort-Object |  Where-Object {$_} |  Out-String))
        Write-Log -Context $Context -Message "Diff list created. Only missing essential apps will be processed. Diff list saved to $diffListPath" -Level 'INFO'

        $essTotal = $appsToInstall.Count
        $essCurrent = 0
        foreach ($app in $appsToInstall) {
            $essCurrent++
            Write-Progress -Activity "Essential Apps Installation" -Status ("Installing: {0} ({1}/{2})" -f $app.Name, $essCurrent, $essTotal) -PercentComplete ([int](($essCurrent / $essTotal) * 100))
            Write-Host ("[Essential Apps] Installing {0} ({1}/{2})..." -f $app.Name, $essCurrent, $essTotal)
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
                            Write-Host ("[Essential Apps] Windows Installer is busy (exit code 1618) for {0}. Attempt {1}/{2}. Retrying in {3} seconds..." -f $app.Name, $retryCount, $maxRetries, $retryDelay)
                            Write-Log -Context $Context -Message "Windows Installer is busy (exit code 1618) for $($app.Name). Attempt $retryCount/$maxRetries. Retrying in $retryDelay seconds..." -Level 'WARNING'
                            Start-Sleep -Seconds $retryDelay
                            continue
                        }
                        $installedVia = 'winget'
                        $installSucceeded = $true
                        Write-Host ("[Essential Apps] Installed {0} via winget." -f $app.Name)
                    } catch {
                        Write-Host ("[Essential Apps] winget failed for {0}: {1}" -f $app.Name, $_)
                        Write-Log -Context $Context -Message "winget failed for $($app.Name): $_" -Level 'WARNING'
                    }
                }
                if (-not $installSucceeded -and $app.Choco -and (Get-Command choco -ErrorAction SilentlyContinue)) {
                    try {
                        $chocoResult = choco install $($app.Choco) -y 2>&1
                        if ($chocoResult -match '1618') {
                            Write-Host ("[Essential Apps] Windows Installer is busy (exit code 1618) for {0} via choco. Attempt {1}/{2}. Retrying in {3} seconds..." -f $app.Name, $retryCount, $maxRetries, $retryDelay)
                            Write-Log -Context $Context -Message "Windows Installer is busy (exit code 1618) for $($app.Name) via choco. Attempt $retryCount/$maxRetries. Retrying in $retryDelay seconds..." -Level 'WARNING'
                            Start-Sleep -Seconds $retryDelay
                            continue
                        }
                        $installedVia = 'choco'
                        $installSucceeded = $true
                        Write-Host ("[Essential Apps] Installed {0} via choco." -f $app.Name)
                    } catch {
                        Write-Host ("[Essential Apps] choco failed for {0}: {1}" -f $app.Name, $_)
                        Write-Log -Context $Context -Message "choco failed for $($app.Name): $_" -Level 'WARNING'
                    }
                }
                break
            }
            if ($installSucceeded -and $installedVia) {
                Write-Log -Context $Context -Message "Installed $($app.Name) via $installedVia." -Level 'SUCCESS'
            } elseif (-not $installSucceeded) {
                Write-Host ("[Essential Apps] Could not install {0} after {1} attempts due to Windows Installer being busy (exit code 1618). Skipping." -f $app.Name, $maxRetries)
                Write-Log -Context $Context -Message "Could not install $($app.Name) after $maxRetries attempts due to Windows Installer being busy (exit code 1618). Skipping." -Level 'ERROR'
            } elseif (-not $installedVia) {
                Write-Host ("[Essential Apps] Could not install {0} via winget or choco." -f $app.Name)
                Write-Log -Context $Context -Message "Could not install $($app.Name) via winget or choco." -Level 'ERROR'
            }
        }
        Write-Progress -Activity "Essential Apps Installation" -Status "All essential apps processed" -Completed
        Write-Host "[Essential Apps] Installation complete. See log for details."
        Write-Log -Context $Context -Message "Essential apps installation complete. Diff list saved to $diffListPath" -Level 'SUCCESS'
        # --- Delete InstalledPrograms_list.txt after installation ---
        if (Test-Path $installedProgramsDiffPath) {
            Remove-Item $installedProgramsDiffPath -Force
            Write-Log -Context $Context -Message "Deleted temp file: $installedProgramsDiffPath" -Level 'INFO'
        }
    } catch {
        Write-Host ("[Essential Apps] Task 6 failed: {0}" -f $_)
        Write-Log -Context $Context -Message "Task 6: Essential apps installation failed: $_" -Level 'ERROR'
    }
    Write-TaskLog -Context $Context -Message "Task 6 completed." -Level 'SUCCESS'
}
# =====================[ END TASK 6 ]====================

# =====================[ TASK 7: UPGRADE ALL PACKAGES ]====================
function Invoke-Task7_UpgradeAllPackages {
    param([hashtable]$Context)
    Write-Host "=====================[ TASK 7: UPGRADE ALL PACKAGES ]===================="
    Write-Log -Context $Context -Message "=====================[ TASK 7: UPGRADE ALL PACKAGES ]====================" -Level 'INFO'
    Write-TaskLog -Context $Context -Message "Task 7: Upgrade All Packages started." -Level 'INFO'
    Write-Log -Context $Context -Message "Task 7: Upgrade All Packages started." -Level 'INFO'
    $transcript = @()
    $transcript += "[{0}] [START] Upgrade All Packages" -f ((Get-Date).ToString('HH:mm:ss'))
    try {
        Write-Log -Context $Context -Message "Checking for upgradable packages via winget..." -Level 'INFO'
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            $wingetOutput = winget upgrade --source winget 2>&1 | Out-String
            $wingetList = @()
            $lines = $wingetOutput -split "`r?`n" | Where-Object { $_.Trim() -ne '' }
            # Find the header line (usually contains 'Name' and 'Id')
            $headerIndex = ($lines | Select-String -Pattern 'Name\s+Id\s+Version').LineNumber - 1
            if ($headerIndex -ge 0) {
                $dataLines = $lines[($headerIndex+2)..($lines.Count-1)]
                foreach ($line in $dataLines) {
                    # Split columns by two or more spaces
                    $cols = $line -split '\s{2,}'
                    if ($cols.Count -ge 4) {
                        $pkg = [PSCustomObject]@{
                            Name = $cols[0]
                            Id = $cols[1]
                            Version = $cols[2]
                            AvailableVersion = $cols[3]
                        }
                        $wingetList += $pkg
                    }
                }
            }
            if (-not $wingetList -or $wingetList.Count -eq 0) {
                Write-Log -Context $Context -Message "No upgradable packages found via winget." -Level 'INFO'
                $transcript += "[{0}] No upgradable packages found via winget." -f ((Get-Date).ToString('HH:mm:ss'))
            } else {
                Write-Log -Context $Context -Message "The following packages will be upgraded via winget:" -Level 'INFO'
                foreach ($pkgObj in $wingetList) {
                    Write-Log -Context $Context -Message ("  - {0} {1} (Current: {2}, Available: {3})" -f $pkgObj.Name, $pkgObj.Id, $pkgObj.Version, $pkgObj.AvailableVersion) -Level 'INFO'
                }
                $wingetTotal = $wingetList.Count
                $wingetCurrent = 0
                foreach ($pkgObj in $wingetList) {
                    $wingetCurrent++
                    Write-Progress -Activity "Winget Upgrade" -Status ("Upgrading: {0} ({1}/{2})" -f $pkgObj.Name, $wingetCurrent, $wingetTotal) -PercentComplete ([int](($wingetCurrent / $wingetTotal) * 100))
                    Write-Log -Context $Context -Message ("Upgrading {0} ({1}/{2})..." -f $pkgObj.Name, $wingetCurrent, $wingetTotal) -Level 'INFO'
                    $result = winget upgrade --id $pkgObj.Id --silent --accept-source-agreements --accept-package-agreements --include-unknown -e 2>&1
                    $transcript += $result
                    if ($result -match 'No applicable update found' -or $result -match 'No installed package found') {
                        Write-Log -Context $Context -Message ("No update found for {0}." -f $pkgObj.Name) -Level 'INFO'
                    } elseif ($result -match 'Successfully installed' -or $result -match 'Successfully upgraded') {
                        Write-Log -Context $Context -Message ("Successfully upgraded {0}." -f $pkgObj.Name) -Level 'SUCCESS'
                    } else {
                        Write-Log -Context $Context -Message ("Output for {0}: {1}" -f $pkgObj.Name, $result) -Level 'WARNING'
                    }
                }
                Write-Progress -Activity "Winget Upgrade" -Status "All packages processed" -Completed
                $transcript += "[{0}] All possible packages processed via winget." -f ((Get-Date).ToString('HH:mm:ss'))
            }
        } else {
            Write-Progress -Activity "Winget Upgrade" -Status "winget not found. Skipping." -Completed
            Write-Log -Context $Context -Message "winget not found. Skipping package upgrade." -Level 'WARNING'
            $transcript += "[{0}] [WARN] winget not found. Skipping package upgrade." -f ((Get-Date).ToString('HH:mm:ss'))
        }
        $transcript += "[{0}] [SUCCESS] Upgrade All Packages" -f ((Get-Date).ToString('HH:mm:ss'))
    } catch {
        Write-Log -Context $Context -Message ("Task 7 failed: {0}" -f $_) -Level 'ERROR'
        $transcript += "[{0}] [ERROR] Package upgrade failed: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $_
    }
    $endTime = Get-Date
    $transcript += "[{0}] [END] Upgrade All Packages" -f ($endTime.ToString('HH:mm:ss'))
    $outPath = Join-Path $Script:TempFolder 'Task7_UpgradeAllPackages_log.txt'
    $transcript | Out-File $outPath -Encoding UTF8
    Write-TaskLog -Context $Context -Message "Task 7 completed." -Level 'SUCCESS'
}
# =====================[ END TASK 7 ]====================

# =====================[ TASK 8: PRIVACY & TELEMETRY ]====================
function Invoke-Task8_PrivacyAndTelemetry {
    param([hashtable]$Context)
    Write-Host "=====================[ TASK 8: PRIVACY & TELEMETRY ]===================="
    Write-Log -Context $Context -Message "=====================[ TASK 8: PRIVACY & TELEMETRY ]====================" -Level 'INFO'
    Write-TaskLog -Context $Context -Message "Task 8: Privacy & Telemetry started." -Level 'INFO'
    Write-Log -Context $Context -Message "Task 8: Privacy & Telemetry started." -Level 'INFO'
    $transcript = @()
    $startTime = Get-Date
    $transcript += "[{0}] [START] Disable Telemetry & Privacy" -f ($startTime.ToString('HH:mm:ss'))
    try {
        $transcript += "[{0}] Applying privacy and telemetry hardening..." -f ((Get-Date).ToString('HH:mm:ss'))

        # 1. Disable Telemetry via Registry
        $regSettings = @(
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'AllowTelemetry'; Value = 0 },
            @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'; Name = 'AllowTelemetry'; Value = 0 },
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'EnableActivityFeed'; Value = 0 },
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'PublishUserActivities'; Value = 0 },
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'UploadUserActivities'; Value = 0 },
            @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo'; Name = 'Enabled'; Value = 0 },
            @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy'; Name = 'TailoredExperiencesWithDiagnosticDataEnabled'; Value = 0 },
            @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy'; Name = 'LetAppsAccessOtherDevices'; Value = 2 },
            @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'; Name = 'IsDeviceSearchHistoryEnabled'; Value = 0 },
            @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'; Name = 'IsCloudSearchEnabled'; Value = 0 },
            @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'; Name = 'SafeSearchMode'; Value = 0 },
            @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'; Name = 'IsMySearchHistoryEnabled'; Value = 0 },
            @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'; Name = 'IsCortanaEnabled'; Value = 0 },
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name = 'AllowCortana'; Value = 0 },
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name = 'ConnectedSearchUseWeb'; Value = 0 },
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name = 'ConnectedSearchUseWebOverMeteredConnections'; Value = 0 },
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name = 'AllowCloudSearch'; Value = 0 },
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'DisableCdp'; Value = 1 },
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'DisableCdpUserSvc'; Value = 1 },
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'DisableCdpUserSvc_Session1'; Value = 1 }
        )
        foreach ($reg in $regSettings) {
            if (-not (Test-Path $reg.Path)) { New-Item -Path $reg.Path -Force | Out-Null }
            Set-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value -Force
            $transcript += "[{0}] Set {1}={2} in {3}" -f ((Get-Date).ToString('HH:mm:ss')), $reg.Name, $reg.Value, $reg.Path
        }

        # 2. Disable Telemetry/Tracking Services
        $services = @(
            'DiagTrack', 'dmwappushservice', 'WMPNetworkSvc', 'XblGameSave', 'MapsBroker', 'WSearch', 'CDPUserSvc*', 'RetailDemo', 'PcaSvc', 'WerSvc', 'RemoteRegistry', 'TrkWks', 'Wecsvc', 'WbioSrvc', 'lfsvc', 'wisvc', 'WpnService', 'WpnUserService*', 'W32Time', 'Fax', 'HomeGroupListener', 'HomeGroupProvider', 'SharedAccess', 'NetTcpPortSharing', 'RemoteAccess', 'RemoteRegistry', 'SysMain', 'TabletInputService', 'WdiServiceHost', 'WdiSystemHost', 'WlanSvc', 'WwanSvc', 'WMPNetworkSvc', 'XboxGipSvc', 'XboxNetApiSvc'
        )
        foreach ($svc in $services) {
            $foundServices = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($foundServices) {
                foreach ($service in $foundServices) {
                    # Skip per-user services (names ending with _[alphanumeric])
                    if ($service.Name -match '_[a-zA-Z0-9]{4,}$') {
                        $transcript += "[{0}] Skipped per-user service: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $service.Name
                        continue
                    }
                    Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $service.Name -StartupType Disabled
                    $transcript += "[{0}] Disabled service: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $service.Name
                }
            }
        }

        # 3. Disable Privacy/Telemetry Scheduled Tasks
        $tasks = @(
            '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
            '\Microsoft\Windows\Autochk\Proxy',
            '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
            '\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask',
            '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
            '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector',
            '\Microsoft\Windows\Maintenance\WinSAT',
            '\Microsoft\Windows\Media Center\ActivateWindowsSearch',
            '\Microsoft\Windows\Media Center\ConfigureInternetTimeService',
            '\Microsoft\Windows\Media Center\DispatchRecoveryTasks',
            '\Microsoft\Windows\Media Center\ehDRMInit',
            '\Microsoft\Windows\Media Center\InstallPlayReady',
            '\Microsoft\Windows\Media Center\mcupdate',
            '\Microsoft\Windows\Media Center\MediaCenterRecoveryTask',
            '\Microsoft\Windows\Media Center\ObjectStoreRecoveryTask',
            '\Microsoft\Windows\Media Center\OCURActivate',
            '\Microsoft\Windows\Media Center\OCURDiscovery',
            '\Microsoft\Windows\Media Center\PBDADiscovery',
            '\Microsoft\Windows\Media Center\PBDADiscoveryW1',
            '\Microsoft\Windows\Media Center\PBDADiscoveryW2',
            '\Microsoft\Windows\Media Center\PvrRecoveryTask',
            '\Microsoft\Windows\Media Center\PvrScheduleTask',
            '\Microsoft\Windows\Media Center\RegisterSearch',
            '\Microsoft\Windows\Media Center\ReindexSearchRoot',
            '\Microsoft\Windows\Media Center\SqlLiteRecoveryTask',
            '\Microsoft\Windows\Media Center\UpdateRecordPath',
            '\Microsoft\Windows\Windows Error Reporting\QueueReporting',
            '\Microsoft\Windows\WindowsUpdate\Automatic App Update',
            '\Microsoft\Windows\WindowsUpdate\Scheduled Start',
            '\Microsoft\Windows\WindowsUpdate\sih',
            '\Microsoft\Windows\WindowsUpdate\sihboot'
        )
        foreach ($task in $tasks) {
            try {
                if (Get-ScheduledTask -TaskPath $task -ErrorAction SilentlyContinue) {
                    Disable-ScheduledTask -TaskPath $task -ErrorAction SilentlyContinue
                    $transcript += "[{0}] Disabled scheduled task: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $task
                }
            } catch {
                $transcript += "[{0}] [WARN] Could not disable scheduled task: {1} - {2}" -f ((Get-Date).ToString('HH:mm:ss')), $task, $_
            }
        }

        # 4. Disable Feedback, Advertising, Location, and Other Privacy Settings
        $privacyReg = @(
            @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo'; Name = 'Enabled'; Value = 0 },
            @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy'; Name = 'TailoredExperiencesWithDiagnosticDataEnabled'; Value = 0 },
            @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy'; Name = 'LetAppsAccessOtherDevices'; Value = 2 },
            @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'; Name = 'IsDeviceSearchHistoryEnabled'; Value = 0 },
            @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'; Name = 'IsCloudSearchEnabled'; Value = 0 },
            @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'; Name = 'SafeSearchMode'; Value = 0 },
            @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'; Name = 'IsMySearchHistoryEnabled'; Value = 0 },
            @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'; Name = 'IsCortanaEnabled'; Value = 0 }
        )
        foreach ($reg in $privacyReg) {
            if (-not (Test-Path $reg.Path)) { New-Item -Path $reg.Path -Force | Out-Null }
            Set-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value -Force
            $transcript += "[{0}] Set {1}={2} in {3}" -f ((Get-Date).ToString('HH:mm:ss')), $reg.Name, $reg.Value, $reg.Path
        }

        # 5. Disable WiFi Sense
        $wifiSensePath = 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config'
        if (-not (Test-Path $wifiSensePath)) { New-Item -Path $wifiSensePath -Force | Out-Null }
        Set-ItemProperty -Path $wifiSensePath -Name 'AutoConnectAllowedOEM' -Value 0 -Force
        $transcript += "[{0}] Disabled WiFi Sense AutoConnectAllowedOEM" -f ((Get-Date).ToString('HH:mm:ss'))

        # 6. Disable Location Tracking
        $locPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
        if (-not (Test-Path $locPath)) { New-Item -Path $locPath -Force | Out-Null }
        Set-ItemProperty -Path $locPath -Name 'Value' -Value 'Deny' -Force
        $transcript += "[{0}] Disabled location tracking (set to Deny)" -f ((Get-Date).ToString('HH:mm:ss'))

        # 7. Disable Cortana
        $cortanaPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
        if (-not (Test-Path $cortanaPath)) { New-Item -Path $cortanaPath -Force | Out-Null }
        Set-ItemProperty -Path $cortanaPath -Name 'AllowCortana' -Value 0 -Force
        $transcript += "[{0}] Disabled Cortana" -f ((Get-Date).ToString('HH:mm:ss'))

        Write-Log -Context $Context -Message "Telemetry and privacy settings configured." -Level 'SUCCESS'
    } catch {
        Write-Log -Context $Context -Message ("Telemetry/privacy hardening failed: {0}" -f $_) -Level 'ERROR'
    }
    Write-TaskLog -Context $Context -Message "Task 8 completed." -Level 'SUCCESS'
}
# =====================[ END TASK 8 ]====================

# =====================[ TASK 9: WINDOWS UPDATE ]====================
function Invoke-Task9_WindowsUpdate {
    param([hashtable]$Context)
    Write-Host "=====================[ TASK 9: WINDOWS UPDATE ]===================="
    Write-Log -Context $Context -Message "=====================[ TASK 9: WINDOWS UPDATE ]====================" -Level 'INFO'
    Write-TaskLog -Context $Context -Message "Task 9: Windows Update started." -Level 'INFO'
    Write-Log -Context $Context -Message "Task 9: Windows Update started." -Level 'INFO'
    $transcript = @()
    $startTime = Get-Date
    $transcript += "[{0}] [START] Windows Update & Upgrade" -f ($startTime.ToString('HH:mm:ss'))
    try {
        Write-Log -Context $Context -Message "Checking and installing Windows updates..." -Level 'INFO'
        Write-Progress -Activity "Windows Update" -Status "Initializing..." -PercentComplete 0
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            try {
                Install-PackageProvider -Name NuGet -Force -Scope CurrentUser -ErrorAction SilentlyContinue
                Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber -ErrorAction SilentlyContinue
                $transcript += "[{0}] PSWindowsUpdate module installed." -f ((Get-Date).ToString('HH:mm:ss'))
            } catch {
                $transcript += "[{0}] [WARN] Could not install PSWindowsUpdate module: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $_
                Write-Log -Context $Context -Message ("Could not install PSWindowsUpdate module: {0}" -f $_) -Level 'WARNING'
            }
        }
        Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
        try {
            Write-Progress -Activity "Windows Update" -Status "Checking and installing updates..." -PercentComplete 50
            Get-WindowsUpdate -AcceptAll -Install -AutoReboot -ErrorAction Stop
            $transcript += "[{0}] Windows Update completed." -f ((Get-Date).ToString('HH:mm:ss'))
            Write-Log -Context $Context -Message "Windows Update completed." -Level 'SUCCESS'
        } catch {
            $transcript += "[{0}] [WARN] Get-WindowsUpdate failed: {1}. Trying wuauclt..." -f ((Get-Date).ToString('HH:mm:ss')), $_
            Write-Progress -Activity "Windows Update" -Status "Triggering wuauclt..." -PercentComplete 80
            wuauclt /detectnow /updatenow
            $transcript += "[{0}] Triggered Windows Update via wuauclt. Please check Windows Update manually if needed." -f ((Get-Date).ToString('HH:mm:ss'))
            Write-Log -Context $Context -Message ("Get-WindowsUpdate failed: {0}. Triggered wuauclt." -f $_) -Level 'WARNING'
        }
        Write-Progress -Activity "Windows Update" -Status "Complete" -Completed
    } catch {
        Write-Log -Context $Context -Message ("Task 9: Windows Update & Upgrade failed: {0}" -f $_) -Level 'ERROR'
    }
    $endTime = Get-Date
    $transcript += "[{0}] [END] Windows Update & Upgrade" -f ($endTime.ToString('HH:mm:ss'))
    $outPath = Join-Path $Script:TempFolder 'Task9_UpdatesMaintenance_log.txt'
    $transcript | Out-File $outPath -Encoding UTF8
    Write-TaskLog -Context $Context -Message "Task 9 completed." -Level 'SUCCESS'
}
# =====================[ END TASK 9 ]====================

# =====================[ TASK 10: RESTORE POINT MANAGEMENT & FULL DISK CLEANUP ]====================
function Invoke-Task10_RestorePointAndDiskCleanup {
    param([hashtable]$Context)
    Write-Host "=====================[ TASK 10: RESTORE POINT MANAGEMENT & FULL DISK CLEANUP ]===================="
    Write-Log -Context $Context -Message "=====================[ TASK 10: RESTORE POINT MANAGEMENT & FULL DISK CLEANUP ]====================" -Level 'INFO'
    Write-TaskLog -Context $Context -Message "Task 10: Restore Point Management & Full Disk Cleanup started." -Level 'INFO'
    Write-Log -Context $Context -Message "Task 10: Restore Point Management & Full Disk Cleanup started." -Level 'INFO'
    
    try {
        # ========== PART 1: RESTORE POINT MANAGEMENT ==========
        Write-Log -Context $Context -Message "Starting restore point management..." -Level 'INFO'
        Write-TaskLog -Context $Context -Message "Phase 1: Restore Point Management" -Level 'INFO'
        
        # Get all restore points
        Write-Log -Context $Context -Message "Validating existing restore points..." -Level 'INFO'
        $allRestorePoints = Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Sort-Object CreationTime -Descending
        
        if (-not $allRestorePoints) {
            Write-Log -Context $Context -Message "No restore points found on the system." -Level 'WARNING'
            Write-TaskLog -Context $Context -Message "No restore points found on the system." -Level 'WARNING'
        } else {
            Write-Log -Context $Context -Message "Found $($allRestorePoints.Count) restore points total." -Level 'INFO'
            
            # Keep only the 5 most recent restore points
            $restorePointsToKeep = $allRestorePoints | Select-Object -First 5
            $restorePointsToDelete = $allRestorePoints | Select-Object -Skip 5
            
            # Log details of the 5 remaining restore points
            Write-Log -Context $Context -Message "Keeping the 5 most recent restore points:" -Level 'INFO'
            foreach ($rp in $restorePointsToKeep) {
                $rpDetails = "Sequence: $($rp.SequenceNumber), Date: $($rp.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')), Type: $($rp.RestorePointType), Description: $($rp.Description)"
                Write-Log -Context $Context -Message "  - $rpDetails" -Level 'INFO'
                Write-TaskLog -Context $Context -Message "Keeping restore point: $rpDetails" -Level 'INFO'
            }
            
            # Delete old restore points if any exist
            if ($restorePointsToDelete.Count -gt 0) {
                Write-Log -Context $Context -Message "Removing $($restorePointsToDelete.Count) old restore points..." -Level 'INFO'
                foreach ($rpToDelete in $restorePointsToDelete) {
                    try {
                        # Use vssadmin to delete specific restore points
                        $shadowCopies = Get-WmiObject -Class Win32_ShadowCopy | Where-Object { 
                            $_.InstallDate -eq $rpToDelete.CreationTime.ToString("yyyyMMddHHmmss.ffffff-000")
                        }
                        
                        foreach ($shadowCopy in $shadowCopies) {
                            $shadowCopy.Delete()
                            Write-Log -Context $Context -Message "Deleted old restore point: Sequence $($rpToDelete.SequenceNumber), Date: $($rpToDelete.CreationTime)" -Level 'SUCCESS'
                        }
                    } catch {
                        Write-Log -Context $Context -Message "Failed to delete restore point $($rpToDelete.SequenceNumber): $_" -Level 'WARNING'
                    }
                }
            } else {
                Write-Log -Context $Context -Message "No old restore points to remove. All restore points are within the keep limit." -Level 'INFO'
            }
            
            # Validate remaining restore points
            Write-Log -Context $Context -Message "Validating remaining restore points..." -Level 'INFO'
            $finalRestorePoints = Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Sort-Object CreationTime -Descending
            if ($finalRestorePoints) {
                Write-Log -Context $Context -Message "Validation complete. $($finalRestorePoints.Count) restore points remain on the system." -Level 'SUCCESS'
                
                # Create detailed summary for transcript
                $restorePointSummary = @()
                $restorePointSummary += "=== RESTORE POINT SUMMARY ==="
                $restorePointSummary += "Total restore points maintained: $($finalRestorePoints.Count)"
                $restorePointSummary += "Restore points details:"
                
                foreach ($rp in $finalRestorePoints) {
                    $ageInDays = [math]::Round((Get-Date).Subtract($rp.CreationTime).TotalDays, 1)
                    $restorePointSummary += "  $($rp.SequenceNumber). Created: $($rp.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')) ($ageInDays days ago)"
                    $restorePointSummary += "     Type: $($rp.RestorePointType) | Description: $($rp.Description)"
                }
                
                # Save summary to temp file for transcript
                $summaryPath = Join-Path $Context.TempFolder 'RestorePoint_Summary.txt'
                $restorePointSummary | Out-File $summaryPath -Encoding UTF8
                
                Write-Log -Context $Context -Message "Restore point summary saved to $summaryPath" -Level 'INFO'
                Write-TaskLog -Context $Context -Message "Restore point management completed successfully" -Level 'SUCCESS'
            }
        }
        
        # ========== PART 2: DISK CLEANUP ==========
        Write-Log -Context $Context -Message "Starting disk cleanup operations..." -Level 'INFO'
        Write-TaskLog -Context $Context -Message "Phase 2: Full Disk Cleanup" -Level 'INFO'
        
        # Get initial disk space
        $systemDrive = $env:SystemDrive
        $initialSpace = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $systemDrive }
        $initialFreeSpace = [math]::Round($initialSpace.FreeSpace / 1GB, 2)
        Write-Log -Context $Context -Message "Initial free space on $systemDrive`: $initialFreeSpace GB" -Level 'INFO'
        
        # 1. Windows Disk Cleanup using cleanmgr
        Write-Log -Context $Context -Message "Running Windows Disk Cleanup..." -Level 'INFO'
        try {
            # Create temporary cleanup configuration
            $cleanupConfig = @{
                'Active Setup Temp Folders' = '2'
                'BranchCache' = '2'
                'Content Indexer Cleaner' = '2'
                'Device Driver Packages' = '2'
                'Downloaded Program Files' = '2'
                'GameNewsFiles' = '2'
                'GameStatisticsFiles' = '2'
                'GameUpdateFiles' = '2'
                'Internet Cache Files' = '2'
                'Memory Dump Files' = '2'
                'Offline Pages Files' = '2'
                'Old ChkDsk Files' = '2'
                'Previous Installations' = '2'
                'Recycle Bin' = '2'
                'Service Pack Cleanup' = '2'
                'Setup Log Files' = '2'
                'System error memory dump files' = '2'
                'System error minidump files' = '2'
                'Temporary Files' = '2'
                'Temporary Setup Files' = '2'
                'Thumbnail Cache' = '2'
                'Update Cleanup' = '2'
                'Upgrade Discarded Files' = '2'
                'User file versions' = '2'
                'Windows Defender' = '2'
                'Windows Error Reporting Archive Files' = '2'
                'Windows Error Reporting Queue Files' = '2'
                'Windows Error Reporting System Archive Files' = '2'
                'Windows Error Reporting System Queue Files' = '2'
                'Windows ESD installation files' = '2'
                'Windows Upgrade Log Files' = '2'
            }
            
            # Apply cleanup configuration to registry
            $sagePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
            foreach ($item in $cleanupConfig.GetEnumerator()) {
                try {
                    $itemPath = Join-Path $sagePath $item.Key
                    if (Test-Path $itemPath) {
                        Set-ItemProperty -Path $itemPath -Name 'StateFlags0001' -Value $item.Value -Type DWord
                    }
                } catch {
                    Write-Log -Context $Context -Message "Failed to set cleanup config for '$($item.Key)': $_" -Level 'WARNING'
                }
            }
            
            # Run cleanmgr with our configuration
            Start-Process -FilePath 'cleanmgr.exe' -ArgumentList '/sagerun:1' -Wait -WindowStyle Hidden
            Write-Log -Context $Context -Message "Windows Disk Cleanup completed" -Level 'SUCCESS'
            Write-TaskLog -Context $Context -Message "Windows Disk Cleanup completed" -Level 'SUCCESS'
        } catch {
            Write-Log -Context $Context -Message "Windows Disk Cleanup failed: $_" -Level 'WARNING'
        }
        Write-Log -Context $Context -Message "Running Windows Disk Cleanup..." -Level 'INFO'
        try {
            # Create temporary cleanup configuration
            $cleanupConfig = @{
                'Active Setup Temp Folders' = '2'
                'BranchCache' = '2'
                'Content Indexer Cleaner' = '2'
                'Device Driver Packages' = '2'
                'Downloaded Program Files' = '2'
                'GameNewsFiles' = '2'
                'GameStatisticsFiles' = '2'
                'GameUpdateFiles' = '2'
                'Internet Cache Files' = '2'
                'Memory Dump Files' = '2'
                'Offline Pages Files' = '2'
                'Old ChkDsk Files' = '2'
                'Previous Installations' = '2'
                'Recycle Bin' = '2'
                'Service Pack Cleanup' = '2'
                'Setup Log Files' = '2'
                'System error memory dump files' = '2'
                'System error minidump files' = '2'
                'Temporary Files' = '2'
                'Temporary Setup Files' = '2'
                'Thumbnail Cache' = '2'
                'Update Cleanup' = '2'
                'Upgrade Discarded Files' = '2'
                'User file versions' = '2'
                'Windows Defender' = '2'
                'Windows Error Reporting Archive Files' = '2'
                'Windows Error Reporting Queue Files' = '2'
                'Windows Error Reporting System Archive Files' = '2'
                'Windows Error Reporting System Queue Files' = '2'
                'Windows ESD installation files' = '2'
                'Windows Upgrade Log Files' = '2'
            }
            
            # Apply cleanup configuration to registry
            $sagePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
            foreach ($item in $cleanupConfig.GetEnumerator()) {
                try {
                    $itemPath = Join-Path $sagePath $item.Key
                    if (Test-Path $itemPath) {
                        Set-ItemProperty -Path $itemPath -Name 'StateFlags0001' -Value $item.Value -Type DWord
                    }
                } catch {
                    Write-Log -Context $Context -Message "Failed to set cleanup config for '$($item.Key)': $_" -Level 'WARNING'
                }
            }
            
            # Run cleanmgr with our configuration
            Start-Process -FilePath 'cleanmgr.exe' -ArgumentList '/sagerun:1' -Wait -WindowStyle Hidden
            Write-Log -Context $Context -Message "Windows Disk Cleanup completed" -Level 'SUCCESS'
            Write-TaskLog -Context $Context -Message "Windows Disk Cleanup completed" -Level 'SUCCESS'
        } catch {
            Write-Log -Context $Context -Message "Windows Disk Cleanup failed: $_" -Level 'WARNING'
        }
        
        # 2. Clear browser caches and data
        Write-Log -Context $Context -Message "Clearing browser caches..." -Level 'INFO'
        
        # Chrome cleanup
        try {
            $chromePaths = @(
                "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache",
                "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache2",
                "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies",
                "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Web Data"
            )
            
            foreach ($path in $chromePaths) {
                if (Test-Path $path) {
                    try {
                        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                        Write-Log -Context $Context -Message "Cleared Chrome cache: $path" -Level 'SUCCESS'
                    } catch {
                        Write-Log -Context $Context -Message "Failed to clear Chrome cache: $path - $_" -Level 'WARNING'
                    }
                }
            }
            Write-TaskLog -Context $Context -Message "Chrome browser cache cleared" -Level 'SUCCESS'
        } catch {
            Write-Log -Context $Context -Message "Chrome cleanup failed: $_" -Level 'WARNING'
        }
        
        # Edge cleanup
        try {
            $edgePaths = @(
                "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache",
                "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cookies",
                "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Web Data"
            )
            
            foreach ($path in $edgePaths) {
                if (Test-Path $path) {
                    try {
                        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                        Write-Log -Context $Context -Message "Cleared Edge cache: $path" -Level 'SUCCESS'
                    } catch {
                        Write-Log -Context $Context -Message "Failed to clear Edge cache: $path - $_" -Level 'WARNING'
                    }
                }
            }
            Write-TaskLog -Context $Context -Message "Microsoft Edge browser cache cleared" -Level 'SUCCESS'
        } catch {
            Write-Log -Context $Context -Message "Edge cleanup failed: $_" -Level 'WARNING'
        }
        
        # Firefox cleanup
        try {
            $firefoxProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
            if (Test-Path $firefoxProfilePath) {
                $firefoxProfiles = Get-ChildItem -Path $firefoxProfilePath -Directory
                foreach ($currentFirefoxProfile in $firefoxProfiles) {
                    $cachePath = Join-Path $currentFirefoxProfile.FullName 'cache2'
                    if (Test-Path $cachePath) {
                        try {
                            Remove-Item -Path $cachePath -Recurse -Force -ErrorAction SilentlyContinue
                            Write-Log -Context $Context -Message "Cleared Firefox cache for profile: $($currentFirefoxProfile.Name)" -Level 'SUCCESS'
                        } catch {
                            Write-Log -Context $Context -Message "Failed to clear Firefox cache for profile $($currentFirefoxProfile.Name): $_" -Level 'WARNING'
                        }
                    }
                }
                Write-TaskLog -Context $Context -Message "Firefox browser cache cleared" -Level 'SUCCESS'
            }
        } catch {
            Write-Log -Context $Context -Message "Firefox cleanup failed: $_" -Level 'WARNING'
        }
        
        # 3. Clear system temporary files
        Write-Log -Context $Context -Message "Clearing system temporary files..." -Level 'INFO'
        
        $tempPaths = @(
            $env:TEMP,
            $env:TMP,
            "$env:SystemRoot\Temp",
            "$env:LOCALAPPDATA\Temp",
            "$env:SystemRoot\Prefetch"
        )
        
        foreach ($tempPath in $tempPaths) {
            if (Test-Path $tempPath) {
                try {
                    $tempFiles = Get-ChildItem -Path $tempPath -Force -ErrorAction SilentlyContinue
                    $fileCount = $tempFiles.Count
                    $tempFiles | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Log -Context $Context -Message "Cleared $fileCount items from: $tempPath" -Level 'SUCCESS'
                } catch {
                    Write-Log -Context $Context -Message "Failed to clear temp path: $tempPath - $_" -Level 'WARNING'
                }
            }
        }
        Write-TaskLog -Context $Context -Message "Temporary files cleanup completed" -Level 'SUCCESS'
        
        # 4. Clear Windows logs
        Write-Log -Context $Context -Message "Clearing Windows event logs..." -Level 'INFO'
        try {
            $logs = Get-WinEvent -ListLog * | Where-Object { $_.RecordCount -gt 0 -and $_.IsEnabled -eq $true }
            foreach ($log in $logs) {
                try {
                    [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($log.LogName)
                    Write-Log -Context $Context -Message "Cleared log: $($log.LogName)" -Level 'SUCCESS'
                } catch {
                    # Some logs cannot be cleared, this is expected
                    Write-Log -Context $Context -Message "Could not clear log: $($log.LogName)" -Level 'INFO'
                }
            }
            Write-TaskLog -Context $Context -Message "Windows event logs cleared" -Level 'SUCCESS'
        } catch {
            Write-Log -Context $Context -Message "Event log cleanup failed: $_" -Level 'WARNING'
        }
        
        # 5. Run Storage Sense if available
        Write-Log -Context $Context -Message "Running Storage Sense..." -Level 'INFO'
        try {
            # Check if Storage Sense is available
            $storageSenseRegPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense'
            if (Test-Path $storageSenseRegPath) {
                # Enable Storage Sense temporarily and run it
                Set-ItemProperty -Path $storageSenseRegPath -Name 'ConfigLastRunTime' -Value 0 -Type DWord -Force
                
                # Trigger Storage Sense via PowerShell
                $storageSenseResult = Start-Process -FilePath "powershell.exe" -ArgumentList "-Command", "Get-StorageHealthAction | Where-Object {`$_.HealthStatus -eq 'Warning'} | Invoke-StorageHealthAction" -Wait -PassThru -WindowStyle Hidden
                
                if ($storageSenseResult.ExitCode -eq 0) {
                    Write-Log -Context $Context -Message "Storage Sense executed successfully" -Level 'SUCCESS'
                    Write-TaskLog -Context $Context -Message "Storage Sense cleanup completed" -Level 'SUCCESS'
                } else {
                    Write-Log -Context $Context -Message "Storage Sense execution completed with warnings" -Level 'INFO'
                }
            } else {
                Write-Log -Context $Context -Message "Storage Sense not available on this system" -Level 'INFO'
            }
        } catch {
            Write-Log -Context $Context -Message "Storage Sense execution failed: $_" -Level 'WARNING'
        }
        
        # 6. Clean up Windows Update cache
        Write-Log -Context $Context -Message "Cleaning Windows Update cache..." -Level 'INFO'
        try {
            Stop-Service -Name 'wuauserv' -Force -ErrorAction SilentlyContinue
            Stop-Service -Name 'cryptSvc' -Force -ErrorAction SilentlyContinue
            Stop-Service -Name 'bits' -Force -ErrorAction SilentlyContinue
            Stop-Service -Name 'msiserver' -Force -ErrorAction SilentlyContinue
            
            $wuCachePath = "$env:SystemRoot\SoftwareDistribution\Download"
            if (Test-Path $wuCachePath) {
                Remove-Item -Path "$wuCachePath\*" -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log -Context $Context -Message "Windows Update cache cleared" -Level 'SUCCESS'
            }
            
            Start-Service -Name 'wuauserv' -ErrorAction SilentlyContinue
            Start-Service -Name 'cryptSvc' -ErrorAction SilentlyContinue
            Start-Service -Name 'bits' -ErrorAction SilentlyContinue
            Start-Service -Name 'msiserver' -ErrorAction SilentlyContinue
            
            Write-TaskLog -Context $Context -Message "Windows Update cache cleanup completed" -Level 'SUCCESS'
        } catch {
            Write-Log -Context $Context -Message "Windows Update cache cleanup failed: $_" -Level 'WARNING'
        }
        
        # 7. Calculate space recovered
        $finalSpace = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $systemDrive }
        $finalFreeSpace = [math]::Round($finalSpace.FreeSpace / 1GB, 2)
        $spaceRecovered = [math]::Round($finalFreeSpace - $initialFreeSpace, 2)
        
        Write-Log -Context $Context -Message "Final free space on $systemDrive`: $finalFreeSpace GB" -Level 'INFO'
        Write-Log -Context $Context -Message "Total space recovered: $spaceRecovered GB" -Level 'SUCCESS'
        Write-TaskLog -Context $Context -Message "Disk cleanup completed. Space recovered: $spaceRecovered GB" -Level 'SUCCESS'
        
        # Save cleanup summary
        $cleanupSummary = @()
        $cleanupSummary += "=== DISK CLEANUP SUMMARY ==="
        $cleanupSummary += "Initial free space: $initialFreeSpace GB"
        $cleanupSummary += "Final free space: $finalFreeSpace GB"
        $cleanupSummary += "Space recovered: $spaceRecovered GB"
        $cleanupSummary += "Cleanup operations performed:"
        $cleanupSummary += "- Windows Disk Cleanup (cleanmgr)"
        $cleanupSummary += "- Browser caches (Chrome, Edge, Firefox)"
        $cleanupSummary += "- System temporary files"
        $cleanupSummary += "- Windows event logs"
        $cleanupSummary += "- Storage Sense execution"
        $cleanupSummary += "- Windows Update cache"
        
        
        # Save combined cleanup summary including restore points
        $cleanupSummary = @()
        $cleanupSummary += "=== COMBINED MAINTENANCE SUMMARY ==="
        $cleanupSummary += "Initial free space: $initialFreeSpace GB"
        $cleanupSummary += "Final free space: $finalFreeSpace GB"
        $cleanupSummary += "Space recovered: $spaceRecovered GB"
        $cleanupSummary += ""
        $cleanupSummary += "Restore point management:"
        if ($finalRestorePoints) {
            $cleanupSummary += "- Validated and maintained $($finalRestorePoints.Count) restore points"
            $cleanupSummary += "- Deleted $($restorePointsToDelete.Count) old restore points"
        } else {
            $cleanupSummary += "- No restore points found on system"
        }
        $cleanupSummary += ""
        $cleanupSummary += "Disk cleanup operations performed:"
        $cleanupSummary += "- Windows Disk Cleanup (cleanmgr)"
        $cleanupSummary += "- Browser caches (Chrome, Edge, Firefox)"
        $cleanupSummary += "- System temporary files"
        $cleanupSummary += "- Windows event logs"
        $cleanupSummary += "- Storage Sense execution"
        $cleanupSummary += "- Windows Update cache"
        
        $summaryPath = Join-Path $Context.TempFolder 'CombinedMaintenance_Summary.txt'
        $cleanupSummary | Out-File $summaryPath -Encoding UTF8
        Write-Log -Context $Context -Message "Combined maintenance summary saved to $summaryPath" -Level 'INFO'
        
    } catch {
        Write-Log -Context $Context -Message "Task 10: Restore Point Management & Full Disk Cleanup failed: $_" -Level 'ERROR'
        Write-TaskLog -Context $Context -Message "Task 10: Restore Point Management & Full Disk Cleanup failed: $_" -Level 'ERROR'
    }
    
    Write-TaskLog -Context $Context -Message "Task 10 completed." -Level 'SUCCESS'
}
# =====================[ END TASK 10 ]====================

# =====================[ TASK 11: GENERATE TRANSCRIPT HTML ]====================
function Invoke-Task11_GenerateTranscriptHtml {
    param([hashtable]$Context)
    Write-Host "=====================[ TASK 11: GENERATE TRANSCRIPT HTML ]===================="
    Write-Log -Context $Context -Message "=====================[ TASK 11: GENERATE TRANSCRIPT HTML ]====================" -Level 'INFO'
    Write-TaskLog -Context $Context -Message "Task 11: Generating comprehensive transcript HTML report..." -Level 'INFO'
    Write-Log -Context $Context -Message "Task 11: Generating comprehensive transcript HTML report..." -Level 'INFO'
    try {
        $tempFolder = $Context.TempFolder
        $logFiles = Get-ChildItem -Path $tempFolder -Filter '*_log.txt' -File -ErrorAction SilentlyContinue
        $summaryFiles = Get-ChildItem -Path $tempFolder -Filter '*_Summary.txt' -File -ErrorAction SilentlyContinue
        $htmlSections = @()
        
        # Add log files
        foreach ($logFile in $logFiles) {
            $taskName = [System.IO.Path]::GetFileNameWithoutExtension($logFile.Name)
            $logContent = Get-Content $logFile.FullName -Raw
            $escapedContent = [System.Web.HttpUtility]::HtmlEncode($logContent) -replace "\r?\n", "<br>"
            $htmlSections += "<section><h2>$taskName</h2><pre>$escapedContent</pre></section>"
        }
        
        # Add summary files (restore points, disk cleanup, etc.)
        foreach ($summaryFile in $summaryFiles) {
            $summaryName = [System.IO.Path]::GetFileNameWithoutExtension($summaryFile.Name)
            $summaryContent = Get-Content $summaryFile.FullName -Raw
            $escapedContent = [System.Web.HttpUtility]::HtmlEncode($summaryContent) -replace "\r?\n", "<br>"
            $htmlSections += "<section><h2>$summaryName</h2><pre>$escapedContent</pre></section>"
        }
        $html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <title>System Maintenance Transcript</title>
    <style>
        body {
            background: #181a1b;
            color: #e8e6e3;
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 0;
            padding: 0 0 2em 0;
        }
        header {
            background: #23272e;
            color: #fff;
            padding: 1.5em 1em 1em 1em;
            text-align: center;
            box-shadow: 0 2px 8px #0008;
        }
        h1 {
            margin: 0 0 0.5em 0;
            font-size: 2.2em;
        }
        section {
            background: #23272e;
            margin: 2em auto;
            max-width: 900px;
            border-radius: 10px;
            box-shadow: 0 2px 8px #0006;
            padding: 1.5em;
        }
        h2 {
            color: #7ecfff;
            margin-top: 0;
        }
        pre {
            background: #181a1b;
            color: #e8e6e3;
            border-radius: 6px;
            padding: 1em;
            overflow-x: auto;
            font-size: 1em;
            line-height: 1.5;
        }
        @media (max-width: 600px) {
            section { padding: 1em; }
            pre { font-size: 0.95em; }
        }
    </style>
</head>
<body>
    <header>
        <h1>System Maintenance Transcript</h1>
        <p>Comprehensive log of all maintenance tasks</p>
    </header>
    $($htmlSections -join "`n")
</body>
</html>
"@
        # Save HTML in the actual script location
        $scriptPath = $MyInvocation.PSCommandPath
        $scriptDir = Split-Path -Parent $scriptPath
        $outPath = Join-Path $scriptDir 'SystemMaintenance_Transcript.html'
        $html | Set-Content -Path $outPath -Encoding UTF8
        Write-Log -Context $Context -Message "Transcript HTML report generated at $outPath" -Level 'SUCCESS'
        Write-TaskLog -Context $Context -Message "Transcript HTML report generated at $outPath" -Level 'SUCCESS'
    } catch {
        Write-Log -Context $Context -Message ("Task 11: Failed to generate transcript HTML: $($_)") -Level 'ERROR'
        Write-TaskLog -Context $Context -Message ("Task 11: Failed to generate transcript HTML: $($_)") -Level 'ERROR'
    }

    Write-TaskLog -Context $Context -Message "Task 11 completed." -Level 'SUCCESS'
}
# =====================[ END TASK 11 ]====================

# =====================[ TASK 12: CHECK AND PROMPT REBOOT ]====================
function Invoke-Task12_CheckAndPromptReboot {
    param([hashtable]$Context)
    Write-Host "=====================[ TASK 12: CHECK AND PROMPT REBOOT ]===================="
    Write-Log -Context $Context -Message "=====================[ TASK 12: CHECK AND PROMPT REBOOT ]====================" -Level 'INFO'
    Write-TaskLog -Context $Context -Message "Task 12: Checking if reboot is required..." -Level 'INFO'
    Write-Log -Context $Context -Message "Task 12: Checking if reboot is required..." -Level 'INFO'
    $rebootRequired = $false
    try {
        # Check for common reboot-required indicators
        $pendingFile = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        $pendingCBS = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        $pendingSession = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' # PendingFileRenameOperations
        if (Test-Path $pendingFile -ErrorAction SilentlyContinue) { $rebootRequired = $true }
        if (Test-Path $pendingCBS -ErrorAction SilentlyContinue) { $rebootRequired = $true }
        $pendingOps = (Get-ItemProperty -Path $pendingSession -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue)
        if ($pendingOps) { $rebootRequired = $true }
    } catch {
        Write-Log -Context $Context -Message "Task 12: Failed to check reboot status: $_" -Level 'WARNING'
    }
    if ($rebootRequired) {
        Write-Log -Context $Context -Message "A system reboot is required." -Level 'WARNING'
        Write-TaskLog -Context $Context -Message "A system reboot is required." -Level 'WARNING'
        Write-Host "\nA system reboot is required to complete maintenance."
        Write-Host "Press any key to restart now, or wait 120 seconds to skip."
        $timeout = 120
        $start = Get-Date
        $end = $start.AddSeconds($timeout)
        $inputReceived = $false
        while ((Get-Date) -lt $end) {
            if ($Host.UI.RawUI.KeyAvailable) {
                $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
                Write-Host "\nRestarting now..."
                Write-Log -Context $Context -Message "User accepted reboot prompt. Restarting now." -Level 'INFO'
                Restart-Computer -Force
                $inputReceived = $true
                break
            }
            Start-Sleep -Milliseconds 250
        }
        if (-not $inputReceived) {
            Write-Host "\nNo input received. Please restart your system manually."
            Write-Log -Context $Context -Message "No user input at reboot prompt. System should be restarted manually." -Level 'WARNING'
            Write-TaskLog -Context $Context -Message "No user input at reboot prompt. System should be restarted manually." -Level 'WARNING'
        }
    } else {
        Write-Log -Context $Context -Message "No reboot required." -Level 'SUCCESS'
        Write-TaskLog -Context $Context -Message "No reboot required." -Level 'SUCCESS'
    }
    Write-TaskLog -Context $Context -Message "Task 12 completed." -Level 'SUCCESS'
}
# =====================[ END TASK 12 ]====================

# =====================[ TASK REGISTRATION & EXECUTION ]====================
$AllTasks = @(
    ${function:Invoke-Task1_CentralCoordinationPolicy},
    ${function:Invoke-Task2_SystemProtection},
    ${function:Invoke-Task3_PackageManagerSetup},
    ${function:Invoke-Task4_SystemInventory},
    ${function:Invoke-Task5_RemoveBloatware},
    ${function:Invoke-Task6_InstallEssentialApps},
    ${function:Invoke-Task7_UpgradeAllPackages},
    ${function:Invoke-Task8_PrivacyAndTelemetry},
    ${function:Invoke-Task9_WindowsUpdate},
    ${function:Invoke-Task10_RestorePointAndDiskCleanup},
    ${function:Invoke-Task11_GenerateTranscriptHtml},
    ${function:Invoke-Task12_CheckAndPromptReboot}
)

Invoke-SystemMaintenancePolicy -Tasks $AllTasks

# =====================[ FINALIZATION ]==================================
