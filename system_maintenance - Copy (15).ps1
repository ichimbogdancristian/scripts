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
        $taskIndex++
        $Context.TaskName = ($Task.ToString() -replace 'function ', '').Trim()
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
    if ($Context.TempFolder -and (Test-Path $Context.TempFolder)) {
        Remove-Item -Path $Context.TempFolder -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log -Context $Context -Message "Temp folder deleted." -Level 'INFO'
    }
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
    $reset = "`e[0m"
    $color = switch ($Level) {
        'INFO'    { "`e[38;2;102;204;255m" }
        'SUCCESS' { "`e[38;2;0;200;83m" }
        'WARNING' { "`e[38;2;246;133;55m" }
        'ERROR'   { "`e[38;2;255;71;87m" }
        default   { "`e[38;2;255;255;255m" }
    }
    Write-Host "$color$entry$reset"
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

# =====================[ TASK 10: CLEANUP ]====================
function Invoke-Task10_Cleanup {
    param([hashtable]$Context)
    Write-Host "=====================[ TASK 10: CLEANUP ]===================="
    Write-Log -Context $Context -Message "=====================[ TASK 10: CLEANUP ]====================" -Level 'INFO'
    Write-TaskLog -Context $Context -Message "Task 10: Cleanup started." -Level 'INFO'
    Write-Log -Context $Context -Message "Task 10: Cleanup started." -Level 'INFO'
    $transcript = @()
    $startTime = Get-Date
    $transcript += "[{0}] [START] Cleanup Browser Data" -f ($startTime.ToString('HH:mm:ss'))
    try {
        Write-Log -Context $Context -Message "Cleaning browser cache and cookies..." -Level 'INFO'
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
        if ($totalProfiles -eq 0) { $totalProfiles = 1 } # Prevent division by zero
        $profileIdx = 0
        foreach ($userProfile in $userProfiles) {
            $profileIdx++
            Write-Host ("[Cleanup] Processing profile {0}/{1}: {2}" -f $profileIdx, $totalProfiles, $userProfile)
            $totalBrowsers = ($browsers | Measure-Object).Count
            if ($totalBrowsers -eq 0) { $totalBrowsers = 1 }
            $browserIdx = 0
            foreach ($browser in $browsers) {
                $browserIdx++
                $pathIdx = 0
                foreach ($relPath in $browser.Paths) {
                    $pathIdx++
                    $progressPercent = [int](($profileIdx / $totalProfiles) * 100)
                    Write-Progress -Activity "Browser Data Cleanup" -Status ("Profile {0}/{1}, {2} {3}/{4}, Path {5}" -f $profileIdx, $totalProfiles, $browser.Name, $browserIdx, $totalBrowsers, $relPath) -PercentComplete $progressPercent
                    $fullPath = Join-Path $userProfile $relPath
                    Write-Host ("[Cleanup] Checking {0} for {1}: {2}" -f $browser.Name, $userProfile, $fullPath)
                    if ($browser.Name -eq 'Firefox') {
                        if (Test-Path $fullPath) {
                            $firefoxProfiles = Get-ChildItem -Path $fullPath -Directory -ErrorAction SilentlyContinue
                            foreach ($ffProfile in $firefoxProfiles) {
                                $ffCachePath = Join-Path $ffProfile.FullName 'cache2'
                                $ffCookiesPath = Join-Path $ffProfile.FullName 'cookies.sqlite'
                                if (Test-Path $ffCachePath) {
                                    try {
                                        Write-Host ("[Cleanup] Removing Firefox cache: {0}" -f $ffCachePath)
                                        Remove-Item -Path $ffCachePath -Recurse -Force -ErrorAction Stop
                                        Write-Log -Context $Context -Message "Cleared Firefox cache: $ffCachePath" -Level 'SUCCESS'
                                    } catch {
                                        Write-Log -Context $Context -Message "Failed to clear Firefox cache: $ffCachePath - $_" -Level 'WARNING'
                                    }
                                }
                                if (Test-Path $ffCookiesPath) {
                                    try {
                                        Write-Host ("[Cleanup] Removing Firefox cookies: {0}" -f $ffCookiesPath)
                                        Remove-Item -Path $ffCookiesPath -Force -ErrorAction Stop
                                        Write-Log -Context $Context -Message "Cleared Firefox cookies: $ffCookiesPath" -Level 'SUCCESS'
                                    } catch {
                                        Write-Log -Context $Context -Message "Failed to clear Firefox cookies: $ffCookiesPath - $_" -Level 'WARNING'
                                    }
                                }
                            }
                        }
                    } else {
                        if (Test-Path $fullPath) {
                            try {
                                Write-Host ("[Cleanup] Removing {0} data: {1}" -f $browser.Name, $fullPath)
                                Remove-Item -Path $fullPath -Recurse -Force -ErrorAction Stop
                                Write-Log -Context $Context -Message "Cleared $($browser.Name) data: $fullPath" -Level 'SUCCESS'
                            } catch {
                                Write-Log -Context $Context -Message "Failed to clear $($browser.Name) data: $fullPath - $_" -Level 'WARNING'
                            }
                        }
                    }
                }
            }
        }
        Write-Progress -Activity "Browser Data Cleanup" -Status "Complete" -Completed
        Write-Host "[Cleanup] Browser cache and cookies cleanup complete."
        Write-Log -Context $Context -Message "Browser cache and cookies cleanup complete." -Level 'SUCCESS'
    } catch {
        Write-Log -Context $Context -Message "Task 10: Browser cleanup failed: $_" -Level 'ERROR'
    }
    try {
        # 1. Run built-in Disk Cleanup (cleanmgr) in silent mode for all options
        Write-TaskLog -Context $Context -Message "Running built-in Disk Cleanup (cleanmgr) in silent mode..." -Level 'INFO'
        Write-Log -Context $Context -Message "Running built-in Disk Cleanup (cleanmgr) in silent mode..." -Level 'INFO'
        $cleanmgrSageset = 99
        # Use Hidden window style for full silence
        Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sageset:$cleanmgrSageset" -WindowStyle Hidden -Wait
        Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:$cleanmgrSageset" -WindowStyle Hidden -Wait
        Write-TaskLog -Context $Context -Message "Disk Cleanup (cleanmgr) completed." -Level 'SUCCESS'
        Write-Log -Context $Context -Message "Disk Cleanup (cleanmgr) completed." -Level 'SUCCESS'
        $transcript += "[{0}] Disk Cleanup (cleanmgr) completed." -f ((Get-Date).ToString('HH:mm:ss'))

        # 2. Remove temp files from common and user locations
        $tempPaths = @(
            "$env:TEMP",
            "$env:TMP",
            "C:\\Windows\\Temp",
            (Join-Path $env:SystemDrive 'Temp'),
            "C:\\Windows\\Prefetch",
            "C:\\Windows\\Logs",
            "C:\\Windows\\SoftwareDistribution\\Download",
            "C:\\Windows\\System32\\LogFiles",
            "C:\\Windows\\System32\\spool\\PRINTERS",
            "C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Temp",
            "C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Temp"
        )
        $userProfiles = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object {
            try {
                $profilePath = (Get-ItemProperty $_.PsPath).ProfileImagePath
                if ($profilePath -and (Test-Path $profilePath)) { $profilePath }
            } catch {}
        } | Where-Object { $_ -and (Test-Path $_) }
        foreach ($userProfile in $userProfiles) {
            $tempPaths += (Join-Path $userProfile 'AppData\Local\Temp')
            $tempPaths += (Join-Path $userProfile 'AppData\Local\Microsoft\Windows\INetCache')
            $tempPaths += (Join-Path $userProfile 'AppData\Local\Microsoft\Windows\WebCache')
            $tempPaths += (Join-Path $userProfile 'AppData\Local\Microsoft\Windows\WER')
            $tempPaths += (Join-Path $userProfile 'AppData\Local\CrashDumps')
        }
        foreach ($path in $tempPaths | Sort-Object -Unique) {
            if (Test-Path $path) {
                try {
                    Write-Log -Context $Context -Message "Cleaning temp files in $path..." -Level 'INFO'
                    Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                    Write-Log -Context $Context -Message "Cleaned temp files in $path." -Level 'SUCCESS'
                    $transcript += ("[{0}] Cleaned temp files in {1}." -f ((Get-Date).ToString('HH:mm:ss'), $path))
                } catch {
                    Write-Log -Context $Context -Message ("Failed to clean $path $_") -Level 'WARNING'
                }
            }
        }

        # 3. Empty Recycle Bin for all drives
        try {
            Write-Log -Context $Context -Message "Emptying Recycle Bin..." -Level 'INFO'
            Clear-RecycleBin -Force -ErrorAction SilentlyContinue
            Write-Log -Context $Context -Message "Recycle Bin emptied." -Level 'SUCCESS'
            $transcript += "[{0}] Recycle Bin emptied." -f ((Get-Date).ToString('HH:mm:ss'))
        } catch {
            Write-Log -Context $Context -Message ("Failed to empty Recycle Bin: {0}" -f $_) -Level 'WARNING'
        }

        # 4. Clean Windows Update cache (SoftwareDistribution, Catroot2)
        $wuCache = "C:\\Windows\\SoftwareDistribution\\Download"
        $catroot2 = "C:\\Windows\\System32\\catroot2"
        foreach ($cachePath in @($wuCache, $catroot2)) {
            if (Test-Path $cachePath) {
                try {
                    Write-Log -Context $Context -Message "Cleaning $cachePath..." -Level 'INFO'
                    Get-ChildItem -Path $cachePath -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                    Write-Log -Context $Context -Message "$cachePath cleaned." -Level 'SUCCESS'
                    $transcript += "[{0}] $cachePath cleaned." -f ((Get-Date).ToString('HH:mm:ss'))
                } catch {
                    Write-Log -Context $Context -Message ("Failed to clean $cachePath $_") -Level 'WARNING'
                }
            }
        }

        # 5. Clean Delivery Optimization files
        $doCache = "C:\\Windows\\SoftwareDistribution\\DeliveryOptimization"
        if (Test-Path $doCache) {
            try {
                Get-ChildItem -Path $doCache -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                $transcript += "[{0}] Delivery Optimization cache cleaned." -f ((Get-Date).ToString('HH:mm:ss'))
            } catch {
                Write-Log -Context $Context -Message ("Failed to clean Delivery Optimization cache: $_") -Level 'WARNING'
            }
        }

        # 6. Clean browser caches (Edge, Chrome, Firefox)
        $browsers = @(
            @{ Name = 'Edge'; Paths = @('AppData\Local\Microsoft\Edge\User Data\Default\Cache', 'AppData\Local\Microsoft\Edge\User Data\Default\Code Cache', 'AppData\Local\Microsoft\Edge\User Data\Default\Service Worker\CacheStorage') },
            @{ Name = 'Chrome'; Paths = @('AppData\Local\Google\Chrome\User Data\Default\Cache', 'AppData\Local\Google\Chrome\User Data\Default\Code Cache', 'AppData\Local\Google\Chrome\User Data\Default\Service Worker\CacheStorage') },
            @{ Name = 'Firefox'; Paths = @('AppData\Local\Mozilla\Firefox\Profiles') }
        )
        foreach ($userProfile in $userProfiles) {
            foreach ($browser in $browsers) {
                foreach ($relPath in $browser.Paths) {
                    $fullPath = Join-Path $userProfile $relPath
                    if (Test-Path $fullPath) {
                        try {
                            Write-Log -Context $Context -Message "Cleaning $($browser.Name) cache in $fullPath..." -Level 'INFO'
                            Get-ChildItem -Path $fullPath -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                            Write-Log -Context $Context -Message "$($browser.Name) cache cleaned in $fullPath." -Level 'SUCCESS'
                            $transcript += ("[{0}] $($browser.Name) cache cleaned in {1}." -f ((Get-Date).ToString('HH:mm:ss'), $fullPath))
                        } catch {
                            Write-Log -Context $Context -Message ("Failed to clean $($browser.Name) cache in $fullPath $_") -Level 'WARNING'
                        }
                    }
                }
            }
        }

        # 7. Clean Windows Error Reporting dumps
        $werPaths = @(
            "C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue",
            "C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive"
        )
        foreach ($werPath in $werPaths) {
            if (Test-Path $werPath) {
                try {
                    Write-Log -Context $Context -Message "Cleaning WER dumps in $werPath..." -Level 'INFO'
                    Get-ChildItem -Path $werPath -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                    Write-Log -Context $Context -Message "WER dumps cleaned in $werPath." -Level 'SUCCESS'
                    $transcript += ("[{0}] WER dumps cleaned in {1}." -f ((Get-Date).ToString('HH:mm:ss'), $werPath))
                } catch {
                    Write-Log -Context $Context -Message ("Failed to clean WER dumps in $werPath ${_}") -Level 'WARNING'
                }
            }
        }

        # 8. Clean Windows Prefetch
        $prefetchPath = "C:\\Windows\\Prefetch"
        if (Test-Path $prefetchPath) {
            try {
                Write-Log -Context $Context -Message "Cleaning Prefetch..." -Level 'INFO'
                Get-ChildItem -Path $prefetchPath -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                Write-Log -Context $Context -Message "Prefetch cleaned." -Level 'SUCCESS'
                $transcript += ("[{0}] Prefetch cleaned." -f ((Get-Date).ToString('HH:mm:ss')))
            } catch {
                Write-Log -Context $Context -Message ("Failed to clean Prefetch: $_") -Level 'WARNING'
            }
        }

        Write-TaskLog -Context $Context -Message "Full disk cleanup completed." -Level 'SUCCESS'
        Write-Log -Context $Context -Message "Full disk cleanup completed." -Level 'SUCCESS'
        $transcript += "[{0}] [SUCCESS] Full Disk Cleanup completed." -f ((Get-Date).ToString('HH:mm:ss'))
    } catch {
        Write-TaskLog -Context $Context -Message ("Task 12: Full Disk Cleanup failed: $($_)") -Level 'ERROR'
        Write-Log -Context $Context -Message ("Task 12: Full Disk Cleanup failed: $($_)") -Level 'ERROR'
        $transcript += "[{0}] [ERROR] Full Disk Cleanup failed: $($_)" -f ((Get-Date).ToString('HH:mm:ss'))
    }
    $endTime = Get-Date
    $transcript += "[{0}] [END] Full Disk Cleanup" -f ($endTime.ToString('HH:mm:ss'))
    $outPath = Join-Path $Script:TempFolder 'Task12_FullDiskCleanup_log.txt'
    $transcript | Out-File $outPath -Encoding UTF8
}
# =====================[ END TASK 10 ]====================

# =====================[ TASK 13: GENERATE TRANSCRIPT HTML ]====================
function Invoke-Task13_GenerateTranscriptHtml {
    param([hashtable]$Context)
    Write-Host "=====================[ TASK 13: GENERATE TRANSCRIPT HTML ]===================="
    Write-Log -Context $Context -Message "=====================[ TASK 13: GENERATE TRANSCRIPT HTML ]====================" -Level 'INFO'
    Write-TaskLog -Context $Context -Message "Task 13: Generating comprehensive transcript HTML report..." -Level 'INFO'
    Write-Log -Context $Context -Message "Task 13: Generating comprehensive transcript HTML report..." -Level 'INFO'
    try {
        $tempFolder = $Context.TempFolder
        $logFiles = Get-ChildItem -Path $tempFolder -Filter '*_log.txt' -File -ErrorAction SilentlyContinue
        $htmlSections = @()
        foreach ($logFile in $logFiles) {
            $taskName = [System.IO.Path]::GetFileNameWithoutExtension($logFile.Name)
            $logContent = Get-Content $logFile.FullName -Raw
            $escapedContent = [System.Web.HttpUtility]::HtmlEncode($logContent) -replace "\r?\n", "<br>"
            $htmlSections += "<section><h2>$taskName</h2><pre>$escapedContent</pre></section>"
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
        Write-Log -Context $Context -Message ("Task 13: Failed to generate transcript HTML: $($_)") -Level 'ERROR'
        Write-TaskLog -Context $Context -Message ("Task 13: Failed to generate transcript HTML: $($_)") -Level 'ERROR'
    }
    try {
        if ($Context.TempFolder -and (Test-Path $Context.TempFolder)) {
            Remove-Item -Path $Context.TempFolder -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log -Context $Context -Message "Temp folder deleted after HTML transcript generation." -Level 'INFO'
        }
    } catch {
        Write-Log -Context $Context -Message ("Task 13: Failed to delete temp folder: $($_)") -Level 'WARNING'
    }
    Write-TaskLog -Context $Context -Message "Task 13 completed." -Level 'SUCCESS'
}
# =====================[ END TASK 13 ]====================

# =====================[ TASK 14: CHECK AND PROMPT REBOOT ]====================
function Invoke-Task14_CheckAndPromptReboot {
    param([hashtable]$Context)
    Write-Host "=====================[ TASK 14: CHECK AND PROMPT REBOOT ]===================="
    Write-Log -Context $Context -Message "=====================[ TASK 14: CHECK AND PROMPT REBOOT ]====================" -Level 'INFO'
    Write-TaskLog -Context $Context -Message "Task 14: Checking if reboot is required..." -Level 'INFO'
    Write-Log -Context $Context -Message "Task 14: Checking if reboot is required..." -Level 'INFO'
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
        Write-Log -Context $Context -Message "Task 14: Failed to check reboot status: $_" -Level 'WARNING'
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
    Write-TaskLog -Context $Context -Message "Task 14 completed." -Level 'SUCCESS'
}
# =====================[ END TASK 14 ]====================

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
    ${function:Invoke-Task10_Cleanup},
    ${function:Invoke-Task11_LoggingAndRestorePoints},
    ${function:Invoke-Task12_FullDiskCleanup},
    ${function:Invoke-Task13_GenerateTranscriptHtml},
    ${function:Invoke-Task14_CheckAndPromptReboot}
)

Invoke-SystemMaintenancePolicy -Tasks $AllTasks

# =====================[ FINALIZATION ]==================================
