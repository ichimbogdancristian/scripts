# =====================[ LOGGING SYSTEM ]====================
function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet('INFO','WARNING','ERROR','SUCCESS')]
        [string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "[$timestamp] [$Level] $Message"
    $logPath = Join-Path $env:TEMP 'SystemMaintenance.log'
    Add-Content -Path $logPath -Value $entry -Encoding UTF8
    $color = switch ($Level) {
        'INFO'    { 'Cyan' }
        'SUCCESS' { 'Green' }
        'WARNING' { 'Yellow' }
        'ERROR'   { 'Red' }
        default   { 'White' }
    }
    Write-Host $entry -ForegroundColor $color
}

function Write-SectionHeader {
    param([string]$Title)
    $line = '=' * ($Title.Length + 10)
    Write-Host "`n$line" -ForegroundColor Magenta
    Write-Host ("     [ $Title ]     ") -ForegroundColor Magenta
    Write-Host $line -ForegroundColor Magenta
}

function Write-TaskHeader {
    param(
        [Parameter(Mandatory)]
        [string]$TaskTitle
    )
    $line = '=' * ([Math]::Max(40, $TaskTitle.Length + 20))
    Write-Host "`n$line" -ForegroundColor Magenta
    Write-Host ("     [ $TaskTitle ]     ") -ForegroundColor Magenta
    Write-Host $line -ForegroundColor Magenta
}

# =====================[ TASK 1: CENTRAL COORDINATION POLICY ]=====================
function Invoke-Task1_CentralCoordinationPolicy {
    Write-TaskHeader 'Task 1: Central Coordination Policy'
    Write-Log "Task 1: Central Coordination Policy enforced." 'INFO'
    # --- Centralized Temp Folder Creation ---
    $Script:TempFolder = Join-Path $env:TEMP "SystemMaintenance_$(Get-Random)"
    if (-not (Test-Path $Script:TempFolder)) {
        New-Item -ItemType Directory -Path $Script:TempFolder -Force | Out-Null
    }
    # --- Unified and Unique Bloatware List ---
    $Script:BloatwareList = @('Acer.AcerCollection',
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

# =====================[ GLOBALS & INITIALIZATION ]========================

# Global error log path
$Script:ErrorLogPath = Join-Path $env:TEMP "SystemMaintenance_ErrorLog.txt"
# Global task report path
$Script:TaskReportPath = Join-Path $env:TEMP "SystemMaintenance_TaskReport.txt"

# Admin rights check
function Test-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Log "This script must be run as Administrator. Exiting." 'ERROR'
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
    Write-Log "Temp folder created: $Script:TempFolder" 'INFO'
}

function Remove-Environment {
    Stop-Transcript | Out-Null
    Remove-Item -Path $Script:TempFolder -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log "Temp folder deleted." 'INFO'
}

# =====================[ ERROR HANDLING ]==================================

# Enhanced Invoke-Task with color, section headers, and summary
function Invoke-Task {
    param(
        [Parameter(Mandatory)]
        [string]$TaskName,
        [Parameter(Mandatory)]
        [scriptblock]$TaskScript
    )
    Write-Log "Starting $TaskName" 'INFO'
    try {
        & $TaskScript
        Write-Log "$TaskName completed successfully" 'SUCCESS'
    } catch {
        Write-Log "$TaskName failed: $_" 'ERROR'
    }
}

# =====================[ TASK 2: SYSTEM PROTECTION ]=====================
function Invoke-Task2_SystemProtection {
    Write-TaskHeader 'Task 2: System Protection'
    $restoreEnabled = $false
    $osDrive = "C:"
    Write-Log "Task 2: Checking if System Restore is enabled on $osDrive" 'INFO'
    $srStatus = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
    if ($srStatus) {
        $restoreEnabled = $true
        Write-Log "System Restore is already enabled." 'INFO'
    } else {
        Write-Log "Enabling System Restore on $osDrive..." 'INFO'
        Enable-ComputerRestore -Drive $osDrive -ErrorAction Stop
        $restoreEnabled = $true
        Write-Log "System Restore enabled." 'SUCCESS'
    }
    if ($restoreEnabled) {
        Write-Log "Creating a system restore point..." 'INFO'
        Checkpoint-Computer -Description "System Maintenance Script" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Log "System restore point created." 'SUCCESS'
    } else {
        Write-Log "Could not enable System Restore on $osDrive." 'WARNING'
    }
}

# =====================[ TASK 3: PACKAGE MANAGER SETUP ]==================
function Invoke-Task3_PackageManagerSetup {
    Write-TaskHeader 'Task 3: Package Manager Setup'
    Write-Log "Task 3: Package Manager Setup" 'INFO'
    try {
        $winget = Get-Command winget -ErrorAction SilentlyContinue
        if (-not $winget) {
            Write-Log "winget not found. Attempting to install..." 'INFO'
            Invoke-WebRequest -Uri "https://aka.ms/getwinget" -OutFile "$Script:TempFolder\AppInstaller.msixbundle" -UseBasicParsing
            Add-AppxPackage -Path "$Script:TempFolder\AppInstaller.msixbundle"
            Write-Log "winget installed." 'SUCCESS'
        } else {
            Write-Log "winget found. Upgrading winget..." 'INFO'
            winget upgrade --id Microsoft.Winget.Source --accept-source-agreements --accept-package-agreements --silent
            Write-Log "winget upgraded." 'SUCCESS'
        }
        $choco = Get-Command choco -ErrorAction SilentlyContinue
        if (-not $choco) {
            Write-Log "Chocolatey not found. Installing..." 'INFO'
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
            Write-Log "Chocolatey installed." 'SUCCESS'
        } else {
            Write-Log "Chocolatey found. Upgrading Chocolatey..." 'INFO'
            choco upgrade chocolatey -y
            Write-Log "Chocolatey upgraded." 'SUCCESS'
        }
        Write-Log "Task 3: Package Manager Setup completed successfully." 'SUCCESS'
    } catch {
        Write-Log "Task 3: Package manager check/installation failed: $_" 'ERROR'
    }
}

# =====================[ TASK 4: SYSTEM INVENTORY ]=======================
function Invoke-Task4_SystemInventory {
    Write-TaskHeader 'Task 4: System Inventory'
    $inventoryPath = Join-Path $Script:TempFolder 'inventory'
    New-Item -ItemType Directory -Path $inventoryPath -Force | Out-Null
    Write-Log "Task 4: Collecting OS info..." 'INFO'
    Get-ComputerInfo | Out-File (Join-Path $inventoryPath 'os_info.txt')
    Write-Log "Collecting hardware info..." 'INFO'
    Get-WmiObject -Class Win32_ComputerSystem | Out-File (Join-Path $inventoryPath 'hardware_info.txt')
    Write-Log "Collecting disk info..." 'INFO'
    Get-PSDrive | Where-Object {$_.Provider -like '*FileSystem*'} | Out-File (Join-Path $inventoryPath 'disk_info.txt')
    Write-Log "Collecting network info..." 'INFO'
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
    Write-Log "Task 4: Inventory collected in $inventoryPath" 'SUCCESS'
}

# =====================[ TASK 5: REMOVE BLOATWARE ]========================
function Invoke-Task5_RemoveBloatware {
    Write-TaskHeader 'Task 5: Remove Bloatware'
    # Remove Bloatware
    Write-Log "Task 5: Starting Remove Bloatware" 'INFO'
    $removed = @()
    try {
        Write-Log "Scanning for bloatware apps to remove..." 'INFO'
        $bloatwareListPath = Join-Path $Script:TempFolder 'Bloatware_list.txt'
        $bloatwareList = @()
        try {
            $bloatwareList = Get-Content $bloatwareListPath -Raw | ConvertFrom-Json
        } catch {
            $bloatwareList = Get-Content $bloatwareListPath | Where-Object { $_ -and $_.Trim() -ne '' } | ForEach-Object { $_ | ConvertFrom-Json }
        }
        $installedProgramsDiffPath = Join-Path $Script:TempFolder 'InstalledPrograms_list.txt'
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
        Write-Log "Diff list created. Only installed bloatware will be processed. Diff list saved to $diffListPath" 'INFO'
        Write-Log ("Diff list contents: {0}" -f ($bloatwareToRemove -join ', ')) 'INFO'

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
                    Write-Log "Removing AppX package: $($case.AppX)" 'INFO'
                    try {
                        Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                        Write-Log "Removed AppX package: $($case.AppX)" 'SUCCESS'
                    } catch {
                        Write-Log "Failed to remove AppX package: $($case.AppX) - $_" 'WARNING'
                    }
                }
            }
            if ($case.Winget -and (Get-Command winget -ErrorAction SilentlyContinue)) {
                $wingetResult = winget uninstall --id $($case.Winget) --exact --silent --accept-source-agreements --accept-package-agreements 2>&1
                if ($wingetResult -notmatch 'No installed package found') {
                    Write-Log "Uninstalled via winget: $($case.Winget)" 'SUCCESS'
                } else {
                    Write-Log "Winget could not uninstall: $($case.Winget)" 'WARNING'
                }
            }
        }

        $total = $bloatwareToRemove.Count
        $current = 0
        foreach ($bloat in $bloatwareToRemove) {
            $current++
            Write-Progress -Activity "Bloatware Removal" -Status ("Uninstalling: {0} ({1}/{2})" -f $bloat, $current, $total) -PercentComplete ([int](($current / $total) * 100))
            Write-Log ("Uninstalling: {0} ({1}/{2})" -f $bloat, $current, $total) 'INFO'
            $bloatMatches = $installed | Where-Object { $_ -and $_.ToLower().Contains($bloat.ToLower()) }
            foreach ($match in $bloatMatches) {
                $uninstallSuccess = $false
                $methodsTried = @()
                # 1. Try AppX removal (use robust mapping if available)
                $appxName = if ($BloatwareSpecialCases.ContainsKey($bloat) -and $BloatwareSpecialCases[$bloat].AppX) { $BloatwareSpecialCases[$bloat].AppX } else { $bloat }
                $pkg = Get-AppxPackage -AllUsers | Where-Object { $_.Name -eq $appxName }
                if ($pkg) {
                    $methodsTried += 'AppX'
                    try {
                        Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                        Write-Log "Removed AppX package: $appxName" 'SUCCESS'
                        $uninstallSuccess = $true
                    } catch {
                        Write-Log ("Failed to remove AppX package: {0} - {1}" -f $appxName, $_) 'WARNING'
                    }
                }
                # 2. Try winget uninstall (use robust mapping if available)
                $wingetId = if ($BloatwareSpecialCases.ContainsKey($bloat) -and $BloatwareSpecialCases[$bloat].Winget) { $BloatwareSpecialCases[$bloat].Winget } else { $match }
                if ($wingetId -and (Get-Command winget -ErrorAction SilentlyContinue)) {
                    $methodsTried += 'winget'
                    try {
                        $wingetResult = winget uninstall --id "$wingetId" --exact --silent --accept-source-agreements --accept-package-agreements 2>&1
                        if ($wingetResult -notmatch 'No installed package found') {
                            Write-Log "Uninstalled via winget: $wingetId" 'SUCCESS'
                            $uninstallSuccess = $true
                        } else {
                            Write-Log "Winget could not uninstall: $wingetId" 'WARNING'
                        }
                    } catch {
                        Write-Log ("winget uninstall failed for {0}: {1}" -f $wingetId, $_) 'WARNING'
                    }
                }
                # 3. Try WMI uninstall
                $wmic = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -eq $match }
                if ($wmic) {
                    $methodsTried += 'WMI'
                    try {
                        $wmic.Uninstall() | Out-Null
                        Write-Log "Uninstalled via WMI: $match" 'SUCCESS'
                        $uninstallSuccess = $true
                    } catch {
                        Write-Log ("WMI uninstall failed for {0}: {1}" -f $match, $_) 'WARNING'
                    }
                }
                # 4. Try Uninstall-Package (PowerShell PackageManagement)
                if (Get-Command Uninstall-Package -ErrorAction SilentlyContinue) {
                    $methodsTried += 'Uninstall-Package'
                    try {
                        Uninstall-Package -Name $match -Force -ErrorAction Stop
                        Write-Log "Uninstalled via Uninstall-Package: $match" 'SUCCESS'
                        $uninstallSuccess = $true
                    } catch {
                        Write-Log ("Uninstall-Package failed for {0}: {1}" -f $match, $_) 'WARNING'
                    }
                }
                # 5. Try registry uninstall string
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
                                Write-Log "Attempting registry uninstall: $uninstallCmd" 'INFO'
                                Start-Process -FilePath "cmd.exe" -ArgumentList "/c $uninstallCmd" -Wait -NoNewWindow
                                Write-Log "Uninstalled via registry string: $match" 'SUCCESS'
                                $uninstallSuccess = $true
                            } catch {
                                Write-Log ("Registry uninstall failed for {0}: {1}" -f $match, $_) 'WARNING'
                            }
                        }
                    }
                }
                if ($uninstallSuccess) {
                    $removed += $match
                } else {
                    Write-Log ("Could not uninstall {0} using any method. Methods tried: {1}" -f $match, ($methodsTried -join ', ')) 'WARNING'
                }
            }
        }
        Write-Progress -Activity "Bloatware Removal" -Status "Complete" -Completed
        Write-Log "Bloatware removal complete. Diff list saved to $diffListPath" 'SUCCESS'
    } catch {
        Write-Log "Task 5: Bloatware removal failed: $_" 'ERROR'
    }
}

# =====================[ TASK 6: INSTALL ESSENTIAL APPLICATIONS ]==========
function Invoke-Task6_InstallEssentialApps {
    Write-TaskHeader 'Task 6: Install Essential Applications'
    # Install Essential Apps
    Write-Log "Task 6: Starting Install Essential Apps" 'INFO'
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
                Write-Log "LibreOffice added to essential apps list." 'INFO'
            } else {
                Write-Log "Microsoft Office is installed. Skipping LibreOffice installation." 'INFO'
            }
        } else {
            Write-Log "LibreOffice is already installed. Skipping." 'INFO'
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
        Write-Log "Diff list created. Only missing essential apps will be processed. Diff list saved to $diffListPath" 'INFO'

        $essTotal = $appsToInstall.Count
        $essCurrent = 0
        foreach ($app in $appsToInstall) {
            $essCurrent++
            Write-Progress -Activity "Essential Apps Installation" -Status ("Installing: {0} ({1}/{2})" -f $app.Name, $essCurrent, $essTotal) -PercentComplete ([int](($essCurrent / $essTotal) * 100))
            Write-Log ("Installing {0}..." -f $app.Name) 'INFO'
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
                            Write-Log "Windows Installer is busy (exit code 1618) for $($app.Name). Attempt $retryCount/$maxRetries. Retrying in $retryDelay seconds..." 'WARNING'
                            Start-Sleep -Seconds $retryDelay
                            continue
                        }
                        $installedVia = 'winget'
                        $installSucceeded = $true
                    } catch {
                        Write-Log "winget failed for $($app.Name): $_" 'WARNING'
                    }
                }
                if (-not $installSucceeded -and $app.Choco -and (Get-Command choco -ErrorAction SilentlyContinue)) {
                    try {
                        $chocoResult = choco install $($app.Choco) -y 2>&1
                        if ($chocoResult -match '1618') {
                            Write-Log "Windows Installer is busy (exit code 1618) for $($app.Name) via choco. Attempt $retryCount/$maxRetries. Retrying in $retryDelay seconds..." 'WARNING'
                            Start-Sleep -Seconds $retryDelay
                            continue
                        }
                        $installedVia = 'choco'
                        $installSucceeded = $true
                    } catch {
                        Write-Log "choco failed for $($app.Name): $_" 'WARNING'
                    }
                }
                break
            }
            if ($installSucceeded -and $installedVia) {
                Write-Log "Installed $($app.Name) via $installedVia." 'SUCCESS'
            } elseif (-not $installSucceeded) {
                Write-Log "Could not install $($app.Name) after $maxRetries attempts due to Windows Installer being busy (exit code 1618). Skipping." 'ERROR'
            } elseif (-not $installedVia) {
                Write-Log "Could not install $($app.Name) via winget or choco." 'ERROR'
            }
        }
        Write-Progress -Activity "Essential Apps Installation" -Status "All essential apps processed" -Completed
        Write-Log "Essential apps installation complete. Diff list saved to $diffListPath" 'SUCCESS'
    } catch {
        Write-Log "Task 6: Essential apps installation failed: $_" 'ERROR'
    }
}

# =====================[ TASK 7: UPGRADE ALL PACKAGES ]====================
function Invoke-Task7_UpgradeAllPackages {
    Write-TaskHeader 'Task 7: Upgrade All Packages'
    $transcript = @()
    $startTime = Get-Date
    $transcript += "[{0}] [START] Upgrade All Packages" -f ($startTime.ToString('HH:mm:ss'))
    try {
        $transcript += "[{0}] Running: winget upgrade --all --include-unknown --accept-source-agreements --accept-package-agreements --silent" -f ((Get-Date).ToString('HH:mm:ss'))
        Write-Progress -Activity "Winget Upgrade" -Status "Upgrading all packages..." -PercentComplete 0
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            $output = winget upgrade --all --include-unknown --accept-source-agreements --accept-package-agreements --silent 2>&1
            $transcript += $output
            Write-Progress -Activity "Winget Upgrade" -Status "All packages processed" -Completed
            $transcript += "[{0}] All packages processed via winget." -f ((Get-Date).ToString('HH:mm:ss'))
            $transcript += "[{0}] [SUCCESS] Upgrade All Packages" -f ((Get-Date).ToString('HH:mm:ss'))
        } else {
            Write-Progress -Activity "Winget Upgrade" -Status "winget not found. Skipping." -Completed
            $transcript += "[{0}] [WARN] winget not found. Skipping package upgrade." -f ((Get-Date).ToString('HH:mm:ss'))
        }
    } catch {
        $transcript += "[{0}] [ERROR] Winget upgrade all failed: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $_
    }
    $endTime = Get-Date
    $transcript += "[{0}] [END] Upgrade All Packages" -f ($endTime.ToString('HH:mm:ss'))
    $outPath = Join-Path $Script:TempFolder 'Task7_UpgradeAllPackages_log.txt'
    $transcript | Out-File $outPath -Encoding UTF8
}

# =====================[ TASK 8: PRIVACY & TELEMETRY ]====================
function Invoke-Task8_PrivacyAndTelemetry {
    Write-TaskHeader 'Task 8: Privacy & Telemetry'
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

        Write-Log "Telemetry and privacy settings configured." 'SUCCESS'
    } catch {
        Write-Log "Telemetry/privacy hardening failed: $_" 'ERROR'
    }
}

# =====================[ TASK 9: WINDOWS UPDATE ]==========================
function Invoke-Task9_WindowsUpdate {
    Write-TaskHeader 'Task 9: Windows Update'
    $transcript = @()
    $startTime = Get-Date
    $transcript += "[{0}] [START] Windows Update & Upgrade" -f ($startTime.ToString('HH:mm:ss'))
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
        Write-Log "Task 9: Windows Update & Upgrade completed successfully." 'SUCCESS'
    } catch {
        Write-Log "Task 9: Windows Update & Upgrade failed: $_" 'ERROR'
    }
    $endTime = Get-Date
    $transcript += "[{0}] [END] Windows Update & Upgrade" -f ($endTime.ToString('HH:mm:ss'))
    $outPath = Join-Path $Script:TempFolder 'Task9_UpdatesMaintenance_log.txt'
    $transcript | Out-File $outPath -Encoding UTF8
}

# =====================[ TASK 10: CLEANUP ]===============================
function Invoke-Task10_Cleanup {
    Write-TaskHeader 'Task 10: Cleanup'
    $transcript = @()
    $startTime = Get-Date
    $transcript += "[{0}] [START] Cleanup Browser Data" -f ($startTime.ToString('HH:mm:ss'))
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
    } catch {
        $transcript += "[{0}] [ERROR] Browser data cleanup failed: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $_
    }
    $endTime = Get-Date
    $transcript += "[{0}] [END] Cleanup Browser Data" -f ($endTime.ToString('HH:mm:ss'))
    $outPath = Join-Path $Script:TempFolder 'Task10_Cleanup_log.txt'
    $transcript | Out-File $outPath -Encoding UTF8
}

    # -- Subtask 8.2: DNS CACHE CLEANUP (was 7.3)
function Clear-DnsCache {
    $transcript = @()
    $startTime = Get-Date
    $transcript += "[{0}] [START] Clear DNS Cache" -f ($startTime.ToString('HH:mm:ss'))
    try {
        $transcript += "[{0}] Clearing DNS client cache..." -f ((Get-Date).ToString('HH:mm:ss'))
        if (Get-Command Clear-DnsClientCache -ErrorAction SilentlyContinue) {
            Clear-DnsClientCache
            $transcript += "[{0}] DNS client cache cleared." -f ((Get-Date).ToString('HH:mm:ss'))
        } else {
            $transcript += "[{0}] [WARN] Clear-DnsClientCache cmdlet not available on this system. Skipping DNS cache cleanup." -f ((Get-Date).ToString('HH:mm:ss'))
        }
        $transcript += "[{0}] [SUCCESS] Clear DNS Cache" -f ((Get-Date).ToString('HH:mm:ss'))
    } catch {
        $transcript += "[{0}] [ERROR] DNS cache cleanup failed: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $_
    }
    $endTime = Get-Date
    $transcript += "[{0}] [END] Clear DNS Cache" -f ($endTime.ToString('HH:mm:ss'))
    $outPath = Join-Path $Script:TempFolder 'Task10_Cleanup_log.txt'
    $transcript | Out-File $outPath -Encoding UTF8 -Append
}

# =====================[ TASK 11: LOGGING & RESTORE POINTS ]===============
function Invoke-Task11_LoggingAndRestorePoints {
    Write-TaskHeader 'Task 11: Logging & Restore Points'
    # Log Survey
    $transcript = @()
    $startTime = Get-Date
    $transcript += "[{0}] [START] Survey Logs" -f ($startTime.ToString('HH:mm:ss'))
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
    } catch {
        $transcript += "[{0}] [ERROR] Log survey failed: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $_
    }
    $endTime = Get-Date
    $transcript += "[{0}] [END] Survey Logs" -f ($endTime.ToString('HH:mm:ss'))
    $outPath = Join-Path $Script:TempFolder 'Task11_LoggingRestore_log.txt'
    $transcript | Out-File $outPath -Encoding UTF8

    # Restore Points Validation
    $transcript = @()
    $startTime = Get-Date
    $transcript += "[{0}] [START] Validate Restore Points" -f ($startTime.ToString('HH:mm:ss'))
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
    } catch {
        $transcript += "[{0}] [ERROR] Restore points validation failed: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $_
    }
    $endTime = Get-Date
    $transcript += "[{0}] [END] Validate Restore Points" -f ($endTime.ToString('HH:mm:ss'))
    $outPath = Join-Path $Script:TempFolder 'Task11_LoggingRestore_log.txt'
    $transcript | Out-File $outPath -Encoding UTF8 -Append
}

# =====================[ TASK 12: FULL DISK CLEANUP ]======================
function Invoke-Task12_FullDiskCleanup {
    Write-TaskHeader 'Task 12: Full Disk Cleanup'
    $transcript = @()
    $startTime = Get-Date
    $transcript += "[{0}] [START] Full Disk Cleanup" -f ($startTime.ToString('HH:mm:ss'))
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
    } catch {
        $transcript += "[{0}] [ERROR] Disk cleanup failed: {1}" -f ((Get-Date).ToString('HH:mm:ss')), $_
    }
    $endTime = Get-Date
    $transcript += "[{0}] [END] Full Disk Cleanup" -f ($endTime.ToString('HH:mm:ss'))
    $outPath = Join-Path $Script:TempFolder 'Task12_FullDiskCleanup_log.txt'
    $transcript | Out-File $outPath -Encoding UTF8
}

# =====================[ TASK 13: CREATE TRANSCRIPT ]======================

# -- Task 13: Create HTML Transcript in Enhanced Dark Mode --
function Export-Transcript {
    Write-TaskHeader 'Task 13: Create Transcript'
    try {
        $htmlHeader = @"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <title>System Maintenance Transcript</title>
    <style>
        body {
            background: #181c20;
            color: #e0e0e0;
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2em;
        }
        h1, h2, h3 {
            color: #7ecfff;
        }
        .toc {
            position: sticky;
            top: 0;
            background: #23272b;
            padding: 1em;
            border-radius: 8px;
            margin-bottom: 2em;
            box-shadow: 0 2px 8px #0006;
        }
        .toc ul {
            list-style: none;
            padding: 0;
        }
        .toc li {
            margin: 0.5em 0;
        }
        .toc a {
            color: #7ecfff;
            text-decoration: none;
        }
        .toc a:hover {
            text-decoration: underline;
        }
        .task-section {
            background: #23272b;
            margin-bottom: 2em;
            border-radius: 8px;
            box-shadow: 0 2px 8px #0006;
            padding: 1.5em;
        }
        .collapsible {
            background: #2d3237;
            color: #7ecfff;
            cursor: pointer;
            padding: 0.75em 1em;
            width: 100%;
            border: none;
            text-align: left;
            outline: none;
            font-size: 1.1em;
            border-radius: 6px;
            margin-bottom: 0.5em;
        }
        .active, .collapsible:hover {
            background: #3a4047;
        }
        .content {
            padding: 0  1em;
            display: none;
            overflow: hidden;
            background: #23272b;
            border-left: 3px solid #7ecfff;
            margin-bottom: 1em;
        }
        .legend {
            background: #23272b;
            border-left: 4px solid #7ecfff;
            padding: 1em;
            margin-bottom: 2em;
            border-radius: 8px;
        }
        .legend span {
            display: inline-block;
            min-width: 80px;
            font-weight: bold;
        }
        .status-INFO { color: #7ecfff; }
        .status-SUCCESS { color: #7fff7e; }
        .status-WARNING { color: #ffe97e; }
        .status-ERROR { color: #ff7e7e; }
        pre {
            background: #181c20;
            color: #e0e0e0;
            padding: 1em;
            border-radius: 6px;
            overflow-x: auto;
        }
        .summary {
            background: #23272b;
            border-left: 4px solid #7fff7e;
            padding: 1em;
            margin-bottom: 2em;
            border-radius: 8px;
        }
    </style>
</head>
<body>
<div class='container'>
    <h1>System Maintenance Transcript</h1>
    <div class='legend'>
        <span class='status-INFO'>INFO</span> - Informational<br>
        <span class='status-SUCCESS'>SUCCESS</span> - Success<br>
        <span class='status-WARNING'>WARNING</span> - Warning<br>
        <span class='status-ERROR'>ERROR</span> - Error<br>
    </div>
    <div class='summary' id='summary'>
        <h2>Summary</h2>
        <ul id='summary-list'></ul>
    </div>
    <div class='toc' id='toc'>
        <h2>Jump to Task</h2>
        <ul id='toc-list'></ul>
    </div>
"@
        # Define the order and mapping of tasks for transcript
        $taskFiles = @(
            @{ Name = 'System Protection'; File = 'Task2_SystemProtection_log.txt' },
            @{ Name = 'Package Manager Setup'; File = 'Task3_PackageManagerSetup_log.txt' },
            @{ Name = 'System Inventory'; File = 'Task4_SystemInventory_log.txt' },
            @{ Name = 'Remove Bloatware'; File = 'Task5_Debloat_log.txt' },
            @{ Name = 'Install Essential Apps'; File = 'Task6_InstallEssential_log.txt' },
            @{ Name = 'Privacy & Telemetry'; File = 'Task8_PrivacyTelemetry_log.txt' },
            @{ Name = 'Windows Update & Upgrade'; File = 'Task9_UpdatesMaintenance_log.txt' },
            @{ Name = 'Cleanup Browser Data'; File = 'Task10_Cleanup_log.txt' },
            @{ Name = 'Clear DNS Cache'; File = 'Task10_Cleanup_log.txt' },
            @{ Name = 'Logging & Restore Points'; File = 'Task11_LoggingRestore_log.txt' },
            @{ Name = 'Full Disk Cleanup'; File = 'Task12_FullDiskCleanup_log.txt' }
        )
        $htmlBody = ""
        $taskIdx = 0
        foreach ($task in $taskFiles) {
            $taskIdx++
            $logPath = Join-Path $PSScriptRoot $task.File
            if (Test-Path $logPath) {
                $logContent = Get-Content $logPath -Raw
                # Try to extract status for summary (look for [SUCCESS], [ERROR], etc.)
                $status = 'INFO'
                if ($logContent -match '\[SUCCESS\]') { $status = 'SUCCESS' }
                elseif ($logContent -match '\[ERROR\]') { $status = 'ERROR' }
                elseif ($logContent -match '\[WARNING\]') { $status = 'WARNING' }
                $sectionId = "task$taskIdx"
                $htmlBody += "<div class='task-section' id='$sectionId' data-title='$(($task.Name) -replace "'", "&apos;")' data-status='$status'>"
                $htmlBody += "<button class='collapsible'>$(($task.Name) -replace "'", "&apos;") <span class='status-$status' style='float:right;'>$status</span></button>"
                $htmlBody += "<div class='content'><pre>$(($logContent -replace '<', '&lt;' -replace '>', '&gt;'))</pre></div>"
                $htmlBody += "</div>"
            }
        }
        $htmlFooter = @"
</div>
<script>
// Collapsible sections
var coll = document.getElementsByClassName('collapsible');
for (var i = 0; i < coll.length; i++) {
  coll[i].addEventListener('click', function() {
    this.classList.toggle('active');
    var content = this.nextElementSibling;
    if (content.style.display === 'block') {
      content.style.display = 'none';
    } else {
      content.style.display = 'block';
    }
  });
}
// Build TOC and Summary
var toc = document.getElementById('toc-list');
var summary = document.getElementById('summary-list');
var sections = document.querySelectorAll('.task-section');
sections.forEach(function(section) {
    var id = section.id;
    var title = section.getAttribute('data-title');
    var status = section.getAttribute('data-status');
    var li = document.createElement('li');
    var a = document.createElement('a');
    a.href = '#' + id;
    a.textContent = title;
    li.appendChild(a);
    toc.appendChild(li);
    // Summary
    var sumli = document.createElement('li');
    sumli.innerHTML = '<span class="status-' + status + '">' + status + '</span> ' + title;
    summary.appendChild(sumli);
});
</script>
</body>
</html>
"@
        $html = $htmlHeader + $htmlBody + $htmlFooter
        $outPath = Join-Path $PSScriptRoot 'SystemMaintenance_Transcript.html'
        $html | Out-File $outPath -Encoding UTF8
        Write-Log "HTML transcript generated at $outPath" 'SUCCESS'
    } catch {
        Write-Log "Failed to generate HTML transcript: $_" 'ERROR'
    }
}

# =====================[ TASK 14: FINALIZATION ]===========================
function Request-RebootIfNeeded {
    Write-TaskHeader 'Task 14: Finalization'
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
            Write-Log "A system reboot is required to complete maintenance tasks." 'INFO'
            Write-Log "Press any key to reboot. If no key is pressed in 120 seconds, this prompt will disappear and you will need to reboot manually." 'INFO'
            $timeout = 120
            $startTime = Get-Date
            $rebootNow = $false
            while (([datetime]::Now - $startTime).TotalSeconds -lt $timeout) {
                if ([System.Console]::KeyAvailable) {
                    [void][System.Console]::ReadKey($true)
                    $rebootNow = $true
                    break
                }
                Start-Sleep -Milliseconds 250
            }
            if ($rebootNow) {
                Write-Log "Rebooting system..." 'INFO'
                Restart-Computer -Force
            } else {
                Write-Log "Please remember to reboot your system later." 'INFO'
            }
        } else {
            Write-Log "No reboot is required." 'INFO'
        }
    } catch {
        Write-Log "Failed to check or request reboot: $_" 'ERROR'
    }
}

# =====================[ MAIN EXECUTION ]==================================

try {
    Test-Admin
    Invoke-Task1_CentralCoordinationPolicy
    Initialize-Environment

    Invoke-Task 'System Protection' { Invoke-Task2_SystemProtection }
    Invoke-Task 'Ensure Package Managers' { Invoke-Task3_PackageManagerSetup }
    Invoke-Task 'Inventory' { Invoke-Task4_SystemInventory }
    Invoke-Task 'Remove Bloatware' { Invoke-Task5_RemoveBloatware }
    Invoke-Task 'Install Essential Applications' { Invoke-Task6_InstallEssentialApps }
    Invoke-Task 'Upgrade All Packages' { Invoke-Task7_UpgradeAllPackages }
    Invoke-Task 'Privacy & Telemetry' { Invoke-Task8_PrivacyAndTelemetry }
    Invoke-Task 'Windows Update' { Invoke-Task9_WindowsUpdate }
    Invoke-Task 'Cleanup' { Invoke-Task10_Cleanup }
    Invoke-Task 'Logging & Restore Points' { Invoke-Task11_LoggingAndRestorePoints }
    Invoke-Task 'Full Disk Cleanup' { Invoke-Task12_FullDiskCleanup }
    Invoke-Task 'Create Transcript' { Export-Transcript }
    Invoke-Task 'Finalization' { Request-RebootIfNeeded }

} finally {
    Remove-Environment
}
