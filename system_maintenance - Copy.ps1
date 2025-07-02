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
    
    =====================[ CHANGELOG ]=====================
    2025-06-28:
    - Added log file rotation (max 5 transcripts)
    - Added error log for full error details
    - Added summary output to console at end
    - Added Write-Progress for bloatware removal
    - Added background jobs for user temp cleanup (if PS 7+)
    - Added config file support for bloatware/essential apps
    - Added plugin system for user scripts
    - Added critical app protection for bloatware removal
    - Added inline help to functions
    - Added PowerShell/OS version check
    =======================================================
!#>

# =====================[ VERSION CHECKS ]=====================
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error "[FATAL] PowerShell 5.0 or higher is required. Exiting."
    exit 1
}
$osVersion = [System.Environment]::OSVersion.Version
if ($osVersion.Major -lt 10) {
    Write-Warning "[WARN] This script is designed for Windows 10/11. Unexpected results may occur."
}

# =====================[ LOG FILE ROTATION ]==================
$transcriptDir = [System.IO.Path]::GetDirectoryName($Script:TranscriptFile)
if (Test-Path $transcriptDir) {
    $transcripts = Get-ChildItem -Path $transcriptDir -Filter 'transcript*.txt' | Sort-Object LastWriteTime -Descending
    if ($transcripts.Count -gt 5) {
        $transcripts | Select-Object -Skip 5 | Remove-Item -Force
    }
}

# =====================[ CONFIG FILE SUPPORT ]================
$Script:ConfigFile = Join-Path $PSScriptRoot 'system_maintenance_config.json'
if (Test-Path $Script:ConfigFile) {
    try {
        $Script:Config = Get-Content $Script:ConfigFile | ConvertFrom-Json
        Write-Host "[INFO] Loaded config from $Script:ConfigFile"
    } catch {
        Write-Warning "[WARN] Failed to load config file: $_"
        $Script:Config = $null
    }
} else {
    $Script:Config = $null
}

# =====================[ PLUGIN SYSTEM ]====================
$Script:PluginsDir = Join-Path $PSScriptRoot 'plugins'
if (Test-Path $Script:PluginsDir) {
    $pluginFiles = Get-ChildItem -Path $Script:PluginsDir -Filter '*.ps1'
    foreach ($plugin in $pluginFiles) {
        try {
            . $plugin.FullName
            Write-Host "[INFO] Loaded plugin: $($plugin.Name)"
        } catch {
            Write-Warning "[WARN] Failed to load plugin $($plugin.Name): $_"
        }
    }
}

# =====================[ ERROR LOGGING ]====================
$Script:ErrorLogFile = Join-Path $Script:TempFolder 'error_log.txt'
function Write-ErrorLog {
    param([string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$timestamp $Message" | Out-File -FilePath $Script:ErrorLogFile -Append -Encoding UTF8
}

# =====================[ INLINE HELP EXAMPLE ]================
<#!
.SYNOPSIS
    Removes bloatware using a comprehensive list and config file overrides.
.DESCRIPTION
    This function removes AppX and provisioned packages defined in the bloatware list, with protection for essential apps.
!#>
function Uninstall-Bloatware {
    try {
        Write-Host "[INFO] Scanning for bloatware apps to remove..."
        # Use config override if present
        if ($Script:Config -and $Script:Config.BloatwareList) {
            $bloatwareList = $Script:Config.BloatwareList
        } else {
            # ENHANCED COMPREHENSIVE BLOATWARE LIST (Updated January 2025)
            $bloatwareList = @(
                # MICROSOFT XBOX & GAMING APPS
                "Microsoft.XboxApp"
                "Microsoft.XboxGameOverlay"
                "Microsoft.XboxGamingOverlay"
                "Microsoft.XboxSpeechToTextOverlay"
                "Microsoft.Xbox.TCUI"
                "Microsoft.GamingApp"
                "Microsoft.XboxGameCallableUI"
                "Microsoft.XboxGameBar"
                "Microsoft.XboxIdentityProvider"
                "Microsoft.GamingServices"
                # MICROSOFT OFFICE & PRODUCTIVITY APPS
                "Microsoft.Office.OneNote"
                "Microsoft.Office.Sway"
                "Microsoft.Office.Lens"
                "Microsoft.Office.Todo.List"
                "Microsoft.MicrosoftOfficeHub"
                "Microsoft.Whiteboard"
                "Microsoft.PowerAutomateDesktop"
                "Microsoft.OutlookForWindows"
                # MICROSOFT COMMUNICATION & SOCIAL APPS
                "Microsoft.SkypeApp"
                "Microsoft.People"
                "Microsoft.YourPhone"
                "Microsoft.Messaging"
                "microsoft.windowscommunicationsapps"
                # MICROSOFT BING & NEWS APPS
                "Microsoft.BingNews"
                "Microsoft.BingWeather"
                "Microsoft.BingFinance"
                "Microsoft.BingSports"
                "Microsoft.MSN.Weather"
                "Microsoft.MSN.News"
                "Microsoft.Bing.Search"
                "Microsoft.News"
                "Microsoft.MSN.Sports"
                "Microsoft.MSN.Money"
                "Microsoft.MSN.Travel"
                "Microsoft.MSN.Health"
                "Microsoft.BingTranslator"
                # MICROSOFT ENTERTAINMENT & MEDIA APPS
                "Microsoft.ZuneMusic"
                "Microsoft.ZuneVideo"
                "Microsoft.WindowsSoundRecorder"
                "Microsoft.WindowsCamera"
                "Microsoft.Windows.Photos"
                # MICROSOFT GAMES & 3D APPS
                "Microsoft.MicrosoftSolitaireCollection"
                "Microsoft.MinecraftUWP"
                "Microsoft.Microsoft3DViewer"
                "Microsoft.Print3D"
                "Microsoft.3DBuilder"
                "Microsoft.MixedReality.Portal"
                "Microsoft.HoloLens.FirstRun"
                "Microsoft.HoloCamera"
                "Microsoft.HoloItemPlayerApp"
                "Microsoft.HoloShell"
                # MICROSOFT UTILITY & PRODUCTIVITY APPS
                "Microsoft.GetHelp"
                "Microsoft.Getstarted"
                "Microsoft.Tips"
                "Microsoft.WindowsAlarms"
                "Microsoft.WindowsMaps"
                "Microsoft.WindowsFeedbackHub"
                "Microsoft.NetworkSpeedTest"
                "Microsoft.OneConnect"
                "Microsoft.Wallet"
                "Microsoft.BioEnrollment"
                "Microsoft.ScreenSketch"
                "Microsoft.WindowsReadingList"
                "Microsoft.StorePurchaseApp"
                # WINDOWS 11 SPECIFIC APPS
                "MicrosoftCorporationII.QuickAssist"
                "MicrosoftWindows.Client.WebExperience"
                "Microsoft.Windows.NarratorQuickStart"
                "Microsoft.Windows.ParentalControls"
                "Microsoft.Family"
                "MicrosoftCorporationII.MicrosoftFamily"
                "MicrosoftWindows.Client.WebExperienceUI"
                "Clipchamp.Clipchamp"
                "Microsoft.DevHome"
                "Microsoft.PowerShell.Preview"
                # THIRD-PARTY PRE-INSTALLED APPS
                "SpotifyAB.SpotifyMusic"
                "4DF9E0F8.Netflix"
                "BytedancePte.Ltd.TikTok"
                "Facebook.Facebook"
                "Facebook.InstagramBeta"
                "Facebook.Instagram"
                "LinkedIn.LinkedIn"
                "Twitter.Twitter"
                "9E2F88E3.Twitter"
                "Amazon.com.Amazon"
                "HuluLLC.HuluPlus"
                "Disney.37853FC22B2CE"
                "AppleInc.iTunes"
                "PricelinePartnerNetwork.Booking.comUSA"
                "PricelinePartnerNetwork.Booking.comEMEABV"
                "Evernote.Evernote"
                "Dropbox.Dropbox"
                "WhatsAppInc.WhatsApp"
                # THIRD-PARTY GAMES
                "king.com.CandyCrushSaga"
                "king.com.CandyCrushSodaSaga"
                "CandyCrush"
                "Microsoft.CandyCrushSaga"
                "Microsoft.CandyCrushSodaSaga"
                "BubbleWitch3Saga"
                "Microsoft.BubbleWitch3Saga"
                "RoyalRevolt2"
                "Playtika.CaesarsSlotsFreeCasino"
                "Playtika.WorldSeriesOfPoker"
                "GAMELOFTSA.Asphalt8Airborne"
                "GAMELOFTSA.Asphalt9"
                "46928bounde.EclipseManager"
                "A278AB0D.DragonManiaLegends"
                "ActiproSoftwareLLC.562882FEEB491"
                "D5EA27B7.Duolingo-LearnLanguagesforfree"
                "D52A8D61.FarmVille2CountryEscape"
                "89006A2E.AutodeskSketchBook"
                "5CB722CC.SeekersNotes"
                "WBGAMES.MortalKombatX"
                "flaregamesGmbH.RoyalRevolt2"
                "KingDigital.CandyCrushFriends"
                "KingDigital.CandyCrushSodaSaga"
                "KingDigital.FarmHeroesSaga"
                "Nordcurrent.CookingFever"
                "3D5319E2.HeartsDeluxe"
                # ADOBE PRODUCTS
                "AdobeSystemsIncorporated.AdobePhotoshopExpress"
                "AdobeSystemIncorporated.AdobePhotoshopElements2022"
                "2FE3CB00.PicsArt-PhotoStudio"
                "AdobePhotoshopExpress"
                # LANGUAGE PACKS
                "Microsoft.LanguageExperiencePackfr-FR"
                "Microsoft.LanguageExperiencePackes-ES"
                "Microsoft.LanguageExperiencePackde-DE"
                "Microsoft.LanguageExperiencePackit-IT"
                "Microsoft.LanguageExperiencePackpt-PT"
                "Microsoft.LanguageExperiencePackru-RU"
                "Microsoft.LanguageExperiencePackzh-CN"
                "Microsoft.LanguageExperiencePackja-JP"
                "Microsoft.LanguageExperiencePackko-KR"
                "Microsoft.LanguageExperiencePacknl-NL"
                "Microsoft.LanguageExperiencePackpl-PL"
                "Microsoft.LanguageExperiencePackar-SA"
                # MULTIMEDIA & STREAMING APPS
                "CAF9E577.Plex"
                "SlingTVLLC.SlingTV"
                "Hulu.HuluPlus"
                "AmazonVideo.PrimeVideo"
                "DisneyPlus.DisneyPlus"
                "TikTok.TikTok"
                "BytedanceTech.TikTok"
                "XINGAG.XING"
                "Zoom.Zoom"
                "PandoraMediaInc.29680B314EFC2"
                "iHeartRadio"
                "Shazam"
                "TuneInRadio"
                "Spotify.Spotify"
                # PRODUCTIVITY & BUSINESS APPS
                "Flipboard.Flipboard"
                "Evernote.Evernote"
                "EvernoteTeam.EvernoteRapidRing"
                "MobiSystemsInc.OfficeSuitePremium"
                "Drawboard.DrawboardPDF"
                "CorelCorporation.PaintShopPro"
                "JetBrains.YouTrack"
                "KeeperSecurityInc.Keeper"
                "1Password.1Password"
                "THEPOWERMBA.ONEPOWERMBA"
                "LinkedInCorporation.LinkedIn"
                # SYSTEM UTILITIES
                "WinZipComputing.WinZipUniversal"
                "PowerISO.PowerISO"
                "CyberLinkCorp.hs.PowerMediaPlayer15ForHPConsumerPC"
                "DB6EA5DB.CyberLinkMediaSuiteEssentials"
                "CyberLink.PowerDirector"
                "CyberLink.PhotoDirector"
                "B9ECED6F.AutodeskSketchBook"
                # VPN & SECURITY APPS
                "ExpressVPNLtd.ExpressVPN"
                "NordVPNS.A.NordVPN"
                "CyberGhostVPN.CyberGhostVPN"
                "KasperskyLab.KasperskyVPN"
                "5A894077.McAfeeSecurity"
                "NortonSecurity.NortonSecurity"
                "NortonLLC.NortonSecurity"
                "McAfee.McAfeeSecurityScanPlus"
                "McAfee.McAfeeWebAdvisor"
                "McAfee.McAfeeCentral"
                "NortonLifeLock.NortonSecurityUltra"
                "PC-Doctor.PCDoctorforWindows"
                "PCDoctor.PCDoctorforWindows"
                "AVG.AVGAntiVirus"
                "AVG.AVGSecure"
                "Avast.AvastAntivirus"
                "Avast.AvastSecureBrowser"
                "ASTRApivotUK.TotalAV"
                "KasperskyLab.KasperskyFree"
                "KasperskyLab.KasperskySecurity"
                "F-Secure.F-SecureOnline"
                "F-Secure.F-SecureSafe"
                "Bullguard.BullguardInternetSecurity"
                "SaferNetworking.SpybotSearchandDestroy"
                "SUPERAntiSpyware.SUPERAntiSpyware"
                "Symantec.NortonLifeLock"
                "Symantec.NortonSecurity"
                "Symantec.NortonAntiVirus"
                "Symantec.NortonInternetSecurity"
                # WEATHER & NEWS APPS
                "dpi.weather.com.dpiweather"
                "USATODAY.USATODAY"
                "NYT.NYTCrossword"
                # TRAVEL & BOOKING APPS
                "PricelinePartnerNetwork.Booking.comBigsavingsonhot"
                "PricelinePartnerNetwork.Booking.comTravel"
                "eBayInc.eBay"
                "TripAdvisor.TripAdvisor"
                # FITNESS & HEALTH APPS
                "Fitbit.FitbitCoach"
                "Microsoft.BingHealthAndFitness"
                "Microsoft.BingFoodAndDrink"
                # COMMUNICATION & MESSAGING APPS
                "Skype.Skype"
                "Telegram.TelegramDesktop"
                "WhatsApp.WhatsApp"
                "Viber.Viber"
                "Slack"
                "FACEBOOK.FACEBOOK"
                "BytedanceTech.CapCut"
                "Zalo.ZaloPC"
                "MoonGate.MoonGate"
                # FILE CONVERTERS & UTILITIES
                "CJTorchLTD.FileConverter3D"
                "PIXTA.PIXTA"
                "DolbyLaboratories.DolbyAccess"
                "WavesAudio.MaxxAudio"
                "WavesAudio.MaxxAudioPro"
                "ACGMediaPlayer.ACGMP"
                "DevolutionsInc.RemoteDesktopManager"
                "SugarSync.SugarSync"
                "DropboxInc.Dropbox"
                # OLDER/DEPRECATED MICROSOFT APPS
                "Microsoft.Advertising.Xaml"
                "Microsoft.MicrosoftStickyNotes"
                "Microsoft.SecHealthUI"
                "Microsoft.MSPaint"
                "Microsoft.WindowsCalculator"
                # MISCELLANEOUS PROMOTIONAL/TRIAL APPS
                "UBISOFTEntertainment.Uplay"
                "EpicGamesLauncher"
                "Asphalt8Airborne"
                "EnterpriseModernAppManagement.device"
                "DriverToaster.DriverToaster"
                "SmartByte.SmartByteDriverAccelerator"
                "Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe"
                "Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe"
                # MANUFACTURER-SPECIFIC BLOATWARE
                "Microsoft.HoloLens.FirstRun"
                "Microsoft.HoloCamera"
                "Microsoft.HoloItemPlayerApp"
                "Microsoft.HoloShell"
                "Microsoft.Asphalt8Airborne"
                "Microsoft.AgeCastles"
                "Microsoft.HyperVClient"
                "Microsoft.MicrosoftStickyNotes"
                "Microsoft.WindowsAlarms"
                "Microsoft.WindowsMaps"
                "Microsoft.WindowsSoundRecorder"
                "Microsoft.WindowsFeedbackHub"
                # Other non-essential apps
                "Microsoft.GetHelp"
                "Microsoft.Getstarted"
                "Microsoft.549981C3F5F10"
                "Microsoft.SkypeApp"
                "Microsoft.MicrosoftOfficeHub"
                "Microsoft.Office.OneNote"
                "Microsoft.Office.Sway"
                "Microsoft.Whiteboard"
                "Microsoft.ScreenSketch"
                "Microsoft.Todos"
                "Microsoft.PowerAutomateDesktop"
                "Microsoft.BingTranslator"
                "Microsoft.OneNote"
                "Microsoft.StorePurchaseApp"
                "Microsoft.Reader"
                "Microsoft.SurfaceHub"
                "Microsoft.WinJS"
                "Microsoft.Windows.FeatureOnDemand.InsiderHub"
                "Microsoft.Office.Lens"
                "Microsoft.OutlookForWindows"
                "Microsoft.WindowsReadingList"
                "Microsoft.LanguageExperiencePackfr-FR"
                "Microsoft.LanguageExperiencePackes-ES"
                "Microsoft.LanguageExperiencePackde-DE"
                "Microsoft.LanguageExperiencePackit-IT"
                "Microsoft.LanguageExperiencePackpt-PT"
                "Microsoft.LanguageExperiencePackru-RU"
                "Microsoft.LanguageExperiencePackzh-CN"
                "Microsoft.LanguageExperiencePackja-JP"
                "Microsoft.LanguageExperiencePackko-KR"
                "Microsoft.LanguageExperiencePacknl-NL"
                "Microsoft.LanguageExperiencePackpl-PL"
                "Microsoft.LanguageExperiencePackar-SA"
                "Microsoft.SecHealthUI"
                # Windows 11 specific
                "MicrosoftCorporationII.QuickAssist"
                "MicrosoftWindows.Client.WebExperience"
                "Microsoft.Windows.NarratorQuickStart"
                "Microsoft.Windows.ParentalControls"
                "Microsoft.Family"
                "MicrosoftCorporationII.MicrosoftFamily"
                "MicrosoftWindows.Client.WebExperienceUI"
                # Third-party apps that come preinstalled
                "Clipchamp.Clipchamp"
            )

        # Batch load all AppX packages for all users
        $allAppx = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        $allProvisioned = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        $removedCount = 0
        $failCount = 0
        $total = $bloatwareList.Count
        $step = 0
        foreach ($bloat in $bloatwareList) {
            $step++
            # Critical app protection
            if ($essentialApps -contains $bloat) {
                Write-Host "[INFO] Skipping essential app: $bloat"
                continue
            }
            $appx = $allAppx | Where-Object { $_.Name -eq $bloat }
            $prov = $allProvisioned | Where-Object { $_.DisplayName -eq $bloat }
            $percent = [math]::Round(($step / $total) * 100)
            Write-Progress -Activity "Removing Bloatware" -Status "$step/$total ($percent%)" -PercentComplete $percent
            if ($appx) {
                foreach ($pkg in $appx) {
                    try {
                        Write-Host "[INFO] Removing AppX package: $($pkg.Name)"
                        Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction SilentlyContinue
                        $removedCount++
                    } catch {
                        Write-Warning "[WARN] Failed to remove AppX package $($pkg.Name): $_"
                        $failCount++
                    }
                }
            }
            if ($prov) {
                foreach ($p in $prov) {
                    try {
                        Write-Host "[INFO] Removing provisioned AppX: $($p.DisplayName)"
                        Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName -ErrorAction SilentlyContinue
                        $removedCount++
                    } catch {
                        Write-Warning "[WARN] Failed to remove provisioned AppX $($p.DisplayName): $_"
                        $failCount++
                    }
                }
            }
            if ($step % 25 -eq 0 -or $step -eq $total) {
                Write-Host ("[INFO] Progress: {0}/{1} bloatware items processed" -f $step, $total)
            }
        }
        Write-Progress -Activity "Removing Bloatware" -Completed
        Write-Host ("[INFO] Bloatware removal complete. Removed: {0}, Failed: {1}" -f $removedCount, $failCount)
    } catch {
        Write-Warning "[ERROR] Bloatware removal failed: $_"
        Write-ErrorLog "[ERROR] Bloatware removal failed: $_"
    }
}

# =====================[ PARALLEL TEMP CLEANUP ]================
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
        # Clean all user temp folders in parallel if PS 7+
        $userProfiles = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object {
            try {
                $profilePath = (Get-ItemProperty $_.PsPath).ProfileImagePath
                if ($profilePath -and (Test-Path $profilePath)) { $profilePath }
            } catch {}
        } | Where-Object { $_ -and (Test-Path $_) }
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $jobs = @()
            foreach ($profile in $userProfiles) {
                $jobs += Start-Job -ScriptBlock {
                    param($userTemp)
                    Remove-Item -Path "$userTemp\*" -Recurse -Force -ErrorAction SilentlyContinue
                } -ArgumentList (Join-Path $profile 'AppData\Local\Temp')
            }
            $jobs | Wait-Job | Out-Null
            $jobs | Remove-Job
            foreach ($profile in $userProfiles) {
                Write-Host ("[INFO] Temp files cleaned for {0}." -f $profile)
            }
        } else {
            foreach ($profile in $userProfiles) {
                $userTemp = Join-Path $profile 'AppData\Local\Temp'
                if (Test-Path $userTemp) {
                    try {
                        Remove-Item -Path "$userTemp\*" -Recurse -Force -ErrorAction SilentlyContinue
                        Write-Host ("[INFO] Temp files cleaned for {0}." -f $profile)
                    } catch {
                        Write-Warning ("[WARN] Failed to clean temp for {0}: {1}" -f $profile, $_)
                        Write-ErrorLog ("[WARN] Failed to clean temp for {0}: {1}" -f $profile, $_)
                    }
                }
            }
        }
        Write-Host "[INFO] Full disk cleanup complete."
    } catch {
        Write-Warning "[ERROR] Disk cleanup failed: $_"
        Write-ErrorLog "[ERROR] Disk cleanup failed: $_"
    }
}

# =====================[ INVENTORY CACHING ]====================
$Script:InventoryCache = $null
function Get-Inventory {
    try {
        if ($Script:InventoryCache) {
            Write-Host "[INFO] Using cached inventory."
            $cached = $Script:InventoryCache
        } else {
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
            $Script:InventoryCache = $true # Set to true to indicate cache (replace with actual inventory object if needed)
            Write-Host "[INFO] Inventory collected in $inventoryPath"
            $cached = $Script:InventoryCache
        }
    } catch {
        Write-Warning "[ERROR] Inventory collection failed: $_"
        Write-ErrorLog "[ERROR] Inventory collection failed: $_"
        $cached = $null
    }
    return $cached
}

# =====================[ SUMMARY OUTPUT ]=======================
function Show-Summary {
    try {
        $summaryPath = Join-Path $Script:TempFolder 'final_transcript.txt'
        if (Test-Path $summaryPath) {
            $lines = Get-Content $summaryPath | Select-Object -First 30
            Write-Host "\n==================== SYSTEM MAINTENANCE SUMMARY ====================" -ForegroundColor Cyan
            $lines | ForEach-Object { Write-Host $_ }
            Write-Host "==================== END OF SUMMARY ====================" -ForegroundColor Cyan
        }
    } catch {
        Write-Warning "[WARN] Could not display summary: $_"
    }
}

# =====================[ MAIN EXECUTION MODS ]==================
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
    Show-Summary
}

# =====================[ END OF SCRIPT ]===================================
