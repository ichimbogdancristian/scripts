# Script parameters for output file and verbosity
param(
    [string]$OutputFile = "network_scan_results.csv",
    [switch]$VerboseOutput = $false,
    [string]$SubnetBase = "192.168.0",
    [int]$StartOctet = 0,
    [int]$EndOctet = 3,
    [int]$MaxThreads = 50,
    [switch]$SingleThreaded = $false
)

# Define the /22 base subnet
$baseIP = $SubnetBase
$startOctet = $StartOctet
$endOctet = $EndOctet
$rangeStart = 1
$rangeEnd = 254

# Performance settings
$maxThreads = $MaxThreads
$useMultithreading = -not $SingleThreaded

# Initialize timing and logging
$scanStart = Get-Date
$logFile = "network_scan_log.txt"

# Function to write log messages
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $logFile -Value $logEntry
    if ($Level -eq "ERROR") {
        Write-Host $logEntry -ForegroundColor Red
    }
}

# Error handling function
function Write-ErrorMessage {
    param([string]$Operation, [System.Exception]$Exception)
    $errorMsg = "Failed during $Operation`: $($Exception.Message)"
    Write-Log -Message $errorMsg -Level "ERROR"
    Write-Host "❌ $errorMsg" -ForegroundColor Red
}

Write-Log "Starting network scan for range: $baseIP.$startOctet.1 - $baseIP.$endOctet.254"


Write-Host "🔎 Scanning /22 range: 192.168.0.1 – 192.168.3.254..."
Write-Host "⚙️  Multithreading: $useMultithreading | Max threads: $maxThreads" -ForegroundColor Cyan

# Calculate total IPs to scan
$totalIPs = ($endOctet - $startOctet + 1) * ($rangeEnd - $rangeStart + 1)
$currentIP = 0

if ($useMultithreading) {
    # Multithreaded scanning
    Write-Host "🚀 Using multithreaded scanning..." -ForegroundColor Green
    
    # Create list of all IPs to scan
    $ipList = @()
    for ($i = $startOctet; $i -le $endOctet; $i++) {
        for ($j = $rangeStart; $j -le $rangeEnd; $j++) {
            $ipList += "192.168.$i.$j"
        }
    }
    
    # Create runspace pool
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $maxThreads)
    $runspacePool.Open()
    $jobs = @()
    
    # Script block for ping test
    $scriptBlock = {
        param($ip)
        $result = Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($using:VerboseOutput) {
            if ($result) {
                Write-Host "[UP]   $ip" -ForegroundColor Green
            } else {
                Write-Host "[DOWN] $ip" -ForegroundColor DarkGray
            }
        }
        $result | Out-Null
    }
    
    # Submit jobs
    foreach ($ip in $ipList) {
        $job = [powershell]::Create().AddScript($scriptBlock).AddParameter("ip", $ip)
        $job.RunspacePool = $runspacePool
        $jobs += @{ Job = $job; Result = $job.BeginInvoke() }
    }
    
    # Wait for completion with progress
    $completed = 0
    while ($completed -lt $jobs.Count) {
        $completed = ($jobs | Where-Object { $_.Result.IsCompleted }).Count
        $percent = [math]::Round(($completed / $jobs.Count) * 100, 1)
        Write-Host "`rProgress: $percent% ($completed/$($jobs.Count))" -NoNewline -ForegroundColor Yellow
        Start-Sleep -Milliseconds 100
    }
    
    # Clean up
    $jobs | ForEach-Object { $_.Job.EndInvoke($_.Result); $_.Job.Dispose() }
    $runspacePool.Close()
    $runspacePool.Dispose()
    
    Write-Host "`n✅ Multithreaded scan complete!" -ForegroundColor Green
} else {
    # Single-threaded scanning (original method)
    for ($i = $startOctet; $i -le $endOctet; $i++) {
        for ($j = $rangeStart; $j -le $rangeEnd; $j++) {
            $ip = "192.168.$i.$j"
            $currentIP++
            # Show progress every 50 IPs
            if ($currentIP % 50 -eq 0) {
                $percent = [math]::Round(($currentIP / $totalIPs) * 100, 1)
                Write-Host "`rProgress: $percent% ($currentIP/$totalIPs)" -NoNewline -ForegroundColor Yellow
            }
            $result = Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue
            if ($VerboseOutput) {
                if ($result) {
                    Write-Host "[UP]   $ip" -ForegroundColor Green
                } else {
                    Write-Host "[DOWN] $ip" -ForegroundColor DarkGray
                }
            }
        }
    }
    Write-Host "`n✅ Scan complete!" -ForegroundColor Green
}

Write-Host "`n⌛ Waiting for ARP table to update..." -ForegroundColor DarkYellow
Start-Sleep -Seconds 5

# Get ARP entries matching 192.168.0-3.*
try {
    $arpEntries = arp -a | Select-String "192\.168\.[0-3]\.\d+"
    Write-Log "Retrieved $($arpEntries.Count) ARP entries"
} catch {
    Write-ErrorMessage "ARP table retrieval" $_
    Write-Host "❌ Could not retrieve ARP table. Ensure you have appropriate permissions." -ForegroundColor Red
    exit 1
}

Write-Host "`n📊 Found $($arpEntries.Count) active devices in ARP table" -ForegroundColor Cyan

# Output ARP table to file (CSV) with error handling
try {
    $parsedForExport = $arpEntries | ForEach-Object {
        if ($_ -match "(\d+\.\d+\.\d+\.\d+)\s+([a-f0-9:-]+)\s+(\w+)") {
            [PSCustomObject]@{
                IP   = $matches[1]
                MAC  = $matches[2].ToLower()
                Type = $matches[3]
            }
        }
    }
    $parsedForExport | Export-Csv -Path $OutputFile -NoTypeInformation -Force
    Write-Host "`n💾 Results exported to $OutputFile" -ForegroundColor Cyan
    Write-Log "Results exported to $OutputFile"
} catch {
    Write-ErrorMessage "CSV export" $_
}

# Extract and format IP & MAC
$parsed = $arpEntries | ForEach-Object {
    if ($_ -match "(\d+\.\d+\.\d+\.\d+)\s+([a-f0-9:-]+)\s+(\w+)") {
        [PSCustomObject]@{
            IP   = $matches[1]
            MAC  = $matches[2].ToLower()
            Type = $matches[3]
        }
    }
}

# Get vendor information for MAC addresses (first 3 octets)
$vendorInfo = @{}
$parsed | ForEach-Object {
    $oui = $_.MAC.Substring(0, 8)  # First 3 octets
    if (-not $vendorInfo.ContainsKey($oui)) {
        # Expanded vendor OUI database
        $vendors = @{
            "00:1b:63" = "Apple"
            "00:50:56" = "VMware"
            "08:00:27" = "VirtualBox"
            "00:0c:29" = "VMware"
            "00:15:5d" = "Microsoft"
            "00:16:3e" = "Xen"
            "52:54:00" = "QEMU"
            "00:1a:a0" = "Dell"
            "00:14:22" = "Dell"
            "00:1d:09" = "Dell"
            "00:23:ae" = "Dell"
            "00:26:b9" = "Dell"
            "00:0d:56" = "HP"
            "00:1b:78" = "HP"
            "00:1f:29" = "HP"
            "00:25:b3" = "HP"
            "00:30:6e" = "HP"
            "00:03:47" = "Intel"
            "00:15:17" = "Intel"
            "00:1b:21" = "Intel"
            "00:1e:67" = "Intel"
            "00:21:6a" = "Intel"
            "00:04:76" = "3Com"
            "00:50:04" = "3Com"
            "00:a0:24" = "3Com"
            "00:10:5a" = "3Com"
            "00:20:af" = "3Com"
            "00:0b:db" = "Cisco"
            "00:17:94" = "Cisco"
            "00:1a:a2" = "Cisco"
            "00:1c:0e" = "Cisco"
            "00:23:04" = "Cisco"
            "00:d0:2b" = "Cisco"
            "00:e0:1e" = "Cisco"
            "00:07:eb" = "D-Link"
            "00:15:e9" = "D-Link"
            "00:17:9a" = "D-Link"
            "00:1b:11" = "D-Link"
            "00:1c:f0" = "D-Link"
            "00:22:b0" = "D-Link"
            "00:26:5a" = "D-Link"
            "00:05:5d" = "Netgear"
            "00:09:5b" = "Netgear"
            "00:0f:b5" = "Netgear"
            "00:14:6c" = "Netgear"
            "00:1b:2f" = "Netgear"
            "00:1e:2a" = "Netgear"
            "00:22:3f" = "Netgear"
            "00:26:f2" = "Netgear"
            "00:13:10" = "Linksys"
            "00:16:b6" = "Linksys"
            "00:18:39" = "Linksys"
            "00:1a:70" = "Linksys"
            "00:1c:10" = "Linksys"
            "00:1d:7e" = "Linksys"
            "00:21:29" = "Linksys"
            "00:22:6b" = "Linksys"
            "00:25:9c" = "Linksys"
            "00:14:bf" = "Asus"
            "00:17:31" = "Asus"
            "00:1a:92" = "Asus"
            "00:1f:c6" = "Asus"
            "00:22:15" = "Asus"
            "00:23:54" = "Asus"
            "00:26:18" = "Asus"
            "00:04:ac" = "IBM"
            "00:06:29" = "IBM"
            "00:0e:7f" = "IBM"
            "00:11:25" = "IBM"
            "00:16:35" = "IBM"
            "00:1a:64" = "IBM"
            "00:21:5e" = "IBM"
        }
        $vendorInfo[$oui] = $vendors[$oui] ?? "Unknown"
    }
}

# Add vendor info to parsed data
$parsed | ForEach-Object {
    $oui = $_.MAC.Substring(0, 8)
    $_ | Add-Member -NotePropertyName "Vendor" -NotePropertyValue $vendorInfo[$oui]
}

# Show device summary
Write-Host "`n📋 Device Summary:" -ForegroundColor Magenta
$parsed | Group-Object -Property Vendor | Sort-Object Count -Descending | ForEach-Object {
    Write-Host " → $($_.Name): $($_.Count) devices" -ForegroundColor White
}

# Log summary to file
$summary = @()
$summary += "Scan date: $(Get-Date)"
$summary += "Total IPs scanned: $totalIPs"
$summary += "Active devices found: $($parsed.Count)"
$summary += "Network utilization: $([math]::Round(($parsed.Count / $totalIPs) * 100, 2))%"
$summary += "Unique vendors: $($vendorInfo.Keys.Count)"
$summary += "--- Device summary by vendor ---"
$parsed | Group-Object -Property Vendor | Sort-Object Count -Descending | ForEach-Object {
    $summary += " → $($_.Name): $($_.Count) devices"
}
$summary | Out-File -FilePath ("summary_" + $OutputFile) -Encoding utf8
Write-Host "📄 Summary exported to summary_$OutputFile" -ForegroundColor Cyan

# Detect MACs used by multiple IPs
$conflicts = $parsed | Group-Object -Property MAC | Where-Object { $_.Count -gt 1 }

# Also check for IPs used by multiple MACs (less common but possible)
$ipConflicts = $parsed | Group-Object -Property IP | Where-Object { $_.Count -gt 1 }

Write-Host "`n🔍 Conflict Analysis:" -ForegroundColor Magenta

if ($conflicts) {
    Write-Host "`n⚠️  MAC Address Conflicts Detected! (Same MAC, Multiple IPs)" -ForegroundColor Yellow
    foreach ($group in $conflicts) {
        $vendor = $group.Group[0].Vendor
        Write-Host "`nMAC Address: $($group.Name) ($vendor)" -ForegroundColor Cyan
        Write-Host "   Conflict Type: One device claiming multiple IP addresses" -ForegroundColor Red
        $group.Group | ForEach-Object {
            Write-Host "   → IP: $($_.IP) (Type: $($_.Type))" -ForegroundColor White
        }
    }
} else {
    Write-Host "`n✅ No MAC address conflicts detected" -ForegroundColor Green
}

if ($ipConflicts) {
    Write-Host "`n⚠️  IP Address Conflicts Detected! (Same IP, Multiple MACs)" -ForegroundColor Yellow
    foreach ($group in $ipConflicts) {
        Write-Host "`nIP Address: $($group.Name)" -ForegroundColor Cyan
        Write-Host "   Conflict Type: Multiple devices claiming same IP address" -ForegroundColor Red
        $group.Group | ForEach-Object {
            $vendor = $_.Vendor
            Write-Host "   → MAC: $($_.MAC) ($vendor) (Type: $($_.Type))" -ForegroundColor White
        }
    }
} else {
    Write-Host "`n✅ No IP address conflicts detected" -ForegroundColor Green
}

# Network statistics
Write-Host "`n📈 Network Statistics:" -ForegroundColor Magenta
Write-Host " → Total IPs scanned: $totalIPs" -ForegroundColor White
Write-Host " → Active devices found: $($parsed.Count)" -ForegroundColor White
Write-Host " → Network utilization: $([math]::Round(($parsed.Count / $totalIPs) * 100, 2))%" -ForegroundColor White
Write-Host " → Unique vendors: $($vendorInfo.Keys.Count)" -ForegroundColor White

# Security Analysis
Write-Host "`n🔒 Security Analysis:" -ForegroundColor Magenta

# Check for suspicious patterns
$suspiciousDevices = $parsed | Where-Object { 
    $_.MAC -match "^(00:00:00|ff:ff:ff)" -or 
    $_.MAC -match "^(02:|06:|0a:|0e:)" -or  # Locally administered addresses
    $_.Type -eq "invalid"
}

if ($suspiciousDevices) {
    Write-Host " ⚠️  Potentially suspicious devices detected:" -ForegroundColor Yellow
    $suspiciousDevices | ForEach-Object {
        Write-Host "   → $($_.IP) - $($_.MAC) ($($_.Vendor))" -ForegroundColor Red
    }
} else {
    Write-Host " ✅ No obviously suspicious devices detected" -ForegroundColor Green
}

# Check for high device density (possible rogue DHCP or network issues)
$deviceDensity = $parsed.Count / $totalIPs
if ($deviceDensity -gt 0.7) {
    Write-Host " ⚠️  High device density detected (>70%). Check for:" -ForegroundColor Yellow
    Write-Host "   → Rogue DHCP servers" -ForegroundColor Red
    Write-Host "   → Network scanning attacks" -ForegroundColor Red
    Write-Host "   → Misconfigured devices" -ForegroundColor Red
} else {
    Write-Host " ✅ Device density appears normal" -ForegroundColor Green
}

# Check for virtual machines (potential security concern in some environments)
$virtualDevices = $parsed | Where-Object { $_.Vendor -match "VMware|VirtualBox|QEMU|Xen|Microsoft" }
if ($virtualDevices.Count -gt 0) {
    Write-Host " ℹ️  Virtual machines detected: $($virtualDevices.Count)" -ForegroundColor Cyan
    if ($VerboseOutput) {
        $virtualDevices | ForEach-Object {
            Write-Host "   → $($_.IP) - $($_.Vendor)" -ForegroundColor White
        }
    }
}


if ($conflicts -or $ipConflicts) {
    Write-Host "`n⚠️  Action Required: Review and resolve conflicts above" -ForegroundColor Yellow
    Add-Content -Path ("summary_" + $OutputFile) -Value "Conflicts detected. Review required."
} else {
    Write-Host "`n✅ Network appears healthy - no conflicts detected" -ForegroundColor Green
    Add-Content -Path ("summary_" + $OutputFile) -Value "No conflicts detected."
}

# Show total scan time
$scanEnd = Get-Date
$duration = $scanEnd - $scanStart
Write-Host "`n⏱️  Total scan time: $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor Cyan
Write-Log "Scan completed in $($duration.ToString('hh\:mm\:ss'))"

# Final summary to log and file
$finalSummary = @"
=== NETWORK SCAN SUMMARY ===
Scan Date: $(Get-Date)
IP Range: $baseIP.$startOctet.1 - $baseIP.$endOctet.254
Total IPs: $totalIPs
Active Devices: $($parsed.Count)
Utilization: $([math]::Round(($parsed.Count / $totalIPs) * 100, 2))%
Conflicts: $(if ($conflicts -or $ipConflicts) { "YES" } else { "NO" })
Scan Duration: $($duration.ToString('hh\:mm\:ss'))
Threading: $(if ($useMultithreading) { "Multi ($maxThreads threads)" } else { "Single" })
Output Files: $OutputFile, summary_$OutputFile, $logFile
"@

Add-Content -Path ("summary_" + $OutputFile) -Value $finalSummary
Write-Log $finalSummary

Write-Host "`n📋 Complete scan summary saved to: summary_$OutputFile" -ForegroundColor Green
Write-Host "📋 Detailed log saved to: $logFile" -ForegroundColor Green
