# Enhanced Network Scanner with Advanced Features
# Script parameters for output file and verbosity
param(
    [ValidateNotNullOrEmpty()]
    [string]$OutputFile = "network_scan_results.csv",
    
    [switch]$VerboseOutput = $false,
    
    [ValidatePattern("^\d{1,3}\.\d{1,3}\.\d{1,3}$")]
    [string]$SubnetBase = "192.168.0",
    
    [ValidateRange(0, 255)]
    [int]$StartOctet = 0,
    
    [ValidateRange(0, 255)]
    [int]$EndOctet = 3,
    
    [ValidateRange(1, 1000)]
    [int]$MaxThreads = 50,
    
    [switch]$SingleThreaded = $false,
    
    # Performance Optimizations (Enhancement 5)
    [ValidateRange(500, 10000)]
    [int]$PingTimeout = 1000,
    
    [ValidateRange(1, 5)]
    [int]$MaxRetries = 2,
    
    [switch]$AdaptiveThreading = $false,
    
    # Advanced Scanning Methods (Enhancement 2)
    [switch]$PortScan = $false,
    
    [int[]]$CommonPorts = @(22, 80, 135, 139, 443, 445, 3389),
    
    [switch]$ReverseDNS = $false,
    
    [switch]$OSFingerprint = $false,
    
    # User Experience (Enhancement 7)
    [switch]$Interactive = $false,
    
    [switch]$WhatIf = $false,
    
    [string]$ConfigFile = "",
    
    [switch]$SaveProfile = $false,
    
    # Advanced Reporting (Enhancement 8)
    [ValidateSet("CSV", "JSON", "XML", "HTML")]
    [string[]]$OutputFormat = @("CSV"),
    
    [switch]$GenerateDashboard = $false,
    
    [switch]$OpenResults = $false,
    
    # Advanced Security Analysis (Enhancement 10)
    [switch]$DeepSecurityScan = $false,
    
    [switch]$DetectRogueDHCP = $false,
    
    [switch]$BaselineComparison = $false,
    
    [string]$BaselineFile = ""
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

# Function to safely extract OUI from MAC address
function Get-OUI {
    param([string]$MacAddress)
    
    if ([string]::IsNullOrEmpty($MacAddress)) {
        return "unknown"
    }
    
    # Remove separators and ensure we have enough characters
    $cleanMac = $MacAddress -replace '[:-]', ''
    if ($cleanMac.Length -ge 6) {
        # Take first 6 characters (3 octets) and format with separators
        return $cleanMac.Substring(0, 6).Insert(2, '-').Insert(5, '-').ToLower()
    } else {
        return "unknown"
    }
}

# Configuration Management Function (Enhancement 7)
function Read-ConfigFile {
    param([string]$ConfigPath)
    
    if ([string]::IsNullOrEmpty($ConfigPath) -or -not (Test-Path $ConfigPath)) {
        return $null
    }
    
    try {
        $config = Get-Content $ConfigPath | ConvertFrom-Json
        Write-Log "Configuration loaded from: $ConfigPath"
        return $config
    } catch {
        Write-Log "Failed to load configuration from: $ConfigPath" -Level "ERROR"
        return $null
    }
}

# Save Configuration Profile Function (Enhancement 7)
function Save-ConfigProfile {
    param([string]$ProfilePath, [hashtable]$Settings)
    
    try {
        $Settings | ConvertTo-Json -Depth 3 | Out-File -FilePath $ProfilePath -Encoding utf8
        Write-Host "✅ Configuration profile saved to: $ProfilePath" -ForegroundColor Green
        Write-Log "Configuration profile saved to: $ProfilePath"
    } catch {
        Write-ErrorMessage "Configuration profile save" $_
    }
}

# Port Scanning Function (Enhancement 2)
function Test-PortConnectivity {
    param(
        [string]$IPAddress,
        [int[]]$Ports,
        [int]$TimeoutMs = 1000
    )
    
    $openPorts = @()
    foreach ($port in $Ports) {
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connection = $tcpClient.BeginConnect($IPAddress, $port, $null, $null)
            $wait = $connection.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
            
            if ($wait) {
                try {
                    $tcpClient.EndConnect($connection)
                    $openPorts += $port
                } catch {
                    # Connection failed
                }
            }
            $tcpClient.Close()
        } catch {
            # Port scan failed
        }
    }
    return $openPorts
}

# Reverse DNS Lookup Function (Enhancement 2)
function Get-ReverseDNS {
    param([string]$IPAddress)
    
    try {
        $hostname = [System.Net.Dns]::GetHostEntry($IPAddress).HostName
        return $hostname
    } catch {
        return "N/A"
    }
}

# OS Fingerprinting Function (Enhancement 2)
function Get-OSFingerprint {
    param([string]$IPAddress)
    
    try {
        $ping = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($IPAddress, 1000)
        
        if ($reply.Status -eq "Success") {
            $ttl = $reply.Options.Ttl
            
            # Basic OS detection based on TTL
            $osGuess = switch ($ttl) {
                { $_ -ge 240 -and $_ -le 255 } { "Windows" }
                { $_ -ge 60 -and $_ -le 70 } { "Linux/Unix" }
                { $_ -ge 250 -and $_ -le 255 } { "Cisco/Network Device" }
                default { "Unknown (TTL: $ttl)" }
            }
            
            return @{
                TTL = $ttl
                OSGuess = $osGuess
                RoundtripTime = $reply.RoundtripTime
            }
        }
    } catch {
        # OS fingerprinting failed
    }
    
    return @{
        TTL = 0
        OSGuess = "Unknown"
        RoundtripTime = 0
    }
}

# Adaptive Threading Function (Enhancement 5)
function Get-OptimalThreadCount {
    param(
        [int]$DefaultThreads,
        [int]$NetworkResponseTime,
        [int]$SystemLoad
    )
    
    if (-not $AdaptiveThreading) {
        return $DefaultThreads
    }
    
    # Adjust thread count based on network performance
    $adjustedThreads = $DefaultThreads
    
    if ($NetworkResponseTime -gt 100) {
        $adjustedThreads = [math]::Max(10, $DefaultThreads * 0.7)
    } elseif ($NetworkResponseTime -lt 50) {
        $adjustedThreads = [math]::Min(100, $DefaultThreads * 1.3)
    }
    
    Write-Log "Adaptive threading: Adjusted from $DefaultThreads to $adjustedThreads threads"
    return [int]$adjustedThreads
}

# Advanced Security Analysis Functions (Enhancement 10)
function Test-RogueDHCP {
    param([string[]]$KnownDHCPServers = @())
    
    if (-not $DetectRogueDHCP) {
        return $null
    }
    
    try {
        Write-Host "🔍 Detecting DHCP servers..." -ForegroundColor Cyan
        
        # Get DHCP lease information
        $dhcpLeases = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | 
                     Where-Object { $_.DHCPEnabled -eq $true -and $_.DHCPServer } |
                     Select-Object DHCPServer, IPAddress
        
        $detectedServers = $dhcpLeases.DHCPServer | Sort-Object -Unique
        $rogueServers = @()
        
        foreach ($server in $detectedServers) {
            if ($server -notin $KnownDHCPServers) {
                $rogueServers += $server
            }
        }
        
        return @{
            DetectedServers = $detectedServers
            RogueServers = $rogueServers
            KnownServers = $KnownDHCPServers
        }
    } catch {
        Write-Log "DHCP detection failed: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

function Compare-NetworkBaseline {
    param(
        [array]$CurrentDevices,
        [string]$BaselineFilePath
    )
    
    if (-not $BaselineComparison -or -not (Test-Path $BaselineFilePath)) {
        return $null
    }
    
    try {
        $baseline = Import-Csv $BaselineFilePath
        
        $newDevices = @()
        $missingDevices = @()
        $changedDevices = @()
        
        # Find new devices
        foreach ($device in $CurrentDevices) {
            $baselineDevice = $baseline | Where-Object { $_.IP -eq $device.IP }
            if (-not $baselineDevice) {
                $newDevices += $device
            } elseif ($baselineDevice.MAC -ne $device.MAC) {
                $changedDevices += @{
                    IP = $device.IP
                    OldMAC = $baselineDevice.MAC
                    NewMAC = $device.MAC
                    OldVendor = $baselineDevice.Vendor
                    NewVendor = $device.Vendor
                }
            }
        }
        
        # Find missing devices
        foreach ($baselineDevice in $baseline) {
            $currentDevice = $CurrentDevices | Where-Object { $_.IP -eq $baselineDevice.IP }
            if (-not $currentDevice) {
                $missingDevices += $baselineDevice
            }
        }
        
        return @{
            NewDevices = $newDevices
            MissingDevices = $missingDevices
            ChangedDevices = $changedDevices
            BaselineDate = (Get-Item $BaselineFilePath).LastWriteTime
        }
    } catch {
        Write-Log "Baseline comparison failed: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

# JSON Export Function (Enhancement 8)
function Export-JSONReport {
    param(
        [array]$DeviceData,
        [hashtable]$Statistics,
        [array]$Conflicts,
        [array]$SuspiciousDevices,
        [string]$OutputPath
    )
    
    $jsonData = @{
        ScanMetadata = @{
            Timestamp = Get-Date -Format 'o'
            Version = "2.0"
            IPRange = "$baseIP.$startOctet.1 - $baseIP.$endOctet.254"
            ScanDuration = $Statistics.ScanDuration
        }
        Statistics = $Statistics
        Devices = $DeviceData
        Conflicts = $Conflicts
        SuspiciousDevices = $SuspiciousDevices
        VendorDistribution = ($DeviceData | Group-Object -Property Vendor | Sort-Object Count -Descending | ForEach-Object {
            @{ Vendor = $_.Name; Count = $_.Count }
        })
    }
    
    try {
        $jsonData | ConvertTo-Json -Depth 4 | Out-File -FilePath $OutputPath -Encoding utf8
        Write-Host "📄 JSON report exported: $OutputPath" -ForegroundColor Green
    } catch {
        Write-ErrorMessage "JSON export" $_
    }
}

# HTML Dashboard Generation Function (Enhancement 8)
function Export-HTMLDashboard {
    param(
        [array]$DeviceData,
        [hashtable]$Statistics,
        [array]$Conflicts,
        [array]$SuspiciousDevices,
        [hashtable]$ScanResults,
        [string]$OutputPath
    )
    
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Scan Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .stat-value { font-size: 2em; font-weight: bold; color: #667eea; }
        .chart-container { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 30px; }
        .device-table { width: 100%; border-collapse: collapse; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .device-table th, .device-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .device-table th { background: #667eea; color: white; }
        .alert { padding: 15px; margin: 10px 0; border-radius: 5px; }
        .alert-danger { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        .alert-warning { background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }
        .alert-success { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 0.8em; }
        .badge-high { background: #dc3545; color: white; }
        .badge-medium { background: #ffc107; color: black; }
        .badge-low { background: #28a745; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Network Scan Dashboard</h1>
            <p>Scan completed on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <p>IP Range: $($Statistics.IPRange) | Duration: $($Statistics.ScanDuration)</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Devices</h3>
                <div class="stat-value">$($DeviceData.Count)</div>
                <p>Active devices found</p>
            </div>
            <div class="stat-card">
                <h3>Network Utilization</h3>
                <div class="stat-value">$($Statistics.NetworkUtilization)%</div>
                <p>IP addresses in use</p>
            </div>
            <div class="stat-card">
                <h3>Unique Vendors</h3>
                <div class="stat-value">$($Statistics.UniqueVendors)</div>
                <p>Different manufacturers</p>
            </div>
            <div class="stat-card">
                <h3>Conflicts Detected</h3>
                <div class="stat-value">$($Conflicts.Count)</div>
                <p>MAC/IP conflicts</p>
            </div>
        </div>
        
        <div class="chart-container">
            <h3>Vendor Distribution</h3>
            <canvas id="vendorChart" width="400" height="200"></canvas>
        </div>
        
        <div class="chart-container">
            <h3>Security Analysis</h3>
            <canvas id="securityChart" width="400" height="200"></canvas>
        </div>
"@

    # Add conflicts section if any exist
    if ($Conflicts.Count -gt 0) {
        $htmlContent += @"
        <div class="alert alert-danger">
            <h4>⚠️ Network Conflicts Detected</h4>
            <p>$($Conflicts.Count) conflicts found that require immediate attention.</p>
        </div>
"@
    }

    # Add suspicious devices section if any exist
    if ($SuspiciousDevices.Count -gt 0) {
        $htmlContent += @"
        <div class="alert alert-warning">
            <h4>🚨 Suspicious Devices Detected</h4>
            <p>$($SuspiciousDevices.Count) devices flagged for security review.</p>
        </div>
"@
    }

    # Add device table
    $htmlContent += @"
        <div class="chart-container">
            <h3>Device Details</h3>
            <table class="device-table">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>MAC Address</th>
                        <th>Vendor</th>
                        <th>Hostname</th>
                        <th>OS Guess</th>
                        <th>Open Ports</th>
                        <th>Response Time</th>
                    </tr>
                </thead>
                <tbody>
"@

    foreach ($device in $DeviceData) {
        $hostname = if ($ScanResults -and $ScanResults[$device.IP]) { $ScanResults[$device.IP].Hostname } else { "N/A" }
        $osGuess = if ($ScanResults -and $ScanResults[$device.IP]) { $ScanResults[$device.IP].OSInfo.OSGuess } else { "Unknown" }
        $openPorts = if ($ScanResults -and $ScanResults[$device.IP]) { $ScanResults[$device.IP].OpenPorts -join ', ' } else { "N/A" }
        $responseTime = if ($ScanResults -and $ScanResults[$device.IP]) { "$($ScanResults[$device.IP].ResponseTime)ms" } else { "N/A" }
        
        $htmlContent += @"
                    <tr>
                        <td>$($device.IP)</td>
                        <td>$($device.MAC)</td>
                        <td>$($device.Vendor)</td>
                        <td>$hostname</td>
                        <td>$osGuess</td>
                        <td>$openPorts</td>
                        <td>$responseTime</td>
                    </tr>
"@
    }

    $htmlContent += @"
                </tbody>
            </table>
        </div>
        
        <script>
            // Vendor Distribution Chart
            const vendorData = {
                labels: [$((($DeviceData | Group-Object -Property Vendor | Sort-Object Count -Descending | Select-Object -First 10).Name | ForEach-Object { "'$_'" }) -join ',')],
                datasets: [{
                    data: [$((($DeviceData | Group-Object -Property Vendor | Sort-Object Count -Descending | Select-Object -First 10).Count) -join ',')],
                    backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', '#FF9F40', '#FF6384', '#C9CBCF', '#4BC0C0', '#FF6384']
                }]
            };
            
            new Chart(document.getElementById('vendorChart'), {
                type: 'doughnut',
                data: vendorData,
                options: {
                    responsive: true,
                    plugins: {
                        legend: { position: 'right' }
                    }
                }
            });
            
            // Security Analysis Chart
            const securityData = {
                labels: ['Normal Devices', 'Suspicious Devices', 'Conflicts'],
                datasets: [{
                    data: [$($DeviceData.Count - $SuspiciousDevices.Count), $($SuspiciousDevices.Count), $($Conflicts.Count)],
                    backgroundColor: ['#28a745', '#ffc107', '#dc3545']
                }]
            };
            
            new Chart(document.getElementById('securityChart'), {
                type: 'bar',
                data: securityData,
                options: {
                    responsive: true,
                    scales: {
                        y: { beginAtZero: true }
                    }
                }
            });
        </script>
    </div>
</body>
</html>
"@

    try {
        $htmlContent | Out-File -FilePath $OutputPath -Encoding utf8
        Write-Host "📊 HTML Dashboard exported: $OutputPath" -ForegroundColor Green
        
        if ($OpenResults) {
            Start-Process $OutputPath
        }
    } catch {
        Write-ErrorMessage "HTML dashboard export" $_
    }
}

# XML Export Function (Enhancement 8)
function Export-XMLReport {
    param(
        [array]$DeviceData,
        [hashtable]$Statistics,
        [array]$Conflicts,
        [array]$SuspiciousDevices,
        [string]$OutputPath
    )
    
    try {
        $xmlDoc = New-Object System.Xml.XmlDocument
        $root = $xmlDoc.CreateElement("NetworkScanReport")
        $xmlDoc.AppendChild($root)
        
        # Add metadata
        $metadata = $xmlDoc.CreateElement("Metadata")
        $metadata.SetAttribute("ScanDate", (Get-Date -Format 'o'))
        $metadata.SetAttribute("Version", "2.0")
        $metadata.SetAttribute("IPRange", $Statistics.IPRange)
        $root.AppendChild($metadata)
        
        # Add statistics
        $stats = $xmlDoc.CreateElement("Statistics")
        foreach ($key in $Statistics.Keys) {
            $stat = $xmlDoc.CreateElement($key)
            $stat.InnerText = $Statistics[$key]
            $stats.AppendChild($stat)
        }
        $root.AppendChild($stats)
        
        # Add devices
        $devices = $xmlDoc.CreateElement("Devices")
        foreach ($device in $DeviceData) {
            $deviceElement = $xmlDoc.CreateElement("Device")
            $deviceElement.SetAttribute("IP", $device.IP)
            $deviceElement.SetAttribute("MAC", $device.MAC)
            $deviceElement.SetAttribute("Vendor", $device.Vendor)
            $deviceElement.SetAttribute("Type", $device.Type)
            $devices.AppendChild($deviceElement)
        }
        $root.AppendChild($devices)
        
        $xmlDoc.Save($OutputPath)
        Write-Host "📄 XML report exported: $OutputPath" -ForegroundColor Green
    } catch {
        Write-ErrorMessage "XML export" $_
    }
}

# Advanced Threat Detection Function (Enhancement 10)
function Invoke-AdvancedThreatDetection {
    param(
        [array]$DeviceData,
        [hashtable]$ScanResults
    )
    
    if (-not $DeepSecurityScan) {
        return @()
    }
    
    Write-Host "`n🔍 Running Advanced Threat Detection..." -ForegroundColor Cyan
    
    $threats = @()
    
    foreach ($device in $DeviceData) {
        $threatLevel = "LOW"
        $indicators = @()
        
        # Check for suspicious port combinations
        if ($ScanResults[$device.IP] -and $ScanResults[$device.IP].OpenPorts) {
            $openPorts = $ScanResults[$device.IP].OpenPorts
            
            # Check for common attack patterns
            if ($openPorts -contains 22 -and $openPorts -contains 23) {
                $indicators += "SSH and Telnet both open (potential backdoor)"
                $threatLevel = "HIGH"
            }
            
            if ($openPorts -contains 135 -and $openPorts -contains 445 -and $openPorts -contains 139) {
                $indicators += "Full Windows SMB stack exposed"
                $threatLevel = "MEDIUM"
            }
            
            if ($openPorts.Count -gt 10) {
                $indicators += "Unusually high number of open ports ($($openPorts.Count))"
                $threatLevel = "MEDIUM"
            }
        }
        
        # Check for MAC address anomalies
        if ($device.MAC -match "^(de-ad-be|ba-ad-f0|ca-fe-ba)") {
            $indicators += "MAC address in known attack range"
            $threatLevel = "HIGH"
        }
        
        # Check for rapid IP changes (if we had historical data)
        if ($device.Vendor -eq "Unknown" -and $ScanResults[$device.IP].ResponseTime -lt 1) {
            $indicators += "Unknown vendor with suspiciously fast response"
            $threatLevel = "MEDIUM"
        }
        
        if ($indicators.Count -gt 0) {
            $threats += [PSCustomObject]@{
                IP = $device.IP
                MAC = $device.MAC
                Vendor = $device.Vendor
                ThreatLevel = $threatLevel
                Indicators = $indicators -join "; "
                OpenPorts = if ($ScanResults[$device.IP]) { $ScanResults[$device.IP].OpenPorts -join "," } else { "" }
                Hostname = if ($ScanResults[$device.IP]) { $ScanResults[$device.IP].Hostname } else { "N/A" }
                Timestamp = Get-Date
            }
        }
    }
    
    if ($threats.Count -gt 0) {
        Write-Host "🚨 Advanced threat detection found $($threats.Count) potential threats" -ForegroundColor Red
        $threats | Export-Csv -Path "threat_analysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation
    } else {
        Write-Host "✅ Advanced threat detection: No immediate threats detected" -ForegroundColor Green
    }
    
    return $threats
}

# Get ARP entries matching our subnet range
try {
    $arpEntries = arp -a | Select-String "192\.168\.[$startOctet-$endOctet]\.\d+"
    Write-Log "Retrieved $($arpEntries.Count) ARP entries"
} catch {
    Write-ErrorMessage "ARP table retrieval" $_
    Write-Host "❌ Could not retrieve ARP table. Ensure you have appropriate permissions." -ForegroundColor Red
    exit 1
}

Write-Host "`n📊 Found $($arpEntries.Count) active devices in ARP table" -ForegroundColor Cyan

# Create a lookup table from scan results
$scanResultsLookup = @{}
foreach ($result in $scanResults) {
    $scanResultsLookup[$result.IP] = $result
}

# Parse ARP entries and enhance with scan data
$parsed = $arpEntries | ForEach-Object {
    if ($_ -match "(\d+\.\d+\.\d+\.\d+)\s+([a-f0-9:-]+)\s+(\w+)") {
        $ip = $matches[1]
        $mac = $matches[2].ToLower()
        # Normalize MAC address format to ensure consistency
        $mac = $mac -replace '[:-]', '-'  # Convert : to -
        if ($mac.Length -lt 17) {
            Write-Log "Short MAC address detected: '$mac' for IP: $ip" -Level "WARNING"
        }
        
        $deviceObj = [PSCustomObject]@{
            IP   = $ip
            MAC  = $mac
            Type = $matches[3]
        }
        
        # Add enhanced scan data if available
        if ($scanResultsLookup.ContainsKey($ip)) {
            $scanData = $scanResultsLookup[$ip]
            $deviceObj | Add-Member -NotePropertyName "ResponseTime" -NotePropertyValue $scanData.ResponseTime
            $deviceObj | Add-Member -NotePropertyName "OpenPorts" -NotePropertyValue ($scanData.OpenPorts -join ',')
            $deviceObj | Add-Member -NotePropertyName "Hostname" -NotePropertyValue $scanData.Hostname
            $deviceObj | Add-Member -NotePropertyName "OSGuess" -NotePropertyValue $scanData.OSInfo.OSGuess
            $deviceObj | Add-Member -NotePropertyName "TTL" -NotePropertyValue $scanData.OSInfo.TTL
        } else {
            # Add default values for devices not caught in enhanced scan
            $deviceObj | Add-Member -NotePropertyName "ResponseTime" -NotePropertyValue 0
            $deviceObj | Add-Member -NotePropertyName "OpenPorts" -NotePropertyValue ""
            $deviceObj | Add-Member -NotePropertyName "Hostname" -NotePropertyValue "N/A"
            $deviceObj | Add-Member -NotePropertyName "OSGuess" -NotePropertyValue "Unknown"
            $deviceObj | Add-Member -NotePropertyName "TTL" -NotePropertyValue 0
        }
        
        return $deviceObj
    }
}

# Get vendor information for MAC addresses (first 3 octets)
$vendorInfo = @{}
$parsed | ForEach-Object {
    $oui = Get-OUI $_.MAC
    
    if (-not $vendorInfo.ContainsKey($oui)) {
        # Expanded vendor OUI database
        $vendors = @{
            "00-1b-63" = "Apple"
            "00-50-56" = "VMware"
            "08-00-27" = "VirtualBox"
            "00-0c-29" = "VMware"
            "00-15-5d" = "Microsoft"
            "00-16-3e" = "Xen"
            "52-54-00" = "QEMU"
            "00-1a-a0" = "Dell"
            "00-14-22" = "Dell"
            "00-1d-09" = "Dell"
            "00-23-ae" = "Dell"
            "00-26-b9" = "Dell"
            "00-0d-56" = "HP"
            "00-1b-78" = "HP"
            "00-1f-29" = "HP"
            "00-25-b3" = "HP"
            "00-30-6e" = "HP"
            "00-03-47" = "Intel"
            "00-15-17" = "Intel"
            "00-1b-21" = "Intel"
            "00-1e-67" = "Intel"
            "00-21-6a" = "Intel"
            "00-04-76" = "3Com"
            "00-50-04" = "3Com"
            "00-a0-24" = "3Com"
            "00-10-5a" = "3Com"
            "00-20-af" = "3Com"
            "00-0b-db" = "Cisco"
            "00-17-94" = "Cisco"
            "00-1a-a2" = "Cisco"
            "00-1c-0e" = "Cisco"
            "00-23-04" = "Cisco"
            "00-d0-2b" = "Cisco"
            "00-e0-1e" = "Cisco"
            "00-07-eb" = "D-Link"
            "00-15-e9" = "D-Link"
            "00-17-9a" = "D-Link"
            "00-1b-11" = "D-Link"
            "00-1c-f0" = "D-Link"
            "00-22-b0" = "D-Link"
            "00-26-5a" = "D-Link"
            "00-05-5d" = "Netgear"
            "00-09-5b" = "Netgear"
            "00-0f-b5" = "Netgear"
            "00-14-6c" = "Netgear"
            "00-1b-2f" = "Netgear"
            "00-1e-2a" = "Netgear"
            "00-22-3f" = "Netgear"
            "00-26-f2" = "Netgear"
            "00-13-10" = "Linksys"
            "00-16-b6" = "Linksys"
            "00-18-39" = "Linksys"
            "00-1a-70" = "Linksys"
            "00-1c-10" = "Linksys"
            "00-1d-7e" = "Linksys"
            "00-21-29" = "Linksys"
            "00-22-6b" = "Linksys"
            "00-25-9c" = "Linksys"
            "00-14-bf" = "Asus"
            "00-17-31" = "Asus"
            "00-1a-92" = "Asus"
            "00-1f-c6" = "Asus"
            "00-22-15" = "Asus"
            "00-23-54" = "Asus"
            "00-26-18" = "Asus"
            "00-04-ac" = "IBM"
            "00-06-29" = "IBM"
            "00-0e-7f" = "IBM"
            "00-11-25" = "IBM"
            "00-16-35" = "IBM"
            "00-1a-64" = "IBM"
            "00-21-5e" = "IBM"
        }
        $vendorInfo[$oui] = $vendors[$oui] ?? "Unknown"
    }
}

# Add vendor info to parsed data
$parsed | ForEach-Object {
    $oui = Get-OUI $_.MAC
    $_ | Add-Member -NotePropertyName "Vendor" -NotePropertyValue $vendorInfo[$oui]
}

# Enhanced Statistics Collection
$scanEnd = Get-Date
$duration = $scanEnd - $scanStart
$statistics = @{
    IPRange = "$baseIP.$startOctet.1 - $baseIP.$endOctet.254"
    TotalIPsScanned = $totalIPs
    ActiveDevices = $parsed.Count
    NetworkUtilization = [math]::Round(($parsed.Count / $totalIPs) * 100, 2)
    UniqueVendors = $vendorInfo.Keys.Count
    ScanDuration = $duration.ToString('hh\:mm\:ss')
    ThreadingMode = if ($useMultithreading) { "Multi ($maxThreads threads)" } else { "Single" }
    PortScanEnabled = $PortScan
    DNSLookupEnabled = $ReverseDNS
    OSFingerprintEnabled = $OSFingerprint
}

# Show enhanced device summary
Write-Host "`n📋 Enhanced Device Summary:" -ForegroundColor Magenta
$parsed | Group-Object -Property Vendor | Sort-Object Count -Descending | ForEach-Object {
    Write-Host " → $($_.Name): $($_.Count) devices" -ForegroundColor White
}

if ($PortScan) {
    $devicesWithPorts = $parsed | Where-Object { $_.OpenPorts -and $_.OpenPorts -ne "" }
    Write-Host " → Devices with open ports: $($devicesWithPorts.Count)" -ForegroundColor Cyan
}

if ($ReverseDNS) {
    $devicesWithHostnames = $parsed | Where-Object { $_.Hostname -and $_.Hostname -ne "N/A" }
    Write-Host " → Devices with hostnames: $($devicesWithHostnames.Count)" -ForegroundColor Cyan
}

if ($OSFingerprint) {
    $devicesWithOS = $parsed | Where-Object { $_.OSGuess -and $_.OSGuess -ne "Unknown" }
    Write-Host " → Devices with OS detection: $($devicesWithOS.Count)" -ForegroundColor Cyan
}

# Export enhanced data in multiple formats
Write-Host "`n💾 Exporting results in multiple formats..." -ForegroundColor Cyan

# CSV Export (enhanced)
try {
    $parsed | Export-Csv -Path $OutputFile -NoTypeInformation -Force
    Write-Host " ✅ CSV exported: $OutputFile" -ForegroundColor Green
    Write-Log "Enhanced results exported to $OutputFile"
} catch {
    Write-ErrorMessage "Enhanced CSV export" $_
}

# JSON Export
if ("JSON" -in $OutputFormat) {
    $jsonFile = $OutputFile -replace '\.csv$', '.json'
    Export-JSONReport -DeviceData $parsed -Statistics $statistics -Conflicts @() -SuspiciousDevices @() -OutputPath $jsonFile
}

# XML Export
if ("XML" -in $OutputFormat) {
    $xmlFile = $OutputFile -replace '\.csv$', '.xml'
    Export-XMLReport -DeviceData $parsed -Statistics $statistics -Conflicts @() -SuspiciousDevices @() -OutputPath $xmlFile
}

# Continue with original conflict analysis but enhanced...
$conflicts = $parsed | Group-Object -Property MAC | Where-Object { $_.Count -gt 1 }
$ipConflicts = $parsed | Group-Object -Property IP | Where-Object { $_.Count -gt 1 }

# Enhanced Security Analysis
Write-Host "`n🔍 Enhanced Conflict Analysis:" -ForegroundColor Magenta

if ($conflicts) {
    Write-Host "`n⚠️  MAC Address Conflicts Detected! (Same MAC, Multiple IPs)" -ForegroundColor Yellow
    $conflictDetails = @()
    
    foreach ($group in $conflicts) {
        $vendor = $group.Group[0].Vendor
        $macAddress = $group.Name
        $ipCount = $group.Count
        
        Write-Host "`n🔴 CONFLICT #$($conflicts.IndexOf($group) + 1)" -ForegroundColor Red
        Write-Host "   MAC Address: $macAddress" -ForegroundColor Cyan
        Write-Host "   Vendor: $vendor" -ForegroundColor White
        Write-Host "   Conflict Type: One device claiming multiple IP addresses" -ForegroundColor Red
        Write-Host "   Impact Level: $(if ($ipCount -gt 3) { "HIGH" } elseif ($ipCount -gt 2) { "MEDIUM" } else { "LOW" })" -ForegroundColor $(if ($ipCount -gt 3) { "Red" } elseif ($ipCount -gt 2) { "Yellow" } else { "DarkYellow" })
        Write-Host "   Associated IPs ($ipCount total):" -ForegroundColor White
        
        $group.Group | Sort-Object IP | ForEach-Object {
            $portInfo = if ($_.OpenPorts) { " | Ports: $($_.OpenPorts)" } else { "" }
            $hostnameInfo = if ($_.Hostname -ne "N/A") { " | Host: $($_.Hostname)" } else { "" }
            Write-Host "      → $($_.IP) (Type: $($_.Type))$portInfo$hostnameInfo" -ForegroundColor Gray
        }
        
        # Enhanced conflict analysis
        Write-Host "   Enhanced Analysis:" -ForegroundColor Yellow
        if ($vendor -match "VMware|VirtualBox|QEMU|Microsoft") {
            Write-Host "      • Virtual machine with multiple network interfaces" -ForegroundColor Gray
        }
        if ($ipCount -gt 5) {
            Write-Host "      • Device performing network scanning or attacks" -ForegroundColor Gray
        }
        Write-Host "      • DHCP lease conflicts or rapid IP changes" -ForegroundColor Gray
        Write-Host "      • Network bridge or router with multiple interfaces" -ForegroundColor Gray
        Write-Host "      • MAC address spoofing attempt" -ForegroundColor Gray
        
        $conflictDetails += [PSCustomObject]@{
            ConflictType = "MAC_CONFLICT"
            MAC = $macAddress
            Vendor = $vendor
            IPCount = $ipCount
            IPs = ($group.Group.IP -join "; ")
            ImpactLevel = if ($ipCount -gt 3) { "HIGH" } elseif ($ipCount -gt 2) { "MEDIUM" } else { "LOW" }
            Timestamp = Get-Date
        }
    }
    
    $conflictDetails | Export-Csv -Path "mac_conflicts_$OutputFile" -NoTypeInformation -Force
    Write-Host "`n📄 MAC conflict details exported to: mac_conflicts_$OutputFile" -ForegroundColor Cyan
} else {
    Write-Host "`n✅ No MAC address conflicts detected" -ForegroundColor Green
}

# Run advanced security scans
$threats = Invoke-AdvancedThreatDetection -DeviceData $parsed -ScanResults $scanResultsLookup

# Run DHCP detection if enabled
if ($DetectRogueDHCP) {
    $dhcpAnalysis = Test-RogueDHCP
    if ($dhcpAnalysis -and $dhcpAnalysis.RogueServers.Count -gt 0) {
        Write-Host "`n🚨 Rogue DHCP Servers Detected!" -ForegroundColor Red
        foreach ($rogueServer in $dhcpAnalysis.RogueServers) {
            Write-Host "   → $rogueServer" -ForegroundColor Yellow
        }
    }
}

# Run baseline comparison if enabled
if ($BaselineComparison -and $BaselineFile) {
    $baselineAnalysis = Compare-NetworkBaseline -CurrentDevices $parsed -BaselineFilePath $BaselineFile
    if ($baselineAnalysis) {
        Write-Host "`n📊 Baseline Comparison Results:" -ForegroundColor Cyan
        Write-Host "   • New devices: $($baselineAnalysis.NewDevices.Count)" -ForegroundColor Green
        Write-Host "   • Missing devices: $($baselineAnalysis.MissingDevices.Count)" -ForegroundColor Yellow
        Write-Host "   • Changed devices: $($baselineAnalysis.ChangedDevices.Count)" -ForegroundColor Red
    }
}

# Generate HTML Dashboard if requested
if ($GenerateDashboard -or "HTML" -in $OutputFormat) {
    $htmlFile = $OutputFile -replace '\.csv$', '.html'
    Export-HTMLDashboard -DeviceData $parsed -Statistics $statistics -Conflicts $conflicts -SuspiciousDevices $threats -ScanResults $scanResultsLookup -OutputPath $htmlFile
}

# Final enhanced summary
Write-Host "`n📈 Enhanced Network Statistics:" -ForegroundColor Magenta
Write-Host " → Total IPs scanned: $($statistics.TotalIPsScanned)" -ForegroundColor White
Write-Host " → Active devices found: $($statistics.ActiveDevices)" -ForegroundColor White
Write-Host " → Network utilization: $($statistics.NetworkUtilization)%" -ForegroundColor White
Write-Host " → Unique vendors: $($statistics.UniqueVendors)" -ForegroundColor White
Write-Host " → Scan duration: $($statistics.ScanDuration)" -ForegroundColor White
Write-Host " → Threading mode: $($statistics.ThreadingMode)" -ForegroundColor White

if ($PortScan) {
    $totalOpenPorts = ($parsed | Where-Object { $_.OpenPorts } | ForEach-Object { $_.OpenPorts.Split(',') }).Count
    Write-Host " → Total open ports found: $totalOpenPorts" -ForegroundColor White
}

Write-Host "`n📄 Generated Enhanced Reports:" -ForegroundColor Magenta
Write-Host "   📊 Main Results: $OutputFile" -ForegroundColor White
if ("JSON" -in $OutputFormat) {
    Write-Host "   📋 JSON Report: $($OutputFile -replace '\.csv$', '.json')" -ForegroundColor White
}
if ("XML" -in $OutputFormat) {
    Write-Host "   📋 XML Report: $($OutputFile -replace '\.csv$', '.xml')" -ForegroundColor White
}
if ($GenerateDashboard -or "HTML" -in $OutputFormat) {
    Write-Host "   📊 HTML Dashboard: $($OutputFile -replace '\.csv$', '.html')" -ForegroundColor White
}

Write-Log "Enhanced network scan completed successfully"
Write-Host "`n🎯 Enhanced Network Scanner v2.0 - Scan Complete!" -ForegroundColor Green
Write-Host "✨ Advanced features provided comprehensive network analysis" -ForegroundColor Cyan
