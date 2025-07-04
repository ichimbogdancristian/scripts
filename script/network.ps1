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

# HTML Dashboard Generation Function (Enhancement 8)
function New-HTMLDashboard {
    param(
        [array]$DeviceData,
        [hashtable]$Statistics,
        [array]$Conflicts = @(),
        [array]$SuspiciousDevices = @(),
        [string]$OutputPath
    )
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Scan Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .stat-number { font-size: 2em; font-weight: bold; color: #667eea; }
        .chart-container { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .device-table { width: 100%; border-collapse: collapse; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .device-table th, .device-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .device-table th { background-color: #667eea; color: white; }
        .alert { padding: 15px; margin: 10px 0; border-radius: 5px; }
        .alert-danger { background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        .alert-warning { background-color: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }
        .alert-success { background-color: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🌐 Network Scan Dashboard</h1>
        <p>Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>
    
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-number">$($Statistics.TotalDevices)</div>
            <div>Total Devices</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">$($Statistics.NetworkUtilization)%</div>
            <div>Network Utilization</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">$($Statistics.UniqueVendors)</div>
            <div>Unique Vendors</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">$($Conflicts.Count + $SuspiciousDevices.Count)</div>
            <div>Security Issues</div>
        </div>
    </div>
"@

    if ($Conflicts.Count -gt 0) {
        $html += '<div class="alert alert-danger"><strong>⚠️ Conflicts Detected:</strong> ' + $Conflicts.Count + ' MAC/IP conflicts found.</div>'
    }
    
    if ($SuspiciousDevices.Count -gt 0) {
        $html += '<div class="alert alert-warning"><strong>🚨 Suspicious Devices:</strong> ' + $SuspiciousDevices.Count + ' potentially suspicious devices detected.</div>'
    }
    
    if ($Conflicts.Count -eq 0 -and $SuspiciousDevices.Count -eq 0) {
        $html += '<div class="alert alert-success"><strong>✅ Network Health:</strong> No conflicts or suspicious devices detected.</div>'
    }

    # Add vendor distribution chart
    $vendorStats = $DeviceData | Group-Object -Property Vendor | Sort-Object Count -Descending | Select-Object -First 10
    $vendorLabels = ($vendorStats | ForEach-Object { "'$($_.Name)'" }) -join ','
    $vendorData = ($vendorStats | ForEach-Object { $_.Count }) -join ','

    $html += @"
    <div class="chart-container">
        <h3>Top 10 Vendors</h3>
        <canvas id="vendorChart" width="400" height="200"></canvas>
    </div>
    
    <script>
        const ctx = document.getElementById('vendorChart').getContext('2d');
        const vendorChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: [$vendorLabels],
                datasets: [{
                    data: [$vendorData],
                    backgroundColor: [
                        '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF',
                        '#FF9F40', '#FF6384', '#C9CBCF', '#4BC0C0', '#36A2EB'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'right'
                    }
                }
            }
        });
    </script>
</body>
</html>
"@

    try {
        $html | Out-File -FilePath $OutputPath -Encoding utf8
        Write-Host "📊 HTML Dashboard generated: $OutputPath" -ForegroundColor Green
        
        if ($OpenResults) {
            Start-Process $OutputPath
        }
    } catch {
        Write-ErrorMessage "HTML Dashboard generation" $_
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

# Interactive Mode Function (Enhancement 7)
function Start-InteractiveMode {
    if (-not $Interactive) {
        return
    }
    
    Write-Host "`n🎮 Interactive Mode" -ForegroundColor Magenta
    Write-Host "Current settings:" -ForegroundColor Cyan
    Write-Host "  Subnet: $SubnetBase.$startOctet.1 - $SubnetBase.$endOctet.254"
    Write-Host "  Threads: $maxThreads"
    Write-Host "  Port Scan: $PortScan"
    Write-Host "  DNS Lookup: $ReverseDNS"
    Write-Host "  OS Fingerprint: $OSFingerprint"
    
    $response = Read-Host "`nContinue with these settings? (Y/n)"
    if ($response -eq 'n' -or $response -eq 'N') {
        Write-Host "Scan cancelled by user." -ForegroundColor Yellow
        exit 0
    }
}

# WhatIf Mode Function (Enhancement 7)
function Show-WhatIfPreview {
    if (-not $WhatIf) {
        return
    }
    
    Write-Host "`n🔍 WhatIf Mode - Preview Only" -ForegroundColor Yellow
    Write-Host "Would scan IP range: $baseIP.$startOctet.1 - $baseIP.$endOctet.254"
    Write-Host "Total IPs to scan: $totalIPs"
    Write-Host "Threading: $(if ($useMultithreading) { "Multi ($maxThreads threads)" } else { "Single" })"
    Write-Host "Port scanning: $PortScan"
    Write-Host "DNS lookup: $ReverseDNS"
    Write-Host "OS fingerprinting: $OSFingerprint"
    Write-Host "Output formats: $($OutputFormat -join ', ')"
    Write-Host "`nNo actual scanning will be performed in WhatIf mode." -ForegroundColor Green
    exit 0
}

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

# HTML Dashboard Generation Function (Enhancement 8)
function New-HTMLDashboard {
    param(
        [array]$DeviceData,
        [hashtable]$Statistics,
        [array]$Conflicts = @(),
        [array]$SuspiciousDevices = @(),
        [string]$OutputPath
    )
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Scan Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .stat-number { font-size: 2em; font-weight: bold; color: #667eea; }
        .chart-container { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .device-table { width: 100%; border-collapse: collapse; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .device-table th, .device-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .device-table th { background-color: #667eea; color: white; }
        .alert { padding: 15px; margin: 10px 0; border-radius: 5px; }
        .alert-danger { background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        .alert-warning { background-color: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }
        .alert-success { background-color: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🌐 Network Scan Dashboard</h1>
        <p>Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>
    
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-number">$($Statistics.TotalDevices)</div>
            <div>Total Devices</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">$($Statistics.NetworkUtilization)%</div>
            <div>Network Utilization</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">$($Statistics.UniqueVendors)</div>
            <div>Unique Vendors</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">$($Conflicts.Count + $SuspiciousDevices.Count)</div>
            <div>Security Issues</div>
        </div>
    </div>
"@

    if ($Conflicts.Count -gt 0) {
        $html += '<div class="alert alert-danger"><strong>⚠️ Conflicts Detected:</strong> ' + $Conflicts.Count + ' MAC/IP conflicts found.</div>'
    }
    
    if ($SuspiciousDevices.Count -gt 0) {
        $html += '<div class="alert alert-warning"><strong>🚨 Suspicious Devices:</strong> ' + $SuspiciousDevices.Count + ' potentially suspicious devices detected.</div>'
    }
    
    if ($Conflicts.Count -eq 0 -and $SuspiciousDevices.Count -eq 0) {
        $html += '<div class="alert alert-success"><strong>✅ Network Health:</strong> No conflicts or suspicious devices detected.</div>'
    }

    # Add vendor distribution chart
    $vendorStats = $DeviceData | Group-Object -Property Vendor | Sort-Object Count -Descending | Select-Object -First 10
    $vendorLabels = ($vendorStats | ForEach-Object { "'$($_.Name)'" }) -join ','
    $vendorData = ($vendorStats | ForEach-Object { $_.Count }) -join ','

    $html += @"
    <div class="chart-container">
        <h3>Top 10 Vendors</h3>
        <canvas id="vendorChart" width="400" height="200"></canvas>
    </div>
    
    <script>
        const ctx = document.getElementById('vendorChart').getContext('2d');
        const vendorChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: [$vendorLabels],
                datasets: [{
                    data: [$vendorData],
                    backgroundColor: [
                        '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF',
                        '#FF9F40', '#FF6384', '#C9CBCF', '#4BC0C0', '#36A2EB'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'right'
                    }
                }
            }
        });
    </script>
</body>
</html>
"@

    try {
        $html | Out-File -FilePath $OutputPath -Encoding utf8
        Write-Host "📊 HTML Dashboard generated: $OutputPath" -ForegroundColor Green
        
        if ($OpenResults) {
            Start-Process $OutputPath
        }
    } catch {
        Write-ErrorMessage "HTML Dashboard generation" $_
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

# Interactive Mode Function (Enhancement 7)
function Start-InteractiveMode {
    if (-not $Interactive) {
        return
    }
    
    Write-Host "`n🎮 Interactive Mode" -ForegroundColor Magenta
    Write-Host "Current settings:" -ForegroundColor Cyan
    Write-Host "  Subnet: $SubnetBase.$startOctet.1 - $SubnetBase.$endOctet.254"
    Write-Host "  Threads: $maxThreads"
    Write-Host "  Port Scan: $PortScan"
    Write-Host "  DNS Lookup: $ReverseDNS"
    Write-Host "  OS Fingerprint: $OSFingerprint"
    
    $response = Read-Host "`nContinue with these settings? (Y/n)"
    if ($response -eq 'n' -or $response -eq 'N') {
        Write-Host "Scan cancelled by user." -ForegroundColor Yellow
        exit 0
    }
}

# WhatIf Mode Function (Enhancement 7)
function Show-WhatIfPreview {
    if (-not $WhatIf) {
        return
    }
    
    Write-Host "`n🔍 WhatIf Mode - Preview Only" -ForegroundColor Yellow
    Write-Host "Would scan IP range: $baseIP.$startOctet.1 - $baseIP.$endOctet.254"
    Write-Host "Total IPs to scan: $totalIPs"
    Write-Host "Threading: $(if ($useMultithreading) { "Multi ($maxThreads threads)" } else { "Single" })"
    Write-Host "Port scanning: $PortScan"
    Write-Host "DNS lookup: $ReverseDNS"
    Write-Host "OS fingerprinting: $OSFingerprint"
    Write-Host "Output formats: $($OutputFormat -join ', ')"
    Write-Host "`nNo actual scanning will be performed in WhatIf mode." -ForegroundColor Green
    exit 0
}

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

# HTML Dashboard Generation Function (Enhancement 8)
function New-HTMLDashboard {
    param(
        [array]$DeviceData,
        [hashtable]$Statistics,
        [array]$Conflicts = @(),
        [array]$SuspiciousDevices = @(),
        [string]$OutputPath
    )
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Scan Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .stat-number { font-size: 2em; font-weight: bold; color: #667eea; }
        .chart-container { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .device-table { width: 100%; border-collapse: collapse; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .device-table th, .device-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .device-table th { background-color: #667eea; color: white; }
        .alert { padding: 15px; margin: 10px 0; border-radius: 5px; }
        .alert-danger { background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        .alert-warning { background-color: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }
        .alert-success { background-color: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🌐 Network Scan Dashboard</h1>
        <p>Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>
    
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-number">$($Statistics.TotalDevices)</div>
            <div>Total Devices</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">$($Statistics.NetworkUtilization)%</div>
            <div>Network Utilization</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">$($Statistics.UniqueVendors)</div>
            <div>Unique Vendors</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">$($Conflicts.Count + $SuspiciousDevices.Count)</div>
            <div>Security Issues</div>
        </div>
    </div>
"@

    if ($Conflicts.Count -gt 0) {
        $html += '<div class="alert alert-danger"><strong>⚠️ Conflicts Detected:</strong> ' + $Conflicts.Count + ' MAC/IP conflicts found.</div>'
    }
    
    if ($SuspiciousDevices.Count -gt 0) {
        $html += '<div class="alert alert-warning"><strong>🚨 Suspicious Devices:</strong> ' + $SuspiciousDevices.Count + ' potentially suspicious devices detected.</div>'
    }
    
    if ($Conflicts.Count -eq 0 -and $SuspiciousDevices.Count -eq 0) {
        $html += '<div class="alert alert-success"><strong>✅ Network Health:</strong> No conflicts or suspicious devices detected.</div>'
    }

    # Add vendor distribution chart
    $vendorStats = $DeviceData | Group-Object -Property Vendor | Sort-Object Count -Descending | Select-Object -First 10
    $vendorLabels = ($vendorStats | ForEach-Object { "'$($_.Name)'" }) -join ','
    $vendorData = ($vendorStats | ForEach-Object { $_.Count }) -join ','

    $html += @"
    <div class="chart-container">
        <h3>Top 10 Vendors</h3>
        <canvas id="vendorChart" width="400" height="200"></canvas>
    </div>
    
    <script>
        const ctx = document.getElementById('vendorChart').getContext('2d');
        const vendorChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: [$vendorLabels],
                datasets: [{
                    data: [$vendorData],
                    backgroundColor: [
                        '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF',
                        '#FF9F40', '#FF6384', '#C9CBCF', '#4BC0C0', '#36A2EB'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'right'
                    }
                }
            }
        });
    </script>
</body>
</html>
"@

    try {
        $html | Out-File -FilePath $OutputPath -Encoding utf8
        Write-Host "📊 HTML Dashboard generated: $OutputPath" -ForegroundColor Green
        
        if ($OpenResults) {
            Start-Process $OutputPath
        }
    } catch {
        Write-ErrorMessage "HTML Dashboard generation" $_
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

# Interactive Mode Function (Enhancement 7)
function Start-InteractiveMode {
    if (-not $Interactive) {
        return
    }
    
    Write-Host "`n🎮 Interactive Mode" -ForegroundColor Magenta
    Write-Host "Current settings:" -ForegroundColor Cyan
    Write-Host "  Subnet: $SubnetBase.$startOctet.1 - $SubnetBase.$endOctet.254"
    Write-Host "  Threads: $maxThreads"
    Write-Host "  Port Scan: $PortScan"
    Write-Host "  DNS Lookup: $ReverseDNS"
    Write-Host "  OS Fingerprint: $OSFingerprint"
    
    $response = Read-Host "`nContinue with these settings? (Y/n)"
    if ($response -eq 'n' -or $response -eq 'N') {
        Write-Host "Scan cancelled by user." -ForegroundColor Yellow
        exit 0
    }
}

# WhatIf Mode Function (Enhancement 7)
function Show-WhatIfPreview {
    if (-not $WhatIf) {
        return
    }
    
    Write-Host "`n🔍 WhatIf Mode - Preview Only" -ForegroundColor Yellow
    Write-Host "Would scan IP range: $baseIP.$startOctet.1 - $baseIP.$endOctet.254"
    Write-Host "Total IPs to scan: $totalIPs"
    Write-Host "Threading: $(if ($useMultithreading) { "Multi ($maxThreads threads)" } else { "Single" })"
    Write-Host "Port scanning: $PortScan"
    Write-Host "DNS lookup: $ReverseDNS"
    Write-Host "OS fingerprinting: $OSFingerprint"
    Write-Host "Output formats: $($OutputFormat -join ', ')"
    Write-Host "`nNo actual scanning will be performed in WhatIf mode." -ForegroundColor Green
    exit 0
}

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

# HTML Dashboard Generation Function (Enhancement 8)
function New-HTMLDashboard {
    param(
        [array]$DeviceData,
        [hashtable]$Statistics,
        [array]$Conflicts = @(),
        [array]$SuspiciousDevices = @(),
        [string]$OutputPath
    )
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Scan Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .stat-number { font-size: 2em; font-weight: bold; color: #667eea; }
        .chart-container { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0.1); margin-bottom: 20px; }
        .device-table { width: 100%; border-collapse: collapse; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .device-table th, .device-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .device-table th { background-color: #667eea; color: white; }
        .alert { padding: 15px; margin: 10px 0; border-radius: 5px; }
        .alert-danger { background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        .alert-warning { background-color: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }
        .alert-success { background-color: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🌐 Network Scan Dashboard</h1>
        <p>Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>
    
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-number">$($Statistics.TotalDevices)</div>
            <div>Total Devices</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">$($Statistics.NetworkUtilization)%</div>
            <div>Network Utilization</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">$($Statistics.UniqueVendors)</div>
            <div>Unique Vendors</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">$($Conflicts.Count + $SuspiciousDevices.Count)</div>
            <div>Security Issues</div>
        </div>
    </div>
"@

    if ($Conflicts.Count -gt 0) {
        $html += '<div class="alert alert-danger"><strong>⚠️ Conflicts Detected:</strong> ' + $Conflicts.Count + ' MAC/IP conflicts found.</div>'
    }
    
    if ($SuspiciousDevices.Count -gt 0) {
        $html += '<div class="alert alert-warning"><strong>🚨 Suspicious Devices:</strong> ' + $SuspiciousDevices.Count + ' potentially suspicious devices detected.</div>'
    }
    
    if ($Conflicts.Count -eq 0 -and $SuspiciousDevices.Count -eq 0) {
        $html += '<div class="alert alert-success"><strong>✅ Network Health:</strong> No conflicts or suspicious devices detected.</div>'
    }

    # Add vendor distribution chart
    $vendorStats = $DeviceData | Group-Object -Property Vendor | Sort-Object Count -Descending | Select-Object -First 10
    $vendorLabels = ($vendorStats | ForEach-Object { "'$($_.Name)'" }) -join ','
    $vendorData = ($vendorStats | ForEach-Object { $_.Count }) -join ','

    $html += @"
    <div class="chart-container">
        <h3>Top 10 Vendors</h3>
        <canvas id="vendorChart" width="400" height="200"></canvas>
    </div>
    
    <script>
        const ctx = document.getElementById('vendorChart').getContext('2d');
        const vendorChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: [$vendorLabels],
                datasets: [{
                    data: [$vendorData],
                    backgroundColor: [
                        '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF',
                        '#FF9F40', '#FF6384', '#C9CBCF', '#4BC0C0', '#36A2EB'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'right'
                    }
                }
            }
        });
    </script>
</body>
</html>
"@

    try {
        $html | Out-File -FilePath $OutputPath -Encoding utf8
        Write-Host "📊 HTML Dashboard generated: $OutputPath" -ForegroundColor Green
        
        if ($OpenResults) {
            Start-Process $OutputPath
        }
    } catch {
        Write-ErrorMessage "HTML Dashboard generation" $_
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

# Interactive Mode Function (Enhancement 7)
function Start-InteractiveMode {
    if (-not $Interactive) {
        return
    }
    
    Write-Host "`n🎮 Interactive Mode" -ForegroundColor Magenta
    Write-Host "Current settings:" -ForegroundColor Cyan
    Write-Host "  Subnet: $SubnetBase.$startOctet.1 - $SubnetBase.$endOctet.254"
    Write-Host "  Threads: $maxThreads"
    Write-Host "  Port Scan: $PortScan"
    Write-Host "  DNS Lookup: $ReverseDNS"
    Write-Host "  OS Fingerprint: $OSFingerprint"
    
    $response = Read-Host "`nContinue with these settings? (Y/n)"
    if ($response -eq 'n' -or $response -eq 'N') {
        Write-Host "Scan cancelled by user." -ForegroundColor Yellow
        exit 0
    }
}

# WhatIf Mode Function (Enhancement 7)
function Show-WhatIfPreview {
    if (-not $WhatIf) {
        return
    }
    
    Write-Host "`n🔍 WhatIf Mode - Preview Only" -ForegroundColor Yellow
    Write-Host "Would scan IP range: $baseIP.$startOctet.1 - $baseIP.$endOctet.254"
    Write-Host "Total IPs to scan: $totalIPs"
    Write-Host "Threading: $(if ($useMultithreading) { "Multi ($maxThreads threads)" } else { "Single" })"
    Write-Host "Port scanning: $PortScan"
    Write-Host "DNS lookup: $ReverseDNS"
    Write-Host "OS fingerprinting: $OSFingerprint"
    Write-Host "Output formats: $($OutputFormat -join ', ')"
    Write-Host "`nNo actual scanning will be performed in WhatIf mode." -ForegroundColor Green
    exit 0
}