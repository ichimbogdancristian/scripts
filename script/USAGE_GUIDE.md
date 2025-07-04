# 🎯 Enhanced Network Scanner - Usage Guide

## All-in-One Comprehensive Scan (Recommended!)

For the most complete network analysis with ALL features enabled:

```powershell
.\network_enhanced.ps1 -ComprehensiveScan
```

This single command enables:
- ✅ Port scanning (21 common ports)
- ✅ Reverse DNS lookup
- ✅ OS fingerprinting
- ✅ Deep security analysis
- ✅ Rogue DHCP detection
- ✅ Adaptive threading
- ✅ HTML dashboard with charts
- ✅ Multiple output formats (CSV, JSON, HTML)
- ✅ Enhanced performance settings

## Other Usage Examples

### Basic Enhanced Scan
```powershell
.\network_enhanced.ps1 -PortScan -ReverseDNS -OSFingerprint
```

### Interactive Comprehensive Scan
```powershell
.\network_enhanced.ps1 -ComprehensiveScan -Interactive
```

### Comprehensive Scan with Custom Settings
```powershell
.\network_enhanced.ps1 -ComprehensiveScan -MaxThreads 100 -SubnetBase "10.0.0"
```

### Security-Focused Scan
```powershell
.\network_enhanced.ps1 -DeepSecurityScan -DetectRogueDHCP -PortScan
```

### Preview Mode (No Actual Scanning)
```powershell
.\network_enhanced.ps1 -ComprehensiveScan -WhatIf
```

## Output Files

The comprehensive scan generates:
- `network_scan_results.csv` - Main device data
- `network_scan_results.json` - Structured data export
- `network_scan_results.html` - Interactive dashboard 📊
- `threat_analysis_*.csv` - Security threat analysis
- `network_scan_log.txt` - Detailed execution log

## Pro Tips

1. **Start with Comprehensive Scan**: `.\network_enhanced.ps1 -ComprehensiveScan`
2. **Open the HTML Dashboard** for best visualization experience
3. **Use Interactive Mode** for first-time setup: `-Interactive`
4. **Save profiles** for repeated scans: `-SaveProfile`
5. **Compare with baselines** for change detection: `-BaselineComparison`

The comprehensive scan is designed to give you maximum network insights with minimal configuration!
