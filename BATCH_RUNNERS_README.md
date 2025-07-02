# System Maintenance Script Runners

This folder contains several batch scripts to easily run the PowerShell system maintenance script with proper execution policies and administrative privileges.

## Files Created

### 1. `run_maintenance.bat` - GitHub Downloader
**Purpose**: Downloads the latest script from GitHub and executes it
**Features**:
- Downloads latest version from GitHub
- Sets unrestricted execution policy for session
- Interactive menu for common options
- Administrator privilege checking
- Cleanup options

**Usage**:
```cmd
# Right-click -> "Run as Administrator"
run_maintenance.bat
```

**Setup Required**:
1. Edit the batch file and update these variables:
   ```batch
   set GITHUB_URL=https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/%SCRIPT_NAME%
   ```
2. Replace `YOUR_USERNAME` and `YOUR_REPO` with your actual GitHub details

### 2. `run_maintenance_local.bat` - Local Script Runner
**Purpose**: Runs the local PowerShell script in the same directory
**Features**:
- Uses local script file
- Sets execution policy
- Simple options menu
- Forces PowerShell 5.1 usage

**Usage**:
```cmd
# Ensure system_maintenance_simplified.ps1 is in same directory
# Right-click -> "Run as Administrator"
run_maintenance_local.bat
```

### 3. `run_maintenance_advanced.bat` - Advanced Runner
**Purpose**: Most flexible option with both local and GitHub support
**Features**:
- Can use local OR download from GitHub
- Command-line arguments support
- Custom GitHub URL support
- Comprehensive options menu
- Detailed help system

**Usage**:
```cmd
# Basic usage (downloads from GitHub)
run_maintenance_advanced.bat

# Use local script
run_maintenance_advanced.bat -local

# Use custom GitHub URL
run_maintenance_advanced.bat -url "https://raw.githubusercontent.com/user/repo/main/script.ps1"
```

## Quick Start Guide

### For Local Testing:
1. Use `run_maintenance_local.bat`
2. Ensure `system_maintenance_simplified.ps1` is in the same folder
3. Right-click the .bat file -> "Run as Administrator"

### For GitHub Distribution:
1. Upload your PowerShell script to GitHub
2. Edit `run_maintenance.bat` or `run_maintenance_advanced.bat`
3. Update the GitHub URL variables
4. Distribute the .bat file to users

## Option Menu Guide

When you run any of the batch scripts, you'll see an interactive menu:

- **Option 1**: Basic maintenance (default) - Runs all standard tasks
- **Option 2**: With HTML report - Includes system tracking and generates HTML report
- **Option 3**: With JSON export - Exports system data to JSON format
- **Option 4**: With CSV export - Exports system data to CSV format
- **Option 5**: Skip bloatware removal - Skips removing Windows bloatware
- **Option 6**: Skip essential apps - Skips installing essential applications
- **Option 7**: Delete temp files - Removes temporary files after completion
- **Option 8**: Full tracking - Enables all tracking and reporting features
- **Option 9**: Custom parameters - Enter your own PowerShell parameters

## PowerShell Parameters Reference

The batch scripts support all PowerShell script parameters:

- `-DeleteTempFiles`: Clean up temp files after execution
- `-SkipBloatwareRemoval`: Skip bloatware removal
- `-SkipEssentialApps`: Skip essential apps installation
- `-GenerateReport`: Generate maintenance reports
- `-TrackChanges`: Track system changes before/after
- `-ExportToJson`: Export data to JSON
- `-ExportToCSV`: Export data to CSV
- `-CustomTasksFile "path"`: Load custom tasks from JSON file

## Troubleshooting

### "Script cannot be loaded because running scripts is disabled"
- The batch scripts automatically set execution policy for the session
- If this persists, run PowerShell as Administrator and execute:
  ```powershell
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
  ```

### "This script must be run as Administrator"
- Right-click the .bat file and select "Run as administrator"
- Do not double-click the .bat file

### GitHub Download Fails
- Check internet connection
- Verify the GitHub URL is correct
- Ensure the repository is public
- Try using the `-local` option instead

### PowerShell Version Issues
- The scripts force PowerShell 5.1 usage
- If you have PowerShell 7+ installed, it will still use 5.1 for compatibility

## Security Notes

- The batch scripts set `ExecutionPolicy Unrestricted` for the current session only
- This does not permanently change your system's execution policy
- Always run from a trusted source
- Review the PowerShell script before execution

## Examples

### Basic usage:
```cmd
run_maintenance_local.bat
# Select option 1 or just press Enter
```

### Full maintenance with tracking:
```cmd
run_maintenance_advanced.bat -local
# Select option 8 for full tracking
```

### Custom parameters:
```cmd
run_maintenance_advanced.bat
# Select option 9
# Enter: -TrackChanges -SkipBloatwareRemoval -ExportToJson
```
