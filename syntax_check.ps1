# PowerShell Syntax Validation Script
try {
    $scriptPath = "c:\Users\Bogdan\OneDrive\Desktop\Projects\Windows\script_mentenanta\system_maintenance.ps1"
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Parse the script to check for syntax errors
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($scriptContent, [ref]$tokens, [ref]$errors)
    
    if ($errors.Count -eq 0) {
        Write-Host "Script syntax is valid - no parse errors found" -ForegroundColor Green
        
        # Check for common patterns that might indicate issues
        $warnings = @()
        
        # Check for unclosed braces
        $openBraces = ($scriptContent -split '' | Where-Object { $_ -eq '{' }).Count
        $closeBraces = ($scriptContent -split '' | Where-Object { $_ -eq '}' }).Count
        if ($openBraces -ne $closeBraces) {
            $warnings += "Unmatched braces: $openBraces open, $closeBraces close"
        }
        
        # Check for basic function structure
        $functions = $tokens | Where-Object { $_.Kind -eq 'Function' }
        Write-Host "Found $($functions.Count) function definitions" -ForegroundColor Cyan
        
        if ($warnings.Count -gt 0) {
            Write-Host "Warnings found:" -ForegroundColor Yellow
            $warnings | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
        } else {
            Write-Host "No structural warnings found" -ForegroundColor Green
        }
        
    } else {
        Write-Host "Script has syntax errors:" -ForegroundColor Red
        $errors | ForEach-Object {
            Write-Host "Line $($_.Extent.StartLineNumber): $($_.Message)" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "Error validating script: $_" -ForegroundColor Red
}
