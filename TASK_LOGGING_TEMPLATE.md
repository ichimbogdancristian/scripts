# TASK EXTENSIVE LOGGING TEMPLATE

This template provides the standard structure for implementing extensive logging in all system maintenance tasks.

## Template Structure

```powershell
function Invoke-TaskX_TaskName {
    param([hashtable]$Context)
    
    # Initialize extensive task logging
    Start-TaskLog -Context $Context -TaskName "Task X: Task Name" -TaskDescription "Description of what this task does" -Parameters @{
        "Parameter1" = $value1
        "Parameter2" = $value2
        "TaskFolder" = $Context.CurrentTaskFolder
    }
    
    # Initialize error tracking and results
    $errors = @()
    $results = @{}
    
    try {
        Write-Host "=====================[ TASK X: TASK NAME ]===================="
        Write-Log -Context $Context -Message "=====================[ TASK X: TASK NAME ]====================" -Level 'INFO'
        
        # ═══════════════════════════════════════════════════════════════════════════════════
        # TASK INITIALIZATION SECTION
        # ═══════════════════════════════════════════════════════════════════════════════════
        Write-TaskSection -Context $Context -SectionName "TASK_INITIALIZATION" -Message "Setting up task environment and parameters"
        
        Write-ExecutionStep -Context $Context -StepName "Environment Setup" -Action "Initialize task variables and validate prerequisites" -Result "Task initialized successfully"
        
        # Capture pre-execution state
        $preState = @{
            "SystemInfo" = "Relevant system information before task execution"
            "ResourceState" = "Current resource usage or relevant metrics"
            "ConfigurationState" = "Current configuration state"
        }
        Write-StateSnapshot -Context $Context -SnapshotType "PRE_EXECUTION" -StateData $preState
        
        # ═══════════════════════════════════════════════════════════════════════════════════
        # MAIN TASK EXECUTION SECTIONS
        # ═══════════════════════════════════════════════════════════════════════════════════
        Write-TaskSection -Context $Context -SectionName "MAIN_EXECUTION" -Message "Performing primary task operations"
        
        # Example of execution step logging
        Write-ExecutionStep -Context $Context -StepName "Step Name" -Action "Description of what this step does"
        
        try {
            # Actual task implementation here
            # ...
            
            Write-ExecutionStep -Context $Context -StepName "Step Name" -Action "Step description" -Result "SUCCESS - Step completed successfully"
            $results.Add("StepResult", "SUCCESS")
            
        } catch {
            $errorMsg = "Step failed: $($_.Exception.Message)"
            $errors += $errorMsg
            Write-ExecutionStep -Context $Context -StepName "Step Name" -Action "Step description" -Result $errorMsg -Level "ERROR"
            $results.Add("StepResult", "FAILED")
        }
        
        # Additional sections as needed for the specific task
        # Write-TaskSection -Context $Context -SectionName "ADDITIONAL_SECTION" -Message "Additional operations"
        
        # Capture post-execution state
        $postState = @{
            "SystemInfoAfter" = "System information after task execution"
            "ResourceStateAfter" = "Resource usage after completion"
            "ConfigurationStateAfter" = "Configuration state after changes"
            "ChangesApplied" = "Summary of changes made"
        }
        Write-StateSnapshot -Context $Context -SnapshotType "POST_EXECUTION" -StateData $postState
        
    } catch {
        $errorMsg = "Critical error in Task X: $($_.Exception.Message)"
        $errors += $errorMsg
        Write-ExecutionStep -Context $Context -StepName "Task Execution" -Action "Complete task execution" -Result $errorMsg -Level "ERROR"
    } finally {
        # Complete the task log with comprehensive summary
        $status = if ($errors.Count -eq 0) { "COMPLETED_SUCCESS" } else { "COMPLETED_WITH_ERRORS" }
        
        Complete-TaskLog -Context $Context -TaskName "Task X: Task Name" -Status $status -Summary $results -Errors $errors -NextSteps "Proceed to next task or final steps"
        
        Write-Log -Context $Context -Message "Task X: Task Name completed with status: $status" -Level 'INFO'
    }
}
```

## Key Implementation Guidelines

### 1. Task Initialization
- Always use `Start-TaskLog` to begin extensive logging
- Capture all relevant parameters and environment information
- Initialize error tracking and results collection

### 2. Section Organization
- Use `Write-TaskSection` for major logical sections
- Follow the standardized section naming convention
- Provide descriptive messages for each section

### 3. Execution Step Logging
- Log every significant operation with `Write-ExecutionStep`
- Include step name, action description, and result
- Use appropriate log levels (INFO, WARNING, ERROR, SUCCESS)

### 4. State Management
- Capture system state before and after execution
- Use `Write-StateSnapshot` for comprehensive state recording
- Include relevant metrics and configuration data

### 5. Error Handling
- Track all errors in the `$errors` array
- Log errors with appropriate context
- Continue execution where possible, but record failures

### 6. Results Tracking
- Store all significant results in `$results` hashtable
- Include success/failure counts, processed items, etc.
- Provide quantitative metrics where applicable

### 7. Task Completion
- Always use `Complete-TaskLog` in the finally block
- Provide comprehensive summary of all operations
- Include next steps or recommendations

## Standard Section Names

Use these standardized section names for consistency:

- **TASK_INITIALIZATION** - Setup and parameter validation
- **PREREQUISITE_CHECK** - Verify dependencies and requirements
- **PRE_EXECUTION_STATE** - System state before changes
- **MAIN_EXECUTION** - Primary task operations
- **VALIDATION** - Verify results and success
- **POST_EXECUTION_STATE** - System state after changes
- **CLEANUP** - Temporary file cleanup and resource release
- **ERROR_HANDLING** - Error processing and recovery
- **PERFORMANCE_METRICS** - Timing and resource usage
- **RESULTS_SUMMARY** - Final results and accomplishments

## Error Handling Best Practices

1. **Capture Context**: Include relevant system information with errors
2. **Categorize Errors**: Use appropriate error levels and categories
3. **Recovery Actions**: Document what recovery steps were attempted
4. **Impact Assessment**: Note the impact of errors on overall task success
5. **Troubleshooting Info**: Provide information useful for debugging

## Results Documentation

Track these types of results:
- Items processed (count, success rate)
- System changes made
- Configuration modifications
- Files created/modified/deleted
- Services started/stopped/modified
- Registry changes
- Network changes
- Performance improvements

## Implementation Checklist

- [ ] Task initialized with `Start-TaskLog`
- [ ] Error tracking array initialized
- [ ] Results hashtable initialized
- [ ] Pre-execution state captured
- [ ] All major sections use `Write-TaskSection`
- [ ] All significant steps use `Write-ExecutionStep`
- [ ] Errors properly logged and tracked
- [ ] Post-execution state captured
- [ ] Task completed with `Complete-TaskLog`
- [ ] Proper error handling in try/catch/finally blocks
- [ ] Meaningful section names and descriptions
- [ ] Appropriate log levels used throughout
