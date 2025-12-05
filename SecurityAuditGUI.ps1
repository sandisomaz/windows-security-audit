<#
.SYNOPSIS
    Windows Security Audit Framework - GUI Application
.DESCRIPTION
    Graphical user interface for the security audit tool
    Makes running comprehensive security audits as easy as clicking a button
.NOTES
    Author: Sandiso Mazibuko
    Version: 5.1 GUI
    Requires: PowerShell 5.1+, .NET Framework
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Get script directory
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

#region Helper Functions

function Write-Log {
    param([string]$Message, [string]$Color = "Black")
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    
    $script:LogTextBox.SelectionStart = $script:LogTextBox.TextLength
    $script:LogTextBox.SelectionLength = 0
    $script:LogTextBox.SelectionColor = [System.Drawing.Color]::FromName($Color)
    $script:LogTextBox.AppendText("$logMessage`r`n")
    $script:LogTextBox.SelectionColor = $script:LogTextBox.ForeColor
    $script:LogTextBox.ScrollToCaret()
    
    [System.Windows.Forms.Application]::DoEvents()
}

function Start-AuditProcess {
    param([string]$Mode)
    
    # Disable controls during scan
    $script:StartButton.Enabled = $false
    $script:QuickButton.Enabled = $false
    $script:StandardButton.Enabled = $false
    $script:DeepButton.Enabled = $false
    $script:ForensicButton.Enabled = $false
    $script:ProgressBar.Value = 0
    $script:ProgressBar.Visible = $true
    $script:StatusLabel.Text = "Status: Running $Mode scan..."
    
    # Clear log
    $script:LogTextBox.Clear()
    
    Write-Log "═══════════════════════════════════════════════════════" "DarkBlue"
    Write-Log "  Windows Security Audit Framework v5.1" "DarkBlue"
    Write-Log "═══════════════════════════════════════════════════════" "DarkBlue"
    Write-Log "Starting $Mode scan..." "Green"
    Write-Log ""
    
    # Update progress
    $script:ProgressBar.Value = 10
    
    # Build command
    $auditScript = Join-Path $ScriptRoot "SecurityAudit.ps1"
    
    if (-not (Test-Path $auditScript)) {
        [System.Windows.Forms.MessageBox]::Show(
            "SecurityAudit.ps1 not found in the same directory as this GUI!",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        Reset-Controls
        return
    }
    
    # Create background job to run audit
    $job = Start-Job -ScriptBlock {
        param($Script, $Mode, $ScriptRoot)
        
        Set-Location $ScriptRoot
        & $Script -Mode $Mode
        
    } -ArgumentList $auditScript, $Mode, $ScriptRoot
    
    # Monitor job progress
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 500
    $progressStep = 20
    
    $timer.Add_Tick({
        if ($job.State -eq 'Completed') {
            $timer.Stop()
            $timer.Dispose()
            
            $script:ProgressBar.Value = 100
            
            # Get job output
            $output = Receive-Job -Job $job
            Remove-Job -Job $job
            
            Write-Log ""
            Write-Log "═══════════════════════════════════════════════════════" "DarkGreen"
            Write-Log "  SCAN COMPLETE!" "DarkGreen"
            Write-Log "═══════════════════════════════════════════════════════" "DarkGreen"
            Write-Log ""
            Write-Log "Reports have been generated on your Desktop." "Green"
            Write-Log "Opening HTML report..." "Green"
            
            # Find and open the report
            $desktop = [Environment]::GetFolderPath("Desktop")
            $latestReport = Get-ChildItem -Path $desktop -Filter "WinSecAudit_*" -Directory |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 1
            
            if ($latestReport) {
                $htmlReport = Join-Path $latestReport.FullName "report.html"
                if (Test-Path $htmlReport) {
                    Start-Process $htmlReport
                }
            }
            
            $script:StatusLabel.Text = "Status: Scan completed successfully"
            $script:StatusLabel.ForeColor = [System.Drawing.Color]::Green
            
            [System.Windows.Forms.MessageBox]::Show(
                "Security audit completed successfully!`r`n`r`nReports have been saved to your Desktop.",
                "Success",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
            
            Reset-Controls
        }
        elseif ($job.State -eq 'Failed') {
            $timer.Stop()
            $timer.Dispose()
            
            $error = Receive-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job
            
            Write-Log ""
            Write-Log "ERROR: Scan failed!" "Red"
            Write-Log "$error" "Red"
            
            $script:StatusLabel.Text = "Status: Scan failed"
            $script:StatusLabel.ForeColor = [System.Drawing.Color]::Red
            
            [System.Windows.Forms.MessageBox]::Show(
                "Security audit failed. Check the log for details.",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            
            Reset-Controls
        }
        else {
            # Still running - update progress
            if ($script:ProgressBar.Value -lt 90) {
                $script:ProgressBar.Value += 2
            }
            
            Write-Log "Scanning..." "Gray"
        }
    }.GetNewClosure())
    
    $timer.Start()
}

function Reset-Controls {
    $script:StartButton.Enabled = $true
    $script:QuickButton.Enabled = $true
    $script:StandardButton.Enabled = $true
    $script:DeepButton.Enabled = $true
    $script:ForensicButton.Enabled = $true
    $script:ProgressBar.Visible = $false
    $script:ProgressBar.Value = 0
}

#endregion

#region Create Main Form

$form = New-Object System.Windows.Forms.Form
$form.Text = "Windows Security Audit Framework v5.1"
$form.Size = New-Object System.Drawing.Size(900, 700)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
$form.MaximizeBox = $false
$form.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 245)

#endregion

#region Header Panel

$headerPanel = New-Object System.Windows.Forms.Panel
$headerPanel.Size = New-Object System.Drawing.Size(900, 80)
$headerPanel.Location = New-Object System.Drawing.Point(0, 0)
$headerPanel.BackColor = [System.Drawing.Color]::FromArgb(102, 126, 234)
$form.Controls.Add($headerPanel)

$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "🛡️ Windows Security Audit Framework"
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
$titleLabel.ForeColor = [System.Drawing.Color]::White
$titleLabel.AutoSize = $true
$titleLabel.Location = New-Object System.Drawing.Point(20, 15)
$headerPanel.Controls.Add($titleLabel)

$subtitleLabel = New-Object System.Windows.Forms.Label
$subtitleLabel.Text = "Comprehensive Security Analysis & Threat Hunting"
$subtitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$subtitleLabel.ForeColor = [System.Drawing.Color]::FromArgb(220, 220, 255)
$subtitleLabel.AutoSize = $true
$subtitleLabel.Location = New-Object System.Drawing.Point(20, 48)
$headerPanel.Controls.Add($subtitleLabel)

#endregion

#region Scan Mode Panel

$modePanel = New-Object System.Windows.Forms.GroupBox
$modePanel.Text = " Select Scan Mode "
$modePanel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$modePanel.Size = New-Object System.Drawing.Size(860, 120)
$modePanel.Location = New-Object System.Drawing.Point(20, 100)
$modePanel.ForeColor = [System.Drawing.Color]::FromArgb(50, 50, 50)
$form.Controls.Add($modePanel)

# Quick Scan Button
$script:QuickButton = New-Object System.Windows.Forms.Button
$script:QuickButton.Text = "⚡ Quick Scan`r`nEssential checks only (2-3 min)"
$script:QuickButton.Size = New-Object System.Drawing.Size(200, 70)
$script:QuickButton.Location = New-Object System.Drawing.Point(20, 30)
$script:QuickButton.BackColor = [System.Drawing.Color]::FromArgb(79, 195, 247)
$script:QuickButton.ForeColor = [System.Drawing.Color]::White
$script:QuickButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$script:QuickButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$script:QuickButton.Cursor = [System.Windows.Forms.Cursors]::Hand
$script:QuickButton.Add_Click({ Start-AuditProcess -Mode "Quick" })
$modePanel.Controls.Add($script:QuickButton)

# Standard Scan Button
$script:StandardButton = New-Object System.Windows.Forms.Button
$script:StandardButton.Text = "📋 Standard Scan`r`nBalanced analysis (5-7 min)"
$script:StandardButton.Size = New-Object System.Drawing.Size(200, 70)
$script:StandardButton.Location = New-Object System.Drawing.Point(230, 30)
$script:StandardButton.BackColor = [System.Drawing.Color]::FromArgb(102, 187, 106)
$script:StandardButton.ForeColor = [System.Drawing.Color]::White
$script:StandardButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$script:StandardButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$script:StandardButton.Cursor = [System.Windows.Forms.Cursors]::Hand
$script:StandardButton.Add_Click({ Start-AuditProcess -Mode "Standard" })
$modePanel.Controls.Add($script:StandardButton)

# Deep Scan Button (Recommended)
$script:DeepButton = New-Object System.Windows.Forms.Button
$script:DeepButton.Text = "🔍 Deep Scan (Recommended)`r`nComprehensive analysis (10-15 min)"
$script:DeepButton.Size = New-Object System.Drawing.Size(200, 70)
$script:DeepButton.Location = New-Object System.Drawing.Point(440, 30)
$script:DeepButton.BackColor = [System.Drawing.Color]::FromArgb(255, 167, 38)
$script:DeepButton.ForeColor = [System.Drawing.Color]::White
$script:DeepButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$script:DeepButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$script:DeepButton.Cursor = [System.Windows.Forms.Cursors]::Hand
$script:DeepButton.Add_Click({ Start-AuditProcess -Mode "Deep" })
$modePanel.Controls.Add($script:DeepButton)

# Forensic Scan Button
$script:ForensicButton = New-Object System.Windows.Forms.Button
$script:ForensicButton.Text = "🔬 Forensic Scan`r`nFull investigation (20+ min)"
$script:ForensicButton.Size = New-Object System.Drawing.Size(200, 70)
$script:ForensicButton.Location = New-Object System.Drawing.Point(650, 30)
$script:ForensicButton.BackColor = [System.Drawing.Color]::FromArgb(239, 83, 80)
$script:ForensicButton.ForeColor = [System.Drawing.Color]::White
$script:ForensicButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$script:ForensicButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$script:ForensicButton.Cursor = [System.Windows.Forms.Cursors]::Hand
$script:ForensicButton.Add_Click({ Start-AuditProcess -Mode "Forensic" })
$modePanel.Controls.Add($script:ForensicButton)

#endregion

#region Log Panel

$logPanel = New-Object System.Windows.Forms.GroupBox
$logPanel.Text = " Scan Progress & Log "
$logPanel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$logPanel.Size = New-Object System.Drawing.Size(860, 370)
$logPanel.Location = New-Object System.Drawing.Point(20, 230)
$logPanel.ForeColor = [System.Drawing.Color]::FromArgb(50, 50, 50)
$form.Controls.Add($logPanel)

$script:LogTextBox = New-Object System.Windows.Forms.RichTextBox
$script:LogTextBox.Size = New-Object System.Drawing.Size(840, 340)
$script:LogTextBox.Location = New-Object System.Drawing.Point(10, 20)
$script:LogTextBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$script:LogTextBox.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$script:LogTextBox.ForeColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
$script:LogTextBox.ReadOnly = $true
$script:LogTextBox.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$logPanel.Controls.Add($script:LogTextBox)

#endregion

#region Progress Bar & Status

$script:ProgressBar = New-Object System.Windows.Forms.ProgressBar
$script:ProgressBar.Size = New-Object System.Drawing.Size(860, 25)
$script:ProgressBar.Location = New-Object System.Drawing.Point(20, 610)
$script:ProgressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
$script:ProgressBar.Visible = $false
$form.Controls.Add($script:ProgressBar)

$script:StatusLabel = New-Object System.Windows.Forms.Label
$script:StatusLabel.Text = "Status: Ready"
$script:StatusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$script:StatusLabel.ForeColor = [System.Drawing.Color]::FromArgb(102, 126, 234)
$script:StatusLabel.AutoSize = $true
$script:StatusLabel.Location = New-Object System.Drawing.Point(20, 642)
$form.Controls.Add($script:StatusLabel)

#endregion

#region Initial Welcome Message

Write-Log "═══════════════════════════════════════════════════════" "DarkBlue"
Write-Log "  Welcome to Windows Security Audit Framework!" "DarkBlue"
Write-Log "═══════════════════════════════════════════════════════" "DarkBlue"
Write-Log ""
Write-Log "Select a scan mode to begin your security analysis:" "Green"
Write-Log ""
Write-Log "⚡ Quick Scan - Essential security checks (recommended for daily use)" "Gray"
Write-Log "📋 Standard Scan - Balanced security analysis" "Gray"
Write-Log "🔍 Deep Scan - Comprehensive analysis (recommended for thorough audits)" "Gray"
Write-Log "🔬 Forensic Scan - Full investigation (for suspected compromises)" "Gray"
Write-Log ""
Write-Log "Reports will be saved to your Desktop and opened automatically." "Green"
Write-Log ""

#endregion

# Show form
$form.Add_Shown({$form.Activate()})
[void]$form.ShowDialog()