<#
.SYNOPSIS
    Windows Security Audit Framework - GUI Application
    Version 5.4 (Replaces dynamic event handler with explicit handlers)
#>
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# --- GUI SETUP ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "Windows Security Audit Framework v5.4"
$form.Size = New-Object System.Drawing.Size(900, 720)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
$form.MaximizeBox = $false
$form.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 245)

$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Size = New-Object System.Drawing.Size(860, 25)
$progressBar.Location = New-Object System.Drawing.Point(20, 610)
$progressBar.Style = "Continuous"
$progressBar.Visible = $false
$form.Controls.Add($progressBar)

$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Status: Ready"
$statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(102, 126, 234)
$statusLabel.AutoSize = $true
$statusLabel.Location = New-Object System.Drawing.Point(20, 642)
$form.Controls.Add($statusLabel)

$logBox = New-Object System.Windows.Forms.RichTextBox
$logBox.Size = New-Object System.Drawing.Size(860, 360)
$logBox.Location = New-Object System.Drawing.Point(20, 230)
$logBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$logBox.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$logBox.ForeColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
$logBox.ReadOnly = $true
$form.Controls.Add($logBox)

$headerPanel = New-Object System.Windows.Forms.Panel
$headerPanel.Size = New-Object System.Drawing.Size(900, 80)
$headerPanel.BackColor = [System.Drawing.Color]::FromArgb(102, 126, 234)
$form.Controls.Add($headerPanel)

$title = New-Object System.Windows.Forms.Label
$title.Text = "Windows Security Audit Framework"
$title.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
$title.ForeColor = [System.Drawing.Color]::White
$title.AutoSize = $true
$title.Location = New-Object System.Drawing.Point(20, 15)
$headerPanel.Controls.Add($title)

$btnQuick = New-Object System.Windows.Forms.Button
$btnQuick.Text = "Quick Scan`r`n(2-3 min)"
$btnQuick.Size = New-Object System.Drawing.Size(160, 70)
$btnQuick.Location = New-Object System.Drawing.Point(20, 100)
$btnQuick.BackColor = [System.Drawing.Color]::FromArgb(79, 195, 247)
$btnQuick.FlatStyle = "Flat"
$form.Controls.Add($btnQuick)

$btnStandard = New-Object System.Windows.Forms.Button
$btnStandard.Text = "Standard Scan`r`n(5-7 min)"
$btnStandard.Size = New-Object System.Drawing.Size(160, 70)
$btnStandard.Location = New-Object System.Drawing.Point(190, 100)
$btnStandard.BackColor = [System.Drawing.Color]::FromArgb(100, 221, 23)
$btnStandard.FlatStyle = "Flat"
$form.Controls.Add($btnStandard)

$btnDeep = New-Object System.Windows.Forms.Button
$btnDeep.Text = "Deep Scan`r`n(Recommended)"
$btnDeep.Size = New-Object System.Drawing.Size(160, 70)
$btnDeep.Location = New-Object System.Drawing.Point(360, 100)
$btnDeep.BackColor = [System.Drawing.Color]::FromArgb(255, 167, 38)
$btnDeep.FlatStyle = "Flat"
$form.Controls.Add($btnDeep)

$btnForensic = New-Object System.Windows.Forms.Button
$btnForensic.Text = "Forensic Scan`r`n(20+ min)"
$btnForensic.Size = New-Object System.Drawing.Size(160, 70)
$btnForensic.Location = New-Object System.Drawing.Point(530, 100)
$btnForensic.BackColor = [System.Drawing.Color]::FromArgb(255, 82, 82)
$btnForensic.ForeColor = [System.Drawing.Color]::White
$btnForensic.FlatStyle = "Flat"
$form.Controls.Add($btnForensic)

$btnStop = New-Object System.Windows.Forms.Button
$btnStop.Text = "STOP"
$btnStop.Size = New-Object System.Drawing.Size(150, 70)
$btnStop.Location = New-Object System.Drawing.Point(730, 100)
$btnStop.BackColor = [System.Drawing.Color]::FromArgb(220, 53, 69)
$btnStop.ForeColor = [System.Drawing.Color]::White
$btnStop.FlatStyle = "Flat"
$btnStop.Enabled = $false
$form.Controls.Add($btnStop)

# --- EVENT HANDLERS & LOGIC ---
$script:currentJob = $null
$AllScanButtons = @($btnQuick, $btnStandard, $btnDeep, $btnForensic)

function Enable-ScanButtons($enabled) {
    foreach ($btn in $AllScanButtons) { $btn.Enabled = $enabled }
}

# --- FIX: Replaced the single faulty line with explicit handlers for each button ---
$btnQuick.Add_Click({ Start-Scan -Mode 'Quick' })
$btnStandard.Add_Click({ Start-Scan -Mode 'Standard' })
$btnDeep.Add_Click({ Start-Scan -Mode 'Deep' })
$btnForensic.Add_Click({ Start-Scan -Mode 'Forensic' })
$btnStop.Add_Click({ Stop-Scan })
# --- End of Fix ---

function Write-Log($msg, $color="Gray") {
    if ($logBox.IsDisposed) { return }
    $logBox.SelectionStart = $logBox.TextLength
    $logBox.SelectionColor = [System.Drawing.Color]::$color
    $logBox.AppendText("[$((Get-Date).ToString('HH:mm:ss'))] $msg`r`n")
    $logBox.ScrollToCaret()
}

function Stop-Scan {
    if ($script:currentJob) {
        Stop-Job $script:currentJob
        Remove-Job $script:currentJob -Force
        $script:currentJob = $null
    }
    
    $statusLabel.Text = "Status: Scan Aborted by User"
    $statusLabel.ForeColor = [System.Drawing.Color]::Red
    Write-Log "!!! SCAN ABORTED BY USER !!!" "Red"
    
    Enable-ScanButtons $true
    $btnStop.Enabled = $false
    $progressBar.Visible = $false
}

function Start-Scan {
    param([string]$Mode)

    Enable-ScanButtons $false
    $btnStop.Enabled = $true
    $progressBar.Visible = $true
    $progressBar.Value = 0
    $statusLabel.Text = "Status: Running $Mode Scan..."
    $statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(102, 126, 234)
    $logBox.Clear()
    
    Write-Log "Starting $Mode Scan..." "Green"

    $scriptPath = Join-Path $ScriptRoot "SecurityAudit.ps1"
    
    $script:currentJob = Start-Job -ScriptBlock {
        param($p, $m) 
        & $p -Mode $m *>&1
    } -ArgumentList $scriptPath, $Mode

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 500
    
    $timer.Add_Tick({
        if (-not $script:currentJob) { $timer.Stop(); return }

        if ($script:currentJob.HasMoreData) {
            $output = Receive-Job $script:currentJob
            if ($output) {
                foreach ($line in $output) {
                    $lineString = $line.ToString()
                    $color = "Gray"
                    if ($lineString -match 'FAIL|CRITICAL') { $color = "Red" }
                    elseif ($lineString -match 'WARN') { $color = "Yellow" }
                    elseif ($lineString -match 'OK|PASS') { $color = "Green" }
                    elseif ($lineString -match '===') { $color = "Cyan" }
                    
                    if ($form.IsHandleCreated) {
                        $form.Invoke([Action[string,string]]{ param($m, $c) Write-Log $m $c }, $lineString, $color)
                    }
                }
            }
        }

        if ($script:currentJob.State -in ('Completed', 'Failed', 'Stopped')) {
            $timer.Stop()
            $finalState = $script:currentJob.State
            
            if ($finalState -eq 'Completed') {
                $progressBar.Value = 100
                $statusLabel.Text = "Status: Scan Complete!"
                $statusLabel.ForeColor = [System.Drawing.Color]::Green
                Write-Log "Scan finished successfully. Generating report..." "Green"
                
                $reportDir = Get-ChildItem -Path (Join-Path $ScriptRoot "Reports") -Filter "WinSecAudit_*" -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($reportDir) {
                    $htmlReport = Join-Path $reportDir.FullName "report.html"
                    if (Test-Path $htmlReport) { Invoke-Item $htmlReport }
                }

            } elseif ($finalState -eq 'Failed') {
                $statusLabel.Text = "Status: Scan Failed!"
                $statusLabel.ForeColor = [System.Drawing.Color]::Red
                if ($script:currentJob.ChildJobs[0].Error.Count -gt 0) {
                    $errorRecord = $script:currentJob.ChildJobs[0].Error[0]
                    Write-Log "ERROR: $($errorRecord.Exception.Message)" "Red"
                } else {
                    Write-Log "ERROR: The scan failed for an unknown reason. Check the transcript log." "Red"
                }
            }
            
            Remove-Job $script:currentJob -Force
            $script:currentJob = $null
            Enable-ScanButtons $true
            $btnStop.Enabled = $false
        } else {
            if ($progressBar.Value -lt 95) { $progressBar.Value += 2 }
        }
    })
    $timer.Start()
}

$form.Add_FormClosing({
    if ($script:currentJob) {
        Stop-Job $script:currentJob
        Remove-Job $script:currentJob -Force
    }
})

$form.ShowDialog()