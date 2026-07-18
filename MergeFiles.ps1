# Script to merge all project files into a single text file for AI context

$rootPath = $PSScriptRoot
$outputFile = Join-Path $rootPath "Full_Project_Context.txt"

# File types to include (add more if needed)
$extensions = @("*.ps1", "*.psm1", "*.psd1", "*.md", "*.bat", "*.html", "*.json", "*.txt")

Write-Host "Scanning for files in: $rootPath" -ForegroundColor Cyan

# Get all files recursively, excluding the output file itself and bloat folders
$files = Get-ChildItem -Path $rootPath -Recurse -Include $extensions -File | 
    Where-Object { 
        $_.FullName -ne $outputFile -and 
        $_.FullName -notmatch "\\(\.git|Reports|node_modules|\.venv|bin|obj)\\" -and
        $_.Name -ne "MergeFiles.ps1"
    }

$sb = [System.Text.StringBuilder]::new()

foreach ($file in $files) {
    $relativePath = $file.FullName.Replace($rootPath, "")
    Write-Host "Adding: $relativePath" -ForegroundColor Gray
    
    # Create a clear separator for the AI to read
    $sb.AppendLine("================================================================================") | Out-Null
    $sb.AppendLine("FILE PATH: $relativePath") | Out-Null
    $sb.AppendLine("================================================================================") | Out-Null
    
    try {
        $content = Get-Content -Path $file.FullName -Raw -ErrorAction Stop
        $sb.AppendLine($content) | Out-Null
    }
    catch {
        $sb.AppendLine("[Error reading file: $($_.Exception.Message)]") | Out-Null
    }
    
    $sb.AppendLine("`n") | Out-Null
}

Set-Content -Path $outputFile -Value $sb.ToString() -Encoding UTF8

Write-Host "Success! All files merged into: $outputFile" -ForegroundColor Green