<#
.SYNOPSIS
    PowerShell script to download NVD data using curl with stdout capture
.DESCRIPTION
    This script uses curl.exe and captures stdout directly instead of using -o
    to avoid file writing issues with cmd /c.
.PARAMETER NvdApiKey
    Your NVD API key
.PARAMETER DataDirectory
    Path where the output files will be stored
.PARAMETER DebugMode
    Switch to enable verbose debugging output
.EXAMPLE
    .\Update-VulnerabilityDB.ps1 -NvdApiKey "your-api-key-here"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$NvdApiKey,
    
    [string]$DataDirectory = (Join-Path $env:USERPROFILE "dependency-check-data"),
    [switch]$DebugMode
)

# Create data directory if it doesn't exist
if (-not (Test-Path $DataDirectory)) {
    New-Item -ItemType Directory -Path $DataDirectory -Force | Out-Null
}

Write-Host "=== PowerShell Vulnerability Cache Builder ===" -ForegroundColor Cyan
Write-Host "Data Directory: $DataDirectory" -ForegroundColor Gray
if ($DebugMode) { Write-Host "DEBUG MODE: ENABLED" -ForegroundColor Yellow }

# Find curl.exe
$foundCurl = (Get-Command curl.exe -ErrorAction SilentlyContinue).Source
if (-not $foundCurl) {
    $foundCurl = "$env:SystemRoot\System32\curl.exe"
}
if (-not (Test-Path $foundCurl)) {
    Write-Host "ERROR: curl.exe not found" -ForegroundColor Red
    exit 1
}

# --- Function to download using curl (capturing stdout directly) ---
function Invoke-NvdApiCurl {
    param(
        [string]$QueryString
    )
    
    $url = "https://services.nvd.nist.gov/rest/json/cves/2.0?$QueryString"
    
    # Build the curl command - WITHOUT -o flag, capture stdout directly
    $curlCommand = "`"$foundCurl`" -s -H 'apiKey: $NvdApiKey' -H 'User-Agent: PowerShell-DependencyCheck-Updater/1.0' `"$url`""
    
    if ($DebugMode) {
        Write-Host "  DEBUG: Command: $curlCommand" -ForegroundColor DarkGray
    }
    
    # Execute with cmd /c and capture stdout
    try {
        $result = cmd.exe /c $curlCommand 2>&1
        $exitCode = $LASTEXITCODE
        
        if ($DebugMode) {
            Write-Host "  DEBUG: Exit code: $exitCode" -ForegroundColor DarkGray
            Write-Host "  DEBUG: Result length: $($result.Length) characters" -ForegroundColor DarkGray
        }
        
        # Check if we got valid JSON
        if ($result -and $result -match '"totalResults"') {
            return $result
        } else {
            Write-Host "  WARNING: Response doesn't contain expected JSON" -ForegroundColor Yellow
            if ($DebugMode) {
                Write-Host "  DEBUG: Response preview: $($result.Substring(0, [Math]::Min(500, $result.Length)))" -ForegroundColor DarkGray
            }
            return $null
        }
    } catch {
        Write-Host "  ERROR: $_" -ForegroundColor Red
        return $null
    }
}

# --- Step 1: Test API ---
Write-Host "`n[1/3] Testing API connection..." -ForegroundColor Cyan

$testContent = Invoke-NvdApiCurl -QueryString "resultsPerPage=1"

if ($testContent) {
    try {
        $testResponse = $testContent | ConvertFrom-Json
        Write-Host "  API connection successful!" -ForegroundColor Green
        Write-Host "  Total results available: $($testResponse.totalResults)" -ForegroundColor Green
    } catch {
        Write-Host "  ERROR: Invalid response from API" -ForegroundColor Red
        if ($DebugMode) {
            Write-Host "  DEBUG: Response preview: $($testContent.Substring(0, [Math]::Min(200, $testContent.Length)))" -ForegroundColor DarkGray
        }
        exit 1
    }
} else {
    Write-Host "  ERROR: API test failed." -ForegroundColor Red
    exit 1
}

# --- Step 2: Download NVD Data ---
Write-Host "`n[2/3] Downloading NVD vulnerability data..." -ForegroundColor Cyan

$allVulnerabilities = @()
$startIndex = 0
$resultsPerPage = 1000
$totalResults = $null
$maxRecords = 10000
$thirtyDaysAgo = (Get-Date).AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

do {
    Write-Host "  Fetching records $startIndex to $($startIndex + $resultsPerPage)..." -ForegroundColor Gray
    
    $queryString = "resultsPerPage=$resultsPerPage&startIndex=$startIndex&pubStartDate=$thirtyDaysAgo"
    $content = Invoke-NvdApiCurl -QueryString $queryString
    
    if ($content) {
        try {
            $response = $content | ConvertFrom-Json
            
            if (-not $totalResults) {
                $totalResults = [Math]::Min($response.totalResults, $maxRecords)
                Write-Host "  Total vulnerabilities available in date range: $totalResults" -ForegroundColor Yellow
            }
            
            if ($response.vulnerabilities) {
                $allVulnerabilities += $response.vulnerabilities
                Write-Host "  Retrieved $($response.vulnerabilities.Count) vulnerabilities" -ForegroundColor Green
            }
            
            $startIndex += $resultsPerPage
            
            # Rate limiting
            Start-Sleep -Milliseconds 600
            
        } catch {
            Write-Host "  Error parsing JSON: $_" -ForegroundColor Red
            if ($DebugMode) {
                Write-Host "  DEBUG: Content preview: $($content.Substring(0, [Math]::Min(200, $content.Length)))" -ForegroundColor DarkGray
            }
            break
        }
    } else {
        Write-Host "  Error downloading data at index $startIndex" -ForegroundColor Red
        break
    }
    
} while ($startIndex -lt $totalResults -and $startIndex -lt $maxRecords)

# If no data with date filter, try without it
if ($allVulnerabilities.Count -eq 0) {
    Write-Host "`n  No data with date filter. Trying without filter..." -ForegroundColor Yellow
    
    $startIndex = 0
    $totalResults = $null
    
    do {
        Write-Host "  Fetching records $startIndex to $($startIndex + $resultsPerPage)..." -ForegroundColor Gray
        
        $queryString = "resultsPerPage=$resultsPerPage&startIndex=$startIndex"
        $content = Invoke-NvdApiCurl -QueryString $queryString
        
        if ($content) {
            try {
                $response = $content | ConvertFrom-Json
                
                if (-not $totalResults) {
                    $totalResults = [Math]::Min($response.totalResults, $maxRecords)
                    Write-Host "  Total vulnerabilities available: $totalResults" -ForegroundColor Yellow
                }
                
                if ($response.vulnerabilities) {
                    $allVulnerabilities += $response.vulnerabilities
                    Write-Host "  Retrieved $($response.vulnerabilities.Count) vulnerabilities" -ForegroundColor Green
                }
                
                $startIndex += $resultsPerPage
                Start-Sleep -Milliseconds 600
                
            } catch {
                Write-Host "  Error parsing JSON: $_" -ForegroundColor Red
                break
            }
        } else {
            Write-Host "  Error downloading data at index $startIndex" -ForegroundColor Red
            break
        }
        
    } while ($startIndex -lt $totalResults -and $startIndex -lt $maxRecords)
}

Write-Host "  Total vulnerabilities downloaded: $($allVulnerabilities.Count)" -ForegroundColor Green

if ($allVulnerabilities.Count -eq 0) {
    Write-Host "`nFATAL: No vulnerabilities downloaded." -ForegroundColor Red
    exit 1
}

# --- Step 3: Parse and Save Data ---
Write-Host "`n[3/3] Parsing and saving data..." -ForegroundColor Cyan

$vendorProductMap = @{}
$cveMap = @{}
$counter = 0

foreach ($item in $allVulnerabilities) {
    $counter++
    if ($counter % 100 -eq 0) {
        Write-Host "  Processing vulnerability $counter of $($allVulnerabilities.Count)..." -ForegroundColor Gray
    }
    
    $cve = $item.cve
    $cveId = $cve.id
    
    $cvssScore = $null
    $severity = "UNKNOWN"
    
    if ($cve.metrics -and $cve.metrics.cvssMetricV31) {
        $cvssScore = $cve.metrics.cvssMetricV31[0].cvssData.baseScore
        $severity = $cve.metrics.cvssMetricV31[0].cvssData.baseSeverity
    } elseif ($cve.metrics -and $cve.metrics.cvssMetricV2) {
        $cvssScore = $cve.metrics.cvssMetricV2[0].cvssData.baseScore
        $severity = if ($cvssScore -ge 7) { "HIGH" } elseif ($cvssScore -ge 4) { "MEDIUM" } else { "LOW" }
    }
    
    $description = ""
    if ($cve.descriptions) {
        $desc = $cve.descriptions | Where-Object { $_.lang -eq "en" } | Select-Object -First 1
        if ($desc) {
            $description = $desc.value
        }
    }
    
    if ($cve.configurations) {
        foreach ($config in $cve.configurations) {
            if ($config.nodes) {
                foreach ($node in $config.nodes) {
                    if ($node.cpeMatch) {
                        foreach ($cpeMatch in $node.cpeMatch) {
                            $cpe = $cpeMatch.criteria
                            
                            if ($cpe -match 'cpe:2\.3:[^:]+:([^:]+):([^:]+)') {
                                $vendor = $matches[1]
                                $product = $matches[2]
                                
                                $key = "$vendor|$product"
                                if (-not $vendorProductMap.ContainsKey($key)) {
                                    $vendorProductMap[$key] = @()
                                }
                                
                                $versionInfo = @{
                                    CVEId = $cveId
                                    Severity = $severity
                                    Score = $cvssScore
                                    Description = if ($description.Length -gt 200) { $description.Substring(0, 200) } else { $description }
                                    VersionStart = $cpeMatch.versionStartExcluding
                                    VersionEnd = $cpeMatch.versionEndExcluding
                                }
                                $vendorProductMap[$key] += $versionInfo
                            }
                        }
                    }
                }
            }
        }
    }
    
    $cveMap[$cveId] = [PSCustomObject]@{
        Id = $cveId
        Severity = $severity
        Score = $cvssScore
        Description = $description
        Published = $cve.published
    }
}

Write-Host "  Processed $($cveMap.Count) CVEs and $($vendorProductMap.Count) vendor/product combinations" -ForegroundColor Green

# Save as JSON
$jsonFile = Join-Path $DataDirectory "vulnerabilities.json"
Write-Host "`n  Creating JSON: $jsonFile" -ForegroundColor Gray

$jsonData = @{
    metadata = @{
        updateDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        totalCVEs = $cveMap.Count
        totalVulnerabilities = $vendorProductMap.Count
        source = "NVD API"
        apiKeyUsed = $true
        recordsDownloaded = $allVulnerabilities.Count
    }
    vulnerabilities = $vendorProductMap
}
$jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8

# Save as CSV
$csvFile = Join-Path $DataDirectory "vulnerabilities.csv"
Write-Host "  Creating CSV: $csvFile" -ForegroundColor Gray

$csvContent = @()
$csvContent += "CVE_ID,Severity,Score,Vendor,Product,VersionStart,VersionEnd,Description"

foreach ($key in $vendorProductMap.Keys) {
    $parts = $key -split '\|'
    $vendor = $parts[0]
    $product = $parts[1]
    
    foreach ($vuln in $vendorProductMap[$key]) {
        $desc = ($vuln.Description -replace ',', ' ') -replace "`n", " " -replace "`r", " "
        $csvLine = "$($vuln.CVEId),$($vuln.Severity),$($vuln.Score),$vendor,$product,$($vuln.VersionStart),$($vuln.VersionEnd),$desc"
        $csvContent += $csvLine
    }
}
$csvContent -join "`n" | Out-File -FilePath $csvFile -Encoding UTF8

# --- Summary ---
Write-Host "`n=== Database Update Complete ===" -ForegroundColor Green
Write-Host "Downloaded: $($allVulnerabilities.Count) vulnerabilities" -ForegroundColor Green
Write-Host "Processed: $($cveMap.Count) CVEs" -ForegroundColor Green
Write-Host "Mappings: $($vendorProductMap.Count) vendor/product combinations" -ForegroundColor Green
Write-Host "Data saved to: $DataDirectory" -ForegroundColor Green

Write-Host "`nFiles created:" -ForegroundColor Cyan
Get-ChildItem -Path $DataDirectory -Include "*.csv","*.json" -ErrorAction SilentlyContinue | ForEach-Object {
    $size = [math]::Round($_.Length / 1KB, 2)
    Write-Host "  - $($_.Name) ($size KB)" -ForegroundColor Gray
}