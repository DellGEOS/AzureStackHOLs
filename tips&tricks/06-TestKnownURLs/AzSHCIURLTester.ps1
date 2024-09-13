# User-editable section for known incorrect URLs
$knownIncorrectUrls = @(
    "wustat.windows.com" # Add known incorrect URLs here
    # Example: "incorrect-url1.com", "incorrect-url2.com"
)

# Check if the AzStackHci.EnvironmentChecker module is installed
$moduleName = "AzStackHci.EnvironmentChecker"
$installedModule = Get-Module -Name $moduleName -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1

if (-not $installedModule) {
    Write-Host "The AzStackHci.EnvironmentChecker module is not installed. Please install it using 'Install-Module AzStackHci.EnvironmentChecker' and try again."
    exit
}

# Check if the installed version is the latest available
$latestModule = Find-Module -Name $moduleName
if ($installedModule.Version -lt $latestModule.Version) {
    Write-Host "The installed version of AzStackHci.EnvironmentChecker is not the latest. Please update it using 'Update-Module AzStackHci.EnvironmentChecker' and try again."
    exit
}

# Initialize the results array
$results = @()

# Function to strip paths from URLs, keeping only the domain and handle port
function Get-DomainFromURL {
    param (
        [string]$url
    )
    # Remove 'http://' or 'https://' if present
    $url = $url -replace "^https?://", ""
    
    # Check if there is a port number specified with a colon
    if ($url -match ":(\d+)$") {
        $port = [int]($url -replace ".*:(\d+)$", '$1') # Extract the port number
        $url = $url -replace ":(\d+)$", "" # Remove the colon and port from the URL
    } else {
        # Default to HTTP/HTTPS ports based on protocol (handled later)
        $port = $null
    }

    # Extract the domain part only (up to the first '/')
    $domain = $url -split '/' | Select-Object -First 1
    return @{ Domain = $domain; Port = $port }
}

# Extract Additional URLs and Convert Protocols
$Location = (Get-Module -Name AzStackHci.EnvironmentChecker -ListAvailable).ModuleBase
$Files = Get-ChildItem -Recurse -Path $Location | Where-Object Name -like "*Targets.json"
$Output = @()

foreach ($File in $Files) {
    # Grab content
    $content = Get-Content -Path $File.FullName
    # Convert to JSON
    $object = $content | ConvertFrom-Json
    # Add to PSCustomObject
    foreach ($item in $Object) {
        foreach ($endpoint in $Item.Endpoint) {
            # Process the URL to get domain and port
            $domainPort = Get-DomainFromURL -url $endpoint
            $url = $domainPort.Domain
            $port = if ($domainPort.Port) { $domainPort.Port } else { if ($item.Protocol -eq 'https') { 443 } else { 80 } }
            
            # Add to the output
            $Output += [PSCustomObject]@{
                URL = $url
                Port = $port
            }
        }
    }
}

# Extracted additional URLs to check
$newURLs = $Output

# Define the URLs for each region
$regionUrls = @{
    "East US" = "https://raw.githubusercontent.com/Azure/AzureStack-Tools/master/HCI/EastUSendpoints/eastus-hci-endpoints.md"
    "West Europe" = "https://raw.githubusercontent.com/Azure/AzureStack-Tools/master/HCI/WestEuropeendpoints/westeurope-hci-endpoints.md"
    "Australia East" = "https://raw.githubusercontent.com/Azure/AzureStack-Tools/master/HCI/AustraliaEastendpoints/AustraliaEast-hci-endpoints.md"
    "Canada Central" = "https://raw.githubusercontent.com/Azure/AzureStack-Tools/master/HCI/CanadaCentralEndpoints/canadacentral-hci-endpoints.md"
}

# Define region-specific azgnrelay endpoints
$azgnrelayEndpoints = @{
    "East US" = "azgnrelay-eastus-l1.servicebus.windows.net"
    "West US" = "azgnrelay-westus2-l1.servicebus.windows.net"
    "Southeast Asia" = "azgnrelay-southeastasia-l1.servicebus.windows.net"
    "West Europe" = "azgnrelay-westeurope-l1.servicebus.windows.net"
}

# Define specific replacements for wildcard URLs
$wildcardReplacements = @{
    "*.dl.delivery.mp.microsoft.com" = @()
    "*.do.dsp.mp.microsoft.com" = @()
    "*.prod.do.dsp.mp.microsoft.com" = @()
    "*.servicebus.windows.net" = @()
    "*.waconazure.com" = @()
    "*.blob.core.windows.net" = @()
    "*.download.windowsupdate.com" = @()
    "*.delivery.mp.microsoft.com" = @()
    "*.windowsupdate.microsoft.com" = @()
    "*.windowsupdate.com" = @()
    "*.update.microsoft.com" = @()
    "*.endpoint.security.microsoft.com" = @()
    "*.blob.storage.azure.net" = @()
}

# Temporary data structure to store changes
$tempReplacements = @{}

# Check new URLs against wildcard patterns
foreach ($entry in $newURLs) {
    $matched = $false
    # Trim the URL to just the domain part
    $entry.URL = (Get-DomainFromURL -url $entry.URL).Domain

    foreach ($wildcard in $wildcardReplacements.Keys) {
        # Extract the part after '*'
        $wildcardPattern = $wildcard -replace '^\*', ''
        
        # Check if the new URL contains the pattern
        if ($entry.URL -like "*$wildcardPattern") {
            if (-not $tempReplacements.ContainsKey($wildcard)) {
                $tempReplacements[$wildcard] = @()
            }
            $tempReplacements[$wildcard] += $entry.URL
            $matched = $true
        }
    }
    
    # If no match was found, add the URL to the test list
    if (-not $matched) {
        $results += [PSCustomObject]@{
            RowID = "New"
            URL = $entry.URL
            Port = $entry.Port
            IsWildcard = $false
            Note = "Additional URL"
        }
    }
}

# Apply changes to wildcardReplacements
foreach ($wildcard in $tempReplacements.Keys) {
    $wildcardReplacements[$wildcard] = $tempReplacements[$wildcard]
}

# Ensure no wildcard has empty placeholders
$wildcardKeysCopy = $wildcardReplacements.Keys | ForEach-Object { $_ } # Create a copy of the keys
foreach ($wildcard in $wildcardKeysCopy) {
    if ($wildcardReplacements[$wildcard].Count -eq 0) {
        $wildcardReplacements[$wildcard] = @("")
    }
}

# Prompt the user to select a region
$region = Read-Host "Select a region (East US, West Europe, Australia East, Canada Central)"
if (-not $regionUrls.ContainsKey($region)) {
    Write-Host "Invalid region selected. Exiting script."
    exit
}

# Get the URL for the selected region
$endpointUrl = $regionUrls[$region]

# Download the endpoint file
$endpointsContent = Invoke-WebRequest -Uri $endpointUrl -UseBasicParsing
$lines = $endpointsContent.Content -split "`n"

# Loop through each line to find table rows and extract the Endpoint URL and Port
foreach ($line in $lines) {
    # Skip header and separator lines
    if ($line -match "^\|\s*(\d+)\s*\|") {
        # Capture the row ID from the line
        $rowId = [int]($line -replace "^\|\s*(\d+)\s*\|.*", '$1')

        # Split the line into columns based on '|' separator
        $columns = $line -split "\|"

        # Trim the whitespace and extract the URL and Port
        $url = $columns[3].Trim()
        $ports = $columns[4].Trim() -split ','

        # Remove any 'http://' or 'https://' from the URL
        $url = (Get-DomainFromURL -url $url).Domain

        # Check for special cases and handle replacements
        $skipTest = $false
        $isUnknownWildcard = $false

        # Handle known wildcard URLs with specific replacements
        if ($url.StartsWith('*')) {
            if ($wildcardReplacements.ContainsKey($url)) {
                foreach ($replacementUrl in $wildcardReplacements[$url]) {
                    foreach ($port in $ports) {
                        if ($replacementUrl -ne "" -and $port -match '^\d+$') {
                            $results += [PSCustomObject]@{
                                RowID = $rowId
                                URL = $replacementUrl
                                Port = [int]$port
                                IsWildcard = $true
                            }
                        }
                    }
                }
                continue
            } else {
                # Mark unknown wildcard URLs
                $isUnknownWildcard = $true
            }
        }

        # Handle azgn*.servicebus.windows.net special case
        if ($url -eq "azgn*.servicebus.windows.net") {
            $url = $azgnrelayEndpoints[$region]  # Use the appropriate endpoint for the chosen region
        }

        # Handle <yourarcgatewayendpointid>.gw.arc.azure.net special case
        if ($url -like "*<yourarcgatewayendpointid>.gw.arc.azure.net*") {
            $skipTest = $true
        }

        # Handle www.msftconnecttest.com/connecttest.txt special case
        if ($url -eq "www.msftconnecttest.com/connecttest.txt") {
            $url = "www.msftconnecttest.com"  # Only test the root domain
        }

        # Handle yourhcikeyvaultname.vault.azure.net special case
        if ($url -eq "yourhcikeyvaultname.vault.azure.net") {
            $url = "demo1.vault.azure.net"  # Replace with the demo key vault
        }

        # Store the extracted data or note unknown wildcard URLs
        if (-not $skipTest) {
            if ($isUnknownWildcard) {
                $results += [PSCustomObject]@{
                    RowID = $rowId
                    URL = $url
                    Port = "N/A"
                    IsWildcard = $true
                    Note = "Unknown Wildcard URL"
                }
            } else {
                foreach ($port in $ports) {
                    if ($url -ne "" -and $port -match '^\d+$') {
                        $results += [PSCustomObject]@{
                            RowID = $rowId
                            URL = $url
                            Port = [int]$port
                            IsWildcard = $false
                        }
                    }
                }
            }
        }
    }
}

# Add Dell URLs to be tested
$additionalUrls = @(
    [PSCustomObject]@{ URL = "downloads.emc.com"; Port = 443; IsWildcard = $false; Note = "Dell URL" },
    [PSCustomObject]@{ URL = "dl.dell.com"; Port = 443; IsWildcard = $false; Note = "Dell URL" },
    [PSCustomObject]@{ URL = "esrs3-core.emc.com"; Port = 443; IsWildcard = $false; Note = "Dell URL" },
    [PSCustomObject]@{ URL = "esrs3-core.emc.com"; Port = 8443; IsWildcard = $false; Note = "Dell URL" },
    [PSCustomObject]@{ URL = "esrs3-coredr.emc.com"; Port = 443; IsWildcard = $false; Note = "Dell URL" },
    [PSCustomObject]@{ URL = "esrs3-coredr.emc.com"; Port = 8443; IsWildcard = $false; Note = "Dell URL" },
    [PSCustomObject]@{ URL = "colu.dell.com"; Port = 443; IsWildcard = $false; Note = "Dell URL" }
)

$results += $additionalUrls

# Output the list of URLs, Ports, and Row IDs to the user
Write-Host "The following URLs, Ports, and Row IDs will be tested:"
$results | Format-Table -Property RowID, URL, Port, IsWildcard, Note -AutoSize

# Ask for user confirmation
$confirmation = Read-Host "Does this look correct? (Y/N)"
if ($confirmation -ne "Y") {
    Write-Host "Exiting script as per user request."
    exit
}

# Function to test NTP using w32tm
function Test-NtpServer {
    param (
        [string]$ntpServer
    )
    
    # Run w32tm command and capture output
    $w32tmOutput = w32tm /stripchart /computer:$ntpServer /dataonly /samples:1 2>&1
    
    # Check for success pattern
    if ($w32tmOutput -match '^\d{2}:\d{2}:\d{2}, \+\d+\.\d+s') {
        return "Success"
    } elseif ($w32tmOutput -match 'error: 0x800705B4') {
        return "Failed"
    } else {
        return "Unknown"
    }
}

# Test connectivity for each URL and Port
foreach ($result in $results) {
    # Check if the URL is in the known incorrect list
    if ($knownIncorrectUrls -contains $result.URL) {
        # Skip and note in the output
        $result | Add-Member -MemberType NoteProperty -Name Status -Value "Skipped: Known Incorrect URL"
        continue
    }

    if ($result.IsWildcard -and $result.Note -eq "Unknown Wildcard URL") {
        continue # Skip testing for unknown wildcard URLs
    }

    # Handle specific case for time.windows.com
    if ($result.URL -eq "time.windows.com") {
        $status = Test-NtpServer -ntpServer $result.URL
    } else {
        # Test only the root domain for wildcard URLs
        $testUrl = $result.URL
        $testResult = Test-NetConnection -ComputerName $testUrl -Port $result.Port -WarningAction SilentlyContinue
        $status = if ($testResult.TcpTestSucceeded) { "Success" } else { "Failed" }
    }

    # Update the result object with the test status
    $result | Add-Member -MemberType NoteProperty -Name Status -Value $status
}

# Export results to CSV
$csvFile = "ConnectivityTestResults.csv"
$results | Export-Csv -Path $csvFile -NoTypeInformation
Write-Host "Test results have been saved to $csvFile"

# Print URLs with Failed or Skipped status
$failedResults = $results | Where-Object { $_.Status -eq "Failed" }
$skippedResults = $results | Where-Object { $_.Status -eq "Skipped: Known Incorrect URL" }

if ($failedResults.Count -gt 0) {
    Write-Host "The following URLs had a status of 'Failed':"
    $failedResults | Format-Table -Property RowID, URL, Port -AutoSize
}

if ($skippedResults.Count -gt 0) {
    Write-Host "The following URLs were skipped as known incorrect URLs:"
    $skippedResults | Format-Table -Property RowID, URL -AutoSize
}

# Prompt user to re-test failed URLs with alternate ports
$retestConfirmation = Read-Host "Would you like to re-test these failed URLs using other common ports? (Y/N)"
if ($retestConfirmation -eq "Y") {
    $retestSuccesses = @()
    foreach ($failed in $failedResults) {
        $retestResult = $null # Reset for each iteration
        $status = "Failed" # Default status

        if ($failed.Port -eq 80) {
            $retestResult = Test-NetConnection -ComputerName $failed.URL -Port 443 -WarningAction SilentlyContinue
            if ($retestResult.TcpTestSucceeded) {
                $status = "Success"
                $failed | Add-Member -MemberType NoteProperty -Name RetestPort -Value 443 -Force
                $failed | Add-Member -MemberType NoteProperty -Name RetestStatus -Value $status -Force
            }
        } elseif ($failed.Port -eq 443) {
            $retestResult = Test-NetConnection -ComputerName $failed.URL -Port 80 -WarningAction SilentlyContinue
            if ($retestResult.TcpTestSucceeded) {
                $status = "Success"
                $failed | Add-Member -MemberType NoteProperty -Name RetestPort -Value 80 -Force
                $failed | Add-Member -MemberType NoteProperty -Name RetestStatus -Value $status -Force
            }
        }

        # Only collect URLs that actually succeeded
        if ($status -eq "Success") {
            $retestSuccesses += $failed
        }
    }

    # Display results of the re-test
    $retestedFailures = $failedResults | Where-Object { $_.RetestStatus -eq "Failed" }
    if ($retestedFailures.Count -gt 0) {
        Write-Host "The following URLs still failed after re-testing:"
        $retestedFailures | Format-Table -Property RowID, URL, RetestPort, RetestStatus -AutoSize
    }

    if ($retestSuccesses.Count -gt 0) {
        Write-Host "The following URLs passed after re-testing:"
        $retestSuccesses | Format-Table -Property RowID, URL, RetestPort, RetestStatus -AutoSize
    } else {
        Write-Host "No URLs passed on re-testing."
    }
} else {
    Write-Host "All URLs passed the connectivity test."
}
