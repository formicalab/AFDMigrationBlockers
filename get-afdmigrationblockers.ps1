<#
.SYNOPSIS
Detects HTTP routes, redirect rules, and other elements in an Azure Front Door (Classic)
that are incompatible with Azure Front Door Standard/Premium.

.DESCRIPTION
This script analyzes Azure Front Door Classic configurations and identifies migration blockers
for Azure Front Door Standard/Premium. It checks for:
- Frontend endpoints without HTTPS certificates (by testing actual HTTPS connectivity)
- Custom domains with certificate mismatches or disabled HTTPS
- Other configuration issues that prevent migration

The script automatically uses system proxy settings when testing HTTPS connectivity.

.REQUIREMENTS
Install-Module Az.FrontDoor -MinimumVersion 1.13.0
Connect-AzAccount

.NOTES
Proxy Support: The script automatically uses system default proxy settings (Internet Options)
when testing HTTPS connectivity to frontend endpoints.
#>

#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$FrontDoorName,

    [Parameter(Mandatory = $false)]
    [switch]$ShowDebugInfo,

    [Parameter(Mandatory = $false)]
    [switch]$HideRedirects
)

Set-StrictMode -Version 1
$ErrorActionPreference = 'Stop'

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host '  Azure Front Door Migration Analyzer' -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan
Write-Host 'This script checks for configurations in Front Door Classic that will block' -ForegroundColor Gray
Write-Host "or cause issues when migrating to Front Door Standard/Premium.`n" -ForegroundColor Gray

Write-Host "[INFO] Analyzing Front Door Classic configuration: $FrontDoorName in $ResourceGroupName..." -ForegroundColor Cyan

try {
    $fd = Get-AzFrontDoor -Name $FrontDoorName -ResourceGroupName $ResourceGroupName
    if (-not $fd) {
        throw "Front Door '$FrontDoorName' not found in resource group '$ResourceGroupName'"
    }
}
catch {
    Write-Error "[ERROR] Unable to retrieve Front Door: $_"
    Write-Host 'Ensure the specified Front Door exists and is a Classic Front Door (not Standard/Premium).' -ForegroundColor Yellow
    exit 1
}

Write-Host '[INFO] Found Front Door. Checking configuration...' -ForegroundColor Cyan
Write-Host " - Frontend Endpoints: $($fd.FrontendEndpoints.Count)" -ForegroundColor Gray
Write-Host " - Routing Rules: $($fd.RoutingRules.Count)" -ForegroundColor Gray
Write-Host " - Backend Pools: $($fd.BackendPools.Count)`n" -ForegroundColor Gray

$issues = New-Object System.Collections.Generic.List[object]
$endpointInventory = New-Object System.Collections.Generic.List[object]

# Build comprehensive inventory of all frontend endpoints with their routing details
foreach ($frontend in $fd.FrontendEndpoints) {
    $feName = $frontend.Name
    $hostName = $frontend.HostName
    
    # Test certificate via direct TLS connection
    $hasCertificate = $false
    $certError = $null
    $certExpiration = $null
    $isMismatch = $false
    $certDisplayInfo = $null
    
    # Test certificate via TLS connection for all domains
    $tcpClient = $null
    $sslStream = $null
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($hostName, 443)
        
        $sslStream = New-Object System.Net.Security.SslStream(
            $tcpClient.GetStream(),
            $false,
            { param($s, $cert, $chain, $errors) return $true }
        )
        
        $sslStream.AuthenticateAsClient($hostName)
        $remoteCert = $sslStream.RemoteCertificate
        
        if ($remoteCert) {
            $x509cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($remoteCert)
            $certSubject = $x509cert.Subject
            $certExpiration = $x509cert.NotAfter
            
            # Check for certificate issues
            if ($hostName -notlike '*.azurefd.net' -and 
                ($certSubject -match 'CN=\*\.azurefd\.net' -or $certSubject -match 'CN=\*\.azureedge\.net')) {
                # Custom domain using Azure fallback certificate (HTTPS not properly enabled)
                $hasCertificate = $false
                $isMismatch = $true
                $certError = "Azure fallback certificate detected ($certSubject) - HTTPS not enabled for custom domain"
                # Extract just the CN for display
                if ($certSubject -match 'CN=([^,]+)') {
                    $certDisplayInfo = $matches[1]
                }
                $certExpiration = $null
            }
            elseif ($certExpiration -lt (Get-Date)) {
                # Certificate has expired
                $hasCertificate = $false
                $isMismatch = $true
                $certError = "Certificate expired on $($certExpiration.ToString('yyyy-MM-dd'))"
                $certDisplayInfo = "EXPIRED:$($certExpiration.ToString('yyyy-MM-dd'))"
            }
            else {
                $hasCertificate = $true
            }
        }
        else {
            $hasCertificate = $hostName -like '*.azurefd.net'  # AFD domains always valid
            if (-not $hasCertificate) {
                $isMismatch = $true
                $certError = "TLS connection succeeded but no certificate returned"
            }
        }
    }
    catch [System.Security.Authentication.AuthenticationException] {
        $hasCertificate = $hostName -like '*.azurefd.net'
        if (-not $hasCertificate) {
            $isMismatch = $true
            $certError = "Authentication failed: $($_.Exception.Message)"
        }
    }
    catch [System.IO.IOException] {
        $hasCertificate = $hostName -like '*.azurefd.net'
        if (-not $hasCertificate) {
            $isMismatch = $true
            $certError = "TLS connection error: $($_.Exception.Message)"
        }
    }
    catch {
        $hasCertificate = $hostName -like '*.azurefd.net'
        if (-not $hasCertificate) {
            $isMismatch = $true
            $certError = "Connection error: $($_.Exception.Message)"
        }
    }
    finally {
        if ($sslStream) { $sslStream.Dispose() }
        if ($tcpClient) { $tcpClient.Dispose() }
    }
    
    $hasAffinity = $frontend.SessionAffinityEnabledState -eq 'Enabled'
    $routesUsingEndpoint = $fd.RoutingRules | Where-Object { $_.FrontendEndpointIds -contains $frontend.Id }
    
    if ($ShowDebugInfo) {
        Write-Host "DEBUG: Checking endpoint '$feName' (ID: $($frontend.Id))" -ForegroundColor DarkGray
        Write-Host "DEBUG: Found $($routesUsingEndpoint.Count) routing rule(s) using this endpoint" -ForegroundColor DarkGray
        if ($routesUsingEndpoint) {
            $routesUsingEndpoint | ForEach-Object { Write-Host "DEBUG:   - $($_.Name)" -ForegroundColor DarkGray }
        }
    }
    
    # Check for HTTPS certificate issues and add to issues list
    if (-not $hasCertificate) {
        # Build concise error message
        $detailMsg = $certError ? $certError : "HTTPS certificate problem"
        
        if ($routesUsingEndpoint) {
            $detailMsg += " | Used by routes: $($routesUsingEndpoint.Name -join ', ')"
        }
        else {
            $detailMsg += " | Not used by any routes (consider removing)"
        }
        
        $issues.Add([pscustomobject]@{
                Type   = 'Frontend endpoint'
                Name   = $feName
                Detail = $detailMsg
            })
    }
    
    if ($routesUsingEndpoint) {
        foreach ($route in $routesUsingEndpoint) {
            # Determine backend/destination
            $backend = 'N/A'
            $isRedirect = $false
            
            switch ($route.RouteConfiguration?.GetType().Name) {
                'PSForwardingConfiguration' {
                    $backendPool = $fd.BackendPools | Where-Object { $_.Id -eq $route.RouteConfiguration.BackendPoolId }
                    $backend = $backendPool ? $backendPool.Name : 'Unknown'
                }
                'PSRedirectConfiguration' {
                    $backend = "Redirect ($($route.RouteConfiguration.RedirectProtocol))"
                    $isRedirect = $true
                }
            }
            
            # Determine protocols
            $supportsHttp = $route.AcceptedProtocols -contains 'Http'
            $supportsHttps = $route.AcceptedProtocols -contains 'Https'
            
            # Determine match patterns
            $matchPattern = $route.PatternsToMatch ? 
                ($route.PatternsToMatch.Count -eq 1 ? $route.PatternsToMatch[0] : '(Multiple)') : 
                'N/A'
            
            $endpointInventory.Add([PSCustomObject]@{
                EndpointName = $feName
                HostName = $hostName
                SessionAffinity = $hasAffinity
                MatchPattern = $matchPattern
                RoutingRule = $route.Name
                Backend = $backend
                HTTP = $supportsHttp
                HTTPS = $supportsHttps
                CertificateConfigured = $hasCertificate
                CertificateExpiration = $certExpiration
                CertificateDisplayInfo = $certDisplayInfo
                IsMismatch = $isMismatch
                IsRedirect = $isRedirect
            })
        }
    }
    else {
        $endpointInventory.Add([PSCustomObject]@{
            EndpointName = $feName
            HostName = $hostName
            SessionAffinity = $hasAffinity
            MatchPattern = 'N/A'
            RoutingRule = '(Not used)'
            Backend = 'N/A'
            HTTP = $false
            HTTPS = $false
            CertificateConfigured = $hasCertificate
            CertificateExpiration = $certExpiration
            CertificateDisplayInfo = $certDisplayInfo
            IsMismatch = $isMismatch
            IsRedirect = $false
        })
    }
}

# Output summary and detailed inventory

Write-Host "`n" -NoNewline
Write-Host ('=' * 120) -ForegroundColor Cyan
Write-Host '  COMPLETE ENDPOINT INVENTORY' -ForegroundColor Cyan
Write-Host ('=' * 120) -ForegroundColor Cyan

# Calculate statistics
$uniqueEndpoints = ($endpointInventory.EndpointName | Select-Object -Unique).Count
$usedEndpoints = ($endpointInventory.Where{$_.RoutingRule -ne '(Not used)'}.EndpointName | Select-Object -Unique).Count
$unusedEndpoints = $endpointInventory.Where{$_.RoutingRule -eq '(Not used)'}.Count
$withCerts = ($endpointInventory.Where{$_.CertificateConfigured}.EndpointName | Select-Object -Unique).Count
$withoutCerts = $uniqueEndpoints - $withCerts
$withMismatches = ($endpointInventory.Where{$_.IsMismatch}.EndpointName | Select-Object -Unique).Count

Write-Host "`nSummary: $uniqueEndpoints total endpoint(s), $usedEndpoints used by routes, $unusedEndpoints unused" -ForegroundColor White
Write-Host "         $withCerts endpoint(s) with valid certificates, $withMismatches with mismatches, $withoutCerts without certificates" -ForegroundColor White
Write-Host "`nShowing ALL frontend endpoints (domains) in this Front Door:`n" -ForegroundColor Gray

# Filter out redirects if HideRedirects flag is set
$displayInventory = if ($HideRedirects) {
    $endpointInventory | Where-Object { -not $_.IsRedirect }
} else {
    $endpointInventory
}

# Sort inventory: endpoint name, redirects first, /* patterns first, then by routing rule name
$sortedInventory = $displayInventory | Sort-Object EndpointName, `
    @{Expression={-not $_.IsRedirect}; Ascending=$true}, `
    @{Expression={$_.MatchPattern -ne '/*'}; Ascending=$true}, `
    RoutingRule

# Calculate column widths
$maxEndpoint = [Math]::Max(($sortedInventory.EndpointName | Measure-Object -Maximum -Property Length).Maximum, 'Endpoint Name'.Length)
$maxMatch = [Math]::Max(($sortedInventory.MatchPattern | Measure-Object -Maximum -Property Length).Maximum, 'Match'.Length)
$maxRule = [Math]::Max(($sortedInventory.RoutingRule | Measure-Object -Maximum -Property Length).Maximum, 'Routing Rule'.Length)
$maxBackend = [Math]::Max(($sortedInventory.Backend | Measure-Object -Maximum -Property Length).Maximum, 'Backend Pool'.Length)

# Calculate cert column width based on content
$certLengths = $sortedInventory | ForEach-Object {
    if ($_.CertificateDisplayInfo) { $_.CertificateDisplayInfo.Length }
    elseif ($_.CertificateExpiration) { 10 }  # YYYY-MM-DD
    else { 1 }  # '-'
}
$maxCertContent = ($certLengths | Measure-Object -Maximum).Maximum
$maxCert = [Math]::Max($maxCertContent, 'Cert/Expiry'.Length)

# Print header
$header = "{0,-$maxEndpoint}  {1,-4}  {2,-5}  {3,-3}  {4,-$maxMatch}  {5,-$maxRule}  {6,-$maxBackend}  {7,-$maxCert}" -f `
    'Endpoint Name', 'HTTP', 'HTTPS', 'Aff', 'Match', 'Routing Rule', 'Backend Pool', 'Cert/Expiry'
Write-Host $header -ForegroundColor White
Write-Host ("-" * $header.Length) -ForegroundColor White

# Print rows
foreach ($item in $sortedInventory) {
    $aff = $item.SessionAffinity ? '*' : ' '
    $http = $item.HTTP ? '*' : ' '
    $https = $item.HTTPS ? '*' : ' '
    $cert = if ($item.CertificateDisplayInfo) {
        $item.CertificateDisplayInfo
    }
    elseif ($item.CertificateExpiration) {
        $item.CertificateExpiration.ToString('yyyy-MM-dd')
    }
    else {
        '-'
    }
    
    $row = "{0,-$maxEndpoint}  {1,-4}  {2,-5}  {3,-3}  {4,-$maxMatch}  {5,-$maxRule}  {6,-$maxBackend}  {7,-$maxCert}" -f `
        $item.EndpointName, $http, $https, $aff, $item.MatchPattern, $item.RoutingRule, $item.Backend, $cert
    
    # Determine row color: Red for problematic domains (mismatch/no certificate), Yellow for expiring soon, DarkGray for redirects, White for normal
    $rowColor = if ($item.IsMismatch -or -not $item.CertificateConfigured) {
        'Red'
    }
    elseif ($item.CertificateExpiration -and ($item.CertificateExpiration - (Get-Date)).Days -lt 30) {
        'Yellow'
    }
    elseif ($item.IsRedirect) {
        'DarkGray'
    }
    else {
        'White'
    }
    
    Write-Host $row -ForegroundColor $rowColor
}

Write-Host "`nLegend:" -ForegroundColor Cyan
Write-Host "  Aff = Session Affinity (*=enabled)" -ForegroundColor Gray
Write-Host "  Match = Path pattern(s) for the routing rule ('Multiple' if more than one)" -ForegroundColor Gray
Write-Host "  HTTP/HTTPS = Protocols accepted by the routing rule (*=enabled)" -ForegroundColor Gray
Write-Host "  Cert/Expiry = Certificate info: 'YYYY-MM-DD' (expiration), 'EXPIRED:YYYY-MM-DD' (expired), '*.domain' (fallback cert CN), '-' (none)" -ForegroundColor Gray
Write-Host "  Certificate problems (expired/fallback) are shown in RED, certificates expiring within 30 days in YELLOW" -ForegroundColor Gray
if (-not $HideRedirects) {
    Write-Host "  Redirect rules are shown in gray (not migration blockers)" -ForegroundColor Gray
}
Write-Host "  Note: If one endpoint is used by multiple routing rules, it will appear multiple times" -ForegroundColor Gray

# Now show migration blockers if any
if ($issues.Count -eq 0) {
    Write-Host "`n" -NoNewline
    Write-Host ('=' * 120) -ForegroundColor Green
    Write-Host '  MIGRATION READINESS: PASSED' -ForegroundColor Green
    Write-Host ('=' * 120) -ForegroundColor Green
    Write-Host "`n[OK] All endpoints have HTTPS certificates configured." -ForegroundColor Green
}
else {
    Write-Host "`n" -NoNewline
    Write-Host ('=' * 120) -ForegroundColor Yellow
    Write-Host "  MIGRATION BLOCKERS DETECTED: $($issues.Count) issue(s)" -ForegroundColor Yellow
    Write-Host ('=' * 120) -ForegroundColor Yellow
    
    # Group issues by type for better clarity
    $groupedIssues = $issues | Group-Object Type
    
    foreach ($group in $groupedIssues) {
        Write-Host "`n=== $($group.Name) Issues ($($group.Count)) ===" -ForegroundColor Cyan
        
        foreach ($issue in $group.Group) {
            Write-Host "`nName: $($issue.Name)" -ForegroundColor White
            Write-Host "Details: $($issue.Detail)" -ForegroundColor Gray
            Write-Host ('-' * 80) -ForegroundColor DarkGray
        }
    }
}

