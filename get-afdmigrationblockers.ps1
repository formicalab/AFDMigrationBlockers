<#
.SYNOPSIS
Detects HTTP routes, redirect rules, and other elements in an Azure Front Door (Classic)
that are incompatible with Azure Front Door Standard/Premium.

.REQUIREMENTS
Install-Module Az.FrontDoor -MinimumVersion 1.13.0
Connect-AzAccount
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
    $httpsCfg = $frontend.CustomHttpsConfiguration
    $hostName = $frontend.HostName
    $httpsProvisioningState = $frontend.CustomHttpsProvisioningState
    
    # Determine certificate status with fallback checks
    $certificateSource = $httpsCfg.CertificateSource ?? $frontend.CertificateSource ?? 
        ($frontend.ProtocolType -eq 'ServerNameIndication' ? 'FrontDoor' : 'None')
    $hasCertificate = $certificateSource -ne 'None'
    
    # Check session affinity
    $hasAffinity = $frontend.SessionAffinityEnabledState -eq 'Enabled'
    
    # Find all routing rules that use this frontend endpoint
    $routesUsingEndpoint = $fd.RoutingRules | Where-Object { 
        $_.FrontendEndpointIds -contains $frontend.Id
    }
    
    if ($ShowDebugInfo) {
        Write-Host "DEBUG: Checking endpoint '$feName' (ID: $($frontend.Id))" -ForegroundColor DarkGray
        Write-Host "DEBUG: Found $($routesUsingEndpoint.Count) routing rule(s) using this endpoint" -ForegroundColor DarkGray
        if ($routesUsingEndpoint) {
            $routesUsingEndpoint | ForEach-Object { Write-Host "DEBUG:   - $($_.Name)" -ForegroundColor DarkGray }
        }
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
                CertificateSource = $certificateSource
                ProvisioningState = $httpsProvisioningState
                IsRedirect = $isRedirect
            })
        }
    }
    else {
        # Endpoint not used by any routing rule
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
            CertificateSource = $certificateSource
            ProvisioningState = $httpsProvisioningState
            IsRedirect = $false
        })
    }
}

# Check for frontend endpoints without HTTPS configuration
# Front Door Standard/Premium requires HTTPS certificates for all custom domains
foreach ($frontend in $fd.FrontendEndpoints) {
    $feName = $frontend.Name
    $httpsCfg = $frontend.CustomHttpsConfiguration
    $hostName = $frontend.HostName
    $httpsProvisioningState = $frontend.CustomHttpsProvisioningState
    
    if (-not $hasCertificate) {
        # Determine the actual issue
        $detailMsg = "Endpoint '$hostName' - "
        
        if ($httpsProvisioningState -eq 'Disabled') {
            $detailMsg += 'HTTPS is DISABLED for this endpoint (HTTP-only). '
        }
        else {
            $detailMsg += 'No HTTPS certificate configured. '
        }
        
        # Check if any routing rules use this frontend endpoint
        $allRoutesUsingFrontend = $fd.RoutingRules | Where-Object { 
            $_.FrontendEndpointIds -contains $frontend.Id
        }
        
        $httpRoutesUsingFrontend = $allRoutesUsingFrontend | Where-Object { 
            $_.AcceptedProtocols -contains 'Http'
        }
        
        if ($httpRoutesUsingFrontend) {
            $detailMsg += "CRITICAL BLOCKER: This endpoint is actively used by HTTP routing rule(s): $($httpRoutesUsingFrontend.Name -join ', '). "
        }
        elseif ($allRoutesUsingFrontend) {
            $detailMsg += "USED BY: Routing rule(s): $($allRoutesUsingFrontend.Name -join ', ') (HTTPS-only routes). Standard/Premium still requires HTTPS certificate. "
        }
        else {
            $detailMsg += 'WARNING: This endpoint appears to NOT be used by any routing rules. Consider removing if unused. However, Standard/Premium requires HTTPS on all endpoints. '
        }
        
        $detailMsg += 'REQUIRED ACTION: Enable HTTPS with either Azure-managed certificate or upload custom certificate from Key Vault before migration.'
        
        $issues.Add([pscustomobject]@{
                Type   = 'Frontend endpoint'
                Name   = $feName
                Detail = $detailMsg
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
$managedCerts = ($endpointInventory.Where{$_.CertificateSource -eq 'FrontDoor'}.EndpointName | Select-Object -Unique).Count
$keyVaultCerts = ($endpointInventory.Where{$_.CertificateSource -eq 'AzureKeyVault'}.EndpointName | Select-Object -Unique).Count

Write-Host "`nSummary: $uniqueEndpoints total endpoint(s), $usedEndpoints used by routes, $unusedEndpoints unused" -ForegroundColor White
Write-Host "         $withCerts endpoint(s) with certificates ($managedCerts Azure-managed, $keyVaultCerts from Key Vault), $withoutCerts without certificates" -ForegroundColor White
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

# Print header
$header = "{0,-$maxEndpoint}  {1,-4}  {2,-5}  {3,-3}  {4,-$maxMatch}  {5,-$maxRule}  {6,-$maxBackend}  {7,-8}" -f `
    'Endpoint Name', 'HTTP', 'HTTPS', 'Aff', 'Match', 'Routing Rule', 'Backend Pool', 'Cert'
Write-Host $header -ForegroundColor White
Write-Host ("-" * $header.Length) -ForegroundColor White

# Print rows
foreach ($item in $sortedInventory) {
    $aff = $item.SessionAffinity ? '*' : ' '
    $http = $item.HTTP ? '*' : ' '
    $https = $item.HTTPS ? '*' : ' '
    $cert = $item.CertificateConfigured ? 
        ($item.CertificateSource -eq 'FrontDoor' ? 'Managed' : 
         $item.CertificateSource -eq 'AzureKeyVault' ? 'KeyVault' : 'Yes') : '-'
    
    $row = "{0,-$maxEndpoint}  {1,-4}  {2,-5}  {3,-3}  {4,-$maxMatch}  {5,-$maxRule}  {6,-$maxBackend}  {7,-8}" -f `
        $item.EndpointName, $http, $https, $aff, $item.MatchPattern, $item.RoutingRule, $item.Backend, $cert
    
    # Redirect rules are shown in gray
    Write-Host $row -ForegroundColor ($item.IsRedirect ? 'DarkGray' : 'White')
}

Write-Host "`nLegend:" -ForegroundColor Cyan
Write-Host "  Aff = Session Affinity (*=enabled)" -ForegroundColor Gray
Write-Host "  Match = Path pattern(s) for the routing rule ('Multiple' if more than one)" -ForegroundColor Gray
Write-Host "  HTTP/HTTPS = Protocols accepted by the routing rule (*=enabled)" -ForegroundColor Gray
Write-Host "  Cert = Certificate type: 'Managed' (Azure-managed), 'KeyVault' (from Azure Key Vault), '-' (none)" -ForegroundColor Gray
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

    Write-Host "`n`n=== EXPLANATION ===" -ForegroundColor Magenta
    Write-Host 'Azure Front Door Standard/Premium has different behavior than Classic:' -ForegroundColor White
    Write-Host ''
    Write-Host 'FRONTEND ENDPOINTS: In Standard/Premium, all endpoints MUST have HTTPS enabled.' -ForegroundColor Yellow
    Write-Host '   - Classic allows endpoints without certificates (HTTP-only)' -ForegroundColor Gray
    Write-Host '   - Standard/Premium requires a certificate for every custom domain' -ForegroundColor Gray
    Write-Host '   - Solution: Enable Azure-managed certificates or upload custom certificates' -ForegroundColor Green
    
    Write-Host "`n`n=== RECOMMENDED ACTIONS ===" -ForegroundColor Magenta
    Write-Host ' 1. For each frontend endpoint without a certificate: Enable custom HTTPS with Azure-managed or custom certificate'
    Write-Host ''
}

