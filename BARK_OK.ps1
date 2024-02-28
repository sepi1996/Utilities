Function Get-TierZeroServicePrincipals {
    <#
    .SYNOPSIS
        Finds all Service Principals that have a Tier Zero AzureAD Admin Role or Tier Zero MS Graph App Role assignment
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Finds all Service Principals that have a Tier Zero AzureAD Admin Role or Tier Zero MS Graph App Role assignment
    
    .PARAMETER Token
        A MS Graph scoped JWT for a user with the ability to read AzureAD and MS Graph app role assignments
    
    .EXAMPLE
    C:\PS> Get-TierZeroServicePrincipals -Token $Token
    
    Description
    -----------
    Retrieve a list of all service principals with Tier Zero privileges
    
    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
    )

    # Get Global Admin service principals:
    $GlobalAdmins = $null 
    $URI = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'&`$expand=principal"
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $GlobalAdmins += $Results.value
        } else {
            $GlobalAdmins += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))
    
    # Get Privileged Role Administrator principals:
    $PrivRoleAdmins = $null
    $URI = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq 'e8611ab8-c189-46e8-94e1-60213ab1f814'&`$expand=principal"
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $PrivRoleAdmins += $Results.value
        } else {
            $PrivRoleAdmins += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))
    
    # Get Privileged Authentication Administrator principals:
    $PrivAuthAdmins = $null
    $URI = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'&`$expand=principal"
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $PrivAuthAdmins += $Results.value
        } else {
            $PrivAuthAdmins += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))
    
    # Get Partner Tier2 Support principals:
    $PartnerTier2Support = $null
    $URI = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq 'e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8'&`$expand=principal"
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $PartnerTier2Support += $Results.value
        } else {
            $PartnerTier2Support += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))
    
    # Get the MS Graph SP
    $URL = "https://graph.microsoft.com/v1.0/servicePrincipals/?`$filter=appId eq '00000003-0000-0000-c000-000000000000'"
    $MSGraphSP = (Invoke-RestMethod `
        -URI $URL `
        -Method "GET" `
        -Headers @{
            Authorization = "Bearer $($Token)"
        }).value
    
    # Get app roles scoped to the Graph SP
    $MGAppRoles = $null
    $URI = "https://graph.microsoft.com/v1.0/servicePrincipals/$($MSGraphSP.id)/appRoleAssignedTo"
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $MGAppRoles += $Results.value
        } else {
            $MGAppRoles += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))
    
    $TierZeroServicePrincipals = @()
    
    $GlobalAdmins | select -expand principal | ?{$_.'@odata.type' -Like "#microsoft.graph.servicePrincipal"} | %{
        $TierZeroServicePrincipal = New-Object PSObject -Property @{
            ServicePrincipalID    = $_.id
            TierZeroPrivilege     = "Global Administrator"
        }
        $TierZeroServicePrincipals += $TierZeroServicePrincipal
    }
    
    $PrivRoleAdmins | select -expand principal | ?{$_.'@odata.type' -Like "#microsoft.graph.servicePrincipal"} | %{
        $TierZeroServicePrincipal = New-Object PSObject -Property @{
            ServicePrincipalID    = $_.id
            TierZeroPrivilege     = "Privileged Role Administrator"
        }
        $TierZeroServicePrincipals += $TierZeroServicePrincipal
    }
    
    $PrivAuthAdmins | select -expand principal | ?{$_.'@odata.type' -Like "#microsoft.graph.servicePrincipal"} | %{
        $TierZeroServicePrincipal = New-Object PSObject -Property @{
            ServicePrincipalID    = $_.id
            TierZeroPrivilege     = "Privileged Authentication Administrator"
        }
        $TierZeroServicePrincipals += $TierZeroServicePrincipal
    }
    
    $PartnerTier2Support | select -expand principal | ?{$_.'@odata.type' -Like "#microsoft.graph.servicePrincipal"} | %{
        $TierZeroServicePrincipal = New-Object PSObject -Property @{
            ServicePrincipalID    = $_.id
            TierZeroPrivilege     = "Partner Tier2 Support"
        }
        $TierZeroServicePrincipals += $TierZeroServicePrincipal
    }
    
    $MGAppRoles | ?{$_.appRoleId -Like "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" -And $_.principalType -Like "ServicePrincipal"} | %{
        $TierZeroServicePrincipal = New-Object PSObject -Property @{
            ServicePrincipalID    = $_.principalId
            TierZeroPrivilege     = "MS Graph App Role: RoleManagement.ReadWrite.Directory"
        }
        $TierZeroServicePrincipals += $TierZeroServicePrincipal
    }
    
    $MGAppRoles | ?{$_.appRoleId -Like "06b708a9-e830-4db3-a914-8e69da51d44f" -And $_.principalType -Like "ServicePrincipal"} | %{
        $TierZeroServicePrincipal = New-Object PSObject -Property @{
            ServicePrincipalID    = $_.principalId
            TierZeroPrivilege     = "MS Graph App Role: AppRoleAssignment.ReadWrite.All"
        }
        $TierZeroServicePrincipals += $TierZeroServicePrincipal
    }
    
    $TierZeroServicePrincipals
}
