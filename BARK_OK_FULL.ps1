Function Parse-JWTToken {
    <#
    .DESCRIPTION
    Decodes a JWT token.

    Author: Vasil Michev
    .LINK
    https://www.michev.info/Blog/Post/2140/decode-jwt-access-and-id-tokens-via-powershell
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]$Token
    )

    #Validate as per https://tools.ietf.org/html/rfc7519
    #Access and ID tokens are fine, Refresh tokens will not work
    if (-not $Token.Contains(".") -or -not $Token.StartsWith("eyJ")) {
        Write-Error "Invalid token" -ErrorAction Stop
    }
 
    #Header
    $tokenheader = $Token.Split(".")[0].Replace('-', '+').Replace('_', '/')

    #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($tokenheader.Length % 4) {
        Write-Verbose "Invalid length for a Base-64 char array or string, adding ="
        $tokenheader += "="
    }

    Write-Verbose "Base64 encoded (padded) header: $tokenheader"

    #Convert from Base64 encoded string to PSObject all at once
    Write-Verbose "Decoded header:"
    $header = ([System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($tokenheader)) | convertfrom-json)
 
    #Payload
    $tokenPayload = $Token.Split(".")[1].Replace('-', '+').Replace('_', '/')

    #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($tokenPayload.Length % 4) {
        Write-Verbose "Invalid length for a Base-64 char array or string, adding ="
        $tokenPayload += "="
    }
    
    Write-Verbose "Base64 encoded (padded) payoad: $tokenPayload"

    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)


    $tokenArray = ([System.Text.Encoding]::ASCII.GetString($tokenByteArray) | ConvertFrom-Json)

    #Converts $header and $tokenArray from PSCustomObject to Hashtable so they can be added together.
    #I would like to use -AsHashTable in convertfrom-json. This works in pwsh 6 but for some reason Appveyor isnt running tests in pwsh 6.
    $headerAsHash = @{}
    $tokenArrayAsHash = @{}
    $header.psobject.properties | ForEach-Object { $headerAsHash[$_.Name] = $_.Value }
    $tokenArray.psobject.properties | ForEach-Object { $tokenArrayAsHash[$_.Name] = $_.Value }
    $output = $headerAsHash + $tokenArrayAsHash

    Write-Output $output
}

Function Get-AzureADServicePrincipal {
    <#
    .SYNOPSIS
        Retrieves the JSON-formatted Azure AD service principal objects specified by its object ID
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves the JSON-formatted Azure AD service principal objects specified by its object ID
    
    .PARAMETER Token
        The MS Graph-scoped JWT for the user with read access to AzureAD service principals

    .PARAMETER ObjectID
        The object ID (NOT the app id) of the service principal
    
    .EXAMPLE
    C:\PS> $ServicePrincipal = Get-AzureADServicePrincipal `
        -Token $Token
        -ObjectID "3e5d6a11-0898-4c1f-ab69-c10115770e57"
    
    Description
    -----------
    Uses the JWT in the $Token variable to fetch the service principal with object id starting with "3e5..."
    
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
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $ObjectID
    )

    # Get the service principal
    $URI = "https://graph.microsoft.com/beta/servicePrincipals/$($ObjectID)"
    $ServicePrincipal = Invoke-RestMethod `
        -Headers @{
            Authorization = "Bearer $($Token)"
            ConsistencyLevel = "eventual"
        } `
        -URI $URI `
        -UseBasicParsing `
        -Method "GET" `
        -ContentType "application/json"

    $ServicePrincipal

}


Function Get-MSGraphTokenWithClientCredentials {
    <#
    .DESCRIPTION
    Uses client credentials to request a token from STS with the MS Graph specified as the resource/intended audience
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]
        $ClientID,

        [Parameter(Mandatory = $True)]
        [string]
        $ClientSecret,

        [Parameter(Mandatory = $True)]
        [string]
        $TenantName,

        [Parameter(Mandatory = $False)]
        [Switch]
        $UseCAE
    )

    $Body = @{
        Grant_Type      =   "client_credentials"
        Scope           =   "https://graph.microsoft.com/.default"
        client_Id       =   $ClientID
        Client_Secret   =   $ClientSecret
    }

    if ($UseCAE) {
        $Claims = (
            @{
                "access_token" = @{
                    "xms_cc" = @{
                        "values" = @(
                            "cp1"
                        )
                    }
                }
            } | ConvertTo-Json -Compress -Depth 3 )
        $Body.Add("claims", $Claims)
    }

    $Token = Invoke-RestMethod `
        -URI    "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token" `
        -Method POST `
        -Body   $Body

    $Token
}
New-Variable -Name 'Get-MSGraphTokenWithClientCredentialsDefinition' -Value (Get-Command -Name "Get-MSGraphTokenWithClientCredentials") -Force
New-Variable -Name 'Get-MSGraphTokenWithClientCredentialsAst' -Value (${Get-MSGraphTokenWithClientCredentialsDefinition}.ScriptBlock.Ast.Body) -Force



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

    $MGAppRoles | ?{$_.appRoleId -Like "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9" -And $_.principalType -Like "ServicePrincipal"} | %{
        $TierZeroServicePrincipal = New-Object PSObject -Property @{
            ServicePrincipalID    = $_.principalId
            TierZeroPrivilege     = "MS Graph App Role: Application.ReadWrite.All"
        }
        $TierZeroServicePrincipals += $TierZeroServicePrincipal
    }

    $MGAppRoles | ?{$_.appRoleId -Like "19dbc75e-c2e2-444c-a770-ec69d8559fc7" -And $_.principalType -Like "ServicePrincipal"} | %{
        $TierZeroServicePrincipal = New-Object PSObject -Property @{
            ServicePrincipalID    = $_.principalId
            TierZeroPrivilege     = "MS Graph App Role: Directory.ReadWrite.All"
        }
        $TierZeroServicePrincipals += $TierZeroServicePrincipal
    }

    $MGAppRoles | ?{$_.appRoleId -Like "62a82d76-70ea-41e2-9197-370581804d09" -And $_.principalType -Like "ServicePrincipal"} | %{
        $TierZeroServicePrincipal = New-Object PSObject -Property @{
            ServicePrincipalID    = $_.principalId
            TierZeroPrivilege     = "MS Graph App Role: Group.ReadWrite.All"
        }
        $TierZeroServicePrincipals += $TierZeroServicePrincipal
    }

    $MGAppRoles | ?{$_.appRoleId -Like "Dbaae8cf-10b5-4b86-a4a1-f871c94c6695" -And $_.principalType -Like "ServicePrincipal"} | %{
        $TierZeroServicePrincipal = New-Object PSObject -Property @{
            ServicePrincipalID    = $_.principalId
            TierZeroPrivilege     = "MS Graph App Role: GroupMember.ReadWrite.All"
        }
        $TierZeroServicePrincipals += $TierZeroServicePrincipal
    }

    $MGAppRoles | ?{$_.appRoleId -Like "89c8469c-83ad-45f7-8ff2-6e3d4285709e" -And $_.principalType -Like "ServicePrincipal"} | %{
        $TierZeroServicePrincipal = New-Object PSObject -Property @{
            ServicePrincipalID    = $_.principalId
            TierZeroPrivilege     = "MS Graph App Role: ServicePrincipalEndpoint.ReadWrite.All"
        }
        $TierZeroServicePrincipals += $TierZeroServicePrincipal
    }
    
    $TierZeroServicePrincipals
}
