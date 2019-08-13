
<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

.NOTES
    Forked by MIXTRIO DERET Raphaël 13/08/2019

    * Set MsGraph API in v1.0
    * Replace function Get-AuthToken by Get-MSGraphAuthenticationToken
    * Add function ManagedUserDevices()

    Company                     : MIXTRIO
    Author                      : DERET Raphaël
    Author email                : raphaël.deret@mixtrio.net
    Version                     : 1.0
    Copyright                   : (c) 2019 MIXTRIO DERET Raphaël. Tous droits réservés.

#>

####################################################

Function Get-MSGraphAuthenticationToken {
    <# 
          .SYNOPSIS 
          This function is used to get an authentication token for the Graph API REST interface 
          .DESCRIPTION 
          Built based on the following example script from Microsoft: https://github.com/microsoftgraph/powershell-intune-samples/blob/master/Authentication/Auth_From_File.ps1 
          .EXAMPLE 
          $Credential = Get-Credential 
          $ClientId = 'f338765e-1cg71-427c-a14a-f3d542442dd' 
          $AuthToken = Get-MSGraphAuthenticationToken -Credential $Credential -ClientId $ClientId 
          .EXAMPLE 
          $ClientId = 'f338765e-1cg71-427c-a14a-f3d542442dd' 
          $AuthToken = Get-MSGraphAuthenticationToken -ClientId $ClientId -Tenant domain.onmicrosoft.com 
      #>
    [cmdletbinding()]
      
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'PSCredential')]
        [PSCredential] $Credential,
        [Parameter(Mandatory = $true)]
        [String]$ClientId,
        [Parameter(Mandatory = $true, ParameterSetName = 'ADAL')]
        [String]$TenantId
    )
      
    Write-Verbose 'Importing prerequisite modules...'
      
    try {
        $AadModule = Import-Module -Name AzureAD -ErrorAction Stop -PassThru
    }
      
    catch {
        throw 'Prerequisites not installed (AzureAD PowerShell module not installed'
    }

    switch ($PsCmdlet.ParameterSetName) { 

        'ADAL' { $tenant = $TenantId } 

        'PSCredential' {
            $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $Credential.Username        
            $tenant = $userUpn.Host
        } 
    } 
          
    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version
      
    $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
    $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
      
    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
      
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    $resourceAppIdURI = "https://graph.microsoft.com"
    $authority = "https://login.microsoftonline.com/$Tenant"
      
    try {
      
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
      
        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
            
        if ($PSBoundParameters.ContainsKey('Credential')) {

            $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
            #$userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($Credential.Username, "OptionalDisplayableId")
             
            $userCredentials = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.UserPasswordCredential -ArgumentList $Credential.Username, $Credential.Password

            $authResult = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContextIntegratedAuthExtensions]::AcquireTokenAsync($authContext, $resourceAppIdURI, $clientid, $userCredentials);

            if ($authResult.Result.AccessToken) {
                
                # Creating header for Authorization token
                
                $authHeader = @{
                    'Content-Type'  = 'application/json'
                    'Authorization' = "Bearer " + $authResult.Result.AccessToken
                    'ExpiresOn'     = $authResult.Result.ExpiresOn
                }
                
                return $authHeader
                
            }
            elseif ($authResult.Exception) {
              
                throw "An error occured getting access token: $($authResult.Exception.InnerException)"
              
            }

        }

        else {

            $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Always"
            $authResult = ($authContext.AcquireTokenAsync($resourceAppIdURI, $ClientID, $RedirectUri, $platformParameters)).Result

            if ($authResult.AccessToken) {                
               
                # Creating header for Authorization token
                
                $authHeader = @{
                    'Content-Type'  = 'application/json'
                    'Authorization' = "Bearer " + $authResult.AccessToken
                    'ExpiresOn'     = $authResult.ExpiresOn
                }
              
                return $authHeader
            }
        }
    }
      
    catch {
        throw $_.Exception.Message 
    }
}

####################################################

Function Get-AADUser() {

    <#
.SYNOPSIS
This function is used to get AAD Users from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any users registered with AAD
.EXAMPLE
Get-AADUser
Returns all users registered with Azure AD
.EXAMPLE
Get-AADUser -userPrincipleName user@domain.com
Returns specific user by UserPrincipalName registered with Azure AD
.NOTES
NAME: Get-AADUser
#>

    [cmdletbinding()]

    param
    (
        $userPrincipalName,
        $Property
    )

    # Defining Variables
    $graphApiVersion = "v1.0"
    $User_resource = "users"

    try {

        if ($userPrincipalName -eq "" -or $userPrincipalName -eq $null) {

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

        }

        else {

            if ($Property -eq "" -or $Property -eq $null) {

                $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)/$userPrincipalName"
                Write-Verbose $uri
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

            }

            else {

                $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)/$userPrincipalName/$Property"
                Write-Verbose $uri
                (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

            }

        }

    }

    catch {

        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break

    }

}

####################################################

Function Get-AADUserDevices() {

    <#
.SYNOPSIS
This function is used to get an AAD User Devices from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets a users devices registered with Azure AD
.EXAMPLE
Get-AADUserDevices -UserID $UserID
Returns all user devices registered in Azure AD
.NOTES
NAME: Get-AADUserDevices
#>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true, HelpMessage = "UserID (guid) for the user you want to take action on must be specified:")]
        $UserID
    )

    # Defining Variables
    $graphApiVersion = "v1.0"
    $Resource = "users/$UserID/ownedDevices"

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)" 
        Write-Verbose $uri
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

    }

    catch {

        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break

    }

}

####################################################

Function Get-ManagedUserDevices() {

    <#
    .SYNOPSIS
    This function is used to get an AAD User Devices from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets a users devices registered with Intune MDM
    .EXAMPLE
    Get-AADUserDevices -UserID $UserID
    Returns all user devices registered in Intune MDM
    .NOTES
    NAME: Get-ManagedUserDevices
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory = $true, HelpMessage = "UserID (guid) for the user you want to take action on must be specified:")]
        $UserID
    )
    
    # Defining Variables
    $graphApiVersion = "v1.0"
    $Resource = "users/$UserID/managedDevices"
    
    try {
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)" 
        Write-Verbose $uri
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    
    }
    
}

####################################################

Function Invoke-DeviceAction() {

    <#
.SYNOPSIS
This function is used to set a generic intune resources from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and sets a generic Intune Resource
.EXAMPLE
Invoke-DeviceAction -DeviceID $DeviceID -remoteLock
Resets a managed device passcode
.NOTES
NAME: Invoke-DeviceAction
#>

    [cmdletbinding()]

    param
    (
        [switch]$RemoteLock,
        [switch]$ResetPasscode,
        [switch]$Wipe,
        [switch]$Retire,
        [switch]$Delete,
        [switch]$Sync,
        [switch]$Rename,
        [Parameter(Mandatory = $true, HelpMessage = "DeviceId (guid) for the Device you want to take action on must be specified:")]
        $DeviceID
    )

    $graphApiVersion = "v1.0"

    try {

        $Count_Params = 0

        if ($RemoteLock.IsPresent) { $Count_Params++ }
        if ($ResetPasscode.IsPresent) { $Count_Params++ }
        if ($Wipe.IsPresent) { $Count_Params++ }
        if ($Retire.IsPresent) { $Count_Params++ }
        if ($Delete.IsPresent) { $Count_Params++ }
        if ($Sync.IsPresent) { $Count_Params++ }
        if ($Rename.IsPresent) { $Count_Params++ }

        if ($Count_Params -eq 0) {

            write-host "No parameter set, specify -RemoteLock -ResetPasscode -Wipe -Delete -Sync or -rename against the function" -f Red

        }

        elseif ($Count_Params -gt 1) {

            write-host "Multiple parameters set, specify a single parameter -RemoteLock -ResetPasscode -Wipe -Delete or -Sync against the function" -f Red

        }

        elseif ($RemoteLock) {

            $Resource = "deviceManagement/managedDevices/$DeviceID/remoteLock"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
            write-verbose $uri
            Write-Verbose "Sending remoteLock command to $DeviceID"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post

        }

        elseif ($ResetPasscode) {

            $Resource = "deviceManagement/managedDevices/$DeviceID/resetPasscode"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
            write-verbose $uri
            Write-Verbose "Sending remotePasscode command to $DeviceID"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post
        }

        elseif ($Wipe) {

            $Resource = "deviceManagement/managedDevices/$DeviceID/wipe"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
            write-verbose $uri
            Write-Verbose "Sending wipe command to $DeviceID"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post
        }

        elseif ($Retire) {

            $Resource = "deviceManagement/managedDevices/$DeviceID/retire"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
            write-verbose $uri
            Write-Verbose "Sending retire command to $DeviceID"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post
        }

        elseif ($Delete) {

            $Resource = "deviceManagement/managedDevices('$DeviceID')"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
            write-verbose $uri
            Write-Verbose "Sending delete command to $DeviceID"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete
        }
        
        elseif ($Sync) {

            $Resource = "deviceManagement/managedDevices('$DeviceID')/syncDevice"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
            write-verbose $uri
            Write-Verbose "Sending sync command to $DeviceID"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post
        }
    }

    catch {

        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    
    }
}