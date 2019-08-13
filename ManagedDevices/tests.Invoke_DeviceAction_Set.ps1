<#
Ref :
* https://dzone.com/articles/getting-access-token-for-microsoft-graph-using-oau
* https://github.com/microsoftgraph/powershell-intune-samples
* https://configmgrblog.com/2017/12/20/how-to-use-powershell-to-access-microsoft-intune-via-microsoft-graph-api/
* https://alexholmeset.blog/2018/10/10/getting-started-with-graph-api-and-powershell/
* https://www.powershellgallery.com/packages/MSGraphIntuneManagement/0.2/Content/Functions%5CGet-MSGraphAuthenticationToken.ps1
* https://developer.microsoft.com/fr-fr/graph/graph-explorer

Utiliser lun compte AAD 'Global Administrator'
#>

Import-Module .\managedDevices\Invoke_DeviceAction_Set.ps1

$ClientId = 'd1ddf0e4-d672-4dae-b554-9d5bdfd93547' #WindowsAutoPilotIntune

# Premet d'avoir le prompt de connection et de valider les droits de l'application sur AzurAD
#$AuthToken = Get-MSGraphAuthenticationToken -ClientId $ClientId -Tenant 'arafer.fr'

write-host "MsGraph API User Principal Name connexion :" -f Yellow
$UpnApiUser = Read-Host
write-host "MsGraph API User password :" -f Yellow
$PwdApiUser = Read-Host

$Pwd = ConvertTo-SecureString $PwdApiUser -AsPlainText -Force
$Cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $UpnApiUser, $Pwd

$global:authToken = Get-MSGraphAuthenticationToken -Credential $Cred -ClientId $ClientId

write-host "User Principal Name to find owned devices : " -f Yellow
$UPN = Read-Host

$User = Get-AADUser -userPrincipalName $UPN

$id = $User.Id
write-host "User ID:"$id
Write-Host "Checking if the user" $User.displayName "has any devices assigned..." -ForegroundColor DarkCyan

$Device = $null
$Devices = Get-AADUserDevices -UserID $id
if ($Devices) {

    $DeviceCount = @($Devices).count
    Write-Host "User has $DeviceCount devices added to Azure AD..."

    foreach ($Device in $Devices) {
        write-host "User $($User.userPrincipalName) has device owned $($Device.displayName)"
    }
}
    
else {
    Write-Host
    write-host "User $UPN doesn't have any owned Devices..." -f Yellow
}

$Devices = $null
$Devices = @(Get-ManagedUserDevices -UserID $id)
if ($Devices) {

    $DeviceCount = @($Devices).count
    Write-Host "User has $DeviceCount devices added to Intune..."

    foreach ($Device in $Devices) {
        write-host "User $($User.userPrincipalName) has device $($Device.displayName)"

        write-host "Are you sure you want to wipe this device ? Y or N ?"
        $Confirm = read-host

        if ($Confirm -eq "y" -or $Confirm -eq "Y") {
            Invoke-DeviceAction -DeviceID $Device.id -Wipe -Verbose
            #Invoke-DeviceAction -DeviceID $SelectedDeviceId -RemoteLock -Verbose
            #Invoke-DeviceAction -DeviceID $SelectedDeviceId -Retire -Verbose
            #Invoke-DeviceAction -DeviceID $SelectedDeviceId -Wipe -Verbose
            #Invoke-DeviceAction -DeviceID $SelectedDeviceId -Delete -Verbose
            #Invoke-DeviceAction -DeviceID $SelectedDeviceId -Sync -Verbose
        }
    }
}

else {
    Write-Host
    write-host "User $UPN doesn't have any owned Devices..." -f Yellow
}

Break