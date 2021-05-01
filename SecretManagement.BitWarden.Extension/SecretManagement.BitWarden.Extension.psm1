using namespace Microsoft.PowerShell.SecretManagement

function Get-Secret {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $Name,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $VaultName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )

    $res = Invoke-bwcmd "get item $Name"


    Switch ($AdditionalParameters.outputType ) {
        'Detailed' {
            Write-Verbose "Getting Detailed Secret"
            $Output = $res
            $Output.PSObject.TypeNames.Insert(0, "BW_SECRET_Detailed")
        }
        'Totp' {
            $Output = Invoke-bwcmd "get totp $Name"
            $Output.PSObject.TypeNames.Insert(0, "BW_SECRET_TOTP")
        }
        Default {
            Write-Verbose "Getting Simple Secret"
            $username = $res.login.Username
            $password = $res.login.Password
            if ($username -or $password) {
                Write-Verbose "Getting Login Account"
                if ($null -eq $username) { $username = '' }
                if ($null -eq $password) { $password = '' }
                if ("" -ne $password) { $password = $password | ConvertTo-SecureString -AsPlainText -Force }
                $Output = [System.Management.Automation.PSCredential]::new($username, $password)
            }
            # Secure Note
            if ($null -ne $res.Notes) {
                Write-Verbose "Getting SecureNote"
                return $res.Notes
            }
        }
    }

    return $Output
}


Function Get-SecretTemplate {
    <#
.SYNOPSIS
Create a BitWarden Secret Template Object
.DESCRIPTION
Create a BitWarden Secret Template Object
.PARAMETER Vault
Name of the vault to connect to.
.PARAMETER User
Username to connect with.
.PARAMETER Trust
Cause subsquent logins to not require multifactor authentication.
.PARAMETER StayConnected
Save the LastPass decryption key on the hard drive so re-entering password once the connection window close is not required anymore. 
This operation will prompt the user.
.PARAMETER Force
Force switch.
.EXAMPLE
PS> Get-SecretTemplate -url 'https://github.com/' -Note "Version control using Git" -Type 'Login' | Set-Secret
Create login templated secret and create secret in BitWarden.  This will automatically prompt to set credentials
PS> Get-SecretTemplate -url 'https://github.com/' -Note "Version control using Git" -Type 'SecureNote' | Set-Secret
Create SecureNote templated secret and create secret in BitWarden.
#>
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [string]$Name, 
        [parameter(Mandatory = $true)]
        [ValidateSet("SecureNote", "Login")]
        [string]$Type,
        [string]$Note, 
        [string]$url
)

    Switch ($type) {
        'Login' {
            $credential = Get-Credential
            $username = $Credential.UserName
            $password = $Credential.GetNetworkCredential().Password
            $object = @"
        {"organizationId":null,"folderId":null,"type":1,"name":"$Name","notes":"$Note","favorite":false,"fields":[],"login":{"uris":[{"match":null,"uri":"$url"}],"username":"$username","password":"$password","totp":"JBSWY3DPEHPK3PXP"},"secureNote":null,"card":null,"identity":null}
"@ 
        }
        'SecureNote' {
            $object = @"
    {"organizationId":null,"folderId":null,"type":2,"name":"$Name","notes":"$Note","favorite":false,"secureNote":{"type":0}}
"@
        }
    }

    $object = $object | ConvertFrom-Json
    $object.PSObject.TypeNames.Insert(0, "BW_SECRET_Template")
    $object
}


function Set-Secret {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $Name,
        [Parameter(ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [ValidateScript( { $_.PSObject.TypeNames[0] -eq 'BW_SECRET_Template' -or $_.PSObject.TypeNames[0] -eq 'BW_SECRET_Detailed' -or [PSCredential] })]
        $Secret,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $VaultName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )
    
    if ($Secret -is [pscredential]) {
        $object = Get-Secret -Name $Name -AdditionalParameters @{OutputType = 'Detailed' }
        $object.login.username = $Secret.Username
        $object.login.password = $Secret.GetNetworkCredential().password
        $res = invoke-bwcmd "edit item $($object.ID) $([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($Object | Convertto-Json -depth 10 -compress))))"
    }
    IF ($Secret.PSObject.TypeNames -eq 'BW_SECRET_Detailed') {
        Write-Verbose "Editing Item $($Secret.Name)"
        $res = invoke-bwcmd "edit item $($secret.ID) $([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($secret | Convertto-Json -depth 10 -compress))))"
    }
    IF ($Secret.PSObject.TypeNames -eq 'BW_SECRET_Template') {
        Write-Verbose "Creating new object $($Secret.Name)"
        $res = invoke-bwcmd "create item $([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($secret | Convertto-Json -depth 10 -compress))))" 
    }
    
    $res 
}

function Remove-Secret {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $Name,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $VaultName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )



    Invoke-bwcmd "delete item $Name"
}

function Get-SecretInfo {
    [CmdletBinding()]
    param(
        [string] $Filter,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    if ([string]::IsNullOrEmpty($Filter))
    {
        $Filter = "*"
    }
    $pattern = [WildcardPattern]::new($Filter)
    $vaultSecretInfos = invoke-bwcmd "list items"

    foreach ($vaultSecretInfo in $vaultSecretInfos) {
        
        if ($pattern.IsMatch($vaultSecretInfo.Name))
        {
            $metadata=get-BWmetadata -vaultSecretInfo $vaultSecretInfo
            IF ($vaultSecretInfo.type -eq 1) {
                $type = [Microsoft.PowerShell.SecretManagement.SecretType]::PSCredential
            }ELSE{
                $type = [Microsoft.PowerShell.SecretManagement.SecretType]::SecureString
            }
            Write-Output (
                [Microsoft.PowerShell.SecretManagement.SecretInformation]::new(
                    $vaultSecretInfo.Name,
                    $type,
                    $VaultName,
                    $metadata)
            ) | Select-Object *, @{Name = 'GUID_Name'; Expression = { $vaultSecretInfo.ID } }
        }
    }
}

function Test-SecretVault {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $VaultName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )
    invoke-bwcmd "sync" | Out-Null 
    $status = invoke-bwcmd "status" 
    return $status
}
