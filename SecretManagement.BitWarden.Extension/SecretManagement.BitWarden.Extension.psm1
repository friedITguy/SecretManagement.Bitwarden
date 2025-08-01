using namespace Microsoft.PowerShell.SecretManagement

# Module-scoped variables
$script:BitwardenSecretsClient = $null
$script:BitwardenSdkLoaded = $false
$script:SessionTimeout = New-TimeSpan -Minutes 30
$script:LastActivity = Get-Date

function Get-Secret {
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    try {
        # Get vault registration info
        $vaultInfo = Get-SecretVault -Name $VaultName -ErrorAction Stop
        if (-not $vaultInfo) {
            throw [System.ArgumentException]::new("Vault '$VaultName' is not registered in PowerShell SecretManagement.")
        }

        # Verify that the BitwardenSecretsClient session is open
        if (-not $script:BitwardenSecretsClient) {
            throw [System.UnauthorizedAccessException]::new("Vault '$VaultName' has not been unlocked. Please run ""Unlock-SecretVault -Name '$VaultName'"" to unlock the vault before using it.")
        }

        # Verify that the session is not expired
        if ((Get-Date) - $script:LastActivity -gt $script:SessionTimeout) {
            $script:BitwardenSecretsClient = $null
            throw [System.UnauthorizedAccessException]::new("Vault '$VaultName' has been locked due to exceeding the idle timeout threshold. You will need to run ""Unlock-SecretVault -Name '$VaultName'"" to unlock the vault before using it again.")
        }

        # Set the LastActivity variable to now
        $script:LastActivity = Get-Date

        # Validate OrganizationId
        if (-not [System.Guid]::TryParse($vaultInfo.VaultParameters.OrganizationId, [ref]$null)) {
            throw [System.ArgumentException]::new("Vault '$VaultName' has an invalid GUID format for the required 'OrganizationId' parameter.")
        }

        # Get a list of all secrets in the vault
        $Private:allSecrets = $script:BitwardenSecretsClient.Secrets.List($vaultInfo.VaultParameters.OrganizationId)

        # Make sure there are secrets in the returned object
        if (-not $Private:allSecrets.Data) {
            throw [System.ArgumentException]::new("Unable to find a secret with an 'Id' matching the provided 'Name' parameter.")
        }

        # Find matching secrets by either Key or Id
        $Private:secretMatch = $Private:allSecrets.Data | Where-Object {($_.Id.Guid -eq $Name) -or ($_.Key -eq $Name)}

        # Check if there was a matching secret found
        if (-not $Private:secretMatch) {
            throw [System.ArgumentException]::new("Unable to find a secret with an 'Id' matching the provided 'Name' parameter.")
        }
        
        # Get the secret from the vault
        $Private:secret = $script:BitwardenSecretsClient.Secrets.Get($Private:secretMatch[0].Id.Guid)

        if (-not $Private:secret) {
            throw [System.ArgumentException]::new("Unable to find a secret with an 'Id' matching the provided 'Name' parameter.")
        }

        if (-not $Private:secret.Value) {
            throw [System.NullReferenceException]::new("A matching secert was found but the secret does not contain a value to return.")
        }

        # Return as SecureString by default for security
        return $Private:secret.Value | ConvertTo-SecureString -AsPlainText -Force
        
    } catch [System.UnauthorizedAccessException] {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $_.Exception,
            'SecretsManagerUnauthorized',
            [System.Management.Automation.ErrorCategory]::AuthenticationError,
            $VaultName
        )
        $PSCmdlet.WriteError($errorRecord)
    } catch {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $_.Exception,
            'SecretsManagerError',
            [System.Management.Automation.ErrorCategory]::ReadError,
            $Name
        )
        $PSCmdlet.WriteError($errorRecord)
    } finally {
        # Clean up sensitive data
        $Private:allSecrets = $null
        $Private:secretMatch = $null
        $Private:secret = $null
        [System.GC]::Collect()
    }
}

function Set-Secret {
    [CmdletBinding()]
    param (
        [string] $Name,
        [object] $Secret,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    try {
        # Get vault registration info
        $vaultInfo = Get-SecretVault -Name $VaultName -ErrorAction Stop
        if (-not $vaultInfo) {
            throw [System.ArgumentException]::new("Vault '$VaultName' is not registered in PowerShell SecretManagement.")
        }

        # Verify that the BitwardenSecretsClient session is open
        if (-not $script:BitwardenSecretsClient) {
            throw [System.UnauthorizedAccessException]::new("Vault '$VaultName' has not been unlocked. Please run ""Unlock-SecretVault -Name '$VaultName'"" to unlock the vault before using it.")
        }

        # Verify that the session is not expired
        if ((Get-Date) - $script:LastActivity -gt $script:SessionTimeout) {
            $script:BitwardenSecretsClient = $null
            throw [System.UnauthorizedAccessException]::new("Vault '$VaultName' has been locked due to exceeding the idle timeout threshold. You will need to run ""Unlock-SecretVault -Name '$VaultName'"" to unlock the vault before using it again.")
        }

        # Set the LastActivity variable to now
        $script:LastActivity = Get-Date


        # Validate OrganizationId
        if (-not [System.Guid]::TryParse($vaultInfo.VaultParameters.OrganizationId, [ref]$null)) {
            throw [System.ArgumentException]::new("Vault '$VaultName' has an invalid GUID format for the required 'OrganizationId' parameter.")
        }

        # Validate ProjectId
        if (-not [System.Guid]::TryParse($vaultInfo.VaultParameters.ProjectId, [ref]$null)) {
            throw [System.ArgumentException]::new("Vault '$VaultName' has an invalid GUID format for the required 'ProjectId' parameter.")
        }
        
        # Convert secret to string value
        $private:secretValue = switch ($Secret.GetType().Name) {
            'SecureString' {
                $Private:ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
                try {
                    [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($Private:ptr)
                } finally {
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Private:ptr)
                    $private:ptr = [System.IntPtr]::Zero
                }
            }
            'PSCredential' {
                # For credentials, store as JSON
                @{
                    username = $Secret.UserName
                    password = $Secret.GetNetworkCredential().Password
                } | ConvertTo-Json -Compress
            }
            'String' {
                $Secret
            }
            default {
                $Secret.ToString()
            }
        }

        # Get all secrets, so we can find the one with a matching name
        $Private:allSecrets = $script:BitwardenSecretsClient.Secrets.List($vaultInfo.VaultParameters.OrganizationId)
        if (-not $Private:allSecrets.Data) {
            Write-Error "Unable to access screts in your Secrets Manager vault" -ErrorAction Stop
        }

        # Find secret with a matching Name or ID
        $Private:existingSecretMatch = $Private:allSecrets.Data | Where-Object {($_.Id -eq $Name) -or ($_.Key -eq $Name)}
        

        if ($Private:existingSecretMatch) {
            # Get the full details of the exisitng secret
            $Private:existingSecret = $script:BitwardenSecretsClient.Secrets.Get($Private:existingSecretMatch[0].Id.Guid)

            # Update existing secret
            $null = $Script:BitwardenSecretsClient.Secrets.Update(
                $vaultInfo.VaultParameters.OrganizationId,
                $Private:existingSecret[0].Id.Guid,
                $Name,
                $Private:secretValue,
                $Private:existingSecret.Note ?? "",
                @($vaultInfo.VaultParameters.ProjectId)
            )
        } else {
            # Create new secret
            $null = $Script:BitwardenSecretsClient.Secrets.Create(
                $vaultInfo.VaultParameters.OrganizationId,
                $Name,
                $Private:secretValue,
                "",
                @($vaultInfo.VaultParameters.ProjectId)
            )
        }

        return $?
        
    } catch [System.UnauthorizedAccessException] {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $_.Exception,
            'SecretsManagerUnauthorized',
            [System.Management.Automation.ErrorCategory]::AuthenticationError,
            $VaultName
        )
        $PSCmdlet.WriteError($errorRecord)
    } catch {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $_.Exception,
            'SecretsManagerError',
            [System.Management.Automation.ErrorCategory]::ReadError,
            $Name
        )
        $PSCmdlet.WriteError($errorRecord)
    } finally {
        # Clean up sensitive data
        $Private:secretValue = $null
        $Private:existingSecretMatch = $null
        $Private:existingSecret = $null
        $Private:ptr = $null
        $Private:allSecrets = $null
        [System.GC]::Collect()
    }
}

function Remove-Secret {
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    
    try {
        
        # Get vault registration info
        $vaultInfo = Get-SecretVault -Name $VaultName -ErrorAction Stop
        if (-not $vaultInfo) {
            throw [System.ArgumentException]::new("Vault '$VaultName' is not registered")
        }

        # Verify that the BitwardenSecretsClient session is open
        if (-not $script:BitwardenSecretsClient) {
            throw [System.UnauthorizedAccessException]::new("Vault '$VaultName' has not been unlocked. Please run ""Unlock-SecretVault -Name '$VaultName'"" to unlock the vault before using it.")
        }

        # Verify that the session is not expired
        if ((Get-Date) - $script:LastActivity -gt $script:SessionTimeout) {
            $script:BitwardenSecretsClient = $null
            throw [System.UnauthorizedAccessException]::new("Vault '$VaultName' has been locked due to exceeding the idle timeout threshold. You will need to run ""Unlock-SecretVault -Name '$VaultName'"" to unlock the vault before using it again.")
        }

        # Set the LastActivity variable to now
        $script:LastActivity = Get-Date


        # To ensure we're going to delete the correct secret, we only search by the secret's Id, not it's Key
        # Validate the ID is a GUID
        if (-not [System.Guid]::TryParse($Name, [ref]$null)) {
            throw [System.ArgumentException]::new("The provided 'Name' is not a GUID. You must provide the ID of the secret you wish to delete in the 'Name' parameter.")
        }
        
        # Find secret with a matching Id
        $Private:existingSecret = $script:BitwardenSecretsClient.Secrets.Get($Name)
        
        # Make sure a match was found
        if (-not $Private:existingSecret) {
            throw [System.ArgumentException]::new("Unable to find a secret with an 'Id' matching the provided 'Name' parameter.")
        }
        
        # Get the full details of the exisitng secret
        $null = $script:BitwardenSecretsClient.Secrets.Delete(@($Private:existingSecret.Id.Guid))
        return $?
    } catch [System.UnauthorizedAccessException] {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $_.Exception,
            'SecretsManagerUnauthorized',
            [System.Management.Automation.ErrorCategory]::AuthenticationError,
            $VaultName
        )
        $PSCmdlet.WriteError($errorRecord)
    } catch {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $_.Exception,
            'SecretsManagerError',
            [System.Management.Automation.ErrorCategory]::ReadError,
            $Name
        )
        $PSCmdlet.WriteError($errorRecord)
    } finally {
        # Clean up sensitive data
        $Private:existingSecret
        [System.GC]::Collect()
    }
}

function Get-SecretInfo {
    [CmdletBinding()]
    param(
        [string] $Filter,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    
    try {
        
        # Get vault registration info
        $vaultInfo = Get-SecretVault -Name $VaultName -ErrorAction Stop
        if (-not $vaultInfo) {
            throw [System.ArgumentException]::new("Vault '$VaultName' is not registered")
        }

        # Verify that the BitwardenSecretsClient session is open
        if (-not $script:BitwardenSecretsClient) {
            throw [System.UnauthorizedAccessException]::new("Vault '$VaultName' has not been unlocked. Please run ""Unlock-SecretVault -Name '$VaultName'"" to unlock the vault before using it.")
        }

        # Verify that the session is not expired
        if ((Get-Date) - $script:LastActivity -gt $script:SessionTimeout) {
            $script:BitwardenSecretsClient = $null
            throw [System.UnauthorizedAccessException]::new("Vault '$VaultName' has been locked due to exceeding the idle timeout threshold. You will need to run ""Unlock-SecretVault -Name '$VaultName'"" to unlock the vault before using it again.")
        }

        # Set the LastActivity variable to now
        $script:LastActivity = Get-Date

        # Validate OrganizationId
        if (-not [System.Guid]::TryParse($vaultInfo.VaultParameters.OrganizationId, [ref]$null)) {
            throw [System.ArgumentException]::new("Vault '$VaultName' has an invalid GUID format for the required 'OrganizationId' parameter.")
        }
        
        if ([string]::IsNullOrEmpty($Filter)) {
            $Filter = "*"
        }
        
        $private:pattern = [WildcardPattern]::new($Filter)

        $private:allSecrets = $Script:BitwardenSecretsClient.Secrets.List($vaultInfo.VaultParameters.OrganizationId)
        
        if (-not $Private:allSecrets.Data) {
            Write-Error "Unable to access screts in your Secrets Manager vault" -ErrorAction Stop
        }
        
        foreach ($Private:secretMatch in $private:allSecrets.Data) {
            if (($private:pattern.IsMatch($Private:secretMatch.Key)) -or ($private:pattern.IsMatch($Private:secretMatch.Id.Guid))) {
                $Private:secret = $script:BitwardenSecretsClient.Secrets.Get($Private:secretMatch.Id.Guid)
                $Private:metadata = @{
                    'Id' = $Private:secret.Id.Guid
                    'Key' = $Private:secret.Key
                    'CreatedDate' = $Private:secret.CreationDate
                    'RevisionDate' = $Private:secret.RevisionDate
                    'Note' = $Private:secret.Note
                }
                
                Write-Output (
                    [Microsoft.PowerShell.SecretManagement.SecretInformation]::new(
                        $Private:secret.Id.Guid, # Name of Secret
                        [Microsoft.PowerShell.SecretManagement.SecretType]::SecureString, # Indicates that Get-Secret will return a SecureString
                        $VaultName, # Name of vault
                        $Private:metadata # Optional metadata
                    )
                )
            }
        }
        
    } catch [System.UnauthorizedAccessException] {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $_.Exception,
            'SecretsManagerUnauthorized',
            [System.Management.Automation.ErrorCategory]::AuthenticationError,
            $VaultName
        )
        $PSCmdlet.WriteError($errorRecord)
    } catch {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $_.Exception,
            'SecretsManagerError',
            [System.Management.Automation.ErrorCategory]::ReadError,
            $Name
        )
        $PSCmdlet.WriteError($errorRecord)
    } finally {
        # Clean up sensitive data
        $Private:pattern = $null
        $Private:secretMatch = $null
        $Private:secret = $null
        $Private:allSecrets = $null
        $Private:metadata = $null
        [System.GC]::Collect()
    }
}

function Test-SecretVault {
    [CmdletBinding()]
    param (
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    
    try {
        # Get vault registration info
        $vaultInfo = Get-SecretVault -Name $VaultName -ErrorAction Stop
        if (-not $vaultInfo) {
            throw [System.ArgumentException]::new("Vault '$VaultName' is not registered")
        }

        # Verify that the BitwardenSecretsClient session is open
        if (-not $script:BitwardenSecretsClient) {
            throw [System.UnauthorizedAccessException]::new("Vault '$VaultName' has not been unlocked. Please run ""Unlock-SecretVault -Name '$VaultName'"" to unlock the vault before using it.")
        }

        # Verify that the session is not expired
        if ((Get-Date) - $script:LastActivity -gt $script:SessionTimeout) {
            $script:BitwardenSecretsClient = $null
            throw [System.UnauthorizedAccessException]::new("Vault '$VaultName' has been locked due to exceeding the idle timeout threshold. You will need to run ""Unlock-SecretVault -Name '$VaultName'"" to unlock the vault before using it again.")
        }

        # Set the LastActivity variable to now
        $script:LastActivity = Get-Date

        # Validate required parameters
        # Validate OrganizationId
        if (-not $vaultInfo.VaultParameters.OrganizationId) {
            throw [System.InvalidOperationException]::new("Vault '$VaultName' is missing the required 'OrganizationId' parameter.")
        }
        if (-not [System.Guid]::TryParse($vaultInfo.VaultParameters.OrganizationId, [ref]$null)) {
            throw [System.ArgumentException]::new("Vault '$VaultName' has an invalid GUID format for the required 'OrganizationId' parameter.")
        }
        # Validate ProjectId
        if (-not $vaultInfo.VaultParameters.ProjectId) {
            throw [System.InvalidOperationException]::new("Vault '$VaultName' is missing the required ProjectId parameter.")
        }
        if (-not [System.Guid]::TryParse($vaultInfo.VaultParameters.ProjectId, [ref]$null)) {
            throw [System.ArgumentException]::new("Vault '$VaultName' has an invalid GUID format for the required 'ProjectId' parameter.")
        }
        # Validate ApiUrl
        if (-not $vaultInfo.VaultParameters.ApiUrl) {
            throw [System.InvalidOperationException]::new("Vault '$VaultName' is missing the required ApiUrl parameter.")
        }
        if (-not [System.Uri]::IsWellFormedUriString($vaultInfo.VaultParameters.ApiUrl, [System.UriKind]::Absolute)) {
            throw [System.ArgumentException]::new("Vault '$VaultName' has an invalid URL format for the required 'ApiUrl' parameter.")
        }
        # Validate IdentityUrl
        if (-not $vaultInfo.VaultParameters.IdentityUrl) {
            throw [System.InvalidOperationException]::new("Vault '$VaultName' is missing the required IdentityUrl parameter.")
        }
        if (-not [System.Uri]::IsWellFormedUriString($vaultInfo.VaultParameters.IdentityUrl, [System.UriKind]::Absolute)) {
            throw [System.ArgumentException]::new("Vault '$VaultName' has an invalid URL format for the required 'IdentityUrl' parameter.")
        }

        # Simple connectivity test
        $script:BitwardenSecretsClient.Secrets.List($vaultInfo.VaultParameters.OrganizationId) | Out-Null
        return $true
    } catch [System.UnauthorizedAccessException] {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $_.Exception,
            'SecretsManagerUnauthorized',
            [System.Management.Automation.ErrorCategory]::AuthenticationError,
            $VaultName
        )
        $PSCmdlet.WriteError($errorRecord)
    } catch {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $_.Exception,
            'SecretsManagerError',
            [System.Management.Automation.ErrorCategory]::ReadError,
            $Name
        )
        $PSCmdlet.WriteError($errorRecord)
    }
}

function Unlock-SecretVault {
    <#
    .SYNOPSIS
    Unlocks a Bitwarden Secrets Manager vault for the current session
    
    .DESCRIPTION
    Authenticates to Bitwarden Secrets Manager using an access token and 
    keeps the vault unlocked for the current PowerShell session.
    
    .PARAMETER Name
    The name of the registered vault to unlock
    
    .PARAMETER Password
    The access token as a SecureString for authenticating to Bitwarden Secrets Manager
    
    .EXAMPLE
    $accessToken = Read-Host -AsSecureString -Prompt "Access Token"
    Unlock-SecretVault -Name "Bitwarden" -Password $accessToken
    #>
    [CmdletBinding()]
    param (
        [string] $VaultName,
        [System.Security.SecureString] $Password,
        [hashtable] $AdditionalParameters
    )
    
    try {
        if(-not $Password){throw "No password provided."}

        Write-Verbose "Unlocking Bitwarden Secrets Manager vault: $VaultName"
        
        # Get vault registration info
        $vaultInfo = Get-SecretVault -Name $VaultName -ErrorAction Stop
        if (-not $vaultInfo) {
            throw [System.ArgumentException]::new("Vault '$VaultName' is not registered")
        }
        
        # Validate required parameters
        # Validate OrganizationId
        if (-not $vaultInfo.VaultParameters.OrganizationId) {
            throw [System.InvalidOperationException]::new("Vault '$VaultName' is missing the required 'OrganizationId' parameter.")
        }
        if (-not [System.Guid]::TryParse($vaultInfo.VaultParameters.OrganizationId, [ref]$null)) {
            throw [System.ArgumentException]::new("Vault '$VaultName' has an invalid GUID format for the required 'OrganizationId' parameter.")
        }
        # Validate ProjectId
        if (-not $vaultInfo.VaultParameters.ProjectId) {
            throw [System.InvalidOperationException]::new("Vault '$VaultName' is missing the required ProjectId parameter.")
        }
        if (-not [System.Guid]::TryParse($vaultInfo.VaultParameters.ProjectId, [ref]$null)) {
            throw [System.ArgumentException]::new("Vault '$VaultName' has an invalid GUID format for the required 'ProjectId' parameter.")
        }
        # Validate ApiUrl
        if (-not $vaultInfo.VaultParameters.ApiUrl) {
            throw [System.InvalidOperationException]::new("Vault '$VaultName' is missing the required ApiUrl parameter.")
        }
        if (-not [System.Uri]::IsWellFormedUriString($vaultInfo.VaultParameters.ApiUrl, [System.UriKind]::Absolute)) {
            throw [System.ArgumentException]::new("Vault '$VaultName' has an invalid URL format for the required 'ApiUrl' parameter.")
        }
        # Validate IdentityUrl
        if (-not $vaultInfo.VaultParameters.IdentityUrl) {
            throw [System.InvalidOperationException]::new("Vault '$VaultName' is missing the required IdentityUrl parameter.")
        }
        if (-not [System.Uri]::IsWellFormedUriString($vaultInfo.VaultParameters.IdentityUrl, [System.UriKind]::Absolute)) {
            throw [System.ArgumentException]::new("Vault '$VaultName' has an invalid URL format for the required 'IdentityUrl' parameter.")
        }

        # Ensure the Bitwarden Secrets Manager SDK is loaded
        if (-not $script:BitwardenSdkLoaded) {
            Write-Verbose "Loading the Bitwarden SDK for C#"
            try{
                Import-BitwardenSdk -ErrorAction Stop
                $script:BitwardenSdkLoaded = $true
            }catch{
                $script:BitwardenSdkLoaded = $false
                throw [System.InvalidOperationException]::new("Unable to load the Bitwarden SDK.")
            }
        }
        
        # Create authenticated session
        try {
            # Convert SecureString to plain text securely
            $Private:ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
            try {
                $Private:plainToken = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($Private:ptr)
            } finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Private:ptr)
                $private:ptr = [System.IntPtr]::Zero
            }

            # Define a path to store the Bitwarden SDK state file
            $stateFilePath = Join-Path $PSScriptRoot "bitwarden-state.json"

            # Initialize SDK client
            $bitwardenSettings = [Bitwarden.Sdk.BitwardenSettings]::new()
            $bitwardenSettings.ApiUrl = $vaultInfo.VaultParameters.ApiUrl
            $bitwardenSettings.IdentityUrl = $vaultInfo.VaultParameters.IdentityUrl
            $script:BitwardenSecretsClient = [Bitwarden.Sdk.BitwardenClient]::new($bitwardenSettings)
            $script:BitwardenSecretsClient.Auth.LoginAccessToken($Private:plainToken, $stateFilePath);

            # Test connection
            try{
                $null = $script:BitwardenSecretsClient.Secrets.List($vaultInfo.VaultParameters.OrganizationId)
            } catch {
                throw "Failed to authenticate with Bitwarden Secrets Manager: $($_.Exception.Message)"
                return $false
            }

            # Connection successful
            # Set the LastActivity variable to now
            $script:LastActivity = Get-Date
            Write-Verbose "Successfully connected to Bitwarden Secrets Manager"
            
        } catch {
            throw [System.UnauthorizedAccessException]::new(
                "Failed to authenticate with Bitwarden Secrets Manager: $($_.Exception.Message)"
            )
        } finally {
            # Clean up sensitive data
            $Private:plainToken = $null
            $Private:ptr = $null
            [System.GC]::Collect()
        }
    } catch [System.UnauthorizedAccessException] {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $_.Exception,
            'VaultUnlockFailed',
            [System.Management.Automation.ErrorCategory]::AuthenticationError,
            $VaultName
        )
        $PSCmdlet.WriteError($errorRecord)
    } catch {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $_.Exception,
            'VaultUnlockError',
            [System.Management.Automation.ErrorCategory]::InvalidOperation,
            $VaultName
        )
        $PSCmdlet.WriteError($errorRecord)
    }
}