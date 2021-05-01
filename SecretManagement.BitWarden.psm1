using namespace Microsoft.PowerShell.SecretManagement

function Invoke-bwcmd {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]$Arguments,
        [bool]$loginrequired = $false
    )
    Begin {
        $bwPath = (Get-Command 'bw').Source
        # Check if logged in or unlocked
        $addsession = $null

        IF ($loginrequired) {
            Write-Verbose 'Login requried'
            $env:BW_Session = $NULL
            $status = invoke-bwcmd "status"
            Write-Verbose $status
            switch ($status.status) {
                'unauthenticated' {
                    Write-Verbose "New login"
                    $credential = Get-Credential
                    $username = $Credential.UserName
                    $password = $Credential.GetNetworkCredential().Password
                    $codetype = Read-Host -Prompt 'Two Step Login Methods - Please enter numeric value 0) Authenticator 1) Email 3) Yubikey'
                    $code = Read-Host -Prompt 'Please enter code'
                    $env:BW_Session = invoke-bwcmd "login ""$username "" ""$password"" --method $codetype --code $code --raw"
                }
                'locked' {
                    Write-Verbose "Unlocking"
                    $credential = Get-Credential $status.userEmail
                    $password = $Credential.GetNetworkCredential().Password
                    $env:BW_Session = invoke-bwcmd "unlock ""$password"" --raw"
                    Start-Sleep 1
                    Write-Verbose $env:BW_Session
                    $loginrequired = $false
                }
                'unlocked' { Write-Verbose 'Account Already Unlocked' }
            }
        }
        IF ($arguments -match 'get|list|create|edit') {
            $addsession = "--session $env:BW_SESSION"
        }
    }
    Process {
        if ($bwPath) {
    
            $ps = new-object System.Diagnostics.Process
            $ps.StartInfo.Filename = $bwPath
            $ps.StartInfo.Arguments = "$Arguments --nointeraction $addsession"
            Write-Verbose $ps.StartInfo.Arguments
            $ps.StartInfo.RedirectStandardOutput = $True
            $ps.StartInfo.RedirectStandardError = $True
            $ps.StartInfo.UseShellExecute = $False
            $ps.start() | Out-Null
            $ps.WaitForExit(1000) | Out-Null
            $BWOutput = $ps.StandardOutput.ReadToEnd() 
            $global:BWError = $ps.StandardError.ReadToEnd() #| Out-String

            IF ($BWError) {
                Switch -Wildcard ($BWError) {
                    '*session*' {
                        Write-Verbose "Wrong Password, Try again $PSBoundParameters"
                        invoke-bwcmd $PSBoundParameters.Item('Arguments') -loginrequired $true

                    }
                    'You are not logged in.' {
                        invoke-bwcmd $PSBoundParameters.Item('Arguments') -loginrequired $true
                    }
                    'Session key is invalid.' {
                        Write-Verbose "Invalid Key"
                    }
                    'Vault is locked.' {
                        Write-Warning $BWError
                        invoke-bwcmd $PSBoundParameters.Item('Arguments') -loginrequired $true
                    }
                    'More than one result was found*' {
                        
                        $errparse = @()
                        $BWError.split("`n") | Select-Object -skip 1 | ForEach-Object {
                            $errparse += invoke-bwcmd "get item $_"
                        }
                        Write-Warning @"
More than one result was found. Try getting a specific object by `id` instead. The following objects were found:
                        $($errparse  | FT ID, Name | Out-String )
"@
                    }
                    Default {
                         
                        Write-Warning "Default -  $BWError"
                    }
                }
            }
            IF ($BWOutput) {
                Write-Verbose "BWOutput"
                Try {
                    $BWOutput | ConvertFrom-Json -ErrorAction Stop
                
                }
                Catch {
                    $BWOutput
                }
            }


        }
        ELSE {
            throw "bw executable not found or installed."
        }
    }
    End {
        #Lock-BWSession
    }
}

function get-BWmetadata{
    param(
        [object]$vaultSecretInfo
    )
    [ReadOnlyDictionary[String,Object]]$metadata = [ordered]@{}
    if ($vaultSecretInfo.login.uris.uri){$metadata.uri=$vaultSecretInfo.login.uris.uri}
    if ($vaultSecretInfo.login.username){$metadata.username=$vaultSecretInfo.login.username}
    if ($vaultSecretInfo.login.totp){$metadata.totp=$vaultSecretInfo.login.totp}
    if ($vaultSecretInfo.login.passwordRevisionDate){$metadata.passwordRevisionDate=$vaultSecretInfo.login.passwordRevisionDate}
    if ($vaultSecretInfo.revisionDate){$metadata.revisionDate=$vaultSecretInfo.revisionDate}
    if ($vaultSecretInfo.notes){$metadata.notes=$vaultSecretInfo.notes}
    if ($vaultSecretInfo.notes){$metadata.notes=$vaultSecretInfo.notes}
    
    return $metadata
} 
