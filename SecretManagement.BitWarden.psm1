function Import-BitwardenSdk {
    <#
    .SYNOPSIS
    Imports the C# (.NET) version of the Bitwarden SDK into the PowerShell session.
    
    .DESCRIPTION
    Imports the required library files all dependencies for the Bitwarden Secrets SDK into the PowerShell session.
    
    .EXAMPLE
    if(-not $script:BitwardenSdkLoaded){Import-BitwardenSdk}
    #>
    [CmdletBinding()]
    param ()
    if ($script:BitwardenSdkLoaded) { return }

    
    # Define the name of the Bitwarden SDK native library for each supported runtime
    $nativeLibraries = [PSCustomObject]@{
        'linux-x64' = 'libbitwarden_c.so'
        'osx-arm64' = 'libbitwarden_c.dylib'
        'osx-x64' = 'libbitwarden_c.dylib'
        'win-x64' = 'bitwarden_c.dll'
    }

    # Determine the OS and Processor Architecture
    $platform = switch -Wildcard ([System.Runtime.InteropServices.RuntimeInformation]::OSDescription) {
        "*Windows*" { "win" }
        "*Linux*"   { "linux" }
        "*Darwin*"  { "osx" } # MacOS is identified as Darwin
        Default     { throw "The operating system your system is running is not supported by the .NET version of the Bitwarden SDK. Supported operating systems are Windows, MacOS, and Linux." }
    }
    $architecture = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
        "X64"  { "x64" }
        "Arm64" { "arm64" }
        Default { throw "The processor architecture your system is running is not supported by the .NET version of the Bitwarden SDK. Supported architectures are x64 and arm64." }
    }

    # Determine if the Runtime is supported
    $supportedRuntimes = ($nativeLibraries | Get-Member -MemberType NoteProperty).Name
    $runtime = "$platform-$architecture"
    
    # Verify
    if($supportedRuntimes -notcontains $runtime){throw "The operating system and processor architecture combination you're running is not a valid runtime for the .NET version of the Bitwarden SDK. Supported runtimes are $($supportedRuntimes -join ', ')."}
    
    # If we got here then the system is running on a supported runtime for the Bitwarden SDK
    # Try to load the libraries from the module's lib folder
    $libPath = Join-Path -Path $PSScriptRoot -ChildPath 'lib'
    $sdkPath = Join-Path -Path $libPath -ChildPath 'Bitwarden.Sdk.dll'
    $nativeLibPath = Join-Path -Path $libPath -ChildPath $nativeLibraries.$runtime

    # Verify the lib directory exists, throw an error if not
    if(-not (Test-Path -Path $libPath)){ throw "The 'lib' directory could not be found within this module. We expected it to be located inside '$($PSScriptRoot)'" }

    # Verify the Bitwarden SDK and the appropraite native library files are present
    $sdkFile = Test-Path -Path $sdkPath -ErrorAction SilentlyContinue
    $nativeLibFile = Test-Path -Path $nativeLibPath -ErrorAction SilentlyContinue

    if(-not $sdkFile){ throw "The required Bitwarden.Sdk.dll file could not be found within the '$($libPath)' directory." }
    if(-not $nativeLibFile){ throw "The required '$($nativeLibraries.$runtime)' file could not be found within the '$($libPath)' directory." }
    
    # Load the Bitwarden.Secrets.Sdk to the PowerShell Session
    Add-Type -Path $sdkPath -ErrorAction Stop
}

function Get-BitwardenStateDirectoryPath {
    [CmdletBinding()]
    param ()

    try{
        $Private:StateDir = if ($IsWindows) {
            if (-not (Test-Path $env:USERPROFILE)) { throw [System.IO.DirectoryNotFoundException]::new("Unable to find the USERPROFILE directory.") }
            Join-Path $env:USERPROFILE ".bitwarden" -ErrorAction Stop
        } else {
            if (-not (Test-Path $env:HOME)) { throw [System.IO.DirectoryNotFoundException]::new("Unable to find the HOME directory.") }
            Join-Path $env:HOME ".bitwarden" -ErrorAction Stop
        }

        if (-not (Test-Path $Private:StateDir -IsValid)) {
            throw [System.InvalidOperationException]::new("Unable to construct a path for the Bitwarden state file directory.")
        }

        return $Private:StateDir
    } finally {
        $Private:StateDir = $null
        [System.GC]::Collect()
    }
}

function Initialize-BitwardenStateDirectory {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string] $StateDirectoryPath
    )

    try {

        # Validate the StateDirectoryPath parameter
        if (-not (Test-Path $StateDirectoryPath -IsValid)){
            throw [System.InvalidOperationException]::new("The provided 'StateDirectoryPath' string does not contain valid syntax for a Path.")
        }

        # Create the StateFileDirectory if it doesn't already exist
        if (-not (Test-Path $StateDirectoryPath)) {
            New-Item -ItemType Directory -Path $StateDirectoryPath -Force -ErrorAction Stop | Out-Null
            Write-Verbose "Created a new Bitwarden state file directory for $($env:USERNAME)."
        }

        # Verify the StateFileDirectory exists
        if (-not (Test-Path $StateDirectoryPath)) {
            throw [System.IO.DirectoryNotFoundException]::new("Unable to create the state file directory at the provided 'StateDirectoryPath'")
        }

        # Set restrictive permissions
        if ($IsWindows) {
            # Windows: Use ACLs for secure permissions
            $Private:acl = Get-Acl $StateDirectoryPath -ErrorAction Stop

            if (-not $Private:acl.AreAccessRulesProtected){
                $Private:acl.SetAccessRuleProtection($true, $false)
            }

            # Get current user SID for more reliable identification
            $Private:currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            
            # Create inheritance flags separately to avoid parsing issues
            $Private:inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
            
            # Configure the new access rule
            $Private:accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $Private:currentUser.User,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                $Private:inheritanceFlags,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            ) -ErrorAction Stop
            
            # Check to see if the directory already has the correct access rule
            if (
                ($Private:acl.Access.Count -eq 1) -and
                ($Private:acl.Access[0].FileSystemRights -eq $Private:accessRule.FileSystemRights) -and
                ($Private:acl.Access[0].AccessControlType -eq $Private:accessRule.AccessControlType) -and
                (($Private:acl.Access[0].IdentityReference.Value -eq $Private:accessRule.IdentityReference.Value) -or ($Private:acl.Access[0].IdentityReference.Value -eq $Private:currentUser.Name)) -and
                ($Private:acl.Access[0].IsInherited -eq $Private:accessRule.IsInherited) -and
                ($Private:acl.Access[0].InheritanceFlags -eq $Private:accessRule.InheritanceFlags) -and
                ($Private:acl.Access[0].PropagationFlags -eq $Private:accessRule.PropagationFlags)
            ) {
                return $null
            }

            # Add the Access Rule to the ACL template
            $Private:acl.SetAccessRule($Private:accessRule)

            # Write the ACL to the directory
            try{
                Set-Acl $StateDirectoryPath $Private:acl -ErrorAction Stop
            }
            catch [System.Security.AccessControl.PrivilegeNotHeldException] {
                throw [System.InvalidOperationException] "The Bitwarden state file directory does not have the expected permissions. The 'Initialize-BitwardenStateDirectory' function attempted to fix the permissions but failed because the directory's access rules are protected. Please delete the '$($StateDirectoryPath)' directory and try again."
            }
            catch {
                throw $_
            }
        } elseif ($IsMacOS) {
            # MacOS: Use chmod for POSIX permissions (owner read/write/execute only)
            & chmod 700 $StateDirectoryPath
            
            # Verify permissions were set correctly
            $permissions = & stat -f "%A" $StateDirectoryPath 2>/dev/null
            if ($permissions -ne "700") {
                throw "Failed to set secure permissions on Bitwarden state directory."
            }
        } else {
            # Linux: Use chmod for POSIX permissions (owner read/write/execute only)
            & chmod 700 $StateDirectoryPath
            
            # Verify permissions were set correctly
            $permissions = & stat -c "%a" $StateDirectoryPath 2>/dev/null
            if ($permissions -ne "700") {
                throw "Failed to set secure permissions on Bitwarden state directory."
            }
        }
    } finally {
        $Private:acl = $null
        $Private:accessRule = $null
        $Private:currentUser = $null
        $Private:inheritanceFlags = $null
        [System.GC]::Collect()
    }

}

function Remove-BitwardenStateFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String] $StateFilePath
    )

    try{
        if(-not (Test-Path $StateFilePath -IsValid)){
            throw [System.InvalidOperationException]::new("The provided 'StateFilePath' string does not contain valid syntax for a Path.")
        }

        if (-not (Test-Path $StateFilePath)) {
            return $false
        }

        $Private:StateDirectoryPath = Get-BitwardenStateDirectoryPath -ErrorAction Stop
        $Private:StateFileParent = Split-Path $StateFilePath -Parent
        
        if (-not $Private:StateDirectoryPath -eq $Private:StateFileParent){
            throw [System.InvalidOperationException]::new("The provided 'StateFilePath' is not located within the Bitwarden state file directory.")
        }

        Remove-Item $StateFilePath -Force -ErrorAction Stop
    } finally {
        $Private:StateDirectoryPath = $null
        $Private:StateFileParent = $null
        [System.GC]::Collect()
    }
}