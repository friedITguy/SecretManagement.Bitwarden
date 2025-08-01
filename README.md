# PowerShell SecretManagement Extension for Bitwarden Secrets Manager

> [!NOTE]
> This is not a maintained project and it's specifically not maintained _by_ Bitwarden.
> I work on it in my free time because I use Bitwarden Secrets Manager personally.

> Special Thanks to @TylerLeonhardt for publishing a baseline for this module extention
> Please check out his [`LastPass Extention`](https://github.com/TylerLeonhardt/SecretManagement.LastPass)

## Prerequisites

### Download and Install:
* [PowerShell 7 (or Above)](https://github.com/PowerShell/PowerShell)
* [.NET SDK](https://dotnet.microsoft.com/en-us/download)

### PowerShell SecretManagement Module:
You can get the `SecretManagement` module from the PowerShell Gallery:

Using PowerShellGet v3:
```pwsh
Install-PSResource Microsoft.PowerShell.SecretManagement
```

## Module Installation
Use PowerShell to create folder to house the module and then clone this repository to it
```pwsh
# Create a new folder
New-Item -ItemType Directory -Name "SecretsManager.Bitwarden"

# Navigate into the folder
Set-Location "SecretsManager.Bitwarden"

# Clone the repository into the current folder
git clone https://github.com/friedITguy/SecretManagement.Bitwarden.git
```

## Obtain Bitwarden SDK Files
This module is dependent on the C# version of the Bitwarden Secrets Manager SDK. However, the SDK is **not** bundled with this module. You will need to download the Bitwarden.Secrets.Sdk and all its runtime dependencies before you can being using this module.

### Build a .NET Project
The easiest method to download all of the dependencies for the SDK, at the time this guide was written, is to create a basic .NET console project that relies on the `Bitwarden.Secrets.Sdk` package.

1. Start by navigating to the `Dependencies` directory within the `SecretManagement.Bitwarden` directory you created in the previous step. 
2. Then create a new .NET project in it.
3. Add the `Bitwarden.Secrets.Sdk` package as a dependency on the project.
4. Build and publish the project.

```bash
cd ./Dependencies
dotnet new console
dotnet add package Bitwarden.Secrets.Sdk
dotnet publish ./Dependencies.csproj
```

### Copy the DLL files
In the below folder strucutre example, you can see that after running the dotnet publish command the Dependencies directory is populated with a bunch of files.

You will need to copy the `Bitwarden.Sdk.dll` nested deep within the `Dependencies` directory, as well as the appropriate runtime library for your system, to the `lib` directory.

For example, if you have a 64-bit Windows 11 system, you would copy the `bitwarden_c.dll` from within the `win-x64` subdirectory into the `lib` directory. You can see this represented in the directory map below.
```
📁 SecretManagement.Bitwarden/
├── 📁 Dependencies/
│   └── 📁 bin/
│       └── 📁 Release/
│           └── 📁 net9.0/
│               └── 📁 publish/
│                   ├── 📁 runtimes/
│                   │   ├── 📁 linux-x64
│                   │   │   └── 📄 libbitwarden_c.so
│                   │   ├── 📁 osx-arm64
│                   │   │   └── 📄 libbitwarden_c.dylib
│                   │   ├── 📁 osx-x64
│                   │   │   └── 📄 libbitwarden_c.dylib
│                   │   └── 📁 win-x64
│                   │       └── 📄 bitwarden_c.dll
│                   └── 📄 Bitwarden.Sdk.dll
└── 📁 lib/
    ├── 📄 bitwarden_c.dll
    └── 📄 Bitwarden.Sdk.dll
```

## Vault Registration
Once you have the module installed and SDK files in place, you need to register Bitwarden as an SecretManagement extension vault in PowerShell:

```pwsh
$params = @{
    AppUrl = 'https://vault.bitwarden.com/api'
    IdentityUrl = 'https://vault.bitwarden.com/identity'
    OrganizationId = "<organization-id>"
    ProjectId = "<project-id>"
}

Register-SecretVault -Name 'Bitwarden' -ModuleName './SecretManagement.Bitwarden.psd1' -VaultParameters $params
```

> [!NOTE]
> Optionally, you can set it as the default vault by also providing the `-DefaultVault` parameter on the `Register-SecretVault` command.

## Unlock the Vault
Now that you have the vault registered in SecretManagement, it's time to start using it. Run the following command to unlock the newly added vault:
```pwsh
Unlock-SecretVault -Name Bitwarden -Password $(Read-Host -AsSecureString -Prompt "Access Token")
```
You will be promtped to enter your machine account access token. Once you enter it the vault be unlocked and ready for you to use `Get-Secret`, `Set-Secret` and all the rest of the `SecretManagement` commands!

## Example Commands
### [Get-Secret](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.secretmanagement/get-secret)
This cmdlet finds and returns the value, in the form of a `SecureString`, of the first secret that matches the provided `-Name`.

#### Example 1
```pwsh
Get-Secret -Name "34131270-8dbd-49e0-bc02-7ca5775e61e8" -Vault Bitwarden
```
In this example, the `-Name` parameter being passed is the 'ID' of the secret in Bitwarden Secrets Manager. If found in the vault, the value of the secret will be returned as a `SecureString` object.

#### Example 2
```pwsh
Get-Secret -Name "ExampleSecret" -Vault Bitwarden
```
In this example, the `-Name` parameter being passed is the 'Name' of the secret in Bitwarden Secrets Manager. If found in the vault, the value of the secret will be returned as a `SecureString` object.

### [Get-SecretInfo](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.secretmanagement/get-secretinfo)
Finds and returns metadata information about secrets in Bitwarden Secrets Manager. It accepts wildcards ( * ) in the `-Name` parameter and will return all secrets matching the query.

#### Example 1
```pwsh
Get-SecretInfo -Name "ExampleSecret" -Vault Bitwarden
```
In this example, any secrets with a 'Name' exactly matching `ExampleSecret` would be returned.

#### Example 2
```pwsh
Get-SecretInfo -Name "ExampleSecret*" -Vault Bitwarden
```
In this example, any secrets with a 'Name' beginning with `ExampleSecret` would be returned.

#### Example 3
```pwsh
Get-SecretInfo -Name "34131270-8dbd-49e0-bc02-7ca5775e61e8" -Vault Bitwarden
```
In this example, any secrets with an 'ID' equal to `34131270-8dbd-49e0-bc02-7ca5775e61e8` would be returned.

### [Remove-Secret](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.secretmanagement/remove-secret)
Removes a secret by 'ID' from a registered extension vault. Both the secret name and extension vault name must be provided.

#### Example 1
```pwsh
Remove-Secret -Name "34131270-8dbd-49e0-bc02-7ca5775e61e8" -Vault Bitwarden
```
In this example, any secrets with an `ID` equal to `34131270-8dbd-49e0-bc02-7ca5775e61e8` would be deleted from Bitwarden Secrets Manager. In order to ensure the correct secret is being deleted, it is **not** possible to delete a secret using its `Name`.

### [Set-Secret](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.secretmanagement/set-secret)
Adds a new secret or updates an existing secret in Bitwarden Secrets Manager.

#### Example 1
```pwsh
Set-Secret -Name "34131270-8dbd-49e0-bc02-7ca5775e61e8" -Vault Bitwarden
```
In this example, the secret with an `ID` equal to `34131270-8dbd-49e0-bc02-7ca5775e61e8` would be updated. However, if one did not exist a new secret would be created with the `Name` equal to `34131270-8dbd-49e0-bc02-7ca5775e61e8`.

#### Example 2
```pwsh
Set-Secret -Name "ExampleSecret" -Vault Bitwarden
```
In this example, the secret with a `Name` equal to `ExampleSecret` would be updated. However, if one did not exist a new secret would be created with the `Name` equal to `ExampleSecret`.

## Legal
>[!IMPORTANT]
>Microsoft® and PowerShell® are registered trademarks or trademarks of Microsoft Corporation. This project is not affiliated with, endorsed by, or sponsored by Microsoft.
>
>Bitwarden® and Bitwarden Secrets Manager™ are trademarks or registered trademarks of Bitwarden Inc. This project is not affiliated with, endorsed by, or sponsored by Bitwarden.
>
>All product names, logos, and brands are property of their respective owners.