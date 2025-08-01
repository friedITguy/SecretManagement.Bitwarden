@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'SecretManagement.BitWarden.psm1'

    # Version number of this module.
    ModuleVersion = '0.2.1'
    
    # ID used to uniquely identify this module
    GUID = '7f2e319c-6ebd-41da-bb89-37ba31728f28'
    
    # Author of this module
    Author = 'Daniel Gauldin'
    
    # Company or vendor of this module
    CompanyName = 'Daniel Gauldin'
    
    # Copyright statement for this module
    Copyright = '(c) Daniel Gauldin. All rights reserved.'
    
    # Description of the functionality provided by this module
    Description = 'Microsoft.PowerShell.SecretManagement extension for Bitwarden Secrets Manager.'
    
    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion  = '7.0'
    CompatiblePSEditions = @('Core')
    
    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules    = @('Microsoft.PowerShell.SecretManagement')
    
    # Assemblies that must be loaded prior to importing this module
    RequiredAssemblies = @(
        './lib/Bitwarden.Sdk.dll'  # The .NET SDK assembly
    )
    
    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()
    
    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()
    
    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules = @('./SecretManagement.Bitwarden.Extension')
    
    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @('Import-BitwardenSdk', 'Initialize-BitwardenStateDirectory', 'Get-BitwardenStateDirectoryPath', 'Remove-BitwardenStateFile')

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = '*'

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData       = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = 'SecretManagement', 'Secrets', 'BitWarden', 'MacOS', 'Linux', 'Windows'
            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/friedITguy/SecretManagement.Bitwarden'
            # A URL to the license for this module.
            LicenseUri = 'https://github.com/friedITguy/SecretManagement.Bitwarden/blob/main/LICENSE.txt'
            RequiredPackages = @(
                @{
                    PackageName = 'Bitwarden.Secrets.Sdk'
                    MinimumVersion = '1.0.0'
                    Source = 'https://api.nuget.org/v3/index.json'
                }
            )
        }
    }
}