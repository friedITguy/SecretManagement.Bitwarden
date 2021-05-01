@{
    # Script module or binary module file associated with this manifest.
    #RootModule        = 'SecretManagement.BitWarden.psm1'

    # Version number of this module.
    ModuleVersion     = '0.1.1'
    
    # ID used to uniquely identify this module
    GUID              = 'ace6b81f-24b2-4f6e-a9ce-ba0563e31c32'
    
    # Author of this module
    Author            = 'Gaston Paquette'
    
    # Company or vendor of this module
    CompanyName       = 'Gaston Paquette'
    
    # Copyright statement for this module
    Copyright         = '(c) Gaston Paquette. All rights reserved.'
    
    # Description of the functionality provided by this module
    Description       = 'SecretManagement extension for BitWarden!'
    
    # Minimum version of the PowerShell engine required by this module
    # PowerShellVersion = ''
    
    # Modules that must be imported into the global environment prior to importing this module
    # RequiredModules = @()
    
    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()
    
    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()
    
    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()
    
    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @()
    RootModule        = 'SecretManagement.BitWarden.psm1'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop','Core')
    FunctionsToExport = @('Invoke-bwcmd','get-BWmetadata')
    CmdletsToExport = @()
    RequiredModules = @('Microsoft.PowerShell.SecretManagement')
    NestedModules     = './SecretManagement.BitWarden.Extension'
    VariablesToExport = '*'
    PrivateData       = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags       = 'SecretManagement', 'Secrets', 'BitWarden', 'MacOS', 'Linux', 'Windows'
            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/Gaspack/SecretManagement.BitWarden'
        }
    }
}