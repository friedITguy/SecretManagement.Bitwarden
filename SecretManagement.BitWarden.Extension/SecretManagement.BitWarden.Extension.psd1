@{
    ModuleVersion = '0.2.1'
    RootModule = 'SecretManagement.Bitwarden.Extension.psm1'
    FunctionsToExport = @('Set-Secret','Get-Secret','Remove-Secret','Get-SecretInfo','Test-SecretVault','Unlock-SecretVault')
}
