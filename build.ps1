[CmdletBinding()]
param ()

Write-Host "Building SecretManagement.Bitwarden Dependencies and publishing DLLs..."

dotnet publish ./Dependencies/Dependencies.csproj -c Release

Write-Host "Build complete. DLLs published to BitwardenModule/lib."