<#
.SYNOPSIS
Clears HyperGuard92 logs and PyInstaller build artifacts.

.DESCRIPTION
Removes generated logs, build folders, distribution output, and PyInstaller spec files.
The cleanup intentionally avoids source files, configuration files, and virtual environments.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSCommandPath
$ArtifactDirectories = @("build", "dist")

foreach ($DirectoryName in $ArtifactDirectories) {
    $DirectoryPath = Join-Path -Path $ProjectRoot -ChildPath $DirectoryName

    if (Test-Path -LiteralPath $DirectoryPath) {
        if ($PSCmdlet.ShouldProcess($DirectoryPath, "Remove generated artifact directory")) {
            Remove-Item -LiteralPath $DirectoryPath -Recurse -Force
        }
    }
}

$LogsPath = Join-Path -Path $ProjectRoot -ChildPath "logs"

if (Test-Path -LiteralPath $LogsPath) {
    Get-ChildItem -LiteralPath $LogsPath -Force | ForEach-Object {
        if ($PSCmdlet.ShouldProcess($_.FullName, "Remove log artifact")) {
            Remove-Item -LiteralPath $_.FullName -Recurse -Force
        }
    }
}
else {
    if ($PSCmdlet.ShouldProcess($LogsPath, "Create empty logs directory")) {
        New-Item -Path $LogsPath -ItemType Directory -Force | Out-Null
    }
}

$SpecFiles = Get-ChildItem -LiteralPath $ProjectRoot -Filter "*.spec" -File -Force

foreach ($SpecFile in $SpecFiles) {
    if ($PSCmdlet.ShouldProcess($SpecFile.FullName, "Remove PyInstaller spec file")) {
        Remove-Item -LiteralPath $SpecFile.FullName -Force
    }
}

Write-Host "Cleanup complete."