<#
.SYNOPSIS
Builds HyperGuard92 as a single-file Windows executable.

.DESCRIPTION
Uses PyInstaller to package src/__main__.py as dist/HyperGuard92.exe and embeds a
UAC manifest so Windows prompts to run the executable with administrative privileges.
#>

[CmdletBinding()]
param(
    [switch]$SkipClean
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSCommandPath
$EntryPoint = Join-Path -Path $ProjectRoot -ChildPath "src\__main__.py"
$OutputName = "HyperGuard92"
$VenvPython = Join-Path -Path $ProjectRoot -ChildPath ".venv\Scripts\python.exe"
$ClearScript = Join-Path -Path $ProjectRoot -ChildPath "clear.ps1"

function Resolve-PythonExecutable {
    if (Test-Path -LiteralPath $VenvPython) {
        return $VenvPython
    }

    $PythonCommand = Get-Command python -ErrorAction SilentlyContinue

    if ($null -ne $PythonCommand) {
        return $PythonCommand.Source
    }

    throw "Python was not found. Create .venv or add python.exe to PATH before building."
}

function Test-PythonModule {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PythonExecutable,

        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )

    & $PythonExecutable -c "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec('$ModuleName') else 1)" *> $null
    return $LASTEXITCODE -eq 0
}

function Ensure-PyInstaller {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PythonExecutable
    )

    if (Test-PythonModule -PythonExecutable $PythonExecutable -ModuleName "PyInstaller") {
        return
    }

    Write-Host "PyInstaller not found. Installing build dependency..."
    & $PythonExecutable -m pip install --upgrade pyinstaller

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install PyInstaller."
    }
}

if (-not (Test-Path -LiteralPath $EntryPoint)) {
    throw "Entry point not found: $EntryPoint"
}

$PythonExecutable = Resolve-PythonExecutable

if (-not $SkipClean) {
    if (-not (Test-Path -LiteralPath $ClearScript)) {
        throw "Cleanup script not found: $ClearScript"
    }

    & $ClearScript
}

Ensure-PyInstaller -PythonExecutable $PythonExecutable

$PyInstallerArguments = @(
    "--noconfirm",
    "--clean",
    "--onefile",
    "--noconsole",
    "--uac-admin",
    "--name", $OutputName,
    "--distpath", (Join-Path -Path $ProjectRoot -ChildPath "dist"),
    "--workpath", (Join-Path -Path $ProjectRoot -ChildPath "build"),
    "--specpath", $ProjectRoot,
    "--paths", $ProjectRoot,
    "--collect-all", "nicegui",
    "--collect-all", "pywebview",
    "--hidden-import", "win32timezone",
    $EntryPoint
)

Write-Host "Building $OutputName.exe with PyInstaller..."
& $PythonExecutable -m PyInstaller @PyInstallerArguments

if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller build failed."
}

$ExecutablePath = Join-Path -Path $ProjectRoot -ChildPath "dist\$OutputName.exe"

if (-not (Test-Path -LiteralPath $ExecutablePath)) {
    throw "Expected executable was not created: $ExecutablePath"
}

Write-Host "Build complete: $ExecutablePath"