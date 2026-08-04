@echo off
setlocal EnableExtensions
set "IMAGE_VIEWER_BLOCKER_SELF=%~f0"

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$identity=[Security.Principal.WindowsIdentity]::GetCurrent(); $principal=[Security.Principal.WindowsPrincipal]::new($identity); if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ try { Start-Process -FilePath $env:IMAGE_VIEWER_BLOCKER_SELF -Verb RunAs | Out-Null; exit 100 } catch { Write-Error $_; exit 101 } }; exit 0"
set "ELEVATION_RESULT=%ERRORLEVEL%"
if "%ELEVATION_RESULT%"=="100" exit /b 0
if not "%ELEVATION_RESULT%"=="0" (
    echo Administrator elevation failed.
    if /i not "%~1"=="--no-pause" pause
    exit /b %ELEVATION_RESULT%
)

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$lines=[IO.File]::ReadAllLines($env:IMAGE_VIEWER_BLOCKER_SELF); $marker=[Array]::IndexOf([string[]]$lines,'::POWERSHELL_PAYLOAD'); if($marker -lt 0){throw 'PowerShell payload marker is missing.'}; $payload=$lines[($marker+1)..($lines.Length-1)] -join [Environment]::NewLine; & ([ScriptBlock]::Create($payload))"
set "EXITCODE=%ERRORLEVEL%"

echo.
if not "%EXITCODE%"=="0" (
    echo The operation failed with exit code %EXITCODE%.
) else (
    echo The operation completed successfully.
)
if /i not "%~1"=="--no-pause" pause
exit /b %EXITCODE%

::POWERSHELL_PAYLOAD
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$everyoneSid = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
$imageViewerPath = Join-Path $env:APPDATA 'baidu\BaiduNetdisk\module\ImageViewer'
$expectedParent = Join-Path $env:APPDATA 'baidu\BaiduNetdisk\module'
$registryBlockers = @(
    [PSCustomObject]@{ Hive = 'CurrentUser'; View = 'Default'; SubKey = 'Software\Baidu\BaiduNetdiskImageViewer'; Display = 'HKCU\Software\Baidu\BaiduNetdiskImageViewer' },
    [PSCustomObject]@{ Hive = 'CurrentUser'; View = 'Default'; SubKey = 'Software\Classes\BaiduNetdiskImageViewerAssociations'; Display = 'HKCU\Software\Classes\BaiduNetdiskImageViewerAssociations' },
    [PSCustomObject]@{ Hive = 'LocalMachine'; View = 'Registry64'; SubKey = 'Software\Classes\BaiduNetdiskImageViewerAssociations'; Display = 'HKLM(64)\Software\Classes\BaiduNetdiskImageViewerAssociations' },
    [PSCustomObject]@{ Hive = 'LocalMachine'; View = 'Registry32'; SubKey = 'Software\Classes\BaiduNetdiskImageViewerAssociations'; Display = 'HKLM(32)\Software\Classes\BaiduNetdiskImageViewerAssociations' }
)
$registeredApplicationLocations = @(
    [PSCustomObject]@{ Hive = 'CurrentUser'; View = 'Default'; SubKey = 'Software\RegisteredApplications' },
    [PSCustomObject]@{ Hive = 'LocalMachine'; View = 'Registry64'; SubKey = 'Software\RegisteredApplications' },
    [PSCustomObject]@{ Hive = 'LocalMachine'; View = 'Registry32'; SubKey = 'Software\RegisteredApplications' }
)

function Test-IsEveryoneRule {
    param([Security.Principal.IdentityReference]$IdentityReference)

    try {
        return $IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $everyoneSid.Value
    } catch {
        return $false
    }
}

function Remove-ExplicitEveryoneDenyRules {
    param([Parameter(Mandatory)][string]$LiteralPath)

    if (-not (Test-Path -LiteralPath $LiteralPath)) {
        return
    }

    $acl = Get-Acl -LiteralPath $LiteralPath
    $changed = $false
    foreach ($rule in @($acl.Access)) {
        if (-not $rule.IsInherited -and
            $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny -and
            (Test-IsEveryoneRule -IdentityReference $rule.IdentityReference)) {
            $acl.RemoveAccessRuleSpecific($rule)
            $changed = $true
        }
    }

    if ($changed) {
        Set-Acl -LiteralPath $LiteralPath -AclObject $acl
    }
}

function Clear-ImageViewerDirectory {
    $absoluteTarget = [IO.Path]::GetFullPath($imageViewerPath).TrimEnd('\')
    $absoluteParent = [IO.Path]::GetFullPath($expectedParent).TrimEnd('\')

    if (-not (Test-Path -LiteralPath $absoluteParent -PathType Container)) {
        New-Item -ItemType Directory -Path $absoluteParent -Force | Out-Null
    }

    if (Test-Path -LiteralPath $absoluteTarget) {
        $target = Get-Item -LiteralPath $absoluteTarget -Force
        $isReparsePoint = ($target.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        if (-not $target.PSIsContainer -or
            $target.Name -cne 'ImageViewer' -or
            $target.Parent.FullName.TrimEnd('\') -ine $absoluteParent -or
            $target.FullName.TrimEnd('\') -ine $absoluteTarget -or
            $isReparsePoint) {
            throw "Safety check failed for ImageViewer directory: $absoluteTarget"
        }

        Remove-ExplicitEveryoneDenyRules -LiteralPath $absoluteTarget
    } else {
        New-Item -ItemType Directory -Path $absoluteTarget -Force | Out-Null
    }

    foreach ($process in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
        if ($process.ExecutablePath -and $process.ExecutablePath.StartsWith($absoluteTarget + '\', [StringComparison]::OrdinalIgnoreCase)) {
            Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
        }
    }

    foreach ($child in @(Get-ChildItem -LiteralPath $absoluteTarget -Force)) {
        $childParent = [IO.Path]::GetDirectoryName($child.FullName).TrimEnd('\')
        if ($childParent -ine $absoluteTarget) {
            throw "Refusing to remove an unexpected path: $($child.FullName)"
        }

        $childIsReparsePoint = ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        if ($child.PSIsContainer -and $childIsReparsePoint) {
            [IO.Directory]::Delete($child.FullName, $false)
        } elseif ($child.PSIsContainer) {
            Remove-Item -LiteralPath $child.FullName -Recurse -Force
        } else {
            Remove-Item -LiteralPath $child.FullName -Force
        }
    }

    if (@(Get-ChildItem -LiteralPath $absoluteTarget -Force).Count -ne 0) {
        throw 'ImageViewer directory is not empty after cleanup.'
    }

    return $absoluteTarget
}

function Protect-ImageViewerDirectory {
    param([Parameter(Mandatory)][string]$LiteralPath)

    $directory = Get-Item -LiteralPath $LiteralPath -Force
    $directory.Attributes = $directory.Attributes -bor [IO.FileAttributes]::ReadOnly

    $acl = Get-Acl -LiteralPath $LiteralPath
    $rights = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $everyoneSid,
        $rights,
        [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Deny
    )
    $acl.AddAccessRule($rule) | Out-Null
    Set-Acl -LiteralPath $LiteralPath -AclObject $acl
}

function Open-RegistryBaseKey {
    param(
        [Parameter(Mandatory)][string]$Hive,
        [Parameter(Mandatory)][string]$View
    )

    $registryHive = [Enum]::Parse([Microsoft.Win32.RegistryHive], $Hive)
    $registryView = [Enum]::Parse([Microsoft.Win32.RegistryView], $View)
    return [Microsoft.Win32.RegistryKey]::OpenBaseKey($registryHive, $registryView)
}

function Reset-AndProtectRegistryKey {
    param([Parameter(Mandatory)]$Definition)

    $baseKey = Open-RegistryBaseKey -Hive $Definition.Hive -View $Definition.View
    try {
        $rightsForAclReset = [Security.AccessControl.RegistryRights]::ReadKey -bor
            [Security.AccessControl.RegistryRights]::ChangePermissions
        $existingKey = $baseKey.OpenSubKey(
            $Definition.SubKey,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            $rightsForAclReset
        )
        if ($null -ne $existingKey) {
            try {
                $security = $existingKey.GetAccessControl([Security.AccessControl.AccessControlSections]::Access)
                foreach ($rule in @($security.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))) {
                    if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny -and
                        $rule.IdentityReference.Value -eq $everyoneSid.Value) {
                        $security.RemoveAccessRuleSpecific($rule)
                    }
                }
                $existingKey.SetAccessControl($security)
            } finally {
                $existingKey.Dispose()
            }
            $baseKey.DeleteSubKeyTree($Definition.SubKey, $false)
        }

        $key = $baseKey.CreateSubKey(
            $Definition.SubKey,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
        )
        try {
            $security = $key.GetAccessControl([Security.AccessControl.AccessControlSections]::Access)
            $rule = [Security.AccessControl.RegistryAccessRule]::new(
                $everyoneSid,
                ([Security.AccessControl.RegistryRights]::WriteKey -bor [Security.AccessControl.RegistryRights]::Delete),
                [Security.AccessControl.InheritanceFlags]::ContainerInherit,
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Deny
            )
            $security.AddAccessRule($rule)
            $key.SetAccessControl($security)
        } finally {
            $key.Dispose()
        }
    } finally {
        $baseKey.Dispose()
    }
}

function Remove-RegisteredApplicationValues {
    foreach ($location in $registeredApplicationLocations) {
        $baseKey = Open-RegistryBaseKey -Hive $location.Hive -View $location.View
        try {
            $key = $baseKey.OpenSubKey($location.SubKey, $true)
            if ($null -ne $key) {
                try {
                    $key.DeleteValue('BaiduNetdiskImageViewer', $false)
                } finally {
                    $key.Dispose()
                }
            }
        } finally {
            $baseKey.Dispose()
        }
    }
}

function Assert-FileSystemProtection {
    param([Parameter(Mandatory)][string]$LiteralPath)

    $probe = Join-Path $LiteralPath '.image-viewer-write-test.tmp'
    $blocked = $false
    try {
        [IO.File]::WriteAllText($probe, 'test')
    } catch [UnauthorizedAccessException] {
        $blocked = $true
    } catch [IO.IOException] {
        $blocked = $true
    }

    if (Test-Path -LiteralPath $probe) {
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
        throw 'Directory protection failed: a test file was created.'
    }
    if (-not $blocked) {
        throw 'Directory protection could not be verified.'
    }
}

function Assert-RegistryProtection {
    param([Parameter(Mandatory)]$Definition)

    $probeName = '__ImageViewerBlockTest'
    $baseKey = Open-RegistryBaseKey -Hive $Definition.Hive -View $Definition.View
    try {
        $readKey = $baseKey.OpenSubKey($Definition.SubKey, $false)
        if ($null -eq $readKey) {
            throw "Protected registry key is missing: $($Definition.Display)"
        }
        $readKey.Dispose()

        try {
            $writeKey = $baseKey.OpenSubKey($Definition.SubKey, $true)
            if ($null -eq $writeKey) {
                return
            }
            try {
                $writeKey.SetValue($probeName, 'test')
                $writeKey.DeleteValue($probeName, $false)
            } finally {
                $writeKey.Dispose()
            }
        } catch [UnauthorizedAccessException] {
            return
        } catch [Security.SecurityException] {
            return
        }
    } finally {
        $baseKey.Dispose()
    }
    throw "Registry protection failed for: $($Definition.Display)"
}

Write-Host 'Removing BaiduNetdisk ImageViewer files and registrations...'
$protectedPath = Clear-ImageViewerDirectory
Remove-RegisteredApplicationValues

foreach ($registryDefinition in $registryBlockers) {
    Reset-AndProtectRegistryKey -Definition $registryDefinition
}

Protect-ImageViewerDirectory -LiteralPath $protectedPath
Assert-FileSystemProtection -LiteralPath $protectedPath
foreach ($registryDefinition in $registryBlockers) {
    Assert-RegistryProtection -Definition $registryDefinition
}
Remove-RegisteredApplicationValues

Write-Host ''
Write-Host 'ImageViewer is removed and blocked.' -ForegroundColor Green
Write-Host "Protected empty directory: $protectedPath"
Write-Host 'Protected registry keys:'
foreach ($registryDefinition in $registryBlockers) {
    Write-Host "  $($registryDefinition.Display)"
}
Write-Host 'The BaiduNetdiskImageViewer RegisteredApplications values are absent.'
