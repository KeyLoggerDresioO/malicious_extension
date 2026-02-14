#!/usr/bin/env pwsh
<#
.SYNOPSIS
    MalExt - Malicious Extension Scanner (PowerShell Edition)

.DESCRIPTION
    Cross-platform tool to check your browser extensions for known threats.
    Supports: Windows, macOS, Linux
    Port of the original Python script (malext.py) by @toborrm9
    Enhanced: Auto-removes malicious extension folders for all users.
    Enhanced: Blocks detected extensions via GPO registry (Chrome & Edge) on Windows.
    Enhanced: Opera & Opera GX support with silent kill/uninstall/reinstall remediation.

.NOTES
    Author:  @toborrm9 (original Python), PowerShell port
    Version: 1.3
    License: MIT
    Requires: PowerShell 5.1+ (Windows) or PowerShell 7+ (cross-platform)
              Run as Administrator for multi-user cleanup.

.EXAMPLE
    pwsh ./malext.ps1
    # or on Windows PowerShell 5.1:
    powershell -ExecutionPolicy Bypass -File .\malext.ps1
#>

#Requires -Version 5.1

# ---- Encoding Setup ---------------------------------------------------------
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $OutputEncoding = [System.Text.Encoding]::UTF8
}
else {
    # PowerShell 5.1 on Windows
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    } catch {}
    $OutputEncoding = [System.Text.Encoding]::UTF8
}

# ---- Emoji / Symbol Setup ---------------------------------------------------
# PS 5.1 Desktop (conhost) cannot render multi-byte emoji from source code.
# We use version-conditional symbols: emoji on PS7+, ASCII markers on PS5.1.
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $S_SHIELD  = [char]::ConvertFromUtf32(0x1F6E1) + [char]0xFE0F  # shield
    $S_DOWN    = [char]::ConvertFromUtf32(0x1F4E5)                  # inbox tray
    $S_CHECK   = [char]::ConvertFromUtf32(0x2705)                   # green check
    $S_CROSS   = [char]::ConvertFromUtf32(0x274C)                   # red cross
    $S_PC      = [char]::ConvertFromUtf32(0x1F4BB)                  # computer
    $S_SEARCH  = [char]::ConvertFromUtf32(0x1F50E)                  # magnifying glass
    $S_CHART   = [char]::ConvertFromUtf32(0x1F4CA)                  # bar chart
    $S_WARN    = [char]::ConvertFromUtf32(0x26A0) + [char]0xFE0F   # warning
    $S_RED     = [char]::ConvertFromUtf32(0x1F534)                  # red circle
    $S_GLOBE   = [char]::ConvertFromUtf32(0x1F310)                  # globe
    $S_PRAY    = [char]::ConvertFromUtf32(0x1F64F)                  # folded hands
    $S_BUG     = [char]::ConvertFromUtf32(0x1F41B)                  # bug
    $S_TRASH   = [char]::ConvertFromUtf32(0x1F5D1) + [char]0xFE0F  # wastebasket
    $S_FOLDER  = [char]::ConvertFromUtf32(0x1F4C1)                  # folder
    $S_USER    = [char]::ConvertFromUtf32(0x1F464)                  # user
    $S_LOCK    = [char]::ConvertFromUtf32(0x1F512)                  # lock
    $S_BLOCK   = [char]::ConvertFromUtf32(0x1F6AB)                  # no entry / blocked
}
else {
    $S_SHIELD  = '[*]'
    $S_DOWN    = '[>]'
    $S_CHECK   = '[+]'
    $S_CROSS   = '[-]'
    $S_PC      = '[i]'
    $S_SEARCH  = '[?]'
    $S_CHART   = '[#]'
    $S_WARN    = '[!]'
    $S_RED     = '[!]'
    $S_GLOBE   = '[~]'
    $S_PRAY    = '[*]'
    $S_BUG     = '[!]'
    $S_TRASH   = '[x]'
    $S_FOLDER  = '[D]'
    $S_USER    = '[U]'
    $S_LOCK    = '[L]'
    $S_BLOCK   = '[B]'
}

# ---- Constants --------------------------------------------------------------
$CSV_URL = "https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/refs/heads/main/Malicious-Extensions.csv"

# ---- Functions --------------------------------------------------------------

function Show-Banner {
    <#
    .SYNOPSIS
        Display the ASCII art banner.
    #>
}

function Get-BrowserPaths {
    <#
    .SYNOPSIS
        Get browser extension paths based on the current OS.
    .OUTPUTS
        Array of hashtables with Browser (string) and Path (string) keys.
    #>
    $paths = @()

    if ($PSVersionTable.PSVersion.Major -ge 7) {
        # PowerShell 7+ cross-platform detection
        if ($IsMacOS) {
            $paths = @(
                @{ Browser = "Chrome"; Path = Join-Path $HOME "Library/Application Support/Google/Chrome" }
                @{ Browser = "Edge";   Path = Join-Path $HOME "Library/Application Support/Microsoft Edge" }
            )
        }
        elseif ($IsWindows) {
            $paths = @(
                @{ Browser = "Chrome";   Path = Join-Path $HOME "AppData/Local/Google/Chrome/User Data" }
                @{ Browser = "Edge";     Path = Join-Path $HOME "AppData/Local/Microsoft/Edge/User Data" }
                @{ Browser = "Opera";    Path = Join-Path $HOME "AppData/Roaming/Opera Software/Opera Stable" }
                @{ Browser = "Opera GX"; Path = Join-Path $HOME "AppData/Roaming/Opera Software/Opera GX Stable" }
            )
        }
        elseif ($IsLinux) {
            $paths = @(
                @{ Browser = "Chrome";   Path = Join-Path $HOME ".config/google-chrome" }
                @{ Browser = "Edge";     Path = Join-Path $HOME ".config/microsoft-edge" }
                @{ Browser = "Chromium"; Path = Join-Path $HOME ".config/chromium" }
            )
        }
    }
    else {
        # PowerShell 5.1 - Windows only
        $paths = @(
            @{ Browser = "Chrome";   Path = Join-Path $HOME "AppData\Local\Google\Chrome\User Data" }
            @{ Browser = "Edge";     Path = Join-Path $HOME "AppData\Local\Microsoft\Edge\User Data" }
            @{ Browser = "Opera";    Path = Join-Path $HOME "AppData\Roaming\Opera Software\Opera Stable" }
            @{ Browser = "Opera GX"; Path = Join-Path $HOME "AppData\Roaming\Opera Software\Opera GX Stable" }
        )
    }

    return $paths
}

function Get-AllUserBrowserExtensionPaths {
    <#
    .SYNOPSIS
        Get browser extension base paths for ALL user accounts on this machine.
    .DESCRIPTION
        Enumerates all user profile directories and returns browser-specific
        extension paths for Chrome, Edge and Chromium (per OS).
    .OUTPUTS
        Array of hashtables with User, Browser, Path keys.
    #>
    $results = New-Object System.Collections.ArrayList

    # Determine user home directories base and browser sub-paths per OS
    $userHomes = @()
    $browserSubPaths = @()

    if ($PSVersionTable.PSVersion.Major -ge 7) {
        if ($IsMacOS) {
            $userHomes = @(Get-ChildItem "/Users" -Directory -ErrorAction SilentlyContinue)
            $browserSubPaths = @(
                @{ Browser = "Chrome"; Sub = "Library/Application Support/Google/Chrome" }
                @{ Browser = "Edge";   Sub = "Library/Application Support/Microsoft Edge" }
            )
        }
        elseif ($IsLinux) {
            $homeEntries = @(Get-ChildItem "/home" -Directory -ErrorAction SilentlyContinue)
            # Also include /root if it exists
            if (Test-Path "/root") {
                $homeEntries += Get-Item "/root"
            }
            $userHomes = $homeEntries
            $browserSubPaths = @(
                @{ Browser = "Chrome";   Sub = ".config/google-chrome" }
                @{ Browser = "Edge";     Sub = ".config/microsoft-edge" }
                @{ Browser = "Chromium"; Sub = ".config/chromium" }
            )
        }
        elseif ($IsWindows) {
            $usersRoot = Join-Path $env:SystemDrive "Users"
            $userHomes = @(Get-ChildItem $usersRoot -Directory -ErrorAction SilentlyContinue)
            $browserSubPaths = @(
                @{ Browser = "Chrome";   Sub = "AppData\Local\Google\Chrome\User Data" }
                @{ Browser = "Edge";     Sub = "AppData\Local\Microsoft\Edge\User Data" }
                @{ Browser = "Opera";    Sub = "AppData\Roaming\Opera Software\Opera Stable" }
                @{ Browser = "Opera GX"; Sub = "AppData\Roaming\Opera Software\Opera GX Stable" }
            )
        }
    }
    else {
        # PowerShell 5.1 - Windows only
        $usersRoot = Join-Path $env:SystemDrive "Users"
        $userHomes = @(Get-ChildItem $usersRoot -Directory -ErrorAction SilentlyContinue)
        $browserSubPaths = @(
            @{ Browser = "Chrome";   Sub = "AppData\Local\Google\Chrome\User Data" }
            @{ Browser = "Edge";     Sub = "AppData\Local\Microsoft\Edge\User Data" }
            @{ Browser = "Opera";    Sub = "AppData\Roaming\Opera Software\Opera Stable" }
            @{ Browser = "Opera GX"; Sub = "AppData\Roaming\Opera Software\Opera GX Stable" }
        )
    }

    foreach ($userDir in $userHomes) {
        foreach ($bp in $browserSubPaths) {
            $browserBase = Join-Path $userDir.FullName $bp.Sub
            if (-not (Test-Path $browserBase)) { continue }

            # Enumerate profiles (Default, Profile 1, Profile 2, ...)
            $profileDirs = Get-ChildItem -Path $browserBase -Directory -ErrorAction SilentlyContinue
            foreach ($profDir in $profileDirs) {
                if ($profDir.Name -ne "Default" -and -not $profDir.Name.StartsWith("Profile")) {
                    continue
                }
                $extBase = Join-Path $profDir.FullName "Extensions"
                if (Test-Path $extBase) {
                    [void]$results.Add(@{
                        User        = $userDir.Name
                        Browser     = $bp.Browser
                        ProfileName = $profDir.Name
                        ExtPath     = $extBase
                    })
                }
            }
        }
    }

    return ,$results.ToArray()
}

function Remove-MaliciousExtensions {
    <#
    .SYNOPSIS
        Remove detected malicious extension folders for ALL users on this machine.
    .PARAMETER ThreatIds
        Array of malicious extension ID strings to remove.
    .OUTPUTS
        Number of folders successfully removed.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ThreatIds
    )

    Write-Host ""
    Write-Host ("=" * 70)
    Write-Host "$S_TRASH AUTOMATIC REMOVAL - Scanning all users..."
    Write-Host ("=" * 70)
    Write-Host ""

    $allPaths   = Get-AllUserBrowserExtensionPaths
    $removed    = 0
    $failed     = 0
    $uniqueIds  = $ThreatIds | Select-Object -Unique

    if ($allPaths.Count -eq 0) {
        Write-Host "$S_WARN  No browser extension paths found for any user."
        Write-Host ""
        return 0
    }

    Write-Host "$S_SEARCH Checking $($allPaths.Count) browser profiles across all users..."
    Write-Host ""

    foreach ($pathInfo in $allPaths) {
        $userName   = $pathInfo.User
        $browser    = $pathInfo.Browser
        $profName   = $pathInfo.ProfileName
        $extBase    = $pathInfo.ExtPath

        foreach ($extId in $uniqueIds) {
            $extFolder = Join-Path $extBase $extId

            if (Test-Path $extFolder) {
                Write-Host "$S_FOLDER Found: $extFolder"
                Write-Host "   $S_USER User: $userName | Browser: $browser | Profile: $profName"

                try {
                    Remove-Item -Path $extFolder -Recurse -Force -ErrorAction Stop
                    $removed++
                    Write-Host "   $S_CHECK REMOVED successfully!"
                }
                catch {
                    $failed++
                    $errMsg = $_.Exception.Message
                    Write-Host "   $S_CROSS FAILED to remove: $errMsg"
                }
                Write-Host ""
            }
        }
    }

    # Summary
    Write-Host ("-" * 70)
    if ($removed -gt 0) {
        Write-Host "$S_CHECK Removal complete: $removed folder(s) deleted."
    }
    else {
        Write-Host "$S_CHECK No malicious extension folders found on disk."
    }
    if ($failed -gt 0) {
        Write-Host "$S_WARN  $failed folder(s) could not be removed (check permissions / close browser)."
    }
    Write-Host ""

    return $removed
}

function Test-IsAdmin {
    <#
    .SYNOPSIS
        Check if the current PowerShell session is running with administrator privileges.
    .OUTPUTS
        [bool] True if running as admin, False otherwise.
    #>
    if ($PSVersionTable.PSVersion.Major -ge 7 -and -not $IsWindows) {
        # On non-Windows, check for root (UID 0)
        return ($(id -u) -eq 0)
    }

    # Windows: check via .NET security principal
    try {
        $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Add-ExtensionToBlocklist {
    <#
    .SYNOPSIS
        Add an extension ID to a browser's GPO blocklist registry key.
    .PARAMETER ExtensionId
        The extension ID to block.
    .PARAMETER RegistryBasePath
        The base registry path for the browser policies
        (e.g. HKLM:\SOFTWARE\Policies\Google\Chrome).
    .PARAMETER BrowserLabel
        Display label for logging (e.g. "Chrome", "Edge").
    .OUTPUTS
        [string] Status: "Blocked", "AlreadyBlocked", or "Error".
    #>
    param(
        [Parameter(Mandatory = $true)] [string]$ExtensionId,
        [Parameter(Mandatory = $true)] [string]$RegistryBasePath,
        [Parameter(Mandatory = $true)] [string]$BrowserLabel
    )

    $regKey = Join-Path $RegistryBasePath "ExtensionInstallBlocklist"

    try {
        # Create the registry key if it does not exist
        if (-not (Test-Path $regKey)) {
            New-Item $regKey -Force | Out-Null
            Write-Host "   $S_LOCK  Created registry key: $regKey"
        }

        # Enumerate existing blocklist entries (numbered 1, 2, 3, ...)
        $existingEntries = New-Object System.Collections.ArrayList
        $number = 0
        $noMore = $false

        do {
            $number++
            try {
                $entry = Get-ItemProperty $regKey -Name $number -ErrorAction Stop
                [void]$existingEntries.Add([PSCustomObject]@{
                    Name  = $number
                    Value = $entry.$number
                })
            }
            catch {
                $noMore = $true
            }
        } until ($noMore)

        # Check if already blocked
        $alreadyBlocked = $existingEntries | Where-Object { $_.Value -eq $ExtensionId }
        if ($alreadyBlocked) {
            Write-Host "   $S_CHECK  [$BrowserLabel] Already blocked: $ExtensionId"
            return "AlreadyBlocked"
        }

        # Determine the next entry number
        if ($existingEntries.Count -gt 0) {
            $nextNumber = $existingEntries[-1].Name + 1
        }
        else {
            $nextNumber = 1
        }

        # Add the new blocklist entry
        New-ItemProperty $regKey -PropertyType String -Name $nextNumber -Value $ExtensionId | Out-Null
        Write-Host "   $S_BLOCK  [$BrowserLabel] BLOCKED: $ExtensionId (entry #$nextNumber)"
        return "Blocked"
    }
    catch {
        Write-Host "   $S_CROSS  [$BrowserLabel] Error blocking $ExtensionId : $($_.Exception.Message)"
        return "Error"
    }
}

function Remove-ExtensionFromForcelist {
    <#
    .SYNOPSIS
        Remove an extension ID from a browser's GPO force-install list.
    .PARAMETER ExtensionId
        The extension ID to remove.
    .PARAMETER RegistryBasePath
        The base registry path for the browser policies.
    .PARAMETER BrowserLabel
        Display label for logging.
    .OUTPUTS
        [string] Status: "Removed", "NotFound", or "Error".
    #>
    param(
        [Parameter(Mandatory = $true)] [string]$ExtensionId,
        [Parameter(Mandatory = $true)] [string]$RegistryBasePath,
        [Parameter(Mandatory = $true)] [string]$BrowserLabel
    )

    $regKey = Join-Path $RegistryBasePath "ExtensionInstallForcelist"

    # If the forcelist key doesn't exist, nothing to do
    if (-not (Test-Path $regKey)) {
        return "NotFound"
    }

    try {
        # Enumerate existing forcelist entries
        $existingEntries = New-Object System.Collections.ArrayList
        $number = 0
        $noMore = $false

        do {
            $number++
            try {
                $entry = Get-ItemProperty $regKey -Name $number -ErrorAction Stop
                [void]$existingEntries.Add([PSCustomObject]@{
                    Name  = $number
                    Value = $entry.$number
                })
            }
            catch {
                $noMore = $true
            }
        } until ($noMore)

        # Forcelist entries may include an update URL suffix, e.g.:
        #   Chrome: "extid;https://clients2.google.com/service/update2/crx"
        #   Edge:   "extid;https://edge.microsoft.com/extensionwebstorebase/v1/crx"
        # Match if the entry starts with the extension ID (with or without suffix)
        $matchingEntry = $existingEntries | Where-Object {
            $_.Value -eq $ExtensionId -or $_.Value -like "$ExtensionId;*"
        }

        if ($matchingEntry) {
            Remove-ItemProperty $regKey -Name $matchingEntry.Name -Force
            Write-Host "   $S_CHECK  [$BrowserLabel] Removed from force-install list: $ExtensionId"
            return "Removed"
        }
        else {
            return "NotFound"
        }
    }
    catch {
        Write-Host "   $S_CROSS  [$BrowserLabel] Error checking forcelist: $($_.Exception.Message)"
        return "Error"
    }
}

function Block-MaliciousExtensionsGPO {
    <#
    .SYNOPSIS
        Block detected malicious extensions via GPO registry for Chrome AND Edge.
    .DESCRIPTION
        For each malicious extension ID:
        1. Adds to ExtensionInstallBlocklist (prevents install/re-install)
        2. Removes from ExtensionInstallForcelist (if force-pushed by policy)
        Applied to BOTH browsers for defense in depth.
    .PARAMETER ThreatIds
        Array of malicious extension ID strings to block.
    .OUTPUTS
        Summary hashtable with Blocked, AlreadyBlocked, ForcelistRemoved counts.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ThreatIds
    )

    Write-Host ""
    Write-Host ("=" * 70)
    Write-Host "$S_LOCK GPO POLICY ENFORCEMENT - Blocking extensions in Chrome & Edge..."
    Write-Host ("=" * 70)
    Write-Host ""

    # ---- Windows-only check --------------------------------------------------
    $isWindows = $false
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $isWindows = $IsWindows
    }
    else {
        $isWindows = $true  # PS 5.1 is always Windows
    }

    if (-not $isWindows) {
        Write-Host "$S_WARN  GPO blocking is only available on Windows. Skipping..."
        Write-Host ""
        return @{ Blocked = 0; AlreadyBlocked = 0; ForcelistRemoved = 0; Skipped = $true }
    }

    # ---- Admin check (soft warning) ------------------------------------------
    if (-not (Test-IsAdmin)) {
        Write-Host "$S_WARN  WARNING: Not running as Administrator!"
        Write-Host "   GPO registry changes require elevated privileges."
        Write-Host "   Re-run this script as Administrator to enable GPO blocking."
        Write-Host "   (Folder removal above still applies without admin rights)"
        Write-Host ""
        return @{ Blocked = 0; AlreadyBlocked = 0; ForcelistRemoved = 0; Skipped = $true }
    }

    # ---- Browser policy registry base paths ----------------------------------
    $browsers = @(
        @{ Label = "Chrome"; BasePath = "HKLM:\SOFTWARE\Policies\Google\Chrome" }
        @{ Label = "Edge";   BasePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge" }
    )

    $uniqueIds       = $ThreatIds | Select-Object -Unique
    $totalBlocked    = 0
    $totalAlready    = 0
    $totalForceDel   = 0

    foreach ($extId in $uniqueIds) {
        Write-Host "$S_SHIELD Processing extension: $extId"

        foreach ($browser in $browsers) {
            # 1. Add to blocklist
            $blockResult = Add-ExtensionToBlocklist `
                -ExtensionId      $extId `
                -RegistryBasePath $browser.BasePath `
                -BrowserLabel     $browser.Label

            switch ($blockResult) {
                "Blocked"        { $totalBlocked++ }
                "AlreadyBlocked" { $totalAlready++ }
            }

            # 2. Remove from force-install list
            $forceResult = Remove-ExtensionFromForcelist `
                -ExtensionId      $extId `
                -RegistryBasePath $browser.BasePath `
                -BrowserLabel     $browser.Label

            if ($forceResult -eq "Removed") {
                $totalForceDel++
            }
        }
        Write-Host ""
    }

    # ---- Summary -------------------------------------------------------------
    Write-Host ("-" * 70)
    Write-Host "$S_LOCK GPO Enforcement Summary:"
    if ($totalBlocked -gt 0) {
        Write-Host "   $S_BLOCK  $totalBlocked extension(s) newly blocked in registry"
    }
    if ($totalAlready -gt 0) {
        Write-Host "   $S_CHECK  $totalAlready extension(s) were already blocked"
    }
    if ($totalForceDel -gt 0) {
        Write-Host "   $S_TRASH  $totalForceDel extension(s) removed from force-install list"
    }
    if ($totalBlocked -eq 0 -and $totalAlready -eq 0 -and $totalForceDel -eq 0) {
        Write-Host "   $S_CHECK  No GPO changes needed"
    }
    Write-Host ""
    Write-Host "$S_WARN  NOTE: Restart Chrome/Edge for policy changes to take full effect."
    Write-Host "   (Opera/Opera GX do not support GPO extension blocking - use reinstall remediation instead.)"
    Write-Host ""

    return @{
        Blocked         = $totalBlocked
        AlreadyBlocked  = $totalAlready
        ForcelistRemoved = $totalForceDel
        Skipped         = $false
    }
}

function Stop-OperaBrowsers {
    <#
    .SYNOPSIS
        Force-kill all Opera and Opera GX processes silently.
    .OUTPUTS
        [int] Number of processes killed.
    #>
    $killed = 0

    # Both Opera and Opera GX use "opera" as their process name.
    # Kill all instances regardless of variant.
    $procs = Get-Process -Name "opera" -ErrorAction SilentlyContinue
    if ($procs) {
        foreach ($p in $procs) {
            try {
                $p | Stop-Process -Force -ErrorAction Stop
                $killed++
            }
            catch {
                Write-Host "   $S_CROSS Failed to kill opera.exe (PID $($p.Id)): $($_.Exception.Message)"
            }
        }
        # Give the OS a moment to release file locks
        Start-Sleep -Seconds 2
    }

    return $killed
}

function Uninstall-OperaSilently {
    <#
    .SYNOPSIS
        Silently uninstall an Opera variant.
    .DESCRIPTION
        Two-tier uninstall strategy:
        1. Native opera.exe --uninstall --runimmediately --deleteuserprofile=1
           (the correct and documented silent uninstall method)
        2. Nuclear: direct directory removal + registry cleanup
    .PARAMETER BrowserLabel
        Display label ("Opera" or "Opera GX").
    .OUTPUTS
        [bool] True if uninstall succeeded.
    #>
    param(
        [Parameter(Mandatory = $true)] [string]$BrowserLabel
    )

    # ---- Locate opera.exe in known install locations ----------------------------
    # Opera per-user:  %LocalAppData%\Programs\Opera\opera.exe
    #                  %LocalAppData%\Programs\Opera GX\opera.exe
    # Opera all-users: %ProgramFiles%\Opera\opera.exe
    #                  %ProgramFiles%\Opera GX\opera.exe

    $dirName = if ($BrowserLabel -eq "Opera GX") { "Opera GX" } else { "Opera" }

    $candidatePaths = New-Object System.Collections.ArrayList

    # Check all user profiles for per-user installations
    $usersRoot = Join-Path $env:SystemDrive "Users"
    $userDirs = Get-ChildItem $usersRoot -Directory -ErrorAction SilentlyContinue
    foreach ($userDir in $userDirs) {
        $perUserPath = Join-Path $userDir.FullName "AppData\Local\Programs\$dirName\opera.exe"
        [void]$candidatePaths.Add($perUserPath)
    }

    # System-wide installations
    [void]$candidatePaths.Add((Join-Path $env:ProgramFiles "$dirName\opera.exe"))
    $x86 = ${env:ProgramFiles(x86)}
    if ($x86) {
        [void]$candidatePaths.Add((Join-Path $x86 "$dirName\opera.exe"))
    }

    $operaExePaths = @($candidatePaths | Where-Object { Test-Path $_ })

    # ---- Tier 1: Native opera.exe --uninstall -----------------------------------
    if ($operaExePaths.Count -gt 0) {
        $allSuccess = $true
        foreach ($operaExe in $operaExePaths) {
            Write-Host "   $S_TRASH  [$BrowserLabel] Uninstalling: $operaExe"

            # The correct silent uninstall command for Opera:
            #   opera.exe --uninstall --runimmediately --deleteuserprofile=1
            #   --uninstall          : trigger uninstall mode
            #   --runimmediately     : skip delay/UI, execute immediately
            #   --deleteuserprofile=1: remove user profile data
            $uninstArgs = "--uninstall --runimmediately --deleteuserprofile=1"

            Write-Host "   $S_SEARCH Running: `"$operaExe`" $uninstArgs"

            try {
                $process = Start-Process -FilePath $operaExe -ArgumentList $uninstArgs `
                    -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop

                if ($process.ExitCode -eq 0) {
                    Write-Host "   $S_CHECK [$BrowserLabel] Uninstalled successfully (exit code 0)."
                }
                else {
                    Write-Host "   $S_WARN  [$BrowserLabel] Uninstaller exited with code $($process.ExitCode)."
                    $allSuccess = $false
                }
            }
            catch {
                Write-Host "   $S_CROSS [$BrowserLabel] Uninstall error: $($_.Exception.Message)"
                $allSuccess = $false
            }
        }

        Start-Sleep -Seconds 3

        # Verify uninstallation - check if opera.exe still exists at any path
        $stillExists = @($operaExePaths | Where-Object { Test-Path $_ })
        if ($stillExists.Count -eq 0) {
            Write-Host "   $S_CHECK [$BrowserLabel] All installations removed successfully."
            return $true
        }
        else {
            Write-Host "   $S_WARN  [$BrowserLabel] $($stillExists.Count) installation(s) still present. Using direct removal..."
            return Remove-OperaDirectly -BrowserLabel $BrowserLabel
        }
    }
    else {
        Write-Host "   $S_WARN  [$BrowserLabel] No opera.exe found in known locations. Using direct removal..."
        return Remove-OperaDirectly -BrowserLabel $BrowserLabel
    }
}

function Remove-OperaDirectly {
    <#
    .SYNOPSIS
        Nuclear option: directly remove Opera installation directory and clean registry.
    .DESCRIPTION
        When the native uninstaller fails, this function forcefully removes
        the Opera program files, user profile data, and cleans up the Windows
        Uninstall registry entries. Matches --deleteuserprofile=1 behavior.
    .PARAMETER BrowserLabel
        Display label ("Opera" or "Opera GX").
    .OUTPUTS
        [bool] True if removal succeeded.
    #>
    param(
        [Parameter(Mandatory = $true)] [string]$BrowserLabel
    )

    Write-Host "   $S_TRASH  [$BrowserLabel] DIRECT REMOVAL (nuclear option)..."

    $removed = $false

    # ---- Find and remove installation directories for ALL users -----------------
    # Opera per-user install paths:
    #   C:\Users\{user}\AppData\Local\Programs\Opera\
    #   C:\Users\{user}\AppData\Local\Programs\Opera GX\
    # Opera system-wide install paths:
    #   C:\Program Files\Opera\
    #   C:\Program Files (x86)\Opera\
    #   C:\Program Files\Opera GX\

    $installDirNames = @()
    if ($BrowserLabel -eq "Opera GX") {
        $installDirNames = @("Opera GX")
    }
    else {
        $installDirNames = @("Opera")
    }

    $dirsToCheck = New-Object System.Collections.ArrayList

    # Per-user install paths
    $usersRoot = Join-Path $env:SystemDrive "Users"
    $userDirs = Get-ChildItem $usersRoot -Directory -ErrorAction SilentlyContinue
    foreach ($userDir in $userDirs) {
        foreach ($dirName in $installDirNames) {
            $path = Join-Path $userDir.FullName "AppData\Local\Programs\$dirName"
            [void]$dirsToCheck.Add($path)
        }
    }

    # System-wide install paths
    foreach ($dirName in $installDirNames) {
        [void]$dirsToCheck.Add((Join-Path $env:ProgramFiles $dirName))
        $x86 = ${env:ProgramFiles(x86)}
        if ($x86) {
            [void]$dirsToCheck.Add((Join-Path $x86 $dirName))
        }
    }

    foreach ($dir in $dirsToCheck) {
        if (Test-Path $dir) {
            Write-Host "   $S_FOLDER Removing: $dir"
            try {
                Remove-Item -Path $dir -Recurse -Force -ErrorAction Stop
                Write-Host "   $S_CHECK Removed: $dir"
                $removed = $true
            }
            catch {
                Write-Host "   $S_CROSS Failed to remove $dir : $($_.Exception.Message)"
                # Try with cmd.exe rd as fallback for locked files
                try {
                    $null = & cmd.exe /c "rd /s /q `"$dir`"" 2>&1
                    if (-not (Test-Path $dir)) {
                        Write-Host "   $S_CHECK Removed via cmd.exe: $dir"
                        $removed = $true
                    }
                }
                catch {}
            }
        }
    }

    # ---- Remove user profile data (matches --deleteuserprofile=1) ---------------
    # Profile paths: AppData\Roaming\Opera Software\Opera Stable
    #                AppData\Roaming\Opera Software\Opera GX Stable
    $profileDirName = if ($BrowserLabel -eq "Opera GX") { "Opera GX Stable" } else { "Opera Stable" }
    foreach ($userDir in $userDirs) {
        $profilePath = Join-Path $userDir.FullName "AppData\Roaming\Opera Software\$profileDirName"
        if (Test-Path $profilePath) {
            Write-Host "   $S_FOLDER Removing profile: $profilePath"
            try {
                Remove-Item -Path $profilePath -Recurse -Force -ErrorAction Stop
                Write-Host "   $S_CHECK Removed profile: $profilePath"
            }
            catch {
                Write-Host "   $S_CROSS Failed to remove profile: $($_.Exception.Message)"
                try {
                    $null = & cmd.exe /c "rd /s /q `"$profilePath`"" 2>&1
                    if (-not (Test-Path $profilePath)) {
                        Write-Host "   $S_CHECK Removed profile via cmd.exe: $profilePath"
                    }
                }
                catch {}
            }
        }
    }

    # ---- Clean up registry uninstall entries ------------------------------------
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($regPath in $registryPaths) {
        if (-not (Test-Path $regPath)) { continue }
        $subKeys = Get-ChildItem $regPath -ErrorAction SilentlyContinue
        foreach ($key in $subKeys) {
            try {
                $props = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
                if (-not $props.DisplayName) { continue }

                $shouldRemove = $false
                if ($BrowserLabel -eq "Opera GX" -and $props.DisplayName -like "*Opera GX*") {
                    $shouldRemove = $true
                }
                elseif ($BrowserLabel -eq "Opera" -and ($props.DisplayName -like "*Opera Stable*" -or $props.DisplayName -eq "Opera") -and $props.DisplayName -notlike "*GX*") {
                    $shouldRemove = $true
                }

                if ($shouldRemove) {
                    Remove-Item $key.PSPath -Recurse -Force -ErrorAction Stop
                    Write-Host "   $S_CHECK Cleaned registry: $($props.DisplayName)"
                }
            }
            catch { continue }
        }
    }

    # ---- Clean up Start Menu shortcuts ------------------------------------------
    $shortcutPaths = @(
        (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"),
        (Join-Path $HOME "AppData\Roaming\Microsoft\Windows\Start Menu\Programs")
    )
    foreach ($smPath in $shortcutPaths) {
        if (-not (Test-Path $smPath)) { continue }
        $shortcuts = Get-ChildItem $smPath -Filter "*$BrowserLabel*" -Recurse -ErrorAction SilentlyContinue
        foreach ($sc in $shortcuts) {
            try {
                Remove-Item $sc.FullName -Force -ErrorAction Stop
                Write-Host "   $S_CHECK Removed shortcut: $($sc.Name)"
            }
            catch {}
        }
    }

    if ($removed) {
        Write-Host "   $S_CHECK [$BrowserLabel] Direct removal completed."
        Start-Sleep -Seconds 2
    }
    else {
        Write-Host "   $S_WARN  [$BrowserLabel] No installation directories found to remove."
    }

    return $removed
}

function Install-OperaSilently {
    <#
    .SYNOPSIS
        Silently reinstall an Opera variant.
    .PARAMETER WingetId
        The winget package ID (e.g. "Opera.Opera" or "Opera.OperaGX").
    .PARAMETER BrowserLabel
        Display label ("Opera" or "Opera GX").
    .OUTPUTS
        [bool] True if install succeeded.
    #>
    param(
        [Parameter(Mandatory = $true)] [string]$WingetId,
        [Parameter(Mandatory = $true)] [string]$BrowserLabel
    )

    # ---- Always try winget first (most reliable silent install) ------------------
    $wingetAvailable = $false
    try {
        $null = & winget --version 2>$null
        if ($LASTEXITCODE -eq 0) { $wingetAvailable = $true }
    } catch {}

    if ($wingetAvailable) {
        Write-Host "   $S_DOWN  [$BrowserLabel] Installing via winget ($WingetId)..."
        try {
            $result = & winget install --id $WingetId --silent --accept-package-agreements --accept-source-agreements 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "   $S_CHECK [$BrowserLabel] Installed successfully via winget."
                return $true
            }
            else {
                Write-Host "   $S_WARN  [$BrowserLabel] Winget install exit code: $LASTEXITCODE"
                # Fall through to direct download
            }
        }
        catch {
            Write-Host "   $S_WARN  [$BrowserLabel] Winget install error: $($_.Exception.Message)"
        }
    }

    # ---- Fallback: Direct download from Opera servers ----------------------------
    Write-Host "   $S_DOWN  [$BrowserLabel] Downloading installer from Opera servers..."

    $downloadUrl = $null
    $installerName = $null
    if ($BrowserLabel -eq "Opera GX") {
        $downloadUrl   = "https://download.opera.com/download/get/?partner=www&opsys=Windows&product=Opera+GX"
        $installerName = "OperaGXSetup.exe"
    }
    else {
        $downloadUrl   = "https://download.opera.com/download/get/?partner=www&opsys=Windows&product=Opera+Stable"
        $installerName = "OperaSetup.exe"
    }

    $tempPath = Join-Path $env:TEMP $installerName

    try {
        # Download the installer
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $tempPath -UseBasicParsing -TimeoutSec 120 -SkipCertificateCheck
        }
        else {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($downloadUrl, $tempPath)
            $webClient.Dispose()
        }

        if (-not (Test-Path $tempPath)) {
            Write-Host "   $S_CROSS [$BrowserLabel] Download failed - file not found."
            return $false
        }

        Write-Host "   $S_CHECK [$BrowserLabel] Downloaded installer to: $tempPath"
        Write-Host "   $S_DOWN  [$BrowserLabel] Running silent install..."

        # Opera installer silent flags:
        #   /silent          - no UI
        #   /launchopera=0   - don't launch after install
        #   /setdefaultbrowser=0 - don't set as default
        #   /allusers=0      - per-user install (matches original)
        $installArgs = "/silent /launchopera=0 /setdefaultbrowser=0 /allusers=0"

        $process = Start-Process -FilePath $tempPath -ArgumentList $installArgs `
            -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop

        if ($process.ExitCode -eq 0) {
            Write-Host "   $S_CHECK [$BrowserLabel] Installed successfully."
            return $true
        }
        else {
            Write-Host "   $S_CROSS [$BrowserLabel] Installer exited with code $($process.ExitCode)."
            return $false
        }
    }
    catch {
        Write-Host "   $S_CROSS [$BrowserLabel] Install error: $($_.Exception.Message)"
        return $false
    }
    finally {
        # Clean up downloaded installer
        if (Test-Path $tempPath) {
            Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-OperaRemediation {
    <#
    .SYNOPSIS
        Full remediation for Opera/Opera GX: kill process, uninstall, reinstall silently.
    .DESCRIPTION
        When malicious extensions are detected in Opera or Opera GX, this function:
        1. Force-kills all Opera processes
        2. Locates opera.exe in known install paths (per-user and system-wide)
        3. Silently uninstalls using: opera.exe --uninstall --runimmediately --deleteuserprofile=1
        4. Silently reinstalls the affected browser(s)
        User profile data is removed (--deleteuserprofile=1) to ensure a clean state.
    .PARAMETER AffectedBrowsers
        Array of browser labels ("Opera", "Opera GX") that had malicious extensions.
    .OUTPUTS
        Hashtable with Killed, Uninstalled, Reinstalled counts.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$AffectedBrowsers
    )

    Write-Host ""
    Write-Host ("=" * 70)
    Write-Host "$S_SHIELD OPERA REMEDIATION - Kill, Uninstall, Reinstall (silent)..."
    Write-Host ("=" * 70)
    Write-Host ""

    # ---- Windows-only check --------------------------------------------------
    $isWindows = $false
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $isWindows = $IsWindows
    }
    else {
        $isWindows = $true
    }

    if (-not $isWindows) {
        Write-Host "$S_WARN  Opera remediation is only available on Windows. Skipping..."
        Write-Host ""
        return @{ Killed = 0; Uninstalled = 0; Reinstalled = 0; Skipped = $true }
    }

    # ---- Admin check ---------------------------------------------------------
    if (-not (Test-IsAdmin)) {
        Write-Host "$S_WARN  WARNING: Not running as Administrator!"
        Write-Host "   Opera uninstall/reinstall requires elevated privileges."
        Write-Host "   Re-run this script as Administrator to enable Opera remediation."
        Write-Host ""
        return @{ Killed = 0; Uninstalled = 0; Reinstalled = 0; Skipped = $true }
    }

    $uniqueBrowsers = $AffectedBrowsers | Select-Object -Unique
    $totalKilled     = 0
    $totalUninstalled = 0
    $totalReinstalled = 0

    # ---- Step 1: Kill all Opera processes ------------------------------------
    Write-Host "$S_CROSS Terminating Opera processes..."
    $killed = Stop-OperaBrowsers
    $totalKilled = $killed
    if ($killed -gt 0) {
        Write-Host "   $S_CHECK Killed $killed opera.exe process(es)."
    }
    else {
        Write-Host "   $S_CHECK No Opera processes were running."
    }
    Write-Host ""

    # ---- Step 2-3: Uninstall & Reinstall per browser variant -----------------
    $wingetIds = @{
        "Opera"    = "Opera.Opera"
        "Opera GX" = "Opera.OperaGX"
    }

    foreach ($browser in $uniqueBrowsers) {
        Write-Host "$S_SHIELD Processing: $browser"
        Write-Host ("-" * 50)

        $wingetId = $wingetIds[$browser]
        if (-not $wingetId) {
            Write-Host "   $S_WARN  Unknown Opera variant: $browser - skipping."
            Write-Host ""
            continue
        }

        # Uninstall using native opera.exe --uninstall --runimmediately
        $uninstalled = Uninstall-OperaSilently -BrowserLabel $browser
        if ($uninstalled) {
            $totalUninstalled++

            # Reinstall
            $reinstalled = Install-OperaSilently `
                -WingetId     $wingetId `
                -BrowserLabel $browser
            if ($reinstalled) {
                $totalReinstalled++
            }
        }
        Write-Host ""
    }

    # ---- Summary -------------------------------------------------------------
    Write-Host ("-" * 70)
    Write-Host "$S_SHIELD Opera Remediation Summary:"
    if ($totalKilled -gt 0) {
        Write-Host "   $S_CROSS  $totalKilled process(es) terminated"
    }
    if ($totalUninstalled -gt 0) {
        Write-Host "   $S_TRASH  $totalUninstalled browser(s) uninstalled"
    }
    if ($totalReinstalled -gt 0) {
        Write-Host "   $S_CHECK  $totalReinstalled browser(s) reinstalled"
    }
    if ($totalUninstalled -eq 0 -and $totalReinstalled -eq 0) {
        Write-Host "   $S_CHECK  No Opera browsers required reinstallation"
    }
    Write-Host ""
    Write-Host "$S_WARN  NOTE: User profile data was removed (--deleteuserprofile=1) for clean state."
    Write-Host ""

    return @{
        Killed       = $totalKilled
        Uninstalled  = $totalUninstalled
        Reinstalled  = $totalReinstalled
        Skipped      = $false
    }
}

function Get-MaliciousDatabase {
    <#
    .SYNOPSIS
        Download the malicious extensions CSV and return a HashSet of IDs.
    .OUTPUTS
        [System.Collections.Generic.HashSet[string]] of extension IDs, or empty HashSet on failure.
    #>
    Write-Host "$S_DOWN Downloading latest malicious extensions database..."

    $maliciousIds = New-Object 'System.Collections.Generic.HashSet[string]'

    try {
        $content = $null

        if ($PSVersionTable.PSVersion.Major -ge 7) {
            # PowerShell 7+: Invoke-WebRequest with cert bypass
            $response = Invoke-WebRequest -Uri $CSV_URL -UseBasicParsing -TimeoutSec 10 -SkipCertificateCheck
            $content  = $response.Content
        }
        else {
            # PowerShell 5.1: Use .NET WebClient (more reliable than Invoke-WebRequest for TLS)
            # Force TLS 1.2 first - GitHub rejects older protocols
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            # Bypass SSL certificate validation
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

            $webClient = New-Object System.Net.WebClient
            $webClient.Encoding = [System.Text.Encoding]::UTF8
            $content = $webClient.DownloadString($CSV_URL)
            $webClient.Dispose()
        }

        if (-not $content) { throw "Empty response from server" }

        # Parse: replace newlines with commas, split, trim, filter empty
        $content = $content -replace '\r?\n', ','
        $ids = $content.Split(',') |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -ne '' }

        foreach ($id in $ids) {
            [void]$maliciousIds.Add($id)
        }

        Write-Host "$S_CHECK Loaded $($maliciousIds.Count) known malicious extension IDs"
        Write-Host ""
    }
    catch {
        Write-Host "$S_CROSS Error: $($_.Exception.Message)"
        Write-Host ""
    }

    return ,$maliciousIds
}

function Get-ExtensionName {
    <#
    .SYNOPSIS
        Get the extension name from its manifest.json file.
    .PARAMETER ExtensionPath
        Full path to the extension directory (containing version subdirectories).
    .OUTPUTS
        [string] Extension name, or "Unknown" on failure.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExtensionPath
    )

    try {
        $versions = Get-ChildItem -Path $ExtensionPath -Directory -ErrorAction Stop |
            Sort-Object Name

        if ($versions.Count -gt 0) {
            $latestVersion = $versions[-1]
            $manifestPath  = Join-Path $latestVersion.FullName "manifest.json"

            if (Test-Path $manifestPath) {
                $data = Get-Content -Path $manifestPath -Raw -Encoding UTF8 -ErrorAction Stop |
                    ConvertFrom-Json -ErrorAction Stop

                $name = $data.name
                if (-not $name) { return "Unknown" }

                if ($name.StartsWith("__MSG_")) {
                    $shortName = $data.short_name
                    if ($shortName) { return $shortName }
                    return "Unknown"
                }

                return $name
            }
        }
    }
    catch {
        # Silently ignore errors - mirrors Python's bare except: pass
    }

    return "Unknown"
}

function Get-InstalledExtensions {
    <#
    .SYNOPSIS
        Get all installed browser extensions across detected browsers and profiles.
    .OUTPUTS
        Array of PSCustomObjects with Id, Name, Browser, Profile properties.
    #>
    $extensions = New-Object System.Collections.ArrayList
    $browsers   = Get-BrowserPaths

    foreach ($entry in $browsers) {
        $browserName = $entry.Browser
        $browserPath = $entry.Path

        if (-not (Test-Path $browserPath)) { continue }

        $profileDirs = Get-ChildItem -Path $browserPath -Directory -ErrorAction SilentlyContinue

        foreach ($profDir in $profileDirs) {
            # Match "Default" or "Profile*" directories
            if ($profDir.Name -ne "Default" -and -not $profDir.Name.StartsWith("Profile")) {
                continue
            }

            $extPath = Join-Path $profDir.FullName "Extensions"
            if (-not (Test-Path $extPath)) { continue }

            $extDirs = Get-ChildItem -Path $extPath -Directory -ErrorAction SilentlyContinue

            foreach ($ext in $extDirs) {
                $name = Get-ExtensionName -ExtensionPath $ext.FullName
                [void]$extensions.Add([PSCustomObject]@{
                    Id      = $ext.Name
                    Name    = $name
                    Browser = $browserName
                    Profile = $profDir.Name
                })
            }
        }
    }

    return ,$extensions.ToArray()
}

function Invoke-MalExtScan {
    <#
    .SYNOPSIS
        Main scan orchestrator. Scans, reports, and removes malicious extensions.
    #>
    Show-Banner
    Start-Sleep -Seconds 1.5

    # ---- Detect OS ----------------------------------------------------------
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        if ($IsMacOS)       { $osDisplay = "macOS";   $osName = "Darwin"  }
        elseif ($IsLinux)   { $osDisplay = "Linux";   $osName = "Linux"   }
        elseif ($IsWindows) { $osDisplay = "Windows"; $osName = "Windows" }
        else                { $osDisplay = "Unknown"; $osName = "Unknown" }
    }
    else {
        # PowerShell 5.1 is Windows-only
        $osDisplay = "Windows"
        $osName    = "Windows"
    }

    Write-Host "$S_PC Detected OS: $osDisplay"
    Write-Host ""

    # ---- Download database --------------------------------------------------
    $malicious = Get-MaliciousDatabase
    if ($malicious.Count -eq 0) { return }

    # ---- Scan extensions ----------------------------------------------------
    Write-Host "$S_SEARCH Scanning installed extensions..."
    $extensions = Get-InstalledExtensions

    if ($extensions.Count -eq 0) {
        Write-Host "$S_CROSS No extensions found"
        Write-Host "   Make sure Chrome, Edge, Opera or Opera GX is installed on $osDisplay"
        Write-Host ""
        return
    }

    # ---- Count by browser ---------------------------------------------------
    $browserCounts = [ordered]@{}
    foreach ($e in $extensions) {
        if ($browserCounts.Contains($e.Browser)) {
            $browserCounts[$e.Browser]++
        }
        else {
            $browserCounts[$e.Browser] = 1
        }
    }

    $countParts = foreach ($key in $browserCounts.Keys) {
        "$($key): $($browserCounts[$key])"
    }
    $countStr = $countParts -join ", "

    Write-Host "$S_CHECK Found $($extensions.Count) extensions ($countStr)"
    Write-Host ""

    # ---- Check for matches --------------------------------------------------
    $threats = @($extensions | Where-Object { $malicious.Contains($_.Id) })

    Write-Host ("=" * 70)
    Write-Host "$S_CHART SCAN RESULTS"
    Write-Host ("=" * 70)
    Write-Host ""

    if ($threats.Count -gt 0) {
        Write-Host "$S_WARN  WARNING: $($threats.Count) MALICIOUS EXTENSION(S) DETECTED!"
        Write-Host ""
        Write-Host "$S_RED REMOVE THESE IMMEDIATELY:"
        Write-Host ("-" * 70)

        foreach ($t in $threats) {
            Write-Host "$S_CROSS $($t.Name)"
            Write-Host "   ID: $($t.Id)"
            Write-Host "   Browser: $($t.Browser) ($($t.Profile))"
            Write-Host "   URL: https://chromewebstore.google.com/detail/$($t.Id)"
            Write-Host ""
        }

        # OS-specific removal instructions
        $firstBrowser = $threats[0].Browser
        if ($osName -eq "Windows") {
            Write-Host "$S_SHIELD  HOW TO REMOVE (Windows):"
            Write-Host "   1. Open $firstBrowser"
            if ($firstBrowser -eq "Opera" -or $firstBrowser -eq "Opera GX") {
                Write-Host "   2. Type: opera://extensions in address bar"
            }
            else {
                Write-Host "   2. Type: chrome://extensions in address bar"
            }
            Write-Host "   3. Find the extension and click 'Remove'"
            if ($firstBrowser -eq "Opera" -or $firstBrowser -eq "Opera GX") {
                Write-Host "   NOTE: Opera will be automatically reinstalled to ensure clean state."
            }
            Write-Host ""
        }
        elseif ($osName -eq "Darwin") {
            Write-Host "$S_SHIELD  HOW TO REMOVE (macOS):"
            Write-Host "   1. Open $firstBrowser"
            Write-Host "   2. Go to Extensions (menu > Extensions > Manage Extensions)"
            Write-Host "   3. Find the extension and click 'Remove'"
            Write-Host ""
        }
        else {
            Write-Host "$S_SHIELD  HOW TO REMOVE (Linux):"
            Write-Host "   1. Open $firstBrowser"
            Write-Host "   2. Type: chrome://extensions in address bar"
            Write-Host "   3. Find the extension and click 'Remove'"
            Write-Host ""
        }

        # ---- AUTO-REMOVAL across all users ----------------------------------
        $threatIds = @($threats | ForEach-Object { $_.Id } | Select-Object -Unique)
        $null = Remove-MaliciousExtensions -ThreatIds $threatIds

        # ---- GPO POLICY ENFORCEMENT - Block in Chrome & Edge ----------------
        $null = Block-MaliciousExtensionsGPO -ThreatIds $threatIds

        # ---- OPERA REMEDIATION - Kill, Uninstall, Reinstall ----------------
        $operaThreats = @($threats | Where-Object {
            $_.Browser -eq "Opera" -or $_.Browser -eq "Opera GX"
        })
        if ($operaThreats.Count -gt 0) {
            $affectedOperaBrowsers = @($operaThreats | ForEach-Object { $_.Browser } | Select-Object -Unique)
            $null = Invoke-OperaRemediation -AffectedBrowsers $affectedOperaBrowsers
        }
    }
    else {
        Write-Host "$S_CHECK GOOD NEWS: No malicious extensions detected!"
        Write-Host ""
        Write-Host "   All $($extensions.Count) extensions are clear."
        Write-Host ""
    }

    Write-Host ("=" * 70)
    Write-Host "$S_CHART Database: $($malicious.Count) known malicious extensions"
    Write-Host "$S_GLOBE Source: $CSV_URL"
    Write-Host ("=" * 70)
    Write-Host ""
    Write-Host "$S_PRAY Star the repo: github.com/toborrm9/malicious_extension_sentry"
    Write-Host "$S_BUG Report threats: Open an issue on GitHub!"
    Write-Host ""
}

# ---- Entry Point ------------------------------------------------------------
try {
    Invoke-MalExtScan
}
catch {
    $errMsg = $_.Exception.Message
    Write-Host ""
    Write-Host "$S_CROSS Error: $errMsg"
    Write-Host ""
}
