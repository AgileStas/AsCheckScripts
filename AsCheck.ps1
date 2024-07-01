﻿    Param
        (
            [Parameter(Mandatory=$true, HelpMessage="Base path for computer info directory")]
            [string]$BasePath
        )

#================================================================================================
<#
.SYNOPSIS
    Adds note properties containing the last modified time and class name of a 
    registry key.

.DESCRIPTION
    Add-RegKeyMember function uses the unmanged RegQueryInfoKey Win32 function
    to get a key's last modified time and class name. It can take a RegistryKey 
    object (which Get-Item and Get-ChildItem output) or a path to a registry key.

.EXAMPLE
    PS c:\> Get-Item HKLM:\SOFTWARE | Get-RegWritetime | Select Name, LastWriteTime

    Show the name and last write time of HKLM:\SOFTWARE

.EXAMPLE
    PS C:\> Get-RegWritetime HKLM:\SOFTWARE | Select Name, LastWriteTime

    Show the name and last write time of HKLM:\SOFTWARE

.EXAMPLE
    PS C:\> Get-ChildItem HKLM:\SOFTWARE | Get-RegWritetime | Select Name, LastWriteTime

    Show the name and last write time of HKLM:\SOFTWARE's child keys

.EXAMPLE
    PS C:\> Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Control\Lsa | Get-RegWritetime | where classname | select name, classname

    Show the name and class name of child keys under Lsa that have a class name defined.

.EXAMPLE
    PS C:\> Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Get-Regtime HKLM:\SOFTWARE | Select Name, LastWriteTime | where lastwritetime -gt (Get-Date).AddDays(-30) | 
    >> select PSChildName, @{ N="DisplayName"; E={gp $_.PSPath | select -exp DisplayName }}, @{ N="Version"; E={gp $_.PSPath | select -exp DisplayVersion }}, lastwritetime |
    >> sort lastwritetime

    Show applications that have had their registry key updated in the last 30 days (sorted by the last time the key was updated).

    NOTE: On a 64-bit machine, you will get different results depending on whether or not the command was executed from a 32-bit
    or 64-bit PowerShell prompt.

#>


Function Get-RegWriteTime {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ParameterSetName="ByKey", Position=0, ValueFromPipeline=$true)]
        [ValidateScript({ $_ -is [Microsoft.Win32.RegistryKey] })]
        # Registry key object returned from Get-ChildItem or Get-Item. Instead of requiring the type to
        # be [Microsoft.Win32.RegistryKey], validation has been moved into a [ValidateScript] parameter
        # attribute. In PSv2, PS type data seems to get stripped from the object if the [RegistryKey]
        # type is an attribute of the parameter.
        $RegistryKey,
        [Parameter(Mandatory=$true, ParameterSetName="ByPath", Position=0)]
        # Path to a registry key
        [string] $Path
    )

    begin {
        # Define the namespace (string array creates nested namespace):
        $Namespace = "CustomNamespace", "SubNamespace"

        # Make sure type is loaded (this will only get loaded on first run):
        Add-Type @"
            using System; 
            using System.Text;
            using System.Runtime.InteropServices; 

            $($Namespace | ForEach-Object {
                "namespace $_ {"
            })

                public class advapi32 {
                    [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
                    public static extern Int32 RegQueryInfoKey(
                        IntPtr hKey,
                        StringBuilder lpClass,
                        [In, Out] ref UInt32 lpcbClass,
                        UInt32 lpReserved,
                        out UInt32 lpcSubKeys,
                        out UInt32 lpcbMaxSubKeyLen,
                        out UInt32 lpcbMaxClassLen,
                        out UInt32 lpcValues,
                        out UInt32 lpcbMaxValueNameLen,
                        out UInt32 lpcbMaxValueLen,
                        out UInt32 lpcbSecurityDescriptor,
                        out Int64 lpftLastWriteTime
                    );

                    [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
                    public static extern Int32 RegOpenKeyEx(
                        IntPtr hKey,
                        string lpSubKey,
                        Int32 ulOptions,
                        Int32 samDesired,
                        out IntPtr phkResult
                    );

                    [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
                    public static extern Int32 RegCloseKey(
                        IntPtr hKey
                    );
                }
            $($Namespace | ForEach-Object { "}" })
"@
    
        # Get a shortcut to the type:    
        $RegTools = ("{0}.advapi32" -f ($Namespace -join ".")) -as [type]
    }

    process {
        switch ($PSCmdlet.ParameterSetName) {
            "ByKey" {
                # Already have the key, no more work to be done :)
            }

            "ByPath" {
                # We need a RegistryKey object (Get-Item should return that)
                $Item = Get-Item -Path $Path -ErrorAction Stop

                # Make sure this is of type [Microsoft.Win32.RegistryKey]
                if ($Item -isnot [Microsoft.Win32.RegistryKey]) {
                    throw "'$Path' is not a path to a registry key!"
                }
                $RegistryKey = $Item
            }
        }

        # Initialize variables that will be populated:
        $ClassLength = 255 # Buffer size (class name is rarely used, and when it is, I've never seen 
                            # it more than 8 characters. Buffer can be increased here, though. 
        $ClassName = New-Object System.Text.StringBuilder $ClassLength  # Will hold the class name
        $LastWriteTime = $null

        # Get a handle to our key via RegOpenKeyEx (PSv3 and higher could use the .Handle property off of registry key):
        $KeyHandle = New-Object IntPtr

        if ($RegistryKey.Name -notmatch "^(?<hive>[^\\]+)\\(?<subkey>.+)$") {
            Write-Error ("'{0}' not a valid registry path!")
            return
        }

        $HiveName = $matches.hive -replace "(^HKEY_|_|:$)", ""  # Get hive in a format that [RegistryHive] enum can handle
        $SubKey = $matches.subkey

        # Get hive. $HiveName should contain a valid MS.Win32.RegistryHive enum, but it will be in all caps. It seems that
        # [enum]::IsDefined is case sensitive, so that won't work. There's an awesome static method [enum]::TryParse, but it
        # appears that it was introduced in .NET 4. So, I'm just wrapping it in a try {} block:
        try {
            $Hive = [Microsoft.Win32.RegistryHive] $HiveName
        }
        catch {
            Write-Error ("Unknown hive: {0} (Registry path: {1})" -f $HiveName, $RegistryKey.Name)
            return  # Exit function or we'll get an error in RegOpenKeyEx call
        }

        Write-Verbose ("Attempting to get handle to '{0}' using RegOpenKeyEx" -f $RegistryKey.Name)
        switch ($RegTools::RegOpenKeyEx(
            $Hive.value__,
            $SubKey,
            0,  # Reserved; should always be 0
            [System.Security.AccessControl.RegistryRights]::ReadKey,
            [ref] $KeyHandle
        )) {
            0 { # Success
                # Nothing required for now
                Write-Verbose "  -> Success!"
            }

            default {
                # Unknown error!
                Write-Error ("Error opening handle to key '{0}': {1}" -f $RegistryKey.Name, $_)
            }
        }
            
        switch ($RegTools::RegQueryInfoKey(
            $KeyHandle,
            $ClassName, 
            [ref] $ClassLength, 
            $null,  # Reserved
            [ref] $null, # SubKeyCount
            [ref] $null, # MaxSubKeyNameLength
            [ref] $null, # MaxClassLength
            [ref] $null, # ValueCount
            [ref] $null, # MaxValueNameLength 
            [ref] $null, # MaxValueValueLength 
            [ref] $null, # SecurityDescriptorSize
            [ref] $LastWriteTime
        )) {

            0 { # Success
                $LastWriteTime = [datetime]::FromFileTime($LastWriteTime)

                # Add properties to object and output them to pipeline
                $RegistryKey | 
                    Add-Member -MemberType NoteProperty -Name LastWriteTime -Value $LastWriteTime -Force -PassThru |
                    Add-Member -MemberType NoteProperty -Name ClassName -Value $ClassName.ToString() -Force -PassThru
            }

            122  { # ERROR_INSUFFICIENT_BUFFER (0x7a)
                throw "Class name buffer too small"
                # function could be recalled with a larger buffer, but for
                # now, just exit
            }

            default {
                throw "Unknown error encountered (error code $_)"
            }
        }

        # Closing key:
        Write-Verbose ("Closing handle to '{0}' using RegCloseKey" -f $RegistryKey.Name)
        switch ($RegTools::RegCloseKey($KeyHandle)) {
            0 {
                # Success, no action required
                Write-Verbose "  -> Success!"
            }
            default {
                Write-Error ("Error closing handle to key '{0}': {1}" -f $RegistryKey.Name, $_)
            }
        }
    }
}
#================================================================================================

Write-Host $env:computername
if (-Not (Test-Path -PathType Container -Path $BasePath)) {
	Write-Host "Specified base path does not exist or is not directory"
	Exit 1
}
$NodePath = Join-Path -Path $BasePath -ChildPath $env:computername
if (Test-Path -PathType Any -Path $NodePath) {
	Write-Host "Specified base path already contains node directory"
	Exit 2
}
New-Item -Path $BasePath -Name $env:computername -ItemType "directory"

$CurFileName = Join-Path -Path $NodePath -ChildPath ComputerInfo.txt
Get-ComputerInfo | Out-File -FilePath $CurFileName

$CurFileName = Join-Path -Path $NodePath -ChildPath WindowsActivationInfo.txt
# https://superuser.com/questions/1422368/how-can-i-check-if-windows-is-activated-from-the-command-prompt-or-powershell
#Get-CimInstance SoftwareLicensingProduct -Filter "partialproductkey is not null" | ? name -like "windows*"
Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%' and partialproductkey <> null" | Out-File -FilePath $CurFileName
#  | select Description, LicenseStatus

$CurFileName = Join-Path -Path $NodePath -ChildPath AntivirusProductInfo.txt
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Out-File -FilePath $CurFileName

$CurFileName = Join-Path -Path $NodePath -ChildPath EsetInfo.txt
Get-ItemProperty -Path 'HKLM:\SOFTWARE\ESET\ESET Security\CurrentVersion\Info' | Out-File -FilePath $CurFileName

#Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB' -Exclude 'ROOT*'
#Where-Object LastWriteTime -gt (Get-Date).AddDays(-1) |
###dir 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB' -Recurse |
###Where-Object LastWriteTime -ge (Get-Date 2024-06-01) |
###Select-Object Name, LastWriteTime |
###Sort LastWriteTime

#ForEach-Object { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USB\*" -ErrorAction SilentlyContinue } |
#ForEach-Object { Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USB" } |
#    Where-Object DisplayName | # Some keys don't have display names
#    Where-Object Name |
#    Select-Object Name, @{Name="LastModified"; Expression={ (Add-RegKeyMember $_.PsPath).LastWriteTime }} #|
#    Sort-Object DisplayName

# https://devblogs.microsoft.com/scripting/leverage-registry-key-time-stamps-via-powershell/
#Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB\*\*' |
#    Where-Object Service -eq USBSTOR |
#    Select-Object Service, Name, @{Name="DeviceDesc"; Expression={ $_.DeviceDesc -split ";" | select -last 1 }},
#        @{Name="SerialNumber"; Expression={ $_.PsChildName }},
#        @{Name="LastModified"; Expression={ (Add-RegKeyMember $_.PsPath).LastWriteTime }}
###Where-Object LastModified -ge (Get-Date 2024-06-01) |

$CurFileName = Join-Path -Path $NodePath -ChildPath UsbInfo.txt
#$RwtScript = Join-Path -Path $PSScriptRoot -ChildPath Get-RegWriteTime.ps1
#Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB' -Exclude 'ROOT*' | Invoke-Expression $RwtScript | Select Name, LastWriteTime
#Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB' | Invoke-Expression -Command $RwtScript | Select Name, LastWriteTime
#Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB' -Exclude 'ROOT*' | E:\AsCheck\Get-RegWriteTime.ps1 | Select Name, LastWriteTime
Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB\*' -Exclude 'ROOT*' | Get-RegWriteTime |
	Select Name, LastWriteTime,
		@{Name="SerialNumber"; Expression={ $_.PsChildName }} |Format-List | Out-File -FilePath $CurFileName
$CurFileName = Join-Path -Path $NodePath -ChildPath UsbStorInfo.txt
Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' | Get-RegWriteTime |
	Select Name, LastWriteTime,
		@{Name="SerialNumber"; Expression={ $_.PsChildName }} | Format-List | Out-File -FilePath $CurFileName