<#
    Package Deployment Module
    Author: Curtis Conard
    Version: 2.0
    Date: 12/05/2017

    This module provides software package deployment capabilities.
#>

<#
.SYNOPSIS
    Tests connection to the specified computer
.DESCRIPTION
    Tests connection to the specified computer. Unlike the "Test-Connection" function, this checks to back sure DNS resolution matches both ways. If a stale DNS entry is present, a host may appear to be online when it is not, and any commands you wanted to run may be run on another host.
.PARAMETER Computer
    The computer to check
.PARAMETER Count
    The number of packets to send
.PARAMETER Quiet
    Supress messages
.NOTES
    Author: Curtis Conard
    Requires: Nothing
#>
Function Test-ConnectionSafe {
    Param (
        [Parameter(Mandatory=$true)]
        [String]
        $Computer,
        [Int]
        $Count=1,
        [Switch]
        $Quiet
    )
    Process {
        $IsIP = $Computer -match "^[\d\.]+$"
        Try {
            $IPs = [System.Net.Dns]::GetHostAddresses($Computer)
        } Catch {

        }
        $HasMatch = $false
        ForEach ($IP in $IPs) {
            Try {
                $Res = [System.Net.Dns]::gethostentry($IP.IPAddressToString)
            } Catch {

            }
            If (($Res.HostName -like $Computer)) {
                $HasMatch = $true
            }
            $DNSSuffix = Get-DnsClientGlobalSetting | Select -ExpandProperty SuffixSearchList
            ForEach ($Suffix In $DNSSuffix) {
                If ($Res.HostName -like "$Computer.$Suffix") {
                    $HasMatch = $true
                }
            }
        }
        If ($HasMatch) {
            Test-Connection -ComputerName $Computer -Count $Count -Quiet -ErrorAction SilentlyContinue
        } Else {
            If ($Quiet -eq $false) {
                Write-Warning "DNS Mismatch"
            }
            $false
        }
    }
}

<#
.SYNOPSIS
    Multi-threaded version of Test-ConnectionSafe
.DESCRIPTION
    Tests connection to the specified computers. Unlike the "Test-Connection" function, this checks to back sure DNS resolution matches both ways. If a stale DNS entry is present, a host may appear to be online when it is not, and any commands you wanted to run may be run on another host.
.PARAMETER Computers
    The computers to check
.NOTES
    Author: Curtis Conard
    Requires: Nothing
#>
Function Test-ConnectionSafeM {
    Param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]
        [String[]]
        $Computers
    )
    Process {
        $ChunkSize = 16
        Write-Verbose "Testing Connection to $($Computers | Measure | Select -ExpandProperty Count) computers. Chunk size = $ChunkSize"
        $ScriptBlock = {
            param($Computer)
            $IsIP = $Computer -match "^[\d\.]+$"
            Try {
                $IPs = [System.Net.Dns]::GetHostAddresses($Computer)
            } Catch {

            }
            $HasMatch = $false
            ForEach ($IP in $IPs) {
                Try {
                    $Res = [System.Net.Dns]::gethostentry($IP.IPAddressToString)
                } Catch {

                }
                If (($Res.HostName -like $Computer) -or ($Res.HostName -like "$Computer.milton.k12.pa.us")) {
                    $HasMatch = $true
                }
            }
            If ($HasMatch) {
                Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue
            } Else {
                $false
            }
        }
        $Chunks = Split-array -inArray $Computers -size $ChunkSize
        ForEach ($Chunk In $Chunks) {
            ForEach ($C in $Chunk) {
                Write-Verbose "Starting Test Connection job for $C"
                [void]$(Start-Job -ArgumentList $C -ScriptBlock $ScriptBlock -Name "TestConn$C")
            }
            While (($(Get-Job | Where {$_.Name -like "TestConn*"} | Measure | Select -ExpandProperty Count) -gt 0)) {
                ForEach ($J In $(Get-Job -State Completed | Where {$_.Name -like "TestConn*"})) {
                    $JobName = $J | Select -ExpandProperty Name
                    Write-Verbose "Processing completed Test Connection job $JobName"
                    $Result = $J | Receive-Job -AutoRemoveJob -Wait
                    If ($Result -eq $true) {
                        $JobName.Replace("TestConn", "")
                    }
                }
            }
        }
    }
}

Function Invoke-RemoteCommand {
    Param (
        [String]
        [Parameter(Mandatory=$true)]
        $Computer,
        [String]
        [Parameter(Mandatory=$true)]
        $Command,
        [String]
        $WorkingDir="C:\Windows\system32",
        [Switch]
        $WaitForOutput
    )
    Process {
        If ($WaitForOutput) {
            $RandSet = "abcdefghijklmnopqrstuvwxyz0123456789".ToCharArray()
            $RandFileName = ""
            for ($x = 0; $x -lt 6; $x++) {
                $RandFileName += $RandSet | Get-Random
            }
            $ResFile = "C:\Windows\Temp\$RandFileName.txt"
            $Command += " > $ResFile"
            $RPIDString = $(Invoke-WmiMethod -ComputerName $Computer -Class Win32_Process -Name Create -ArgumentList $Command,$WorkingDir | findstr "ProcessId") -split(":",2)[1]
            $RPID = $RPIDString.Trim()
            $IsEnded = $(Get-WmiObject -ComputerName $Computer -Class Win32_Process | Where {$_.ProcessId -eq $RPID}) -eq $null
            While (-not $IsEnded) {
                $IsEnded = $(Get-WmiObject -ComputerName $Computer -Class Win32_Process | Where {$_.ProcessId -eq $PID}) -eq $null
                Start-Sleep -Seconds 2
            }
            $FileFound = $false
            $FileFindCount = 0
            While (-not ($FileFound) -and $FileFindCount -lt 10) {
                If (Test-Path -Path "\\$Computer\C$\Windows\Temp\$RandFileName.txt") {
                    $FileFound = $true
                } Else {
                    $FileFindCount++
                    Start-Sleep -Seconds 5
                }
            }
            If ($FileFound) {
                #Write-Host "File found $RandFileName"
                Try {
                    #Write-Host "Reading $RandFileName"
                    Get-Content -Path "\\$Computer\C$\Windows\Temp\$RandFileName.txt"
                } Catch {
                    #Write-Host "$RandFileName is locked. Retrying..."
                    $Locked = $true
                    $LockCount = 0
                    While ($Locked -and $LockCount -lt 10) {
                        Start-Sleep -Seconds 5
                        Try {
                            Get-Content -Path "\\$Computer\C$\Windows\Temp\$RandFileName.txt"
                            #Write-Host "Read previously locked $RandFileName"
                            $Locked = $false
                        } Catch {
                            $LockCount += 1
                        }
                    }
                    If ($LockCount -ge 10) {
                        Write-Error "Tried accessing locked file 10 times. File is still locked or it is now deleted"
                    }
                }
                
                Try {
                    #Write-Host "Removing $RandFileName"
                    Remove-Item "\\$Computer\C$\Windows\Temp\$RandFileName.txt" -Force
                    If (Test-Path "\\$Computer\C$\Windows\Temp\$RandFileName.txt") {
                        Write-Warning "Failed to remove output file $RandFileName"
                        Start-Sleep -Seconds 5
                        Remove-Item "\\$Computer\C$\Windows\Temp\$RandFileName.txt" -Force
                    }
                } Catch {
                    Write-Warning "Failed to remove output file $RandFileName"
                    Start-Sleep -Seconds 5
                    Remove-Item "\\$Computer\C$\Windows\Temp\$RandFileName.txt" -Force
                }
            } Else {
                Write-Error "No output file. Command may not of run properly"
            }
        } Else {
            Invoke-WmiMethod -ComputerName $Computer -Class Win32_Process -Name Create -ArgumentList $Command,$WorkingDir
        }
    }
}

Function Get-PackageStorageLocation {
    Process {
        $ConfigFile = Get-Content $PSScriptRoot\PSDeploy.cfg
        $LineMatches = $ConfigFile | Where {$_ -like "$PackageLocation*"}
        If ($LineMatches -eq $null) {
            Return "C:\Storage\Packages"
        } Else {
            $PropValue = (($LineMatches | Select -First 1 -ErrorAction SilentlyContinue).Trim() -replace "$($PackageLocation):", "").Trim()
            Return $PropValue
        }
    }
}
<#
.SYNOPSIS
    Reads the specified property from the package's package.info file.
.DESCRIPTION
    Reads the specified property from the package's package.info file. If the package doesn't have a package.info file or the property is not specified, $null will be returned.
.PARAMETER Package
    The name of the package
.PARAMETER PropertyName
    The name of the property to read from the package.info file
.NOTES
    Author: Curtis Conard
    Requires: Nothing
#>
Function Get-PackageProperty {
    Param (
        [Parameter(Mandatory=$true)]
        [String]
        $Package,
        [Parameter(Mandatory=$true)]
        [String]
        $PropertyName
    )
    Begin {
        $PackageLocation = Get-PackageStorageLocation
    }
    Process {
        If (Test-Path "$PackageLocation\$Package") {
            If (Test-Path "$PackageLocation\$Package\package.info") {
                $PackageInfo = Get-Content "$PackageLocation\$Package\package.info"
                $LineMatches = $PackageInfo | Where {$_ -like "$PropertyName*"}
                If ($LineMatches -eq $null) {
                    Return $null
                } Else {
                    $PropValue = (($LineMatches | Select -First 1 -ErrorAction SilentlyContinue).Trim() -replace "$($PropertyName):", "").Trim()
                    Return $PropValue
                }
            } Else {
                Return $null
            }
        } Else {
            Write-Host "$Package is not a valid package"
        }
    }
}

<#
.SYNOPSIS
    Waits until all Microsoft Installer processes finish.
.DESCRIPTION
    Waits until all Microsoft Installer processes finish. Since there is always 1 msiexec process, it waits until the number of msiexec processes equals 1.
.PARAMETER Computer
    The name of the computer
.NOTES
    Author: Curtis Conard
    Requires: Administrator access on remote computer
#>
Function Start-WaitForMSI {
    Param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=1)]
        [String]
        $Computer
    )
    Process {
        $MSIExecCount = 0
        $RemoteProcs = tasklist /S $Computer
        ForEach ($RemoteProc In $RemoteProcs) {
            If ($RemoteProc -like "msiexec.exe*") {
                $MSIExecCount = $MSIExecCount + 1
            }
        }

        While ($MSIExecCount -gt 1) {
            Write-Host "Another installation is in progress. Sleeping for 20 seconds"
            Start-Sleep -Seconds 20

            $MSIExecCount = 0
            $RemoteProcs = tasklist /S $Computer
            ForEach ($RemoteProc In $RemoteProcs) {
                If ($RemoteProc -like "msiexec.exe*") {
                    $MSIExecCount = $MSIExecCount + 1
                }
            }
        }
    }
}

<#
.SYNOPSIS
    Installs the specified package on the specified computer
.DESCRIPTION
    Installs the specified package on the specified computer
.PARAMETER Computer
    The name of the computer
.PARAMETER Package
    The name of the package
.PARAMETER Unsafe
    Switch to suppress InstallDanger warnings
.NOTES
    Author: Curtis Conard
    Requires: Administrator access on remote computer
#>
Function Deploy-SoftwarePackage {
    Param (
        [Parameter(Mandatory=$true)]
        [String]
        $Computer,
        [Parameter(Mandatory=$true)]
        [String]
        $Package,
        [Switch]
        $Unsafe
    )
    Begin {
        $PackageLocation = Get-PackageStorageLocation
    }
    Process {
        If (Test-Path "$PackageLocation\$Package") {
            If ($(Test-ConnectionSafe -Computer $Computer) -eq $true) {
                $PackageBase = Get-PackageProperty -Package $Package -PropertyName ParentPackage
                $PackageDeps = Get-PackageProperty -Package $Package -PropertyName Dependencies
                $InstallAction = Get-PackageProperty -Package $Package -PropertyName InstallAction
                $NeedSources = Get-PackageProperty -Package $Package -PropertyName InstallNeedsSources
                $RequiresMSI = Get-PackageProperty -Package $Package -PropertyName RequiresMSI
                $Danger = Get-PackageProperty -Package $Package -PropertyName InstallDanger

                If ($Danger -ne $null -and (-not $Unsafe)) {
                    Write-Host "Installing this package is dangerous. Reason: $Danger"
                    $Resp = Read-Host "Continue? (y/n)"
                    If ($Resp -ne "y") {
                        Write-Host "Aborted"
                        Return
                    }
                }
                If ($InstallAction -eq $null) {
                    $InstallAction = "install.cmd"
                }
                If ($NeedSources -eq $null) {
                    $NeedSources = $true
                }
                If ($RequiresMSI -eq $null) {
                    $RequiresMSI = $true
                }

                Remove-Item -Path "\\$Computer\C$\Windows\Temp\$Package" -Recurse -Force -ErrorAction SilentlyContinue
                    
                If ($PackageBase -ne $null) {
                    If (Test-Path "$PackageLocation\$PackageBase") {
                        Copy-Item "$PackageLocation\$PackageBase" "\\$Computer\C$\Windows\Temp\$Package\$($_.Name)" -Recurse -Force -Exclude "package.info"
                    } Else {
                        Write-Host "Invalid base package $PackageBase"
                        Return
                    }
                } Else {
                    # Write-Host "No base package for $Package"
                }
                If ($PackageDeps -ne $null -and $PackageDeps.Trim().Length -gt 3) {
                    ForEach ($PackageDep In ($PackageDeps -split ',')) {
                        $PackageDep = $PackageDep.Trim()
                        If (Test-Path "$PackageLocation\$PackageDep") {
                            Deploy-SoftwarePackage -Computer $Computer -Package $PackageDep
                        } Else {
                            Write-Host "Invalid dependency package $PackageDep"
                            Return
                        }
                    }
                }
                If ($NeedSources -eq $true) {
                    Write-Host "Deploying $Package to $Computer."
                    Copy-Item C:\Storage\Packages\$Package -Destination "\\$Computer\C$\Windows\Temp\" -Recurse -Force -Exclude "package.info"
                    
                    If (($RequiresMSI -eq $null) -or ($RequiresMSI -eq $true)) {
                        Start-WaitForMSI -Computer $Computer
                    }
                    $Proc = Invoke-RemoteCommand -Computer $Computer -Command "cmd.exe /c `"$InstallAction`"" -WorkingDir "C:\Windows\Temp\$Package\"
                } Else {
                    If (($RequiresMSI -eq $null) -or ($RequiresMSI -eq $true)) {
                        Start-WaitForMSI -Computer $Computer
                    }
                    $Proc = Invoke-RemoteCommand -Computer $Computer -Command "cmd.exe /c `"$InstallAction`"" -WorkingDir "C:\Windows\System32"
                }

            } Else {
                Write-Host "$Computer is Offline"
            }
        } Else {
            Write-Host "$Package is not a valid package"
        }
    }
}

<#
.SYNOPSIS
    Lists all packages
.DESCRIPTION
    Lists all packages in the package directory
.NOTES
    Author: Curtis Conard
    Requires: Nothing
#>
Function List-SoftwarePackage {
    Process {
        Get-ChildItem $(Get-PackageStorageLocation) | Where {$_.Attributes -like "*Directory*"} | Select -ExpandProperty Name
    }
}

<#
.SYNOPSIS
    Installs the specified package on the specified computers
.DESCRIPTION
    Installs the specified package on the specified computers. This is a multi-threaded wrapper for Deploy-SoftwarePackage. It groups the computers into chunks of $BatchSize size, and deploys package to 1 chunk at a time.
.PARAMETER Computers
    The names of the computers
.PARAMETER Package
    The name of the package
.PARAMETER BatchSize
    Number of computers to deploy the package to at a time
.PARAMETER Online
    Filter computers and only try to deploy package to computers that are online. The online check is also multithreaded.
.NOTES
    Author: Curtis Conard
    Requires: Administrator access on remote computer
    Requires: CustomUtil module
#>
Function Deploy-SoftwarePackageBatch {
    Param (
        [Parameter(Mandatory=$true)]
        [String[]]
        $Computers,
        [Parameter(Mandatory=$true)]
        [String]
        $Package,
        [int]
        $BatchSize=16,
        [boolean]
        $Online=$true
    )
    Process {
        $ScriptBlock = {
            Param($_Computer,$_Package)
            Deploy-SoftwarePackage -Computer $_Computer -Package $_Package
        }
        If ($Online) {
            $AllCount = $Computers | Measure | Select -ExpandProperty Count
            Write-Host "Checking for online computers"
            $Computers = Test-ConnectionSafeM -Computers $Computers
            Write-Host "$($Computers | Measure | Select -ExpandProperty Count) / $AllCount online"
        }
        $Chunks = Split-array -inArray $Computers -size $BatchSize
        ForEach ($Chunk In $Chunks) {
            ForEach ($C in $Chunk) {
                [void](Start-Job -ArgumentList $C,$Package -ScriptBlock $ScriptBlock -Name "SDeploy$C-$Package")
            }

            While (($(Get-Job | Where {$_.Name -like "SDeploy*"} | Measure | Select -ExpandProperty Count) -gt 0)) {
                ForEach ($J In $(Get-Job -State Completed | Where {$_.Name -like "SDeploy*"})) {
                    $JobName = $J | Select -ExpandProperty Name
                    $J | Receive-Job -AutoRemoveJob -Wait
                }
            }
        }
    }
}

<#
.SYNOPSIS
    Uninstalls the specified package from the specified computer
.DESCRIPTION
    Uninstalls the specified package from the specified computer
.PARAMETER Computer
    The name of the computer
.PARAMETER Package
    The name of the package
.PARAMETER Unsafe
    Switch to suppress UninstallDanger warnings
.NOTES
    Author: Curtis Conard
    Requires: Administrator access on remote computer
    Requires: CustomUtil module
#>
Function Remove-SoftwarePackage {
    Param (
        [Parameter(Mandatory=$true)]
        [String]
        $Computer,
        [Parameter(Mandatory=$true)]
        [String]
        $Package,
        [Switch]
        $Unsafe
    )
    Begin {
        $PackageLocation = Get-PackageStorageLocation
    }
    Process {
        If (Test-Path "$PackageLocation\$Package") {
            If (Test-ConnectionSafe -ComputerName $Computer) {
                $PackageBase = Get-PackageProperty -Package $Package -PropertyName ParentPackage
                $PackageDeps = Get-PackageProperty -Package $Package -PropertyName Dependencies
                $UninstallAction = Get-PackageProperty -Package $Package -PropertyName UninstallAction
                $NeedSources = Get-PackageProperty -Package $Package -PropertyName UninstallNeedsSources
                $RequiresMSI = Get-PackageProperty -Package $Package -PropertyName RequiresMSI
                $Danger = Get-PackageProperty -Package $Package -PropertyName UninstallDanger

                If (($Danger -ne $null) -and ($Unsafe -ne $false)) {
                    Write-Host "Uninstalling this package is dangerous. Reason: $Danger"
                    $Resp = Read-Host "Continue? (y/n)"
                    If ($Resp -ne "y") {
                        Write-Host "Aborted"
                        Return
                    }
                }

                If ($UninstallAction -eq $null) {
                    $UninstallAction = "uninstall.cmd"
                }

                If ($PackageDeps -ne $null -and $PackageDeps.Trim().Length -gt 3) {
                    ForEach ($PackageDep In ($PackageDeps -split ',')) {
                        $PackageDep = $PackageDep.Trim()
                        If (Test-Path "$PackageLocation\$PackageDep") {
                            Remove-SoftwarePackage -Computer $Computer -Package $PackageDep
                        } Else {
                            Write-Host "Invalid dependency package $PackageDep"
                            Return
                        }
                    }
                }
                If ($NeedSources -eq $true) {
                    Write-Host "Removing $Package from $Computer. Sources will be cached on the remote computer."
                    Remove-Item -Path "\\$Computer\C$\Windows\Temp\$Package" -Recurse -Force -ErrorAction SilentlyContinue
                    Copy-Item C:\Storage\Packages\$Package -Destination "\\$Computer\C$\Windows\Temp\$Package" -Recurse -Force -Exclude "package.info"
                    
                    If (($RequiresMSI -eq $null) -or ($RequiresMSI -eq $true)) {
                        Start-WaitForMSI -Computer $Computer
                    }
                    $Proc = Invoke-RemoteCommand -Computer $Computer -Command "cmd.exe /c `"$UninstallAction`"" -WorkingDir "C:\Windows\Temp\$Package\"
                } Else {
                    If (($RequiresMSI -eq $null) -or ($RequiresMSI -eq $true)) {
                        Start-WaitForMSI -Computer $Computer
                    }
                    Invoke-RemoteCommand -Computer $Computer -Command "cmd.exe /c `"$UninstallAction`"" -WorkingDir "C:\Windows\System32"
                }

            } Else {
                Write-Host "$Computer is Offline"
            }
        } Else {
            Write-Host "$Package is not a valid package"
        }
    }
}

<#
.SYNOPSIS
    Removes all cached package files on the specified computer
.DESCRIPTION
    Removes all cached package files on the specified computer
.PARAMETER Computer
    The name of the computer
.NOTES
    Author: Curtis Conard
    Requires: Administrator access on remote computer
#>
Function Clear-PackageCache {
    Param (
        [String]
        [Parameter(Mandatory=$true)]
        $Computer
    )
    Process {
        $AllPackages = List-SoftwarePackage
        ForEach ($Package In $AllPackages) {
            Remove-Item -Path "\\$Computer\C$\Windows\Temp\$Package" -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

<#
.SYNOPSIS
    Lists installed software
.DESCRIPTION
    Lists installed software by name and product code
.PARAMETER Computer
    The name of the computer
.NOTES
    Author: Curtis Conard
    Requires: Administrator access on remote computer
#>
Function List-InstalledSoftware {
    Param (
        [String]
        $Computer=$env:COMPUTERNAME
    )
    Process {
        $RRService = Get-WmiObject -ComputerName $Computer -Class Win32_Service -Filter "name='RemoteRegistry'"
        [void]$RRService.ChangeStartMode("Manual")
        [void]$RRService.StartService()
        $RemoteList = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('localmachine', $Computer)
        $AllInstalled = New-Object -TypeName System.Collections.Hashtable
        $UninstallRoot = $RemoteList.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        $UninstallKeys = $UninstallRoot.GetSubKeyNames()
        ForEach ($UninstallKey In $UninstallKeys) {
            $DisplayName = $RemoteList.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$UninstallKey").GetValue("DisplayName")
            If ($DisplayName -ne $null) {
                If (-not $AllInstalled.Contains($DisplayName)) {
                    [void]($AllInstalled.Add($DisplayName, $UninstallKey))
                }
            }
        }
        $UninstallRoot = $RemoteList.OpenSubKey("SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
        $UninstallKeys = $UninstallRoot.GetSubKeyNames()
        ForEach ($UninstallKey In $UninstallKeys) {
            $DisplayName = $RemoteList.OpenSubKey("SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$UninstallKey").GetValue("DisplayName")
            If ($DisplayName -ne $null) {
                If (-not $AllInstalled.Contains($DisplayName)) {
                    [void]($AllInstalled.Add($DisplayName, $UninstallKey))
                }
            }
        }
        [void]$RRService.ChangeStartMode("Disabled")
        $AllInstalled.GetEnumerator() | Sort -Property Name
    }
}

<#
.SYNOPSIS
    Checks if any installed software matches the specified pattern
.DESCRIPTION
    Checks if any installed software matches the specified pattern
.PARAMETER Computer
    The name of the computer
.PARAMETER SoftwareMatch
    The pattern to match
.NOTES
    Author: Curtis Conard
    Requires: Administrator access on remote computer
#>
Function Test-InstalledSoftware {
    Param (
        [String]
        $Computer=$env:COMPUTERNAME,
        [String]
        [Parameter(Mandatory=$true)]
        $SoftwareMatch
    )
    Process {
        $RRService = Get-WmiObject -ComputerName $Computer -Class Win32_Service -Filter "name='RemoteRegistry'"
        [void]$RRService.ChangeStartMode("Manual")
        [void]$RRService.StartService()
        $RemoteList = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('localmachine', $Computer)
        $UninstallRoot = $RemoteList.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        $UninstallKeys = $UninstallRoot.GetSubKeyNames()
        ForEach ($UninstallKey In $UninstallKeys) {
            $DisplayName = $RemoteList.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$UninstallKey").GetValue("DisplayName")
            If ($DisplayName -ne $null) {
                 If ($DisplayName -like $SoftwareMatch) {
                    [void]$RRService.ChangeStartMode("Disabled")
                    Return $true
                 }
            }
        }
        $UninstallRoot = $RemoteList.OpenSubKey("SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
        $UninstallKeys = $UninstallRoot.GetSubKeyNames()
        ForEach ($UninstallKey In $UninstallKeys) {
            $DisplayName = $RemoteList.OpenSubKey("SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$UninstallKey").GetValue("DisplayName")
            If ($DisplayName -ne $null) {
                If ($DisplayName -like $SoftwareMatch) {
                    [void]$RRService.ChangeStartMode("Disabled")
                    Return $true
                 }
            }
        }
        [void]$RRService.ChangeStartMode("Disabled")
        Return $false
    }
}

Export-ModuleMember -Function @("Get-PackageStorageLocation", "Get-PackageProperty", "Start-WaitForMSI", 
"Deploy-SoftwarePackage", "Deploy-SoftwarePackageBatch", "List-SoftwarePackage", "Remove-SoftwarePackage",
"Clear-PackageCache","List-InstalledSoftware","Test-InstalledSoftware")