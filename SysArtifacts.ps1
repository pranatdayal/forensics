<# 
.SYNOPSIS 

Powershell script for digital forensics and incident response on windows. 

.DESCRIPTION

Script collects various system artifacts that are useful for incident response and forensics. 
 

.OUTPUTS 
CSV format and console

.PARAMETER ComputerName 
specify computerName for PSRemote 

.PARAMETER Remote 
Switch to enable PSRemote 

.PARAMETER CSV
To output to CSV File  
#> 

Param(
    [string]$ComputerName,
    [switch]$Remote,

    [switch]$CSV 
)


function param1{
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$False)]
   [string]$ComputerName,
    
   [switch]$Remote,

   [switch]$CSV
)
}

if($CSV=$True)
{
     Invoke-Expression .\SysArtifacts.ps1 | Export-csv -Append -path artifacts.csv
     exit
}


if ($Remote=$False){
    $Session = New-PSSession -ComputerName $ComputerName -Credential (Get-Credential) -UseSSL 
    $FileContents = Get-Content -Path ($PSSCriptRoot+"\SysArtifacts.ps1")
    Invoke-Command -Session $Session -ScriptBlock {
        param($FilePath,$data)
        Set-Content -Path $FilePath -Value $data
    } -ArgumentList "C:\Windows\SysArtifacts.ps1",$FileContents
    Invoke-Command -Session $Session -ScriptBlock{'C:\Windows\SysArtifacts.ps1'}
}

else{

clear


write-host " "
write-host "Digital forensics and incident response script" 
write-host "this script collects system artifacts"
write-host " " 
write-host " " 

write-host "Use -ComputerName and -Remote for remote session"
write-host " " 
write-host "Use -CSV to export to CSV file"
write-host  " "  

##########################################################
# Date and time object 

$dateObj = New-Object PSObject

$date = Get-Date #system date and time 
$timezone = Get-TimeZone #PC timezone
$PCUptime = (get-date) - (gcim Win32_OperatingSystem).LastBootUpTime #PC up time 

$dateObj | Add-Member Current_Date_Time $date 
$dateObj | Add-Member TimeZone $timezone
$dateObj | Add-Member PC_Uptime_hours $PCUptime

write-host "##########################################################"
write-host "SYSTEM DATE AND TIME INFORMATION:  "
write-host ($dateObj | format-list | Out-String) 

##########################################################
#OS information 

$OSobj = New-Object PSObject #OS object

$TypicalName = gwmi win32_operatingsystem | % caption #Windows typical name 
$FullVer = [System.Environment]::OSVersion.Version  #Major, Minor, Build and revision

$OSobj | Add-Member TypicalName $TypicalName
$OSobj | Add-Member Major_Minor_Build_Revision $FullVer

write-host "##########################################################"
write-host "OS INFORMATION: " 
Write-host ($OSobj | Format-list |  Out-String)

##########################################################

#System hardware specs 

$HardwareObj =  New-Object PSObject #System information object 

$cpuname = gwmi win32_processor | % name #processor name and speed 
$RAM =  gwmi win32_physicalmemoryarray | % maxcapacity
$ramGB = $RAM/1MB
$HDD = gwmi win32_diskdrive | % size 
$hddGB = $HDD/1gb

 
$AllDrives = gdr -PSProvider FileSystem | % Name
$logicalDrives = gwmi win32_logicalDisk | % VolumeName


$HardwareObj | Add-Member CPU_Brand_Type $cpuname
$HardwareObj | Add-Member RAM_AmountGB $ramGB
$HardwareObj | Add-Member HDD_AmountGB $hddGB
$HardwareObj | Add-Member Drives $AllDrives
$Hardwareobj | Add-Member MountPoints $logicalDrives


write-host "##########################################################"

write-host "SYSTEM HARDWARE INFORMATION:"
write-host ($HardwareObj | format-list| out-string)

##########################################################

#Domain controller information 

$DomainObj = New-Object PSobject # new Domain controller object 


##########################################################
#hostname information 

$hostname = gwmi win32_computersystem | ft Name, Domain


write-host "##########################################################"
write-host "HOSTNAME AND DOMAIN INFORMATION"
write-host ($hostname |out-string)

##########################################################

#Local users 

$SID = gwmi win32_useraccount | ft Name, SID 

write-host "##########################################################"
write-host "LOCAL USER INFORMATION: " 

write-host ($SID | format-list | Out-String)

##########################################################
#Start at boot 

$services = get-service | where {$_.starttype -eq 'Automatic'} | ft Name, DisplayName 
$Programs = Get-Ciminstance win32_startupcommand | ft Name,command, user, Location

write-host "##########################################################"
write-host "BOOT SERVICES: "
write-host ($services | format-list | out-string )
write-host "BOOT PROGRAMS" 
write-host ($Programs | format-list| out-string) 


##########################################################
#scheduled tasks 
$Tasks = Get-Scheduledtask | where {$_.State -eq 'Ready'} | ft TaskName

write-host "SCHEDULED TASKS : "
write-host ($Tasks| fl| out-string)


##########################################################
#Network information 
$arptable = arp -a 
$macaddress = getmac 
$route = Get-NetRoute
$IP = Get-NetIPAddress | ft IPAddress, InterfaceAlias
$dhcp = Get-WmiObject Win32_NetworkAdapterConfiguration | ? {$_.DHCPEnabled -eq $true -and $_.DHCPServer -ne $null} | select DHCPServer
$DNSservers = Get-DnsClientServerAddress | select-object -ExpandProperty Serveraddresses
$gatewayIPv4 = Get-NetIPConfiguration | % IPv4defaultgateway | fl nexthop
$gatewayIPv6 = Get-NetIPConfiguration | % IPv46defaultgateway | fl nexthop
$listeningports = Get-NetTCPConnection -State Listen | ft State, localport, ElemenetName, LocalAddress, RemoteAddress #listening ports
$tcpconnections = Get-NetTCPConnection | where {$_.State -ne "Listen"} | ft creationtime,LocalPort,LocalAddress,remoteaddress,owningprocess, state
$DNScache = Get-DnsClientCache | ft 
$nwshares = get-smbshare
$printers = Get-Printer
$wifi = netsh.exe wlan show profiles 

write-host "#########################################################"
write-host "NETWORK INFORMATION: "
write-host " " 
write-host "ARP table : " 
write-host ($arptable| format-list | out-string)

write-host " " 
write-host "MAC Addresses for all interface: " 
Write-host ($macaddress| fl| out-string)
write-host "Routing table: " 
write-host ($route| out-string) 
write-host "IP Addresses: "
write-host ($IP|fl|out-string)

write-host ($dhcp|ft| out-string)  

write-host "DNS Server addresses"
write-host "--------------------"
write-host ($DNSservers | ft| out-string)

write-host "GatewayIPv4:"
write-host ($gatewayIPv4 |fl| out-string)
write-host "GatewayIPv6:"
write-host ($gatewayIPv6 |fl| out-string)

write-host "Listening services:"
write-host ($listeningports | fl| out-string)

write-host "Established connections: " 
write-host ($tcpconnections | out-string)

write-host "DNS cache :" 

write-host ($DNScache | out-string)


write-host "Network Shares: " 
write-host ($nwshares | out-string)


write-host "Printers: "
write-host ($printers | out-string)  


write-host "Wifi Access profiles:" 
write-host ($wifi | fl | out-string) 

##########################################################
#Installed programs 
$prog = gwmi win32_product | ft

write-host "#########################################################"
write-host "INSTALLED PROGRAMS : "
write-host ($prog | fl | out-string)

##########################################################
#PROCESSES 
$processes = get-process | ft processname,id,path,owner

write-host "#########################################################"
write-host "RUNNING PROCESSES : "
write-host ($processes | Out-String)

write-host "Process Tree :" 
Function Show-ProcessTree
{
    Function Get-ProcessTree($proc,$depth=1)
    {
        $process | Where-Object {$_.ParentProcessId -eq $proc.ProcessID -and $_.ParentProcessId -ne 0} | ForEach-Object {
            "{0}|--{1} pid={2} ppid={3}" -f (" "*3*$depth),$_.Name,$_.ProcessID,$_.ParentProcessId
            Get-ProcessTree $_ (++$depth)
            $depth--
        }
    }

    $filter = {-not (Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue) -or $_.ParentProcessId -eq 0}
    $process = gwmi Win32_Process
    $top = $process | Where-Object $filter | Sort-Object ProcessID
    foreach ($proc in $top)
    {
        "{0} pid={1}" -f $proc.Name, $proc.ProcessID
        Get-ProcessTree $proc
    }
}

Show-ProcessTree
##########################################################
#DRIVER 

$driver = Get-WmiObject Win32_PnPSignedDriver| ft devicename, driverversion,installdate,location
write-host "#########################################################"
write-host "DRIVER INFORMATION : "
write-host($driver|ft|out-string)

##########################################################
#DOWNLOADS AND DOCUMENTS 

write-host "#########################################################"
write-host "DOWNLOADS AND DOCUMENTS : "


read-host "Press enter to exit"
}

