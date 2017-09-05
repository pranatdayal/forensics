<# 
.SYNOPSIS 

Powershell script for digital forensics and incident response on windows. 

.DESCRIPTION

Script collects various system artifacts that are useful for incident response and forensics. 
 

.OUTPUTS 

CSV format and email 
#> 

clear
$dateObj = New-Object PSObject # Date and time object 

$date = Get-Date #system date and time 
$timezone = Get-TimeZone #PC timezone
$PCUptime = (get-date) - (gcim Win32_OperatingSystem).LastBootUpTime #PC up time 

$dateObj | Add-Member Current_Date_Time $date 
$dateObj | Add-Member TimeZone $timezone
$dateObj | Add-Member PC_Uptime_hours $PCUptime

write-host "System Date and Time information: "
write-host ($dateObj | format-table | Out-String) 
#OS information 

$OSobj = New-Object PSObject #OS object

$TypicalName = gwmi win32_operatingsystem | % caption #Windows typical name 
$FullVer = [System.Environment]::OSVersion.Version  #Major, Minor, Build and revision

$OSobj | Add-Member TypicalName $TypicalName
$OSobj | Add-Member Major_Minor_Build_Revision $FullVer

write-host "OS information: " 
Write-host ($OSobj | Format-Table |  Out-String)

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



write-host "System Hardware information:"
write-host ($HardwareObj | format-table| out-string)

#Domain controller information 

$DomainObj = New-Object PSobject # new Domain controller object 

$DCIP = 
