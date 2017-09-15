<#
#Author : Pranat Dayal 
#github: /pranatdayal/DFIR_pxd5104_CSEC475

.SYNOPSis 
Powershell script to parse $MFT csv dump from mft2csv.exe 

.DESCRIPTION 
Parse CSV from dump
● List all NTFS file streams
○ List file paths
○ List file names
○ List $SI timestamps
○ LIST $FN timestamps
● Dump the $DATA section of a particular file
○ Take filename in as input
○ List file paths
● Identify potential time stomping entries

.PARAMETER filename 
CSV file to parse through

.PARAMETER timestomp
switch that attempts to identify potential timestomping entries 
If timestomp did occur then we will be able to see a difference in the 
$MFT entry and in the $FILE_NAME.lastaccessedtime 

Right now it just prints out both timestamps and lets the user compare 
because the output of lastaccessedtime is in a different date format as 
$MFT. 

.PARAMETER dumpData
Dumps $DATA from a particular file 
still need to implement this 
#>

Param (
    [string]$filename,
    [switch]$timestomp

)

function parameter{
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True)]
    [string]$filename
)

if($timestomp=$true){
import-csv $filename '|' |
ForEach-Object{
    if($_.type="File Accessed")
    {
        $mftDate = $_.date
        $mftTime = $_.time

        $filepath = $_.desc
        $filetime = $(get-item $filepath).lastaccesstimeUTC

        write-host("If timestomping occured then these two values should be different")

        write-host ($mftDate + $mftTime)
        write-host($filetime)
    }

}

}
}
(Import-Csv $filename '|'|

ForEach-Object {
    write-host ("Filename :"+ $_.Filename| ft| out-string)
    write-host ("FilePath :"+ $_.desc| ft| out-string)
    if($_.short="FN1"-or"FN2"){
        write-host("FN Timestamp: "+ $_.time| ft| out-string)
    }
    if($_short="SI"){
        write-host("SI Timestamp: " + $_.time|ft|out-string)
    }
    write-host ************************************************
    
})




