# Parameters
Param (
    [Parameter(Mandatory = $False, HelpMessage = "Specify the path for the file with IP's to be parsed")]
    [string]$IPFilePath = "",
    [Parameter(Mandatory = $False, HelpMessage = "Specify if to run the port scan on the generated DomRec-IPS")]
    [switch]$IPPortScan,
    [Parameter(Mandatory = $False, HelpMessage = "Specify how many port scans to run simultaneously, default is 5")]
    [int]$ConcurrentScans = 5
)

# Constants
$IPV4Regex = [regex] "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"

# Creating all Folders and Files
if (!(Test-Path "$PSScriptRoot/DomRec")) { New-Item -Path "$PSScriptRoot" -Name "DomRec" -ItemType "directory" }
if (!(Test-Path "$PSScriptRoot/DomRec/Data")) { New-Item -Path "$PSScriptRoot/DomRec" -Name "Data" -ItemType "directory" }
if (!(Test-Path "$PSScriptRoot/DomRec/Scanned Hosts")) { New-Item -Path "$PSScriptRoot/DomRec" -Name "Scanned Hosts" -ItemType "directory" }

# Creating the config file for the unWinter protocol
#if (!(Test-Path "$PSScriptRoot/DomRec/Data/unWinter.txt")) { 
#    $CONFIG = "SkipIPResolver=No"
#    $CONFIG += "SkipIPPortScan=No"
#    New-Item -Path "$PSScriptRoot/DomRec/Data" -Name "unWinter.txt" -ItemType "file" -Value $CONFIG
#}

# Outputting all ip addresses to DomRec-IPS.txt
if ($IPFilePath -ne "") {
    $IPS = (Get-Content -Path $IPFilePath) -split (" ")
    if (Test-Path "$PSScriptRoot/DomRec/Data/DomRec-IPS.txt") { Remove-Item "$PSScriptRoot/DomRec/Data/DomRec-IPS.txt" }
    For ( $i = 0; $i -lt $IPS.length ; $i++ )
    { ((Select-String -InputObject $IPS[$i] -Pattern $IPV4Regex).Matches.groups).Value | Out-File -Append "$PSScriptRoot/DomRec/Data/DomRec-IPS.txt" }
}

# Scanning all IPS
if ($IPPortScan.IsPresent) {
    if (!(Test-Path "$PSScriptRoot/DomRec/Data/UnfinishedPortScans.txt")) { New-Item -Path "$PSScriptRoot/DomRec/Data" -Name "UnfinishedPortScans.txt" -ItemTye "file" }
    $IPS = (Get-Content -Path "$PSScriptRoot/DomRec/Data/DomRec-IPS.txt") -split ("\n")
    $UnfinishedPortScans = (Get-Content -Path "$PSScriptRoot/DomRec/Data/UnfinishedPortScans.txt") -split ("\n")

    $IPCounter = 0
    while (!($UnfinishedPortScans.Contains($IPS[$IPCounter])) -and ($UnfinishedPortScans -ne "")) 
    { $IPCounter++ }

    while (($UnfinishedPortScans -split ("\n")).count -lt $ConcurrentScans) { 
        $IPCounter++
        if (!($UnfinishedPortScans.Contains($IPS[$IPCounter])))
        { Out-File -FilePath "$PSScriptRoot/DomRec/Data/UnfinishedPortScans.txt" -InputObject $IPS[$IPCounter] -Append }
    }
    $IPCounter++
    $UnfinishedPortScans = (Get-Content -Path "$PSScriptRoot/DomRec/Data/UnfinishedPortScans.txt") -split ("\n")

    $UnfinishedPortScansIndex = 0
    while ($UnfinishedPortScans -ne "") {
        if ((Get-Job).count -lt $ConcurrentScans)
        { Start-Job -Name $UnfinishedPortScans[$UnfinishedPortScansIndex] { nmap.exe -A -p- -v --min-rate 10000000 $IPS [$i] > "PSScriptRoot/DomRec/Scanned Hosts/$UnfinishedPortScans[$UnfinishedPortScansIndex].txt" } }

        else {
            while ((Get-Job).count -eq $ConcurrentScans) { 
                Start-Sleep(10)
                if ((Get-Job -State "Completed").count -gt 0) {
                    $CompletedScanIP = ((Get-Job -State "Completed")[0]).Name
                    Remove-Job -Name $CompletedScanIP
                    #Get-Content -Path "$PSScriptRoot/DomRec/Data/UnfinishedPortScans.txt" | -replace $CompletedScanIP, "" | Out-File -FilePath "$PSScriptRoot/DomRec/Data/UnfinishedPortScans.txt"
                    #$UnfinishedPortScans.Replace($CompletedScanIP, "")
                }
            }
            Start-Job -Name $IPS[$i] { nmap.exe -A -p- -v --min-rate 10000000 $IPS[$i] > "PSScriptRoot/DomRec/Scanned Hosts/$UnfinishedPortScans[$UnfinishedPortScansIndex].txt" }
        }
        $UnfinishedPortScansIndex++
    }

    For ( ; $IPCounter -lt $IPS.length ; $IPCounter++ ) {
        if ((Get-Job).count -lt $ConcurrentScans) {
            Start-Job -Name $IPS[$i] { nmap.exe -A -p- -v --min-rate 10000000 $IPS[$i] > "PSScriptRoot/DomRec/Scanned Hosts/$IPS[$i].txt" }
            Out-File -FilePath "$PSScriptRoot/DomRec/Data/UnfinishedPortScans.txt" -InputObject $IPS[$IPCounter] -Append
        }

        else {
            while ((Get-Job).count -eq $ConcurrentScans) { 
                Start-Sleep(10)
                if ((Get-Job -State Completed).count -gt 0) {
                    $CompletedScanIP = ((Get-Job -State Completed)[0]).Name
                    Remove-Job -Name $CompletedScanIP
                    #Get-Content -Path "$PSScriptRoot/DomRec/Data/UnfinishedPortScans.txt" | -replace $CompletedScanIP, "" | Out-File -FilePath "$PSScriptRoot/DomRec/Data/UnfinishedPortScans.txt"
                }
            }
            Start-Job -Name $IPS[$i] { nmap.exe -A -p- -v --min-rate 10000000 $IPS[$i] > "PSScriptRoot/DomRec/Scanned Hosts/$IPS[$i].txt" }
            Out-File -FilePath "$PSScriptRoot/DomRec/Data/UnfinishedPortScans.txt" -InputObject $IPS[$IPCounter] -Append
        }
    }
    Get-Job | Wait-Job

}