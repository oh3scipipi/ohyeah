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

### Linux


Network Enumeration
ping $IP #63 ttl = linux #127 ttl = windows
nmap -p- --min-rate 1000 $IP
nmap -p- --min-rate 1000 $IP -Pn #disables the ping command and only scans ports
nmap -p <ports> -sV -sC -A $IP
Stealth Scan
nmap -sS -p- --min-rate=1000 10.11.1.229 -Pn #stealth scans
Rust Scan
target/release/rustscan -a 10.11.1.252
UDP Scan
sudo nmap -F -sU -sV $IP
Script to automate Network Enumeration
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
