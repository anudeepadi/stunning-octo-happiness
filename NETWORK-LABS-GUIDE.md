# Network Analysis Labs - Complete Guide

## Table of Contents
1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Lab 1: Packet Crafting with Scapy](#lab-1-packet-crafting-with-scapy)
4. [Lab 2: Man-in-the-Middle Attacks](#lab-2-man-in-the-middle-attacks)
5. [Lab 3: Network Forensics CTF](#lab-3-network-forensics-ctf)
6. [Lab 4: Protocol Deep-Dive](#lab-4-protocol-deep-dive)
7. [Lab 5: Active Reconnaissance](#lab-5-active-reconnaissance)
8. [Lab 6: Traffic Generation](#lab-6-traffic-generation)
9. [Lab 7: Intrusion Detection](#lab-7-intrusion-detection)
10. [Lab 8: Wireless Concepts](#lab-8-wireless-concepts)
11. [Lab 9: Firewall & Defense](#lab-9-firewall--defense)
12. [Standalone Scapy Scripts](#standalone-scapy-scripts)
13. [PCAP Challenge Solutions](#pcap-challenge-solutions)
14. [Command Reference](#command-reference)

---

## Overview

This lab environment provides hands-on cybersecurity training focused on:
- **Network packet analysis** - Understanding what travels over the wire
- **Traffic interception** - MITM techniques in isolated environments
- **Protocol analysis** - Deep understanding of TCP/IP, HTTP, DNS, etc.
- **Forensics** - Extracting evidence from network captures
- **Defense** - Firewalls, IDS, and network monitoring

### Key Locations

| Component | Path |
|-----------|------|
| Web Dashboard | http://localhost/network-labs/ |
| Lab Web Files | /var/www/html/network-labs/ |
| Helper Scripts | /opt/network-labs/ |
| Scapy Tools | /opt/network-labs/scapy/ |
| PCAP Challenges | /var/www/html/network-labs/forensics-lab/pcaps/ |
| IDS Rules | /etc/snort/rules/local.rules |

### Prerequisites Check

```bash
# Verify Apache is running
sudo systemctl status apache2

# Verify all services
sudo systemctl start apache2
sudo systemctl start vsftpd  # Optional: for FTP labs

# Check MITM environment
sudo /opt/network-labs/mitm/setup-mitm-env.sh status

# Test web dashboard
curl -s http://localhost/network-labs/ | head -5
```

---

## Quick Start

### 1. Start the Environment
```bash
# Start web server
sudo systemctl start apache2

# Start MITM isolated network
sudo /opt/network-labs/mitm/setup-mitm-env.sh start

# Open dashboard
firefox http://localhost/network-labs/ &
```

### 2. Test Login Form (for packet capture practice)
```bash
# Terminal 1: Start packet capture
sudo tcpdump -i lo -w /tmp/login_capture.pcap port 80

# Terminal 2: Submit test credentials
curl -X POST http://localhost/network-labs/login.php \
    -d "username=admin&password=secret123"

# Terminal 1: Stop capture (Ctrl+C), then analyze
wireshark /tmp/login_capture.pcap &
```

### 3. Validate a PCAP Challenge Flag
```bash
python3 /opt/network-labs/forensics/pcap-validator.py 1 'FLAG{your_flag_here}'
```

---

## Lab 1: Packet Crafting with Scapy

### Concepts
**Scapy** is a Python library for crafting, sending, and analyzing network packets. It allows you to:
- Build packets layer by layer (Ethernet → IP → TCP → Payload)
- Send custom packets to test network behavior
- Sniff and analyze live traffic
- Create custom protocol implementations

### Key Concepts to Understand

#### The OSI/TCP-IP Stack
```
Layer 7: Application (HTTP, FTP, DNS)
Layer 4: Transport (TCP, UDP)
Layer 3: Network (IP, ICMP)
Layer 2: Data Link (Ethernet, ARP)
Layer 1: Physical (Cables, Signals)
```

#### Scapy Syntax
```python
# Layers are combined with /
packet = Ether()/IP(dst="target")/TCP(dport=80)

# Send at Layer 2 (includes Ethernet)
sendp(packet)

# Send at Layer 3 (IP and above)
send(packet)

# Send and receive
response = sr1(packet)  # Get one response
responses = sr(packet)  # Get all responses
```

### Practice Exercises

#### Exercise 1: Basic Packet Inspection
```python
# Start Scapy
sudo scapy

# Create and inspect an IP packet
>>> pkt = IP(dst="8.8.8.8")
>>> pkt.show()

# Create a TCP SYN packet
>>> syn = IP(dst="127.0.0.1")/TCP(dport=80, flags="S")
>>> syn.show()

# See raw bytes
>>> hexdump(syn)
```

#### Exercise 2: ICMP Ping
```python
>>> from scapy.all import *

# Create ICMP echo request
>>> ping = IP(dst="127.0.0.1")/ICMP()
>>> response = sr1(ping, timeout=2)
>>> response.show()
```

#### Exercise 3: TCP Three-Way Handshake
```python
# SYN
>>> syn = IP(dst="127.0.0.1")/TCP(dport=80, flags="S", seq=1000)
>>> syn_ack = sr1(syn, timeout=2)

# If server responds with SYN-ACK
>>> if syn_ack and syn_ack[TCP].flags == "SA":
...     # Send ACK
...     ack = IP(dst="127.0.0.1")/TCP(dport=80, flags="A",
...             seq=syn_ack.ack, ack=syn_ack.seq + 1)
...     send(ack)
```

#### Exercise 4: ARP Discovery
```python
# Discover hosts on local network
>>> ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"),
...                  timeout=2, verbose=False)
>>> for sent, received in ans:
...     print(f"{received.psrc} is at {received.hwsrc}")
```

### Standalone Scapy Scripts

Located at `/opt/network-labs/scapy/`:

```bash
# ARP Scanner - Discover live hosts
sudo python3 /opt/network-labs/scapy/arp_scanner.py -t 192.168.1.0/24

# Port Scanner - Find open ports
sudo python3 /opt/network-labs/scapy/port_scanner.py -t 127.0.0.1 -p 22,80,443

# Packet Sniffer - Capture live traffic
sudo python3 /opt/network-labs/scapy/packet_sniffer.py -i lo -f "tcp port 80"

# DNS Spoofer Demo (educational)
sudo python3 /opt/network-labs/scapy/dns_spoofer.py -i lo --spoof example.com=127.0.0.1
```

---

## Lab 2: Man-in-the-Middle Attacks

### Concepts

**Man-in-the-Middle (MITM)** attacks involve intercepting communication between two parties. The attacker positions themselves in the middle of the conversation.

#### Attack Types:
1. **ARP Spoofing** - Poison ARP caches to redirect traffic
2. **DNS Spoofing** - Return fake DNS responses
3. **SSL Stripping** - Downgrade HTTPS to HTTP
4. **Session Hijacking** - Steal session cookies

### The Isolated Lab Environment

The MITM lab uses Linux **network namespaces** to create an isolated network:

```
┌─────────────────────────────────────────────────────────┐
│                    Bridge (br-mitm)                      │
│                     10.0.0.254                           │
├─────────────┬──────────────┬────────────────────────────┤
│             │              │                            │
│    Victim   │   Attacker   │   Gateway                  │
│   10.0.0.2  │   10.0.0.3   │   10.0.0.1                 │
│  victim_ns  │  attacker_ns │   gateway_ns               │
└─────────────┴──────────────┴────────────────────────────┘
```

### Practice Exercises

#### Setup: Start the Environment
```bash
# Start MITM environment
sudo /opt/network-labs/mitm/setup-mitm-env.sh start

# Verify namespaces exist
ip netns list
```

#### Exercise 1: Basic Network Testing
```bash
# Enter victim namespace
sudo ip netns exec victim_ns bash

# From inside victim, ping gateway
ping -c 3 10.0.0.1

# Exit namespace
exit
```

#### Exercise 2: ARP Spoofing (Educational Demo)
```bash
# Terminal 1: Enter attacker namespace
sudo ip netns exec attacker_ns bash

# Enable IP forwarding (so traffic flows through)
echo 1 > /proc/sys/net/ipv4/ip_forward

# Start ARP spoofing (tell victim we are the gateway)
arpspoof -i veth-atk -t 10.0.0.2 10.0.0.1

# Terminal 2: Enter victim namespace and check ARP cache
sudo ip netns exec victim_ns bash
arp -a  # Gateway MAC should show attacker's MAC
```

#### Exercise 3: Traffic Capture During MITM
```bash
# Terminal 1 (Attacker): Capture intercepted traffic
sudo ip netns exec attacker_ns tcpdump -i veth-atk -w /tmp/mitm_capture.pcap

# Terminal 2 (Victim): Generate traffic
sudo ip netns exec victim_ns curl http://10.0.0.1/

# Analyze capture
wireshark /tmp/mitm_capture.pcap &
```

#### Cleanup
```bash
sudo /opt/network-labs/mitm/setup-mitm-env.sh stop
```

### Key Tools
| Tool | Purpose |
|------|---------|
| arpspoof | ARP cache poisoning |
| ettercap | Multi-purpose MITM framework |
| mitmproxy | HTTP/HTTPS proxy for interception |
| dsniff | Collection of network auditing tools |
| sslstrip | Downgrade HTTPS connections |

---

## Lab 3: Network Forensics CTF

### Concepts

**Network forensics** involves analyzing captured network traffic to:
- Reconstruct events and timelines
- Extract transferred files
- Identify malicious activity
- Find hidden data (data exfiltration, tunneling)

### Tools for PCAP Analysis

| Tool | Use Case |
|------|----------|
| Wireshark | GUI packet analyzer |
| tshark | Command-line Wireshark |
| tcpdump | Capture and basic analysis |
| zeek (bro) | Generate structured logs |
| NetworkMiner | Windows forensics tool |

### Challenge Files Location
```
/var/www/html/network-labs/forensics-lab/pcaps/
├── challenge1_password.pcap  # Password exfiltration
├── challenge2_c2beacon.pcap  # C2 beacon detection
├── challenge3_ftp.pcap       # FTP file recovery
├── challenge4_dns_tunnel.pcap # DNS tunneling
├── challenge5_http.pcap      # HTTP session analysis
├── challenge6_icmp_tunnel.pcap # ICMP data hiding
├── challenge7_smb.pcap       # SMB enumeration
└── challenge8_telnet.pcap    # Telnet credentials
```

### Practice Exercises

#### Exercise 1: Basic Wireshark Navigation
```bash
# Open a challenge file
wireshark /var/www/html/network-labs/forensics-lab/pcaps/challenge1_password.pcap &
```

**Wireshark Tips:**
- `Ctrl+F` - Find packet
- Right-click → Follow → TCP/HTTP Stream
- Statistics → Conversations (see all connections)
- Statistics → Protocol Hierarchy (traffic breakdown)
- File → Export Objects → HTTP (extract files)

#### Exercise 2: Tshark One-Liners
```bash
PCAP="/var/www/html/network-labs/forensics-lab/pcaps/challenge1_password.pcap"

# List all IP conversations
tshark -r $PCAP -q -z conv,ip

# Extract HTTP data
tshark -r $PCAP -Y "http" -T fields -e http.request.uri -e http.file_data

# Find DNS queries
tshark -r $PCAP -Y "dns.flags.response == 0" -T fields -e dns.qry.name

# Extract credentials from POST
tshark -r $PCAP -Y "http.request.method == POST" -T fields -e http.file_data
```

#### Exercise 3: Zeek Log Generation
```bash
cd /tmp
zeek -r /var/www/html/network-labs/forensics-lab/pcaps/challenge2_c2beacon.pcap

# View generated logs
ls *.log
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p service
```

### Challenge Approach Guide

| Challenge | Analysis Technique |
|-----------|-------------------|
| Password | Follow HTTP stream, look for POST data |
| C2 Beacon | Check for periodic connections to suspicious IPs |
| FTP | Follow FTP data stream, extract files |
| DNS Tunnel | Look at DNS query names, decode subdomains |
| HTTP Session | Export HTTP objects, check headers |
| ICMP Tunnel | Examine ICMP payload data field |
| SMB | Filter SMB2, look for Tree Connect |
| Telnet | Follow TCP stream on port 23 |

### Flag Validation
```bash
# Validate your answer
python3 /opt/network-labs/forensics/pcap-validator.py <challenge_num> 'FLAG{...}'

# Example
python3 /opt/network-labs/forensics/pcap-validator.py 1 'FLAG{p4ssw0rd_3xf1ltr4t10n_d3t3ct3d}'
```

---

## Lab 4: Protocol Deep-Dive

### Concepts

Understanding protocols at a packet level is fundamental to network security.

### TCP Three-Way Handshake
```
Client                    Server
  |                          |
  |------ SYN (seq=x) ------>|
  |                          |
  |<-- SYN-ACK (ack=x+1) ----|
  |                          |
  |------ ACK (ack=y+1) ---->|
  |                          |
  [Connection Established]
```

### Common Wireshark Filters

```
# TCP filters
tcp.flags.syn == 1 && tcp.flags.ack == 0  # SYN only (new connections)
tcp.flags.rst == 1                         # Reset packets
tcp.analysis.retransmission               # Retransmissions

# HTTP filters
http.request.method == "GET"
http.request.method == "POST"
http.response.code == 200
http.host contains "example"

# DNS filters
dns.flags.response == 0                   # Queries only
dns.flags.response == 1                   # Responses only
dns.qry.name contains "suspicious"

# ARP filters
arp.opcode == 1                           # ARP requests
arp.opcode == 2                           # ARP replies
```

### Practice Exercises

#### Exercise 1: Capture and Analyze a TCP Handshake
```bash
# Terminal 1: Capture
sudo tcpdump -i lo -w /tmp/handshake.pcap port 80

# Terminal 2: Generate connection
curl http://localhost/network-labs/

# Analyze
tshark -r /tmp/handshake.pcap -Y "tcp.flags.syn==1"
```

#### Exercise 2: DNS Resolution Analysis
```bash
# Capture DNS traffic
sudo tcpdump -i any -w /tmp/dns.pcap udp port 53 &

# Generate DNS queries
nslookup google.com
dig facebook.com
host github.com

# Stop capture and analyze
kill %1
tshark -r /tmp/dns.pcap -Y "dns" -T fields -e dns.qry.name -e dns.a
```

#### Exercise 3: HTTP vs HTTPS
```bash
# Capture HTTP (cleartext)
sudo tcpdump -i any -w /tmp/http.pcap port 80 &
curl http://localhost/network-labs/
kill %1

# Analyze - you can see content
strings /tmp/http.pcap | grep -i html

# HTTPS would show encrypted data only
```

---

## Lab 5: Active Reconnaissance

### Concepts

**Reconnaissance** is the information-gathering phase of penetration testing:
- **Passive**: No direct interaction (OSINT, DNS lookups)
- **Active**: Direct interaction (port scanning, banner grabbing)

### Practice Exercises

#### Exercise 1: Port Scanning with Nmap
```bash
# Basic TCP scan
nmap -sT 127.0.0.1

# SYN scan (stealthier, requires root)
sudo nmap -sS 127.0.0.1

# Version detection
sudo nmap -sV 127.0.0.1 -p 22,80,443

# OS fingerprinting
sudo nmap -O 127.0.0.1

# Aggressive scan (version + OS + scripts)
sudo nmap -A 127.0.0.1
```

#### Exercise 2: Banner Grabbing
```bash
# With netcat
nc -v 127.0.0.1 22    # SSH banner
nc -v 127.0.0.1 80    # Then type: HEAD / HTTP/1.0 + Enter twice

# With nmap
nmap -sV --script=banner 127.0.0.1

# With curl
curl -I http://localhost/network-labs/
```

#### Exercise 3: SNMP Enumeration
```bash
# If SNMP is running
snmpwalk -v2c -c public 127.0.0.1

# Get system info
snmpwalk -v2c -c public 127.0.0.1 system
```

#### Exercise 4: Custom Port Scanner (Scapy)
```bash
sudo python3 /opt/network-labs/scapy/port_scanner.py -t 127.0.0.1 -p 1-1000 --connect
```

---

## Lab 6: Traffic Generation

### Concepts

Generating controlled traffic helps you:
- Practice packet analysis
- Test IDS rules
- Understand protocol behavior
- Create training datasets

### Practice Exercises

#### Exercise 1: Use the Traffic Generator
```bash
# Generate all traffic types
sudo python3 /opt/network-labs/traffic/traffic-generator.py --all

# Specific traffic
sudo python3 /opt/network-labs/traffic/traffic-generator.py --http
sudo python3 /opt/network-labs/traffic/traffic-generator.py --dns
sudo python3 /opt/network-labs/traffic/traffic-generator.py --icmp
```

#### Exercise 2: Capture Your Own Traffic
```bash
# Terminal 1: Start capture
sudo tcpdump -i lo -w /tmp/my_traffic.pcap

# Terminal 2: Generate various traffic
curl http://localhost/network-labs/
ping -c 5 127.0.0.1
nslookup localhost

# Terminal 1: Stop (Ctrl+C) and analyze
wireshark /tmp/my_traffic.pcap &
```

#### Exercise 3: HTTP POST Credentials
```bash
# Terminal 1: Capture
sudo tcpdump -i lo -w /tmp/creds.pcap port 80

# Terminal 2: Submit test login
curl -X POST http://localhost/network-labs/login.php \
    -d "username=testuser&password=testpass123"

# Analyze - find credentials in cleartext
tshark -r /tmp/creds.pcap -Y "http.request.method==POST" -T fields -e http.file_data
```

---

## Lab 7: Intrusion Detection

### Concepts

**IDS (Intrusion Detection System)** monitors network traffic for suspicious activity:
- **Signature-based**: Matches known attack patterns
- **Anomaly-based**: Detects deviations from baseline
- **Snort/Suricata**: Popular open-source IDS tools

### Snort Rule Syntax
```
action protocol src_ip src_port -> dst_ip dst_port (options)

# Example: Detect SQL injection
alert tcp any any -> any 80 (msg:"SQL Injection Attempt";
    content:"' OR '1'='1"; nocase; sid:1000001; rev:1;)
```

### Practice Exercises

#### Exercise 1: View Lab IDS Rules
```bash
cat /etc/snort/rules/local.rules
```

#### Exercise 2: Test Snort with PCAP
```bash
# Run Snort against a PCAP file
sudo snort -A console -q -c /etc/snort/snort.conf \
    -r /var/www/html/network-labs/forensics-lab/pcaps/challenge1_password.pcap
```

#### Exercise 3: Write Custom Rules
```bash
# Add to /etc/snort/rules/local.rules
sudo nano /etc/snort/rules/local.rules

# Example rule to detect ICMP
alert icmp any any -> any any (msg:"ICMP Detected"; sid:1000010; rev:1;)

# Test with ping traffic
sudo tcpdump -i lo -w /tmp/icmp_test.pcap icmp &
ping -c 5 127.0.0.1
kill %1

sudo snort -A console -q -c /etc/snort/snort.conf -r /tmp/icmp_test.pcap
```

---

## Lab 8: Wireless Concepts

### Concepts

Wireless security involves:
- **WPA/WPA2 Handshake**: 4-way authentication process
- **Deauthentication**: Forcing clients to reconnect
- **PMKID Attack**: Newer attack requiring only one frame
- **Evil Twin**: Fake access point attacks

### WPA 4-Way Handshake
```
Client                          AP
  |                              |
  |<-------- ANonce -------------|  Message 1
  |                              |
  |--------- SNonce + MIC ------>|  Message 2
  |                              |
  |<-------- GTK + MIC ---------|  Message 3
  |                              |
  |--------- ACK -------------->|  Message 4
  |                              |
  [Encryption Keys Derived]
```

### Practice Exercises

#### Exercise 1: Analyze WPA Handshake Sample
```bash
# Open the sample capture
wireshark /var/www/html/network-labs/wireless-lab/captures/wpa_handshake.cap &

# Filter for EAPOL (handshake frames)
# Use filter: eapol
```

#### Exercise 2: Aircrack-ng Basics
```bash
# View capture info
aircrack-ng /var/www/html/network-labs/wireless-lab/captures/wpa_handshake.cap

# Attempt to crack (with wordlist)
aircrack-ng -w /usr/share/wordlists/rockyou.txt \
    /var/www/html/network-labs/wireless-lab/captures/wpa_handshake.cap
```

**Note**: Real wireless attacks require a compatible wireless adapter in monitor mode. This lab uses pre-captured samples for educational analysis.

---

## Lab 9: Firewall & Defense

### Concepts

**Defensive security** focuses on:
- **Firewalls**: Control traffic flow (iptables, nftables)
- **Log Analysis**: Detect attacks from logs
- **Network Monitoring**: Baseline and detect anomalies
- **Intrusion Prevention**: Active blocking

### IPTables Basics

```bash
# Chains: INPUT, OUTPUT, FORWARD
# Targets: ACCEPT, DROP, REJECT, LOG

# View current rules
sudo iptables -L -n -v

# Allow SSH
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Block specific IP
sudo iptables -A INPUT -s 192.168.1.100 -j DROP

# Allow established connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Log dropped packets
sudo iptables -A INPUT -j LOG --log-prefix "DROPPED: "

# Default deny
sudo iptables -P INPUT DROP
```

### Practice Exercises

#### Exercise 1: Basic Firewall Rules
```bash
# Save current rules
sudo iptables-save > /tmp/iptables_backup

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow established
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTP
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# Drop everything else
sudo iptables -A INPUT -j DROP

# Test
curl http://localhost/network-labs/  # Should work
nc -v localhost 23                    # Should be blocked

# Restore
sudo iptables-restore < /tmp/iptables_backup
```

#### Exercise 2: Rate Limiting SSH
```bash
# Limit SSH connections (prevent brute force)
sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW \
    -m recent --set --name SSH

sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW \
    -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP
```

#### Exercise 3: Log Analysis
```bash
# View SSH authentication attempts
sudo grep "sshd" /var/log/auth.log | tail -20

# Find failed logins
sudo grep "Failed password" /var/log/auth.log

# Apache access analysis
sudo cat /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | sort -rn
```

#### Exercise 4: Network Monitoring
```bash
# Show all connections
ss -tunapl

# Watch network connections
watch -n 1 'ss -tun'

# Network statistics
netstat -s

# Monitor with tcpdump
sudo tcpdump -i any -n
```

---

## Standalone Scapy Scripts

### ARP Scanner
```bash
# Scan local network for hosts
sudo python3 /opt/network-labs/scapy/arp_scanner.py -t 192.168.1.0/24

# Save results
sudo python3 /opt/network-labs/scapy/arp_scanner.py -t 10.0.0.0/24 -o hosts.txt
```

### Port Scanner
```bash
# Quick connect scan
python3 /opt/network-labs/scapy/port_scanner.py -t 127.0.0.1 -p 1-1000 --connect

# SYN scan (requires root)
sudo python3 /opt/network-labs/scapy/port_scanner.py -t 127.0.0.1 -p 22,80,443 --syn

# With banner grabbing
python3 /opt/network-labs/scapy/port_scanner.py -t 127.0.0.1 -p 22,80 --connect --banner
```

### Packet Sniffer
```bash
# Basic capture
sudo python3 /opt/network-labs/scapy/packet_sniffer.py -i lo

# With filter
sudo python3 /opt/network-labs/scapy/packet_sniffer.py -i lo -f "tcp port 80"

# Credential detection mode
sudo python3 /opt/network-labs/scapy/packet_sniffer.py -i lo --credentials

# Save to PCAP
sudo python3 /opt/network-labs/scapy/packet_sniffer.py -i lo -o /tmp/capture.pcap -c 100
```

### DNS Spoofer (Educational)
```bash
# Spoof example.com to localhost
sudo python3 /opt/network-labs/scapy/dns_spoofer.py -i lo --spoof example.com=127.0.0.1

# Test in another terminal
dig @127.0.0.1 example.com
```

---

## PCAP Challenge Solutions

### Challenge 1: Password Exfiltration
**Flag**: `FLAG{p4ssw0rd_3xf1ltr4t10n_d3t3ct3d}`

**Method**:
1. Open in Wireshark
2. Filter: `http.request.method == POST`
3. Follow HTTP Stream
4. Look for form data with username/password

```bash
tshark -r challenge1_password.pcap -Y "http.request.method==POST" -T fields -e http.file_data
```

### Challenge 2: C2 Beacon
**Flag**: `FLAG{c2_b34c0n_1d3nt1f13d_443}`

**Method**:
1. Look for periodic connections
2. Check destination IPs and ports
3. The beacon pattern reveals the flag

```bash
tshark -r challenge2_c2beacon.pcap -q -z conv,ip
```

### Challenge 3: FTP File Recovery
**Flag**: `FLAG{ftp_f1l3_r3c0v3r3d_s3cr3t}`

**Method**:
1. Filter: `ftp-data`
2. Follow TCP Stream on data channel
3. Extract the transferred file content

### Challenge 4: DNS Tunneling
**Flag**: `FLAG{dns_tunn3l_d4t4_3xtr4ct3d}`

**Method**:
1. Filter: `dns`
2. Look at unusually long subdomain queries
3. Decode base64/hex in subdomain names

```bash
tshark -r challenge4_dns_tunnel.pcap -Y "dns.qry.name" -T fields -e dns.qry.name
```

### Challenge 5: HTTP Session
**Flag**: `FLAG{http_s3ss10n_r3c0nstruct3d}`

**Method**:
1. File → Export Objects → HTTP
2. Or follow HTTP stream
3. Check response headers and body

### Challenge 6: ICMP Tunneling
**Flag**: `FLAG{1cmp_tunn3l_d4t4_h1dd3n}`

**Method**:
1. Filter: `icmp`
2. Look at the Data field in ICMP packets
3. The payload contains hidden data (may be base64)

```bash
tshark -r challenge6_icmp_tunnel.pcap -Y "icmp" -T fields -e data.data
```

### Challenge 7: SMB Enumeration
**Flag**: `FLAG{smb_sh4r3_3num3r4t3d}`

**Method**:
1. Filter: `smb2`
2. Look for Tree Connect requests
3. Share names contain the flag

### Challenge 8: Telnet Session
**Flag**: `FLAG{t3ln3t_cr3ds_c4ptur3d}`

**Method**:
1. Filter: `telnet` or `tcp.port == 23`
2. Follow TCP Stream
3. Credentials are in cleartext

---

## Command Reference

### Packet Capture
```bash
# tcpdump
sudo tcpdump -i eth0                    # Capture on interface
sudo tcpdump -i any -w file.pcap        # Save to file
sudo tcpdump -r file.pcap               # Read from file
sudo tcpdump host 192.168.1.1           # Filter by host
sudo tcpdump port 80                    # Filter by port
sudo tcpdump -A                         # ASCII output
sudo tcpdump -X                         # Hex + ASCII

# tshark
tshark -i eth0                          # Capture
tshark -r file.pcap                     # Read file
tshark -Y "http"                        # Display filter
tshark -T fields -e ip.src -e ip.dst    # Extract fields
tshark -q -z conv,ip                    # Statistics
```

### Network Analysis
```bash
# nmap
nmap -sS 192.168.1.1                    # SYN scan
nmap -sV 192.168.1.1                    # Version detection
nmap -O 192.168.1.1                     # OS detection
nmap -p- 192.168.1.1                    # All ports
nmap --script vuln 192.168.1.1          # Vulnerability scan

# netcat
nc -v host port                         # Connect
nc -l -p port                           # Listen
nc -z host 1-1000                       # Port scan
```

### Wireless
```bash
# aircrack-ng suite
airmon-ng start wlan0                   # Monitor mode
airodump-ng wlan0mon                    # Scan networks
airodump-ng -c 6 --bssid XX:XX -w cap wlan0mon  # Capture
aircrack-ng -w wordlist cap.cap         # Crack
```

### Firewall
```bash
# iptables
iptables -L -n -v                       # List rules
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -s IP -j DROP
iptables -F                             # Flush rules
iptables-save > backup                  # Save
iptables-restore < backup               # Restore
```

---

## Troubleshooting

### Apache Not Running
```bash
sudo systemctl start apache2
sudo systemctl status apache2
```

### MITM Environment Issues
```bash
# Stop and restart
sudo /opt/network-labs/mitm/setup-mitm-env.sh stop
sudo /opt/network-labs/mitm/setup-mitm-env.sh start
```

### Permission Denied
```bash
# Most network tools require root
sudo <command>
```

### Wireshark Can't Capture
```bash
# Add user to wireshark group
sudo usermod -aG wireshark $USER
# Then logout/login
```

---

## Next Steps

1. **Complete all 8 PCAP challenges** - Practice forensic analysis
2. **Build custom Scapy scripts** - Extend the provided tools
3. **Write IDS rules** - Detect the attacks you've learned
4. **Set up a home lab** - Use VMs for more realistic practice
5. **Try CTF competitions** - PicoCTF, HackTheBox, TryHackMe

---

## Resources

- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [Snort Rules Documentation](https://www.snort.org/documents)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

*Generated for Network Analysis Labs - Educational Use Only*
