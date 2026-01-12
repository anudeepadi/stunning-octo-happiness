# CyberLab - Comprehensive Cybersecurity Learning Platform

A complete, hands-on cybersecurity learning environment with 50+ labs, Docker-based vulnerable systems, and a modern black/white UI.

```
  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██╗      █████╗ ██████╗
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██║     ██╔══██╗██╔══██╗
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║     ███████║██████╔╝
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║     ██╔══██║██╔══██╗
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████╗██║  ██║██████╔╝
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝
```

## Features

- **Modern UI** - Black/white minimalist dashboard built with React + Tailwind
- **50+ Hands-on Labs** - From beginner to advanced
- **Docker-based Targets** - DVWA, Juice Shop, WebGoat, Metasploitable2, and more
- **Isolated Environment** - All attacks stay contained
- **Progress Tracking** - Track your learning journey
- **CTF Challenges** - 60+ flags to capture

## Quick Start

### Prerequisites

- Kali Linux (VM or bare metal)
- 8GB+ RAM recommended
- 50GB+ free disk space

### Installation

```bash
# Clone or copy to your Kali machine
cd /path/to/learning

# Run the master setup script
sudo ./setup/master-setup.sh

# Wait for installation (10-20 minutes)
# All Docker images will be pulled and configured
```

### Start Learning

```bash
# Start all services
./tools/scripts/start-all.sh

# Open dashboard
firefox http://localhost/cyberlab/
```

## Target Systems

| Service | Port | Credentials | Purpose |
|---------|------|-------------|---------|
| **DVWA** | 8081 | admin:password | Web vulnerabilities (beginner) |
| **Juice Shop** | 8082 | - | Modern OWASP challenges |
| **WebGoat** | 8083 | - | Guided web security |
| **bWAPP** | 8084 | bee:bug | 100+ web vulnerabilities |
| **Mutillidae** | 8085 | - | OWASP testing |
| **MySQL** | 3307 | admin:admin123 | SQL injection practice |
| **PostgreSQL** | 5433 | postgres:postgres | Database attacks |
| **Redis** | 6380 | (no auth) | Unauthorized access |
| **MongoDB** | 27018 | (no auth) | NoSQL injection |
| **SSH** | 2222 | admin:admin | Weak credentials |
| **FTP** | 2121 | anonymous | Directory traversal |
| **Buffer Overflow** | 9999 | - | Binary exploitation |

## Learning Modules

### Module 1: Foundations (Beginner)
- Linux basics, networking fundamentals

### Module 2: Network Analysis
- Scapy, MITM attacks, packet forensics, IDS, wireless

### Module 3: Web Application Security
- SQL Injection, XSS, CSRF, Command Injection, File Upload, XXE

### Module 4: System Exploitation
- Enumeration, Metasploit, shells, privilege escalation, buffer overflow

### Module 5: Cryptography
- Encoding, encryption, hash cracking, steganography

### Module 6: Wireless Security
- WPA attacks, deauth, evil twin (theory)

### Module 7: Active Directory
- Kerberoasting, pass-the-hash, golden ticket (theory + tools)

### Module 8: CTF Challenges
- 60+ challenges across all domains

## Directory Structure

```
learning/
├── docker/                 # Docker infrastructure
│   ├── docker-compose.yml  # Main orchestration
│   ├── web-apps/          # DVWA, bWAPP, etc.
│   ├── databases/         # Vulnerable databases
│   └── custom-services/   # SSH, FTP, buffer overflow
├── ui/                    # React dashboard
│   └── src/
├── curriculum/            # Lab documentation
│   ├── 01-foundations/
│   ├── 02-network-analysis/
│   ├── 03-web-security/
│   └── ...
├── setup/                 # Installation scripts
│   ├── master-setup.sh
│   └── verify-installation.sh
├── tools/                 # Utilities
│   ├── progress-tracker/
│   └── flag-validator/
├── network-lab-setup.sh   # Existing network labs
└── NETWORK-LABS-GUIDE.md  # Network labs documentation
```

## Commands

```bash
# Start all services
cd docker && docker-compose up -d

# Stop all services
docker-compose down

# Check status
docker ps

# View logs
docker-compose logs -f [service-name]

# Verify installation
./setup/verify-installation.sh

# Validate a flag
python3 tools/flag-validator/validator.py sql-injection-basic 'FLAG{...}'
```

## Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Host Machine (Kali)                       │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │             Docker Network: lab-network               │   │
│  │                  172.20.0.0/16                        │   │
│  │                                                       │   │
│  │   ┌─────────┐  ┌─────────┐  ┌─────────┐             │   │
│  │   │  DVWA   │  │ Juice   │  │ WebGoat │             │   │
│  │   │ :8081   │  │ :8082   │  │ :8083   │             │   │
│  │   └─────────┘  └─────────┘  └─────────┘             │   │
│  │                                                       │   │
│  │   ┌─────────┐  ┌─────────┐  ┌─────────┐             │   │
│  │   │ MySQL   │  │ Redis   │  │ MongoDB │             │   │
│  │   │ :3307   │  │ :6380   │  │ :27018  │             │   │
│  │   └─────────┘  └─────────┘  └─────────┘             │   │
│  │                                                       │   │
│  │   ┌──────────────┐  ┌───────────────────┐           │   │
│  │   │ Metasploitable│  │ Buffer Overflow  │           │   │
│  │   │    :various   │  │     :9999        │           │   │
│  │   └──────────────┘  └───────────────────┘           │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  Dashboard: http://localhost/cyberlab/                       │
└─────────────────────────────────────────────────────────────┘
```

## Tips

1. **Start with DVWA** - Best for beginners, set security to LOW
2. **Use Burp Suite** - Essential for web testing
3. **Read the guides** - Each lab has detailed walkthroughs
4. **Take notes** - Document your findings
5. **Try harder** - Don't look at solutions too quickly

## Troubleshooting

### Services won't start
```bash
# Check Docker status
sudo systemctl status docker

# Check container logs
docker-compose logs [service-name]
```

### Port conflicts
```bash
# Check what's using a port
sudo lsof -i :8081
```

### Reset everything
```bash
# Stop and remove all containers
docker-compose down -v

# Restart
docker-compose up -d
```

## Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [HackTricks](https://book.hacktricks.xyz/)
- [GTFOBins](https://gtfobins.github.io/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

## Disclaimer

This platform is for **educational purposes only**. All attacks must be performed within the isolated lab environment. Never attack systems without explicit authorization.

---

Happy Hacking! 🔓
