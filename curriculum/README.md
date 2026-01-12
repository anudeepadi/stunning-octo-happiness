# CyberLab Curriculum

A comprehensive cybersecurity learning curriculum with 129+ labs across 8 modules.

## Learning Path

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│ Foundations │ → │   Network   │ → │    Web      │ → │   System    │
│  (Beginner) │   │  Analysis   │   │  Security   │   │ Exploitation│
└─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
       ↓                                                     ↓
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│    CTF      │ ← │   Active    │ ← │  Wireless   │ ← │ Cryptography│
│ Challenges  │   │  Directory  │   │  Security   │   │             │
└─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
```

## Modules Overview

| Module | Labs | Duration | Difficulty |
|--------|------|----------|------------|
| 01 - Foundations | 5 | 8 hrs | Beginner |
| 02 - Network Analysis | 9 | 12 hrs | Intermediate |
| 03 - Web Security | 16 | 20 hrs | Intermediate |
| 04 - System Exploitation | 15 | 25 hrs | Advanced |
| 05 - Cryptography | 10 | 12 hrs | Intermediate |
| 06 - Wireless Security | 8 | 10 hrs | Intermediate |
| 07 - Active Directory | 6 | 15 hrs | Advanced |
| 08 - CTF Challenges | 60+ | 40+ hrs | Mixed |

## Prerequisites

- Kali Linux VM (2GB+ RAM recommended)
- Docker and docker-compose installed
- Basic command line familiarity
- Network fundamentals understanding

## Getting Started

1. Run the setup script:
   ```bash
   sudo ./setup/master-setup.sh
   ```

2. Start Docker services:
   ```bash
   cd docker && docker-compose up -d
   ```

3. Open the dashboard:
   ```bash
   firefox http://localhost/cyberlab/
   ```

## Lab Format

Each lab follows this structure:

```
lab-name/
├── README.md        # Overview and introduction
├── objectives.md    # Learning objectives
├── walkthrough.md   # Step-by-step guide
├── hints.md         # Progressive hints
└── solutions.md     # Full solutions (spoiler warning!)
```

## Target Systems

| Target | Port | Purpose |
|--------|------|---------|
| DVWA | 8081 | Web vulnerabilities (beginner) |
| Juice Shop | 8082 | Modern web app challenges |
| WebGoat | 8083 | Guided web security lessons |
| MySQL | 3307 | SQL injection practice |
| Metasploitable2 | - | Full OS exploitation |
| Buffer Overflow | 9999 | Binary exploitation |

## CTF Flag Format

All flags follow the format: `FLAG{...}`

Example: `FLAG{sql_1nj3ct10n_m4st3r}`

## Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [GTFOBins](https://gtfobins.github.io/)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
