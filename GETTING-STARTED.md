# CyberLab - Getting Started Guide

## 🚀 Quick Start After Pulling

### Step 1: Pull the Latest Changes

```bash
cd /path/to/learning
git pull origin master
```

### Step 2: Install Dependencies (First Time Only)

If you haven't set up the environment yet:

```bash
# Install Node.js dependencies for the UI
cd ui
npm install
cd ..
```

### Step 3: Start All Services

You have **two options** for starting the environment:

#### Option A: Using the Quick Start Script (Recommended)

```bash
# Start Docker containers only
cd docker
docker-compose up -d

# Check status
docker ps
```

#### Option B: Using the Start-All Script

```bash
# Start everything including Apache (if available)
./tools/scripts/start-all.sh
```

### Step 4: Start the UI Dashboard

Open a new terminal window:

```bash
cd ui
npm run dev
```

The UI will start at: **http://localhost:5173**

### Step 5: Access Target Systems

All vulnerable applications are now running:

| Service | URL | Credentials |
|---------|-----|-------------|
| **CyberLab UI** | http://localhost:5173 | - |
| **DVWA** | http://localhost:8081 | admin:password |
| **Juice Shop** | http://localhost:8082 | - |
| **WebGoat** | http://localhost:8083 | - |
| **bWAPP** | http://localhost:8084 | bee:bug |
| **Mutillidae** | http://localhost:8085 | - |

---

## 📚 Complete Walkthrough

### Understanding the CyberLab Environment

CyberLab consists of **three main components**:

1. **Docker Containers** - Vulnerable applications and services
2. **UI Dashboard** - Modern React-based progress tracker
3. **Curriculum** - 50+ hands-on labs across 8 modules

---

## 🎯 Your First Lab

### Lab 1: Environment Verification

Let's verify everything is working correctly!

#### 1. Check Docker Containers

```bash
docker ps
```

You should see containers running:
- `lab-dvwa`
- `lab-juice-shop`
- `lab-webgoat`
- `lab-bwapp`
- `lab-mutillidae`
- `lab-mysql-vuln`
- `lab-postgres-vuln`
- `lab-redis-vuln`
- `lab-mongodb-vuln`
- `lab-vuln-ssh`
- `lab-vuln-ftp`
- `lab-buffer-overflow`

#### 2. Test DVWA (Your Main Target)

```bash
# Test connectivity
curl -I http://localhost:8081
```

Open in browser: http://localhost:8081

**First time setup:**
1. Click "Create / Reset Database"
2. Login with `admin:password`
3. Set Security Level to **LOW** (DVWA Security button)

#### 3. Access the UI Dashboard

Open http://localhost:5173 in your browser

You should see:
- **Dashboard** - Overview of all modules and your progress
- **Labs** - All 52 labs organized by module
- **Curriculum** - Full learning path with markdown content
- **Progress** - Track completed labs, tasks, and flags
- **Docker** - Manage containers from the UI

---

## 📖 Using the UI Dashboard

### Dashboard Page

The main dashboard shows:
- **Quick stats** - Total labs, your progress, flags captured
- **Module cards** - 8 modules with lab counts
- **Quick access** - Jump to any module

### Labs Page

Browse all 52 labs with:
- **Filters** - By category (web, network, system, crypto, ctf)
- **Difficulty badges** - Beginner, Intermediate, Advanced
- **Lab cards** - Click any lab to see details

### Lab Detail Page

Each lab shows:
- **Description** - What you'll learn
- **Objectives** - Learning goals
- **Tasks** - Step-by-step checklist with checkboxes
- **Tools** - Required tools for the lab
- **Target info** - Which system to attack
- **Flag submission** - Submit flags when found

**Track your progress:**
- ✅ Check off tasks as you complete them
- 🚩 Submit flags when you find them
- 📊 Your progress is saved automatically in browser localStorage

### Progress Page

Your learning dashboard:
- **Stats cards** - Labs completed, tasks done, flags captured, time invested
- **Export/Import buttons** - Backup your progress
- **Achievements** - Unlock badges as you progress
- **Recent activity** - See your last completed labs

**Export your progress:**
1. Click the "Export" button
2. Save `cyberlab-progress.json` file
3. Keep it as a backup or share with others

**Import progress:**
1. Click the "Import" button
2. Select your saved JSON file
3. Your progress is restored instantly

### Curriculum Page

Access the full learning materials:
- Browse all 8 modules
- Read markdown guides, walkthroughs, and theory
- Follow along with hands-on exercises

### Docker Page

Manage your lab environment:
- View all container statuses
- Start/stop individual containers
- See port mappings and IPs
- Quick access links to web interfaces

---

## 🗺️ Learning Path Recommendation

### Absolute Beginner? Start Here:

**Week 1-2: Module 01 - Foundations**
1. Lab: Linux Basics (2 hrs)
2. Lab: Command Line Mastery (2 hrs)
3. Lab: Networking Fundamentals (3 hrs)
4. Lab: Security Tools Intro (2 hrs)
5. Lab: Lab Environment Setup (1.5 hrs)

**Week 3-4: Module 03 - Web Security Basics**
1. Lab: SQL Injection Basics (45 min)
2. Lab: XSS Reflected (30 min)
3. Lab: Command Injection (45 min)

**Week 5: Practice & Reinforce**
- Repeat labs at higher difficulty levels in DVWA
- Try beginner CTF challenges

### Intermediate Path:

Start with Module 02 (Network Analysis) or Module 04 (System Exploitation)

### Advanced Path:

Jump to Module 06 (Wireless), Module 07 (Active Directory), or Module 08 (CTF Challenges)

---

## 🎓 Typical Lab Workflow

### Example: SQL Injection Lab

1. **Open the Lab in UI**
   - Go to Labs page → Filter "Web" → Click "SQL Injection - Basics"

2. **Read the Curriculum**
   - Click "Curriculum" tab → Module 03 → 01-sql-injection
   - Read README.md for concepts
   - Check hints.md if you get stuck

3. **Access the Target**
   - Open DVWA: http://localhost:8081
   - Navigate to SQL Injection page
   - Set security to LOW

4. **Follow the Tasks**
   - Task 1: ✅ Login to DVWA
   - Task 2: ✅ Set security level to LOW
   - Task 3: ✅ Navigate to SQL Injection
   - Task 4: ⬜ Try payload: `' OR '1'='1`
   - Task 5: ⬜ Extract usernames with UNION
   - Task 6: ⬜ Find admin password hash

5. **Capture the Flag**
   - When you find the flag, submit it in the lab page
   - Format: `FLAG{sql_1nj3ct10n_m4st3r}`

6. **Mark as Complete**
   - All tasks checked ✅
   - Flag submitted 🚩
   - Lab marked complete 🎉

---

## 🛠️ Common Commands

### Docker Management

```bash
# Start all containers
cd docker && docker-compose up -d

# Stop all containers
docker-compose down

# View logs
docker-compose logs -f [container-name]

# Restart a specific container
docker-compose restart dvwa

# Check container IPs
docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' lab-dvwa
```

### UI Development

```bash
# Start dev server (with hot reload)
cd ui && npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

### Progress Tracking

Your progress is stored in browser localStorage with key: `cyberlab-progress`

**View in browser console:**
```javascript
JSON.parse(localStorage.getItem('cyberlab-progress'))
```

---

## 🐛 Troubleshooting

### Docker Containers Won't Start

```bash
# Check if ports are already in use
sudo lsof -i :8081

# Remove old containers
docker-compose down -v
docker-compose up -d --force-recreate
```

### UI Shows "Cannot connect"

- Make sure you're using the correct URL: http://localhost:5173
- Check that `npm run dev` is running
- Try clearing browser cache

### DVWA Database Not Working

1. Open http://localhost:8081
2. Click "Setup / Reset Database"
3. Scroll down and click "Create / Reset Database"
4. Login again with admin:password

### Container Keeps Restarting

```bash
# Check logs for errors
docker logs lab-dvwa

# May need to rebuild
cd docker
docker-compose build dvwa
docker-compose up -d
```

### Progress Not Saving

- Check browser console for errors
- Progress is stored in localStorage (cleared if you clear browser data)
- Use Export feature regularly to backup progress

---

## 📊 Available Target Systems

### Web Applications (Module 03)

| Target | Port | Purpose | Difficulty |
|--------|------|---------|-----------|
| DVWA | 8081 | OWASP Top 10 practice | Beginner |
| Juice Shop | 8082 | Modern web vulnerabilities | Intermediate |
| WebGoat | 8083 | Guided tutorials | Beginner |
| bWAPP | 8084 | 100+ vulnerabilities | Beginner |
| Mutillidae | 8085 | OWASP training | Intermediate |

### Databases (Module 03)

| Target | Port | Purpose |
|--------|------|---------|
| MySQL | 3307 | SQL injection practice |
| PostgreSQL | 5433 | Database attacks |
| Redis | 6380 | Unauthorized access |
| MongoDB | 27018 | NoSQL injection |

### Services (Module 04)

| Target | Port | Purpose |
|--------|------|---------|
| SSH | 2222 | Weak credentials |
| FTP | 2121 | Anonymous access |
| Buffer Overflow | 9999 | Binary exploitation |

---

## 🎯 Next Steps

Now that you're set up:

1. ✅ **Verify all services are running**
   - `docker ps` shows all containers
   - UI is accessible at localhost:5173
   - DVWA is accessible at localhost:8081

2. 📚 **Start Module 01**
   - Read curriculum/01-foundations/README.md
   - Complete first lab: Linux Basics

3. 🎓 **Track Your Progress**
   - Use the UI to check off tasks
   - Submit flags when you find them
   - Export progress regularly

4. 🏆 **Set Goals**
   - Complete 1 module per week
   - Capture all flags in a category
   - Unlock all achievements

---

## 📞 Need Help?

- **Read the curriculum** - Each lab has detailed walkthroughs
- **Check hints.md** - Every lab has progressive hints
- **Review walkthrough.md** - Complete solutions available
- **Check GitHub issues** - Report bugs or ask questions

---

## 🔒 Important Security Notes

⚠️ **This environment contains intentionally vulnerable applications**

- **Only use in isolated lab environment**
- **Never expose to the internet**
- **Do not install on production systems**
- **All attacks must stay within your lab**

Docker containers are on isolated networks (172.20.0.0/16) for safety.

---

## 🎉 Happy Hacking!

You're all set! Start with Module 01 and work your way through the curriculum.

**Remember:**
- ✅ Check off tasks as you complete them
- 🚩 Submit flags when you find them
- 📊 Track your progress in the UI
- 💾 Export your progress regularly
- 🎓 Learn, practice, and have fun!

Good luck on your cybersecurity journey! 🚀🔐
