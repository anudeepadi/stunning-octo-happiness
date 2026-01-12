export interface LabTask {
  id: string
  title: string
  hint?: string
}

export interface Lab {
  id: string
  name: string
  description: string
  category: 'web' | 'network' | 'system' | 'crypto' | 'ctf'
  difficulty: 'beginner' | 'intermediate' | 'advanced'
  duration: string
  target: string
  targetUrl?: string
  objectives: string[]
  tasks: LabTask[]
  tools: string[]
  tags: string[]
  flag?: string
}

export const labs: Lab[] = [
  // ============================================================================
  // WEB SECURITY LABS
  // ============================================================================
  {
    id: 'sql-injection-basic',
    name: 'SQL Injection - Basics',
    description: 'Learn fundamental SQL injection techniques to bypass authentication and extract data.',
    category: 'web',
    difficulty: 'beginner',
    duration: '45 min',
    target: 'DVWA',
    targetUrl: 'http://localhost:8081',
    objectives: [
      'Understand how SQL injection vulnerabilities occur',
      'Bypass login authentication using SQLi',
      'Extract data using UNION-based injection',
      'Identify SQLi vulnerable parameters',
    ],
    tasks: [
      { id: 'sqli-1', title: 'Login to DVWA with default credentials (admin:password)', hint: 'Check the DVWA documentation' },
      { id: 'sqli-2', title: 'Set security level to LOW', hint: 'Look in DVWA Security settings' },
      { id: 'sqli-3', title: 'Navigate to SQL Injection page' },
      { id: 'sqli-4', title: "Use ' OR '1'='1 to bypass authentication", hint: 'Classic SQLi payload' },
      { id: 'sqli-5', title: 'Extract all usernames from the database', hint: 'Use UNION SELECT' },
      { id: 'sqli-6', title: 'Find the admin password hash' },
    ],
    tools: ['Burp Suite', 'sqlmap', 'Browser DevTools'],
    tags: ['SQL Injection', 'OWASP', 'Authentication Bypass', 'DVWA'],
    flag: 'FLAG{sql_1nj3ct10n_m4st3r}',
  },
  {
    id: 'sql-injection-union',
    name: 'SQL Injection - UNION Based',
    description: 'Master UNION-based SQL injection to extract data from multiple tables.',
    category: 'web',
    difficulty: 'intermediate',
    duration: '1 hr',
    target: 'DVWA',
    targetUrl: 'http://localhost:8081',
    objectives: [
      'Determine the number of columns in a query',
      'Use UNION SELECT to combine result sets',
      'Extract data from information_schema',
      'Enumerate database structure',
    ],
    tasks: [
      { id: 'union-1', title: 'Find the number of columns using ORDER BY', hint: 'Increment until error' },
      { id: 'union-2', title: 'Confirm column count with UNION SELECT NULL,...' },
      { id: 'union-3', title: 'Extract database version', hint: '@@version or version()' },
      { id: 'union-4', title: 'List all databases' },
      { id: 'union-5', title: 'List all tables in current database' },
      { id: 'union-6', title: 'Extract data from users table' },
    ],
    tools: ['Burp Suite', 'sqlmap', 'HackBar'],
    tags: ['SQL Injection', 'UNION', 'Data Extraction', 'Database Enumeration'],
    flag: 'FLAG{un10n_b4s3d_pwn3d}',
  },
  {
    id: 'xss-reflected',
    name: 'XSS - Reflected Cross-Site Scripting',
    description: 'Learn to identify and exploit reflected XSS vulnerabilities.',
    category: 'web',
    difficulty: 'beginner',
    duration: '30 min',
    target: 'DVWA',
    targetUrl: 'http://localhost:8081',
    objectives: [
      'Understand how reflected XSS works',
      'Inject JavaScript into URL parameters',
      'Steal cookies via XSS',
      'Bypass basic XSS filters',
    ],
    tasks: [
      { id: 'xss-r-1', title: 'Navigate to XSS (Reflected) page' },
      { id: 'xss-r-2', title: 'Test basic <script>alert(1)</script> payload' },
      { id: 'xss-r-3', title: 'Extract cookies using document.cookie' },
      { id: 'xss-r-4', title: 'Try img tag with onerror handler', hint: '<img src=x onerror=...>' },
      { id: 'xss-r-5', title: 'Create a crafted URL that triggers XSS' },
    ],
    tools: ['Browser DevTools', 'Burp Suite'],
    tags: ['XSS', 'JavaScript', 'Cookie Theft', 'OWASP'],
    flag: 'FLAG{r3fl3ct3d_xss_pwn3d}',
  },
  {
    id: 'command-injection',
    name: 'Command Injection',
    description: 'Exploit command injection vulnerabilities to execute system commands.',
    category: 'web',
    difficulty: 'intermediate',
    duration: '45 min',
    target: 'DVWA',
    targetUrl: 'http://localhost:8081',
    objectives: [
      'Understand command injection vulnerabilities',
      'Chain commands using ; | && ||',
      'Read sensitive files',
      'Achieve remote code execution',
    ],
    tasks: [
      { id: 'cmdi-1', title: 'Navigate to Command Injection page' },
      { id: 'cmdi-2', title: 'Test basic ping command' },
      { id: 'cmdi-3', title: 'Inject ; to chain commands', hint: 'Try 127.0.0.1; whoami' },
      { id: 'cmdi-4', title: 'Read /etc/passwd file' },
      { id: 'cmdi-5', title: 'Try to get a reverse shell', hint: 'Use netcat or bash' },
    ],
    tools: ['netcat', 'Burp Suite', 'Terminal'],
    tags: ['Command Injection', 'RCE', 'System Commands', 'OWASP'],
    flag: 'FLAG{c0mm4nd_1nj3ct10n_pwn3d}',
  },

  // ============================================================================
  // NETWORK ANALYSIS LABS
  // ============================================================================
  {
    id: 'packet-crafting-scapy',
    name: 'Packet Crafting with Scapy',
    description: 'Build and analyze custom network packets using Python Scapy library.',
    category: 'network',
    difficulty: 'intermediate',
    duration: '1 hr',
    target: 'localhost',
    objectives: [
      'Understand TCP/IP packet structure',
      'Build packets layer by layer',
      'Send and receive custom packets',
      'Analyze packet responses',
    ],
    tasks: [
      { id: 'scapy-1', title: 'Start Scapy as root' },
      { id: 'scapy-2', title: 'Create and inspect an IP packet' },
      { id: 'scapy-3', title: 'Build a TCP SYN packet' },
      { id: 'scapy-4', title: 'Perform a TCP SYN scan on port 80' },
      { id: 'scapy-5', title: 'Craft an ICMP echo request' },
      { id: 'scapy-6', title: 'Sniff packets on loopback interface' },
    ],
    tools: ['Scapy', 'Python3', 'Wireshark'],
    tags: ['Scapy', 'Packet Crafting', 'TCP/IP', 'Network Analysis'],
  },
  {
    id: 'network-forensics-ctf',
    name: 'Network Forensics CTF',
    description: 'Analyze PCAP files to find hidden flags and evidence.',
    category: 'network',
    difficulty: 'intermediate',
    duration: '1.5 hrs',
    target: 'PCAP Files',
    objectives: [
      'Analyze network captures with Wireshark',
      'Extract credentials from traffic',
      'Reconstruct transferred files',
      'Identify suspicious traffic patterns',
    ],
    tasks: [
      { id: 'forensics-1', title: 'Open challenge1_password.pcap' },
      { id: 'forensics-2', title: 'Find exfiltrated password in HTTP traffic' },
      { id: 'forensics-3', title: 'Analyze DNS tunneling in challenge4_dns_tunnel.pcap' },
      { id: 'forensics-4', title: 'Extract file from FTP traffic' },
      { id: 'forensics-5', title: 'Identify C2 beacon patterns' },
    ],
    tools: ['Wireshark', 'tshark', 'tcpdump', 'NetworkMiner'],
    tags: ['Forensics', 'PCAP', 'Wireshark', 'Traffic Analysis'],
    flag: 'FLAG{p4ck3t_f0r3ns1cs_m4st3r}',
  },
  {
    id: 'mitm-attacks',
    name: 'Man-in-the-Middle Attacks',
    description: 'Learn ARP spoofing and traffic interception in isolated networks.',
    category: 'network',
    difficulty: 'advanced',
    duration: '1.5 hrs',
    target: 'Network Namespace',
    objectives: [
      'Understand ARP protocol and poisoning',
      'Set up MITM position using ARP spoofing',
      'Intercept and analyze traffic',
      'Modify packets in transit',
    ],
    tasks: [
      { id: 'mitm-1', title: 'Start the isolated MITM lab environment' },
      { id: 'mitm-2', title: 'Scan the network to identify hosts' },
      { id: 'mitm-3', title: 'Perform ARP spoofing with ettercap' },
      { id: 'mitm-4', title: 'Capture credentials in transit' },
      { id: 'mitm-5', title: 'DNS spoof a target domain' },
    ],
    tools: ['ettercap', 'arpspoof', 'mitmproxy', 'Wireshark'],
    tags: ['MITM', 'ARP Spoofing', 'Traffic Interception', 'Network'],
  },

  // ============================================================================
  // SYSTEM EXPLOITATION LABS
  // ============================================================================
  {
    id: 'buffer-overflow-basics',
    name: 'Buffer Overflow - Stack Smashing',
    description: 'Exploit stack-based buffer overflows to control program execution.',
    category: 'system',
    difficulty: 'advanced',
    duration: '2 hrs',
    target: 'Custom Server',
    targetUrl: 'nc localhost 9999',
    objectives: [
      'Understand stack memory layout',
      'Find buffer overflow offset',
      'Overwrite return address',
      'Execute shellcode or call functions',
    ],
    tasks: [
      { id: 'bof-1', title: 'Connect to vulnerable server on port 9999' },
      { id: 'bof-2', title: 'Identify the buffer size (64 bytes)' },
      { id: 'bof-3', title: "Find offset to overwrite RIP using pattern_create" },
      { id: 'bof-4', title: 'Note the address of secret_function' },
      { id: 'bof-5', title: 'Craft payload to call secret_function' },
      { id: 'bof-6', title: 'Capture the flag!' },
    ],
    tools: ['gdb', 'pwntools', 'Python', 'netcat'],
    tags: ['Buffer Overflow', 'Binary Exploitation', 'Stack', 'Memory Corruption'],
    flag: 'FLAG{buff3r_0v3rfl0w_m4st3r}',
  },
  {
    id: 'linux-privesc-suid',
    name: 'Linux PrivEsc - SUID Binaries',
    description: 'Escalate privileges by exploiting misconfigured SUID binaries.',
    category: 'system',
    difficulty: 'intermediate',
    duration: '1 hr',
    target: 'Metasploitable2',
    objectives: [
      'Understand SUID permission bit',
      'Find SUID binaries on system',
      'Exploit common SUID misconfigurations',
      'Escalate to root privileges',
    ],
    tasks: [
      { id: 'suid-1', title: 'Find all SUID binaries: find / -perm -4000 2>/dev/null' },
      { id: 'suid-2', title: 'Check GTFOBins for exploitable binaries' },
      { id: 'suid-3', title: 'Exploit a SUID binary to read /etc/shadow' },
      { id: 'suid-4', title: 'Get a root shell using SUID exploit' },
    ],
    tools: ['find', 'GTFOBins', 'Linux CLI'],
    tags: ['Privilege Escalation', 'SUID', 'Linux', 'Post-Exploitation'],
  },
  {
    id: 'metasploit-basics',
    name: 'Metasploit Framework Basics',
    description: 'Learn to use Metasploit for vulnerability scanning and exploitation.',
    category: 'system',
    difficulty: 'intermediate',
    duration: '1.5 hrs',
    target: 'Metasploitable2',
    objectives: [
      'Navigate Metasploit console',
      'Search and select exploits',
      'Configure exploit options',
      'Get a Meterpreter shell',
    ],
    tasks: [
      { id: 'msf-1', title: 'Start msfconsole' },
      { id: 'msf-2', title: 'Search for vsftpd exploits' },
      { id: 'msf-3', title: 'Configure RHOSTS and LHOST' },
      { id: 'msf-4', title: 'Run the exploit and get a shell' },
      { id: 'msf-5', title: 'Use post-exploitation modules' },
    ],
    tools: ['Metasploit', 'msfconsole', 'msfvenom'],
    tags: ['Metasploit', 'Exploitation', 'Meterpreter', 'Framework'],
  },

  // ============================================================================
  // CRYPTOGRAPHY LABS
  // ============================================================================
  {
    id: 'hash-cracking',
    name: 'Password Hash Cracking',
    description: 'Crack password hashes using various techniques and tools.',
    category: 'crypto',
    difficulty: 'intermediate',
    duration: '1 hr',
    target: 'Hash Files',
    objectives: [
      'Identify hash types',
      'Use dictionary attacks with wordlists',
      'Apply rule-based attacks',
      'Crack MD5, SHA1, and bcrypt hashes',
    ],
    tasks: [
      { id: 'hash-1', title: 'Identify hash type using hash-identifier' },
      { id: 'hash-2', title: 'Crack MD5 hash with john and rockyou.txt' },
      { id: 'hash-3', title: 'Use hashcat with rules' },
      { id: 'hash-4', title: 'Crack shadow file passwords' },
    ],
    tools: ['John the Ripper', 'Hashcat', 'hash-identifier'],
    tags: ['Hash Cracking', 'Passwords', 'John', 'Hashcat'],
  },
  {
    id: 'steganography-images',
    name: 'Image Steganography',
    description: 'Find hidden data concealed within image files.',
    category: 'crypto',
    difficulty: 'beginner',
    duration: '45 min',
    target: 'Image Files',
    objectives: [
      'Understand steganography concepts',
      'Use tools to detect hidden data',
      'Extract hidden messages and files',
      'Analyze image metadata',
    ],
    tasks: [
      { id: 'stego-1', title: 'Check image metadata with exiftool' },
      { id: 'stego-2', title: 'Use strings to find hidden text' },
      { id: 'stego-3', title: 'Extract data with steghide' },
      { id: 'stego-4', title: 'Analyze with binwalk for embedded files' },
    ],
    tools: ['steghide', 'binwalk', 'exiftool', 'strings', 'zsteg'],
    tags: ['Steganography', 'Hidden Data', 'Images', 'CTF'],
  },

  // ============================================================================
  // CTF CHALLENGES
  // ============================================================================
  {
    id: 'ctf-web-beginner',
    name: 'CTF: Web Challenges (Beginner)',
    description: 'Beginner-level CTF challenges focused on web vulnerabilities.',
    category: 'ctf',
    difficulty: 'beginner',
    duration: '2 hrs',
    target: 'Multiple',
    objectives: [
      'Solve 5 beginner web challenges',
      'Practice SQL injection',
      'Find hidden directories',
      'Exploit weak authentication',
    ],
    tasks: [
      { id: 'ctf-web-1', title: 'Challenge 1: Find the hidden admin page' },
      { id: 'ctf-web-2', title: 'Challenge 2: Bypass login with SQLi' },
      { id: 'ctf-web-3', title: 'Challenge 3: Extract flag from cookies' },
      { id: 'ctf-web-4', title: 'Challenge 4: Directory traversal to read flag' },
      { id: 'ctf-web-5', title: 'Challenge 5: Exploit IDOR vulnerability' },
    ],
    tools: ['Burp Suite', 'dirb', 'Browser DevTools'],
    tags: ['CTF', 'Web', 'Challenges', 'Beginner'],
  },
]
