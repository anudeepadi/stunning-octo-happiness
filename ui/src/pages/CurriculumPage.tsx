import { Link } from 'react-router-dom'
import {
  Globe,
  Network,
  Terminal,
  Lock,
  Wifi,
  Shield,
  Target,
  ChevronRight,
} from 'lucide-react'
import { useProgressStore } from '../store'

const modules = [
  {
    id: 'foundations',
    name: 'Foundations',
    icon: Terminal,
    description: 'Linux basics, networking fundamentals, terminal proficiency',
    difficulty: 'beginner',
    labs: 5,
    duration: '8 hours',
    topics: ['Linux CLI', 'TCP/IP', 'Networking basics', 'Terminal tools'],
  },
  {
    id: 'network-analysis',
    name: 'Network Analysis',
    icon: Network,
    description: 'Packet capture, traffic analysis, protocol deep-dive',
    difficulty: 'intermediate',
    labs: 9,
    duration: '12 hours',
    topics: [
      'Scapy',
      'MITM attacks',
      'Forensics',
      'IDS',
      'Wireless',
      'Firewall',
    ],
  },
  {
    id: 'web-security',
    name: 'Web Application Security',
    icon: Globe,
    description: 'Master OWASP Top 10 vulnerabilities hands-on',
    difficulty: 'intermediate',
    labs: 16,
    duration: '20 hours',
    topics: [
      'SQL Injection',
      'XSS',
      'CSRF',
      'XXE',
      'SSRF',
      'File Upload',
      'Auth bypass',
    ],
  },
  {
    id: 'system-exploitation',
    name: 'System Exploitation',
    icon: Terminal,
    description: 'Shells, privilege escalation, post-exploitation',
    difficulty: 'advanced',
    labs: 15,
    duration: '25 hours',
    topics: [
      'Enumeration',
      'Metasploit',
      'Reverse shells',
      'PrivEsc Linux',
      'Buffer overflow',
    ],
  },
  {
    id: 'cryptography',
    name: 'Cryptography & Steganography',
    icon: Lock,
    description: 'Encryption, hashing, hidden data extraction',
    difficulty: 'intermediate',
    labs: 10,
    duration: '12 hours',
    topics: ['Encoding', 'AES/RSA', 'Hash cracking', 'Image stego', 'TLS/SSL'],
  },
  {
    id: 'wireless-security',
    name: 'Wireless Security',
    icon: Wifi,
    description: 'WLAN attacks, WPA cracking, evil twin',
    difficulty: 'intermediate',
    labs: 8,
    duration: '10 hours',
    topics: [
      'WLAN fundamentals',
      'WEP cracking',
      'WPA attacks',
      'Deauth',
      'Evil twin',
    ],
  },
  {
    id: 'active-directory',
    name: 'Active Directory',
    icon: Shield,
    description: 'AD enumeration, Kerberos attacks, lateral movement',
    difficulty: 'advanced',
    labs: 6,
    duration: '15 hours',
    topics: [
      'AD fundamentals',
      'Kerberoasting',
      'Pass-the-hash',
      'Golden ticket',
      'BloodHound',
    ],
  },
  {
    id: 'ctf-challenges',
    name: 'CTF Challenges',
    icon: Target,
    description: '60+ challenges across all security domains',
    difficulty: 'mixed',
    labs: 60,
    duration: '40+ hours',
    topics: ['Web', 'Forensics', 'Crypto', 'Binary', 'Misc', 'OSINT'],
  },
]

export default function CurriculumPage() {
  const { completedLabs } = useProgressStore()

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-cyber-white mb-2">Curriculum</h1>
        <p className="text-cyber-muted">
          Structured learning path from beginner to advanced
        </p>
      </div>

      {/* Learning Path Overview */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-6">
        <h2 className="text-lg font-bold text-cyber-white mb-4">
          Recommended Learning Path
        </h2>
        <div className="flex items-center gap-2 overflow-x-auto pb-2">
          {['Foundations', 'Network', 'Web', 'System', 'Advanced'].map(
            (step, i) => (
              <div key={step} className="flex items-center gap-2">
                <div className="px-4 py-2 bg-cyber-dark border border-cyber-border rounded-lg text-sm text-cyber-white whitespace-nowrap">
                  {step}
                </div>
                {i < 4 && (
                  <ChevronRight className="w-4 h-4 text-cyber-muted flex-shrink-0" />
                )}
              </div>
            )
          )}
        </div>
      </div>

      {/* Modules Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {modules.map((module) => (
          <div
            key={module.id}
            className="bg-cyber-card border border-cyber-border rounded-xl p-6 hover:border-cyber-white/20 transition-colors"
          >
            <div className="flex items-start gap-4 mb-4">
              <div className="w-12 h-12 bg-cyber-dark border border-cyber-border rounded-xl flex items-center justify-center flex-shrink-0">
                <module.icon className="w-6 h-6 text-cyber-white" />
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <h3 className="text-lg font-bold text-cyber-white">
                    {module.name}
                  </h3>
                  <span
                    className={`px-2 py-0.5 rounded text-xs font-medium ${
                      module.difficulty === 'beginner'
                        ? 'badge-beginner'
                        : module.difficulty === 'intermediate'
                        ? 'badge-intermediate'
                        : module.difficulty === 'advanced'
                        ? 'badge-advanced'
                        : 'bg-cyber-dark text-cyber-muted border border-cyber-border'
                    }`}
                  >
                    {module.difficulty}
                  </span>
                </div>
                <p className="text-sm text-cyber-muted">{module.description}</p>
              </div>
            </div>

            <div className="flex items-center gap-4 text-sm text-cyber-muted mb-4">
              <span>{module.labs} labs</span>
              <span>|</span>
              <span>{module.duration}</span>
            </div>

            <div className="flex flex-wrap gap-2 mb-4">
              {module.topics.slice(0, 5).map((topic) => (
                <span
                  key={topic}
                  className="px-2 py-1 bg-cyber-dark rounded text-xs text-cyber-muted"
                >
                  {topic}
                </span>
              ))}
              {module.topics.length > 5 && (
                <span className="px-2 py-1 text-xs text-cyber-disabled">
                  +{module.topics.length - 5} more
                </span>
              )}
            </div>

            <div className="space-y-2 mb-4">
              <div className="flex items-center justify-between text-xs">
                <span className="text-cyber-muted">Progress</span>
                <span className="text-cyber-white font-mono">0/{module.labs}</span>
              </div>
              <div className="progress-bar">
                <div className="progress-fill" style={{ width: '0%' }} />
              </div>
            </div>

            <Link
              to={`/labs?category=${module.id}`}
              className="block w-full text-center px-4 py-2 border border-cyber-border rounded-lg text-cyber-white hover:bg-cyber-dark transition-colors text-sm font-medium"
            >
              Start Module
            </Link>
          </div>
        ))}
      </div>

      {/* Total Stats */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-6">
        <h2 className="text-lg font-bold text-cyber-white mb-4">
          Total Curriculum
        </h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="text-center">
            <p className="text-3xl font-bold text-cyber-white font-mono">129</p>
            <p className="text-sm text-cyber-muted">Total Labs</p>
          </div>
          <div className="text-center">
            <p className="text-3xl font-bold text-cyber-white font-mono">60+</p>
            <p className="text-sm text-cyber-muted">CTF Challenges</p>
          </div>
          <div className="text-center">
            <p className="text-3xl font-bold text-cyber-white font-mono">140+</p>
            <p className="text-sm text-cyber-muted">Hours Content</p>
          </div>
          <div className="text-center">
            <p className="text-3xl font-bold text-cyber-white font-mono">8</p>
            <p className="text-sm text-cyber-muted">Modules</p>
          </div>
        </div>
      </div>
    </div>
  )
}
