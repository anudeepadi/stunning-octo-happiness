import { Link } from 'react-router-dom'
import {
  FlaskConical,
  Target,
  Trophy,
  TrendingUp,
  ArrowRight,
  Play,
  Clock,
} from 'lucide-react'
import { useProgressStore } from '../store'

const stats = [
  { name: 'Total Labs', value: '50+', icon: FlaskConical },
  { name: 'Challenges', value: '60+', icon: Target },
  { name: 'Your Progress', value: '0%', icon: TrendingUp },
  { name: 'Flags Captured', value: '0', icon: Trophy },
]

const featuredLabs = [
  {
    id: 'sql-injection',
    name: 'SQL Injection Fundamentals',
    category: 'Web Security',
    difficulty: 'beginner',
    duration: '45 min',
    target: 'DVWA',
  },
  {
    id: 'buffer-overflow',
    name: 'Stack Buffer Overflow',
    category: 'Binary Exploitation',
    difficulty: 'advanced',
    duration: '2 hrs',
    target: 'Custom Server',
  },
  {
    id: 'network-forensics',
    name: 'PCAP Analysis CTF',
    category: 'Network Analysis',
    difficulty: 'intermediate',
    duration: '1 hr',
    target: 'PCAP Files',
  },
]

const learningPaths = [
  {
    name: 'Web Application Security',
    description: 'Master OWASP Top 10 vulnerabilities',
    progress: 0,
    totalLabs: 16,
  },
  {
    name: 'Network Analysis',
    description: 'Packet capture and traffic analysis',
    progress: 0,
    totalLabs: 9,
  },
  {
    name: 'System Exploitation',
    description: 'Shells, privilege escalation, post-exploitation',
    progress: 0,
    totalLabs: 15,
  },
]

export default function Dashboard() {
  const { completedLabs, totalFlags } = useProgressStore()

  return (
    <div className="space-y-8">
      {/* Welcome Banner */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-cyber-white mb-2 font-mono">
              Welcome to CyberLab
            </h1>
            <p className="text-cyber-muted max-w-xl">
              A comprehensive cybersecurity learning platform with hands-on labs,
              vulnerable systems, and CTF challenges. From beginner to advanced.
            </p>
            <div className="flex gap-4 mt-6">
              <Link
                to="/labs"
                className="inline-flex items-center gap-2 px-6 py-3 bg-cyber-white text-cyber-black rounded-lg font-medium hover:bg-cyber-muted transition-colors"
              >
                <Play className="w-4 h-4" />
                Start Learning
              </Link>
              <Link
                to="/curriculum"
                className="inline-flex items-center gap-2 px-6 py-3 border border-cyber-border rounded-lg text-cyber-white hover:bg-cyber-card transition-colors"
              >
                View Curriculum
                <ArrowRight className="w-4 h-4" />
              </Link>
            </div>
          </div>
          <div className="hidden lg:block">
            <pre className="text-cyber-muted text-xs font-mono opacity-50">
{`  ██████╗██╗   ██╗██████╗ ███████╗██████╗
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝`}
            </pre>
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map((stat) => (
          <div
            key={stat.name}
            className="bg-cyber-card border border-cyber-border rounded-xl p-6 hover:border-cyber-white/20 transition-colors"
          >
            <div className="flex items-center justify-between mb-4">
              <stat.icon className="w-8 h-8 text-cyber-muted" />
            </div>
            <p className="text-3xl font-bold text-cyber-white font-mono">
              {stat.name === 'Your Progress'
                ? `${Math.round((completedLabs.length / 50) * 100)}%`
                : stat.name === 'Flags Captured'
                ? totalFlags
                : stat.value}
            </p>
            <p className="text-sm text-cyber-muted mt-1">{stat.name}</p>
          </div>
        ))}
      </div>

      {/* Featured Labs */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold text-cyber-white">Featured Labs</h2>
          <Link
            to="/labs"
            className="text-sm text-cyber-muted hover:text-cyber-white flex items-center gap-1"
          >
            View all <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {featuredLabs.map((lab) => (
            <Link
              key={lab.id}
              to={`/labs/${lab.id}`}
              className="lab-card bg-cyber-card border border-cyber-border rounded-xl p-6 hover:border-cyber-white/20"
            >
              <div className="flex items-start justify-between mb-4">
                <span
                  className={`px-2 py-1 rounded text-xs font-medium badge-${lab.difficulty}`}
                >
                  {lab.difficulty}
                </span>
                <div className="flex items-center gap-1 text-cyber-muted text-xs">
                  <Clock className="w-3 h-3" />
                  {lab.duration}
                </div>
              </div>
              <h3 className="text-lg font-semibold text-cyber-white mb-2">
                {lab.name}
              </h3>
              <p className="text-sm text-cyber-muted mb-4">{lab.category}</p>
              <div className="flex items-center justify-between text-xs">
                <span className="text-cyber-disabled">Target: {lab.target}</span>
                <ArrowRight className="w-4 h-4 text-cyber-muted" />
              </div>
            </Link>
          ))}
        </div>
      </div>

      {/* Learning Paths */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold text-cyber-white">Learning Paths</h2>
          <Link
            to="/curriculum"
            className="text-sm text-cyber-muted hover:text-cyber-white flex items-center gap-1"
          >
            View curriculum <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {learningPaths.map((path) => (
            <div
              key={path.name}
              className="bg-cyber-card border border-cyber-border rounded-xl p-6"
            >
              <h3 className="text-lg font-semibold text-cyber-white mb-2">
                {path.name}
              </h3>
              <p className="text-sm text-cyber-muted mb-4">{path.description}</p>
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-cyber-muted">Progress</span>
                  <span className="text-cyber-white font-mono">
                    {path.progress}/{path.totalLabs} labs
                  </span>
                </div>
                <div className="progress-bar">
                  <div
                    className="progress-fill"
                    style={{
                      width: `${(path.progress / path.totalLabs) * 100}%`,
                    }}
                  />
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
