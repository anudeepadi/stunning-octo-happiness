import { useState } from 'react'
import {
  Container,
  Play,
  Square,
  RefreshCw,
  ExternalLink,
  Terminal,
  Database,
  Globe,
  Server,
} from 'lucide-react'

interface DockerService {
  name: string
  container: string
  port: number | null
  status: 'running' | 'stopped' | 'starting'
  category: 'web' | 'database' | 'os' | 'service'
  description: string
}

const dockerServices: DockerService[] = [
  {
    name: 'DVWA',
    container: 'lab-dvwa',
    port: 8081,
    status: 'stopped',
    category: 'web',
    description: 'Damn Vulnerable Web Application',
  },
  {
    name: 'Juice Shop',
    container: 'lab-juice-shop',
    port: 8082,
    status: 'stopped',
    category: 'web',
    description: 'OWASP Juice Shop - Modern web app',
  },
  {
    name: 'WebGoat',
    container: 'lab-webgoat',
    port: 8083,
    status: 'stopped',
    category: 'web',
    description: 'OWASP WebGoat - Guided lessons',
  },
  {
    name: 'bWAPP',
    container: 'lab-bwapp',
    port: 8084,
    status: 'stopped',
    category: 'web',
    description: 'Buggy Web Application',
  },
  {
    name: 'Mutillidae',
    container: 'lab-mutillidae',
    port: 8085,
    status: 'stopped',
    category: 'web',
    description: 'OWASP Mutillidae II',
  },
  {
    name: 'MySQL',
    container: 'lab-mysql-vuln',
    port: 3307,
    status: 'stopped',
    category: 'database',
    description: 'Vulnerable MySQL with SQLi targets',
  },
  {
    name: 'PostgreSQL',
    container: 'lab-postgres-vuln',
    port: 5433,
    status: 'stopped',
    category: 'database',
    description: 'PostgreSQL with weak security',
  },
  {
    name: 'Redis',
    container: 'lab-redis-vuln',
    port: 6380,
    status: 'stopped',
    category: 'database',
    description: 'Unauthenticated Redis',
  },
  {
    name: 'MongoDB',
    container: 'lab-mongodb-vuln',
    port: 27018,
    status: 'stopped',
    category: 'database',
    description: 'NoSQL injection practice',
  },
  {
    name: 'Metasploitable 2',
    container: 'lab-metasploitable2',
    port: null,
    status: 'stopped',
    category: 'os',
    description: 'Classic vulnerable Linux VM',
  },
  {
    name: 'Vulnerable SSH',
    container: 'lab-vuln-ssh',
    port: 2222,
    status: 'stopped',
    category: 'service',
    description: 'SSH with weak crypto & credentials',
  },
  {
    name: 'Vulnerable FTP',
    container: 'lab-vuln-ftp',
    port: 2121,
    status: 'stopped',
    category: 'service',
    description: 'FTP with anonymous access',
  },
  {
    name: 'Buffer Overflow',
    container: 'lab-buffer-overflow',
    port: 9999,
    status: 'stopped',
    category: 'service',
    description: 'Binary exploitation practice',
  },
]

const categoryIcons = {
  web: Globe,
  database: Database,
  os: Server,
  service: Terminal,
}

export default function DockerPage() {
  const [services, setServices] = useState(dockerServices)
  const [filter, setFilter] = useState<string>('all')

  const filteredServices =
    filter === 'all'
      ? services
      : services.filter((s) => s.category === filter)

  const runningCount = services.filter((s) => s.status === 'running').length

  const handleStartAll = () => {
    setServices(services.map((s) => ({ ...s, status: 'running' as const })))
  }

  const handleStopAll = () => {
    setServices(services.map((s) => ({ ...s, status: 'stopped' as const })))
  }

  const toggleService = (container: string) => {
    setServices(
      services.map((s) =>
        s.container === container
          ? { ...s, status: s.status === 'running' ? 'stopped' : 'running' }
          : s
      )
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-cyber-white mb-2">
            Docker Services
          </h1>
          <p className="text-cyber-muted">
            Manage vulnerable systems and target environments
          </p>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-sm text-cyber-muted">
            {runningCount}/{services.length} running
          </span>
          <div className="flex gap-2">
            <button
              onClick={handleStartAll}
              className="flex items-center gap-2 px-4 py-2 bg-cyber-white text-cyber-black rounded-lg font-medium hover:bg-cyber-muted transition-colors"
            >
              <Play className="w-4 h-4" />
              Start All
            </button>
            <button
              onClick={handleStopAll}
              className="flex items-center gap-2 px-4 py-2 border border-cyber-border rounded-lg text-cyber-white hover:bg-cyber-card transition-colors"
            >
              <Square className="w-4 h-4" />
              Stop All
            </button>
          </div>
        </div>
      </div>

      {/* Quick Commands */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-4">
        <h3 className="text-sm font-medium text-cyber-muted mb-3">
          Quick Commands
        </h3>
        <div className="flex flex-wrap gap-2">
          <code className="px-3 py-1 bg-cyber-dark rounded text-xs text-cyber-white font-mono">
            docker-compose up -d
          </code>
          <code className="px-3 py-1 bg-cyber-dark rounded text-xs text-cyber-white font-mono">
            docker-compose down
          </code>
          <code className="px-3 py-1 bg-cyber-dark rounded text-xs text-cyber-white font-mono">
            docker ps
          </code>
          <code className="px-3 py-1 bg-cyber-dark rounded text-xs text-cyber-white font-mono">
            docker logs -f [container]
          </code>
        </div>
      </div>

      {/* Category Filter */}
      <div className="flex gap-2">
        {['all', 'web', 'database', 'os', 'service'].map((cat) => (
          <button
            key={cat}
            onClick={() => setFilter(cat)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              filter === cat
                ? 'bg-cyber-white text-cyber-black'
                : 'text-cyber-muted hover:text-cyber-white hover:bg-cyber-card'
            }`}
          >
            {cat.charAt(0).toUpperCase() + cat.slice(1)}
          </button>
        ))}
      </div>

      {/* Services Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredServices.map((service) => {
          const Icon = categoryIcons[service.category]
          return (
            <div
              key={service.container}
              className="bg-cyber-card border border-cyber-border rounded-xl p-6 hover:border-cyber-white/20 transition-colors"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-cyber-dark border border-cyber-border rounded-lg flex items-center justify-center">
                    <Icon className="w-5 h-5 text-cyber-muted" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-cyber-white">
                      {service.name}
                    </h3>
                    <p className="text-xs text-cyber-muted font-mono">
                      {service.container}
                    </p>
                  </div>
                </div>
                <span
                  className={`status-dot ${
                    service.status === 'running'
                      ? 'status-running'
                      : 'status-stopped'
                  }`}
                />
              </div>

              <p className="text-sm text-cyber-muted mb-4">
                {service.description}
              </p>

              {service.port && (
                <p className="text-xs text-cyber-disabled mb-4 font-mono">
                  Port: {service.port}
                </p>
              )}

              <div className="flex items-center gap-2">
                <button
                  onClick={() => toggleService(service.container)}
                  className={`flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                    service.status === 'running'
                      ? 'bg-cyber-dark border border-cyber-border text-cyber-white hover:border-cyber-white'
                      : 'bg-cyber-white text-cyber-black hover:bg-cyber-muted'
                  }`}
                >
                  {service.status === 'running' ? (
                    <>
                      <Square className="w-4 h-4" />
                      Stop
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4" />
                      Start
                    </>
                  )}
                </button>
                {service.port && service.status === 'running' && (
                  <a
                    href={`http://localhost:${service.port}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-2 border border-cyber-border rounded-lg text-cyber-muted hover:text-cyber-white hover:border-cyber-white transition-colors"
                  >
                    <ExternalLink className="w-4 h-4" />
                  </a>
                )}
              </div>
            </div>
          )
        })}
      </div>

      {/* Network Info */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-6">
        <h2 className="text-lg font-bold text-cyber-white mb-4">
          Network Configuration
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 bg-cyber-dark rounded-lg">
            <p className="text-sm text-cyber-muted mb-1">Lab Network</p>
            <p className="text-cyber-white font-mono">172.20.0.0/16</p>
          </div>
          <div className="p-4 bg-cyber-dark rounded-lg">
            <p className="text-sm text-cyber-muted mb-1">Isolated Web</p>
            <p className="text-cyber-white font-mono">172.21.0.0/24</p>
          </div>
          <div className="p-4 bg-cyber-dark rounded-lg">
            <p className="text-sm text-cyber-muted mb-1">Isolated DB</p>
            <p className="text-cyber-white font-mono">172.22.0.0/24</p>
          </div>
        </div>
      </div>
    </div>
  )
}
