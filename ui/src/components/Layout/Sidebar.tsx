import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  FlaskConical,
  Container,
  GraduationCap,
  TrendingUp,
  Terminal,
  Shield,
} from 'lucide-react'
import clsx from 'clsx'

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Labs', href: '/labs', icon: FlaskConical },
  { name: 'Curriculum', href: '/curriculum', icon: GraduationCap },
  { name: 'Docker', href: '/docker', icon: Container },
  { name: 'Progress', href: '/progress', icon: TrendingUp },
]

const quickLaunch = [
  { name: 'DVWA', port: 8081, status: 'running' },
  { name: 'Juice Shop', port: 8082, status: 'running' },
  { name: 'WebGoat', port: 8083, status: 'stopped' },
  { name: 'Metasploitable', port: null, status: 'stopped' },
]

export default function Sidebar() {
  return (
    <aside className="w-64 bg-cyber-dark border-r border-cyber-border flex flex-col">
      {/* Logo */}
      <div className="p-6 border-b border-cyber-border">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-cyber-card border border-cyber-border rounded-lg flex items-center justify-center">
            <Shield className="w-6 h-6 text-cyber-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-cyber-white font-mono">
              CyberLab
            </h1>
            <p className="text-xs text-cyber-muted">Security Platform</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4">
        <ul className="space-y-1">
          {navigation.map((item) => (
            <li key={item.name}>
              <NavLink
                to={item.href}
                className={({ isActive }) =>
                  clsx(
                    'flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200',
                    'text-sm font-medium',
                    isActive
                      ? 'bg-cyber-card text-cyber-white border border-cyber-border'
                      : 'text-cyber-muted hover:text-cyber-white hover:bg-cyber-card/50'
                  )
                }
              >
                <item.icon className="w-5 h-5" />
                {item.name}
              </NavLink>
            </li>
          ))}
        </ul>

        {/* Quick Launch */}
        <div className="mt-8">
          <h3 className="px-4 text-xs font-semibold text-cyber-muted uppercase tracking-wider mb-3">
            Quick Launch
          </h3>
          <ul className="space-y-1">
            {quickLaunch.map((service) => (
              <li key={service.name}>
                <a
                  href={service.port ? `http://localhost:${service.port}` : '#'}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center justify-between px-4 py-2 rounded-lg text-sm text-cyber-muted hover:text-cyber-white hover:bg-cyber-card/50 transition-colors"
                >
                  <span className="flex items-center gap-2">
                    <span
                      className={clsx(
                        'status-dot',
                        service.status === 'running'
                          ? 'status-running'
                          : 'status-stopped'
                      )}
                    />
                    {service.name}
                  </span>
                  {service.port && (
                    <span className="text-xs text-cyber-disabled font-mono">
                      :{service.port}
                    </span>
                  )}
                </a>
              </li>
            ))}
          </ul>
        </div>
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-cyber-border">
        <div className="flex items-center gap-3 px-4 py-2">
          <Terminal className="w-4 h-4 text-cyber-muted" />
          <span className="text-xs text-cyber-muted font-mono">
            Kali Linux VM
          </span>
        </div>
      </div>
    </aside>
  )
}
