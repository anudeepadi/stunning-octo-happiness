import {
  Trophy,
  Target,
  Clock,
  TrendingUp,
  Download,
  Upload,
  Trash2,
} from 'lucide-react'
import { useProgressStore } from '../store'

export default function ProgressPage() {
  const {
    completedLabs,
    completedTasks,
    totalFlags,
    startedAt,
    exportProgress,
    importProgress,
    resetProgress,
  } = useProgressStore()

  const handleExport = () => {
    const data = exportProgress()
    const blob = new Blob([data], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'cyberlab-progress.json'
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleImport = () => {
    const input = document.createElement('input')
    input.type = 'file'
    input.accept = '.json'
    input.onchange = (e) => {
      const file = (e.target as HTMLInputElement).files?.[0]
      if (file) {
        const reader = new FileReader()
        reader.onload = () => {
          try {
            importProgress(reader.result as string)
            alert('Progress imported successfully!')
          } catch {
            alert('Failed to import progress')
          }
        }
        reader.readAsText(file)
      }
    }
    input.click()
  }

  const handleReset = () => {
    if (
      confirm(
        'Are you sure you want to reset all progress? This cannot be undone.'
      )
    ) {
      resetProgress()
    }
  }

  const stats = [
    {
      name: 'Labs Completed',
      value: completedLabs.length,
      total: 50,
      icon: Target,
    },
    {
      name: 'Tasks Done',
      value: Object.keys(completedTasks).reduce(
        (acc, key) => acc + completedTasks[key].length,
        0
      ),
      total: 200,
      icon: TrendingUp,
    },
    { name: 'Flags Captured', value: totalFlags, total: 60, icon: Trophy },
    {
      name: 'Time Invested',
      value: startedAt
        ? Math.round(
            (Date.now() - new Date(startedAt).getTime()) / (1000 * 60 * 60)
          )
        : 0,
      total: null,
      unit: 'hrs',
      icon: Clock,
    },
  ]

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-cyber-white mb-2">
            Your Progress
          </h1>
          <p className="text-cyber-muted">Track your cybersecurity journey</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleExport}
            className="flex items-center gap-2 px-4 py-2 border border-cyber-border rounded-lg text-cyber-white hover:bg-cyber-card transition-colors text-sm"
          >
            <Download className="w-4 h-4" />
            Export
          </button>
          <button
            onClick={handleImport}
            className="flex items-center gap-2 px-4 py-2 border border-cyber-border rounded-lg text-cyber-white hover:bg-cyber-card transition-colors text-sm"
          >
            <Upload className="w-4 h-4" />
            Import
          </button>
          <button
            onClick={handleReset}
            className="flex items-center gap-2 px-4 py-2 border border-cyber-border rounded-lg text-cyber-red hover:bg-cyber-card transition-colors text-sm"
          >
            <Trash2 className="w-4 h-4" />
            Reset
          </button>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map((stat) => (
          <div
            key={stat.name}
            className="bg-cyber-card border border-cyber-border rounded-xl p-6"
          >
            <div className="flex items-center justify-between mb-4">
              <stat.icon className="w-8 h-8 text-cyber-muted" />
              {stat.total && (
                <span className="text-xs text-cyber-muted font-mono">
                  / {stat.total}
                </span>
              )}
            </div>
            <p className="text-3xl font-bold text-cyber-white font-mono">
              {stat.value}
              {stat.unit && (
                <span className="text-lg text-cyber-muted ml-1">
                  {stat.unit}
                </span>
              )}
            </p>
            <p className="text-sm text-cyber-muted mt-1">{stat.name}</p>
            {stat.total && (
              <div className="mt-4">
                <div className="progress-bar">
                  <div
                    className="progress-fill"
                    style={{ width: `${(stat.value / stat.total) * 100}%` }}
                  />
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Achievements */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-6">
        <h2 className="text-lg font-bold text-cyber-white mb-4">Achievements</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
          {[
            { name: 'First Blood', desc: 'Complete first lab', unlocked: completedLabs.length > 0 },
            { name: 'SQL Master', desc: 'Complete all SQLi labs', unlocked: false },
            { name: 'Packet Ninja', desc: 'Analyze 10 PCAPs', unlocked: false },
            { name: 'Shell Hunter', desc: 'Get 5 reverse shells', unlocked: false },
            { name: 'Crypto King', desc: 'Crack 10 hashes', unlocked: false },
            { name: 'Flag Collector', desc: 'Capture 25 flags', unlocked: totalFlags >= 25 },
          ].map((achievement) => (
            <div
              key={achievement.name}
              className={`p-4 rounded-lg text-center ${
                achievement.unlocked
                  ? 'bg-cyber-dark border border-cyber-white/20'
                  : 'bg-cyber-dark/50 opacity-50'
              }`}
            >
              <div className="w-12 h-12 mx-auto mb-2 rounded-full bg-cyber-card border border-cyber-border flex items-center justify-center">
                <Trophy
                  className={`w-6 h-6 ${
                    achievement.unlocked ? 'text-diff-beginner' : 'text-cyber-muted'
                  }`}
                />
              </div>
              <p className="text-sm font-medium text-cyber-white">
                {achievement.name}
              </p>
              <p className="text-xs text-cyber-muted mt-1">{achievement.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Recent Activity */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-6">
        <h2 className="text-lg font-bold text-cyber-white mb-4">
          Recent Activity
        </h2>
        {completedLabs.length > 0 ? (
          <ul className="space-y-3">
            {completedLabs.slice(-5).reverse().map((lab) => (
              <li
                key={lab}
                className="flex items-center gap-3 p-3 bg-cyber-dark rounded-lg"
              >
                <Target className="w-5 h-5 text-diff-beginner" />
                <span className="text-cyber-white">Completed: {lab}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-cyber-muted text-center py-8">
            No activity yet. Start a lab to track your progress!
          </p>
        )}
      </div>
    </div>
  )
}
