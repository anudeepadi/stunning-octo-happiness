import { Link } from 'react-router-dom'
import { Clock, ArrowRight, CheckCircle2 } from 'lucide-react'
import clsx from 'clsx'
import { useProgressStore } from '../../store'
import type { Lab } from '../../data/labs'

interface LabCardProps {
  lab: Lab
  viewMode: 'grid' | 'list'
}

export default function LabCard({ lab, viewMode }: LabCardProps) {
  const { isLabComplete } = useProgressStore()
  const completed = isLabComplete(lab.id)

  if (viewMode === 'list') {
    return (
      <Link
        to={`/labs/${lab.id}`}
        className="lab-card flex items-center gap-6 p-4 bg-cyber-card border border-cyber-border rounded-xl hover:border-cyber-white/20"
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 mb-1">
            <h3 className="text-lg font-semibold text-cyber-white truncate">
              {lab.name}
            </h3>
            {completed && (
              <CheckCircle2 className="w-5 h-5 text-diff-beginner flex-shrink-0" />
            )}
          </div>
          <p className="text-sm text-cyber-muted truncate">{lab.description}</p>
        </div>
        <div className="flex items-center gap-4 flex-shrink-0">
          <span
            className={clsx(
              'px-2 py-1 rounded text-xs font-medium',
              `badge-${lab.difficulty}`
            )}
          >
            {lab.difficulty}
          </span>
          <span className="flex items-center gap-1 text-cyber-muted text-sm">
            <Clock className="w-4 h-4" />
            {lab.duration}
          </span>
          <span className="text-xs text-cyber-disabled">{lab.target}</span>
          <ArrowRight className="w-5 h-5 text-cyber-muted" />
        </div>
      </Link>
    )
  }

  return (
    <Link
      to={`/labs/${lab.id}`}
      className="lab-card bg-cyber-card border border-cyber-border rounded-xl p-6 hover:border-cyber-white/20 block"
    >
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-2">
          <span
            className={clsx(
              'px-2 py-1 rounded text-xs font-medium',
              `badge-${lab.difficulty}`
            )}
          >
            {lab.difficulty}
          </span>
          {completed && (
            <CheckCircle2 className="w-4 h-4 text-diff-beginner" />
          )}
        </div>
        <div className="flex items-center gap-1 text-cyber-muted text-xs">
          <Clock className="w-3 h-3" />
          {lab.duration}
        </div>
      </div>

      <h3 className="text-lg font-semibold text-cyber-white mb-2">
        {lab.name}
      </h3>
      <p className="text-sm text-cyber-muted mb-4 line-clamp-2">
        {lab.description}
      </p>

      <div className="flex flex-wrap gap-1 mb-4">
        {lab.tags.slice(0, 3).map((tag) => (
          <span
            key={tag}
            className="px-2 py-0.5 bg-cyber-dark rounded text-xs text-cyber-disabled"
          >
            {tag}
          </span>
        ))}
      </div>

      <div className="flex items-center justify-between text-xs">
        <span className="text-cyber-disabled">Target: {lab.target}</span>
        <ArrowRight className="w-4 h-4 text-cyber-muted" />
      </div>
    </Link>
  )
}
