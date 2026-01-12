import { useParams, Link } from 'react-router-dom'
import {
  ArrowLeft,
  Clock,
  Target,
  CheckCircle2,
  Circle,
  ExternalLink,
  Flag,
  BookOpen,
} from 'lucide-react'
import { labs } from '../data/labs'
import { useProgressStore } from '../store'

export default function LabDetail() {
  const { labId } = useParams()
  const lab = labs.find((l) => l.id === labId)
  const { isTaskComplete, toggleTask, isLabComplete, completeLab } =
    useProgressStore()

  if (!lab) {
    return (
      <div className="text-center py-12">
        <p className="text-cyber-muted">Lab not found</p>
        <Link to="/labs" className="text-cyber-white hover:underline mt-4 inline-block">
          Back to labs
        </Link>
      </div>
    )
  }

  const completedTasks = lab.tasks.filter((task) =>
    isTaskComplete(lab.id, task.id)
  ).length
  const progress = (completedTasks / lab.tasks.length) * 100

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      {/* Back Link */}
      <Link
        to="/labs"
        className="inline-flex items-center gap-2 text-cyber-muted hover:text-cyber-white transition-colors"
      >
        <ArrowLeft className="w-4 h-4" />
        Back to labs
      </Link>

      {/* Header */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-8">
        <div className="flex items-start justify-between mb-6">
          <div>
            <span
              className={`px-2 py-1 rounded text-xs font-medium badge-${lab.difficulty}`}
            >
              {lab.difficulty}
            </span>
            <span className="ml-2 text-xs text-cyber-muted">{lab.category}</span>
          </div>
          <div className="flex items-center gap-4 text-sm text-cyber-muted">
            <span className="flex items-center gap-1">
              <Clock className="w-4 h-4" />
              {lab.duration}
            </span>
            <span className="flex items-center gap-1">
              <Target className="w-4 h-4" />
              {lab.target}
            </span>
          </div>
        </div>

        <h1 className="text-3xl font-bold text-cyber-white mb-4">{lab.name}</h1>
        <p className="text-cyber-muted text-lg mb-6">{lab.description}</p>

        {/* Progress */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span className="text-cyber-muted">Progress</span>
            <span className="text-cyber-white font-mono">
              {completedTasks}/{lab.tasks.length} tasks
            </span>
          </div>
          <div className="progress-bar h-2">
            <div className="progress-fill" style={{ width: `${progress}%` }} />
          </div>
        </div>

        {/* Target System */}
        {lab.targetUrl && (
          <a
            href={lab.targetUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 mt-6 px-4 py-2 bg-cyber-dark border border-cyber-border rounded-lg text-cyber-white hover:border-cyber-white transition-colors"
          >
            <ExternalLink className="w-4 h-4" />
            Open {lab.target}
          </a>
        )}
      </div>

      {/* Objectives */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-6">
        <h2 className="text-xl font-bold text-cyber-white mb-4 flex items-center gap-2">
          <BookOpen className="w-5 h-5" />
          Learning Objectives
        </h2>
        <ul className="space-y-2">
          {lab.objectives.map((objective, index) => (
            <li key={index} className="flex items-start gap-3 text-cyber-muted">
              <span className="text-cyber-white font-mono text-sm">
                {String(index + 1).padStart(2, '0')}
              </span>
              {objective}
            </li>
          ))}
        </ul>
      </div>

      {/* Tasks */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-6">
        <h2 className="text-xl font-bold text-cyber-white mb-4 flex items-center gap-2">
          <Target className="w-5 h-5" />
          Tasks
        </h2>
        <ul className="space-y-3">
          {lab.tasks.map((task) => {
            const isComplete = isTaskComplete(lab.id, task.id)
            return (
              <li
                key={task.id}
                className="flex items-start gap-3 p-3 rounded-lg hover:bg-cyber-dark transition-colors cursor-pointer"
                onClick={() => toggleTask(lab.id, task.id)}
              >
                {isComplete ? (
                  <CheckCircle2 className="w-5 h-5 text-diff-beginner flex-shrink-0 mt-0.5" />
                ) : (
                  <Circle className="w-5 h-5 text-cyber-muted flex-shrink-0 mt-0.5" />
                )}
                <div>
                  <p
                    className={`font-medium ${
                      isComplete
                        ? 'text-cyber-muted line-through'
                        : 'text-cyber-white'
                    }`}
                  >
                    {task.title}
                  </p>
                  {task.hint && (
                    <p className="text-sm text-cyber-disabled mt-1">
                      Hint: {task.hint}
                    </p>
                  )}
                </div>
              </li>
            )
          })}
        </ul>
      </div>

      {/* Flag Submission */}
      {lab.flag && (
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-6">
          <h2 className="text-xl font-bold text-cyber-white mb-4 flex items-center gap-2">
            <Flag className="w-5 h-5" />
            Capture the Flag
          </h2>
          <form
            onSubmit={(e) => {
              e.preventDefault()
              const input = e.currentTarget.flag as HTMLInputElement
              if (input.value === lab.flag) {
                completeLab(lab.id)
                alert('Correct! Flag captured!')
              } else {
                alert('Incorrect flag. Try again!')
              }
              input.value = ''
            }}
            className="flex gap-4"
          >
            <input
              type="text"
              name="flag"
              placeholder="Enter flag (e.g., FLAG{...})"
              className="flex-1 bg-cyber-dark border border-cyber-border rounded-lg px-4 py-2 text-cyber-white font-mono placeholder-cyber-muted focus:outline-none focus:border-cyber-white"
            />
            <button
              type="submit"
              className="px-6 py-2 bg-cyber-white text-cyber-black rounded-lg font-medium hover:bg-cyber-muted transition-colors"
            >
              Submit
            </button>
          </form>
        </div>
      )}

      {/* Tools */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-6">
        <h2 className="text-xl font-bold text-cyber-white mb-4">
          Recommended Tools
        </h2>
        <div className="flex flex-wrap gap-2">
          {lab.tools.map((tool) => (
            <span
              key={tool}
              className="px-3 py-1 bg-cyber-dark border border-cyber-border rounded-full text-sm text-cyber-muted font-mono"
            >
              {tool}
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}
