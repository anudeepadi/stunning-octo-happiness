import { useState } from 'react'
import { Search, Bell, Settings, User } from 'lucide-react'
import { useNavigate } from 'react-router-dom'

export default function Header() {
  const [searchQuery, setSearchQuery] = useState('')
  const navigate = useNavigate()

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    if (searchQuery.trim()) {
      navigate(`/labs?search=${encodeURIComponent(searchQuery)}`)
    }
  }

  return (
    <header className="h-16 bg-cyber-dark border-b border-cyber-border flex items-center justify-between px-6">
      {/* Search */}
      <form onSubmit={handleSearch} className="flex-1 max-w-xl">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-cyber-muted" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search labs, challenges, tools..."
            className="w-full bg-cyber-card border border-cyber-border rounded-lg pl-10 pr-4 py-2 text-sm text-cyber-white placeholder-cyber-muted focus:outline-none focus:border-cyber-white transition-colors"
          />
          <kbd className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-cyber-disabled font-mono bg-cyber-dark px-2 py-0.5 rounded border border-cyber-border">
            /
          </kbd>
        </div>
      </form>

      {/* Actions */}
      <div className="flex items-center gap-2 ml-6">
        <button className="p-2 rounded-lg text-cyber-muted hover:text-cyber-white hover:bg-cyber-card transition-colors">
          <Bell className="w-5 h-5" />
        </button>
        <button className="p-2 rounded-lg text-cyber-muted hover:text-cyber-white hover:bg-cyber-card transition-colors">
          <Settings className="w-5 h-5" />
        </button>
        <div className="w-px h-6 bg-cyber-border mx-2" />
        <button className="flex items-center gap-2 px-3 py-2 rounded-lg text-cyber-muted hover:text-cyber-white hover:bg-cyber-card transition-colors">
          <div className="w-8 h-8 bg-cyber-card border border-cyber-border rounded-full flex items-center justify-center">
            <User className="w-4 h-4" />
          </div>
          <span className="text-sm font-medium">Hacker</span>
        </button>
      </div>
    </header>
  )
}
