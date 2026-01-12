import { useState, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Filter, Grid, List } from 'lucide-react'
import LabCard from '../components/Labs/LabCard'
import { labs } from '../data/labs'

type Difficulty = 'all' | 'beginner' | 'intermediate' | 'advanced'
type Category = 'all' | 'web' | 'network' | 'system' | 'crypto' | 'ctf'

export default function LabsPage() {
  const [searchParams] = useSearchParams()
  const initialSearch = searchParams.get('search') || ''

  const [search, setSearch] = useState(initialSearch)
  const [difficulty, setDifficulty] = useState<Difficulty>('all')
  const [category, setCategory] = useState<Category>('all')
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid')

  const filteredLabs = useMemo(() => {
    return labs.filter((lab) => {
      const matchesSearch =
        lab.name.toLowerCase().includes(search.toLowerCase()) ||
        lab.description.toLowerCase().includes(search.toLowerCase()) ||
        lab.tags.some((tag) => tag.toLowerCase().includes(search.toLowerCase()))

      const matchesDifficulty =
        difficulty === 'all' || lab.difficulty === difficulty

      const matchesCategory = category === 'all' || lab.category === category

      return matchesSearch && matchesDifficulty && matchesCategory
    })
  }, [search, difficulty, category])

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-cyber-white mb-2">Labs</h1>
        <p className="text-cyber-muted">
          Hands-on security labs with real vulnerable systems
        </p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-4 p-4 bg-cyber-card border border-cyber-border rounded-xl">
        {/* Search */}
        <div className="flex-1 min-w-[200px]">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search labs..."
            className="w-full bg-cyber-dark border border-cyber-border rounded-lg px-4 py-2 text-sm text-cyber-white placeholder-cyber-muted focus:outline-none focus:border-cyber-white transition-colors"
          />
        </div>

        {/* Difficulty Filter */}
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-cyber-muted" />
          <select
            value={difficulty}
            onChange={(e) => setDifficulty(e.target.value as Difficulty)}
            className="bg-cyber-dark border border-cyber-border rounded-lg px-3 py-2 text-sm text-cyber-white focus:outline-none focus:border-cyber-white"
          >
            <option value="all">All Levels</option>
            <option value="beginner">Beginner</option>
            <option value="intermediate">Intermediate</option>
            <option value="advanced">Advanced</option>
          </select>
        </div>

        {/* Category Filter */}
        <select
          value={category}
          onChange={(e) => setCategory(e.target.value as Category)}
          className="bg-cyber-dark border border-cyber-border rounded-lg px-3 py-2 text-sm text-cyber-white focus:outline-none focus:border-cyber-white"
        >
          <option value="all">All Categories</option>
          <option value="web">Web Security</option>
          <option value="network">Network Analysis</option>
          <option value="system">System Exploitation</option>
          <option value="crypto">Cryptography</option>
          <option value="ctf">CTF Challenges</option>
        </select>

        {/* View Toggle */}
        <div className="flex items-center border border-cyber-border rounded-lg overflow-hidden">
          <button
            onClick={() => setViewMode('grid')}
            className={`p-2 ${
              viewMode === 'grid'
                ? 'bg-cyber-white text-cyber-black'
                : 'text-cyber-muted hover:text-cyber-white'
            }`}
          >
            <Grid className="w-4 h-4" />
          </button>
          <button
            onClick={() => setViewMode('list')}
            className={`p-2 ${
              viewMode === 'list'
                ? 'bg-cyber-white text-cyber-black'
                : 'text-cyber-muted hover:text-cyber-white'
            }`}
          >
            <List className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Results Count */}
      <p className="text-sm text-cyber-muted">
        Showing {filteredLabs.length} of {labs.length} labs
      </p>

      {/* Labs Grid/List */}
      <div
        className={
          viewMode === 'grid'
            ? 'grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4'
            : 'space-y-4'
        }
      >
        {filteredLabs.map((lab) => (
          <LabCard key={lab.id} lab={lab} viewMode={viewMode} />
        ))}
      </div>

      {/* Empty State */}
      {filteredLabs.length === 0 && (
        <div className="text-center py-12">
          <p className="text-cyber-muted">No labs found matching your filters</p>
          <button
            onClick={() => {
              setSearch('')
              setDifficulty('all')
              setCategory('all')
            }}
            className="mt-4 text-sm text-cyber-white hover:underline"
          >
            Clear filters
          </button>
        </div>
      )}
    </div>
  )
}
