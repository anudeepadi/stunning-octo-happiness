import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface ProgressState {
  completedLabs: string[]
  completedTasks: Record<string, string[]>
  totalFlags: number
  startedAt: string | null

  // Actions
  isLabComplete: (labId: string) => boolean
  isTaskComplete: (labId: string, taskId: string) => boolean
  toggleTask: (labId: string, taskId: string) => void
  completeLab: (labId: string) => void
  captureFlag: () => void
  exportProgress: () => string
  importProgress: (data: string) => void
  resetProgress: () => void
}

export const useProgressStore = create<ProgressState>()(
  persist(
    (set, get) => ({
      completedLabs: [],
      completedTasks: {},
      totalFlags: 0,
      startedAt: null,

      isLabComplete: (labId: string) => {
        return get().completedLabs.includes(labId)
      },

      isTaskComplete: (labId: string, taskId: string) => {
        const tasks = get().completedTasks[labId] || []
        return tasks.includes(taskId)
      },

      toggleTask: (labId: string, taskId: string) => {
        set((state) => {
          const tasks = state.completedTasks[labId] || []
          const isComplete = tasks.includes(taskId)

          // Set startedAt if this is the first action
          const startedAt = state.startedAt || new Date().toISOString()

          if (isComplete) {
            return {
              completedTasks: {
                ...state.completedTasks,
                [labId]: tasks.filter((t) => t !== taskId),
              },
              startedAt,
            }
          } else {
            return {
              completedTasks: {
                ...state.completedTasks,
                [labId]: [...tasks, taskId],
              },
              startedAt,
            }
          }
        })
      },

      completeLab: (labId: string) => {
        set((state) => {
          if (state.completedLabs.includes(labId)) {
            return state
          }
          return {
            completedLabs: [...state.completedLabs, labId],
            totalFlags: state.totalFlags + 1,
            startedAt: state.startedAt || new Date().toISOString(),
          }
        })
      },

      captureFlag: () => {
        set((state) => ({
          totalFlags: state.totalFlags + 1,
          startedAt: state.startedAt || new Date().toISOString(),
        }))
      },

      exportProgress: () => {
        const state = get()
        return JSON.stringify({
          completedLabs: state.completedLabs,
          completedTasks: state.completedTasks,
          totalFlags: state.totalFlags,
          startedAt: state.startedAt,
          exportedAt: new Date().toISOString(),
        })
      },

      importProgress: (data: string) => {
        try {
          const parsed = JSON.parse(data)
          set({
            completedLabs: parsed.completedLabs || [],
            completedTasks: parsed.completedTasks || {},
            totalFlags: parsed.totalFlags || 0,
            startedAt: parsed.startedAt || null,
          })
        } catch (e) {
          console.error('Failed to import progress:', e)
          throw e
        }
      },

      resetProgress: () => {
        set({
          completedLabs: [],
          completedTasks: {},
          totalFlags: 0,
          startedAt: null,
        })
      },
    }),
    {
      name: 'cyberlab-progress',
    }
  )
)
