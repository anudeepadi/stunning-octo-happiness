/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Pure black and white palette
        'cyber-black': '#000000',
        'cyber-dark': '#0a0a0a',
        'cyber-card': '#141414',
        'cyber-border': '#333333',
        'cyber-border-light': '#1a1a1a',
        'cyber-white': '#ffffff',
        'cyber-muted': '#a0a0a0',
        'cyber-disabled': '#666666',
        // Minimal accent colors (used sparingly)
        'cyber-green': '#00ff00',
        'cyber-red': '#ff0000',
        'cyber-yellow': '#ffff00',
        // Difficulty badges
        'diff-beginner': '#22c55e',
        'diff-intermediate': '#eab308',
        'diff-advanced': '#ef4444',
      },
      fontFamily: {
        'mono': ['JetBrains Mono', 'Fira Code', 'Monaco', 'Consolas', 'monospace'],
        'sans': ['Inter', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(255, 255, 255, 0.1)' },
          '100%': { boxShadow: '0 0 20px rgba(255, 255, 255, 0.2)' },
        },
      },
    },
  },
  plugins: [],
}
