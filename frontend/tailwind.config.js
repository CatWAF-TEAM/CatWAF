const themeColor = (name, fallback) => `var(${name}, ${fallback})`

export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cat: {
          bg:      themeColor('--cat-bg-final', 'var(--cat-bg)'),
          surface: themeColor('--cat-surface-final', 'var(--cat-surface)'),
          card:    themeColor('--cat-card-final', 'var(--cat-card)'),
          border:  themeColor('--cat-border-final', 'var(--cat-border)'),
          muted:   themeColor('--cat-muted', '#2a3045'),
          accent:  themeColor('--cat-accent', '#4f8ef7'),
          accentL: themeColor('--cat-accentL', '#6aa3ff'),
          green:   '#22d3a0',
          red:     '#f25c5c',
          orange:  '#f59e0b',
          purple:  '#a78bfa',
          text:    themeColor('--cat-text', '#e2e8f0'),
          sub:     themeColor('--cat-sub', '#7c8db0'),
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      animation: {
        'fade-in':   'fadeIn 0.25s ease',
        'slide-up':  'slideUp 0.3s cubic-bezier(0.16,1,0.3,1)',
        'slide-in':  'slideIn 0.3s cubic-bezier(0.16,1,0.3,1)',
        'pulse-dot': 'pulseDot 2s ease-in-out infinite',
        'shimmer':   'shimmer 1.5s infinite',
      },
      keyframes: {
        fadeIn:   { from: { opacity: 0 }, to: { opacity: 1 } },
        slideUp:  { from: { opacity: 0, transform: 'translateY(12px)' }, to: { opacity: 1, transform: 'translateY(0)' } },
        slideIn:  { from: { opacity: 0, transform: 'translateX(-10px)' }, to: { opacity: 1, transform: 'translateX(0)' } },
        pulseDot: { '0%,100%': { opacity: 1 }, '50%': { opacity: 0.3 } },
        shimmer:  { '0%': { backgroundPosition: '-200% 0' }, '100%': { backgroundPosition: '200% 0' } },
      },
    }
  },
  plugins: []
}
