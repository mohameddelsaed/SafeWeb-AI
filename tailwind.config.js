/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    safelist: [
        'glitch-text',
        'glitch-active',
        'btn-border-trace',
        'typewriter-cursor',
        'typewriter-wrapper',
        'typewriter-track',
        'typewriter-text',
        'typewriter-cursor--hidden',
        'animate-page-enter',
        'animate-badge-pulse-green',
        'animate-badge-pulse-yellow',
        'animate-badge-pulse-orange',
        'animate-badge-pulse-red',
    ],
    darkMode: 'class',
    theme: {
        extend: {
            colors: {
                // Background colors
                'bg-primary': 'rgb(var(--bg-primary) / <alpha-value>)',
                'bg-secondary': 'rgb(var(--bg-secondary) / <alpha-value>)',
                'bg-tertiary': 'rgb(var(--bg-tertiary) / <alpha-value>)',
                'bg-card': 'rgb(var(--bg-card) / <alpha-value>)',
                'bg-hover': 'rgb(var(--bg-hover) / <alpha-value>)',

                // Accent colors
                'accent-green': 'rgb(var(--accent-green) / <alpha-value>)',
                'accent-green-hover': '#00E67A',
                'accent-blue': 'rgb(var(--accent-blue) / <alpha-value>)',
                'accent-blue-hover': '#2E95E8',

                // Status colors
                'status-critical': '#FF3B3B',
                'status-high': '#FF8A3D',
                'status-medium': '#FFD93D',
                'status-low': '#6BCF7F',
                'status-info': '#3AA9FF',

                // Text colors
                'text-primary': 'rgb(var(--text-primary) / <alpha-value>)',
                'text-secondary': 'rgb(var(--text-secondary) / <alpha-value>)',
                'text-tertiary': 'rgb(var(--text-tertiary) / <alpha-value>)',
                'text-muted': 'rgb(var(--text-muted) / <alpha-value>)',

                // Border colors
                'border-primary': 'rgb(var(--border-primary) / <alpha-value>)',
                'border-secondary': 'rgb(var(--border-secondary) / <alpha-value>)',
                'border-accent': 'rgb(var(--accent-green) / <alpha-value>)',
            },
            fontFamily: {
                'sans': ['Cairo', 'Inter', 'system-ui', 'sans-serif'],
                'heading': ['Cairo', 'Space Grotesk', 'Inter', 'sans-serif'],
                'mono': ['JetBrains Mono', 'Fira Code', 'monospace'],
            },
            maxWidth: {
                'container': '1200px',
                'content': '720px',
            },
            spacing: {
                'header': '80px',
            },
            animation: {
                'glow': 'glow 2s ease-in-out infinite alternate',
                'float': 'float 3s ease-in-out infinite',
                'terminal-blink': 'blink 1s step-end infinite',
                'page-enter': 'page-enter 0.5s cubic-bezier(0, 0, 0.2, 1) both',
                'badge-pulse-green': 'badge-pulse-green 3s ease-in-out infinite',
                'badge-pulse-yellow': 'badge-pulse-yellow 3s ease-in-out infinite',
                'badge-pulse-orange': 'badge-pulse-orange 2.5s ease-in-out infinite',
                'badge-pulse-red': 'badge-pulse-red 2.8s ease-in-out infinite',
            },
            keyframes: {
                glow: {
                    '0%': { boxShadow: '0 0 5px rgba(0, 255, 136, 0.2), 0 0 10px rgba(0, 255, 136, 0.1)' },
                    '100%': { boxShadow: '0 0 10px rgba(0, 255, 136, 0.4), 0 0 20px rgba(0, 255, 136, 0.2)' },
                },
                float: {
                    '0%, 100%': { transform: 'translateY(0px)' },
                    '50%': { transform: 'translateY(-10px)' },
                },
                blink: {
                    '0%, 100%': { opacity: '1' },
                    '50%': { opacity: '0' },
                },
                'page-enter': {
                    '0%': { opacity: '0', transform: 'translateY(8px)' },
                    '100%': { opacity: '1', transform: 'translateY(0)' },
                },
                'badge-pulse-green': {
                    '0%, 100%': { boxShadow: '0 0 2px rgba(107, 207, 127, 0.2)' },
                    '50%': { boxShadow: '0 0 8px rgba(107, 207, 127, 0.4)' },
                },
                'badge-pulse-yellow': {
                    '0%, 100%': { boxShadow: '0 0 2px rgba(255, 217, 61, 0.2)' },
                    '50%': { boxShadow: '0 0 8px rgba(255, 217, 61, 0.35)' },
                },
                'badge-pulse-orange': {
                    '0%, 100%': { boxShadow: '0 0 3px rgba(255, 138, 61, 0.2)' },
                    '50%': { boxShadow: '0 0 10px rgba(255, 138, 61, 0.4)' },
                },
                'badge-pulse-red': {
                    '0%, 100%': { boxShadow: '0 0 3px rgba(255, 59, 59, 0.2)' },
                    '50%': { boxShadow: '0 0 10px rgba(255, 59, 59, 0.4)' },
                },
            },
            boxShadow: {
                'glow-green': '0 0 15px rgba(0, 255, 136, 0.3)',
                'glow-blue': '0 0 15px rgba(58, 169, 255, 0.3)',
                'card': '0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 2px 4px -1px rgba(0, 0, 0, 0.2)',
                'card-hover': '0 10px 15px -3px rgba(0, 0, 0, 0.4), 0 4px 6px -2px rgba(0, 0, 0, 0.3)',
            },
        },
    },
    plugins: [],
}
