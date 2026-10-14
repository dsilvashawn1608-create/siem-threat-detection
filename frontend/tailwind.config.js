/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        console: {
          bg: "#0a0e14",
          panel: "#10151f",
          border: "#1f2a3a",
          text: "#c9d6e3",
          dim: "#5c6b7e",
          accent: "#00e0a0",
          warn: "#f0b429",
          crit: "#ff4d6d",
          high: "#ff8f4d",
          med: "#f0d429",
          low: "#4da3ff",
        },
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
};
