/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: { extend: {
    colors: { paper: "#F1F3F2", ink: "#17232B", harbor: "#123039", signal: "#0E7C86", line: "#D5DBDA",
      sev: { critical: "#9F1239", high: "#C2410C", medium: "#B7791F", low: "#2B6CB0", info: "#64748B" } },
    fontFamily: { sans: ['"IBM Plex Sans"', '"Segoe UI"', "system-ui", "sans-serif"], mono: ['"IBM Plex Mono"', "ui-monospace", "monospace"] },
  } },
  plugins: [],
};
