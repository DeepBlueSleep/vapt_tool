import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        surface: "#f7f8fb",
        ink: "#111827",
        accent: "#0f766e"
      }
    }
  },
  plugins: [require("@tailwindcss/forms")]
};

export default config;
