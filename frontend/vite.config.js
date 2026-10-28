import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    emptyOutDir: true,
    outDir: "../public",
  },
  server: {
    proxy: {
      "/webhook": "http://127.0.0.1:8000",
      "/analyze": "http://127.0.0.1:8000",
    },
  },
});
