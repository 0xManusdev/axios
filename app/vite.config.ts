import { defineConfig } from "vite";

export default defineConfig({
  clearScreen: false,
  server: { port: 1420, strictPort: true, host: "localhost" },
  build: { outDir: "dist", emptyOutDir: true, target: "es2022" },
});
