import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The build lands directly in the backend's static directory, which app/main.py
// mounts when it exists. One artefact, one origin, no CORS in production.
// Resolved relative to this config file's directory.
const outDir = "../backend/app/static";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir,
    emptyOutDir: true,
    sourcemap: false,
    // The CSP allows 'self' scripts only, so nothing may be inlined.
    assetsInlineLimit: 0,
  },
  server: {
    port: 5173,
    proxy: {
      // Dev server talks to a locally running backend. Cookies are same-site
      // because the proxy keeps everything on one origin.
      "/api": { target: "http://127.0.0.1:8000", changeOrigin: false },
      "/healthz": { target: "http://127.0.0.1:8000", changeOrigin: false },
    },
  },
});
