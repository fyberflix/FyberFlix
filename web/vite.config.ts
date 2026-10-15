import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In dev, the browser talks only to this server; /v1 is forwarded to the gateway,
// so there is no CORS to configure. In production a reverse proxy does the same.
const gateway = process.env.GATEWAY_URL ?? "http://127.0.0.1:8080";

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 5173,
    allowedHosts: [".app.github.dev", "localhost", "127.0.0.1"],
    proxy: {
      "/v1": gateway,
      "/.well-known": gateway,
    },
  },
  build: { sourcemap: true, target: "es2022" },
});
