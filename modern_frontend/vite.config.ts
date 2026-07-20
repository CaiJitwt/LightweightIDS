import { loadEnv } from "vite";
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const environment = loadEnv(mode, ".", "");
  const apiTarget = environment.VITE_IDS_API_PROXY_TARGET;

  return {
    plugins: [react()],
    server: {
      host: "127.0.0.1",
      ...(apiTarget ? {
        proxy: {
          "/api": {
            target: apiTarget,
            changeOrigin: true,
          },
        },
      } : {}),
    },
    preview: {
      host: "127.0.0.1",
    },
    test: {
      environment: "jsdom",
      setupFiles: "./vitest.setup.ts",
      globals: true,
      exclude: ["e2e/**", "node_modules/**", "dist/**"],
    },
  };
});
