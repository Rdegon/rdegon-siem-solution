import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: true,
    fileParallelism: false,
    maxWorkers: 1,
    minWorkers: 1,
  },
});
