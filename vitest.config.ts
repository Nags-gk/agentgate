import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    fileParallelism: false,
    testTimeout: 60_000,
    hookTimeout: 120_000,
    env: {
      PORT: process.env.TEST_PORT ?? "8799",
      PUBLIC_URL: `http://127.0.0.1:${process.env.TEST_PORT ?? "8799"}`,
      DATABASE_URL: process.env.TEST_DATABASE_URL ?? "postgresql://root@localhost:26257/agentgate_test?sslmode=disable",
      DEMO_MODE: "true",
      RATE_LIMIT_PER_MIN: "600",
    },
  },
});
